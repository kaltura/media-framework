#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_ts_avc.h>
#include <ngx_kmp_push_track.h>
#include <ngx_kmp_push_track_internal.h>
#include <ngx_kmp_push_utils.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_ts_kmp_track.h"


#define NGX_TS_KMP_MAX_FRAME_NALS  16
#define NGX_TS_KMP_CAPTION_TRIES   10

#define NGX_TS_TIMESCALE           90000

#define NGX_TS_AVC_NAL_IDR         5
#define NGX_TS_AVC_NAL_SEI         6
#define NGX_TS_AVC_NAL_SPS         7
#define NGX_TS_AVC_NAL_PPS         8
#define NGX_TS_AVC_NAL_AUD         9

#define NGX_TS_AAC_FRAME_SAMPLES   1024


#define ngx_ts_aac_adts_frame_len(h)                                         \
     (((h)[3] & 0b11) << 11) | ((h)[4] << 3) | ((h)[5] >> 5)

#define ngx_ts_kmp_write_be32(p, dw) {                                       \
        (p)[0] = ((dw) >> 24) & 0xff;                                        \
        (p)[1] = ((dw) >> 16) & 0xff;                                        \
        (p)[2] = ((dw) >> 8) & 0xff;                                         \
        (p)[3] = (dw) & 0xff;                                                \
    }


typedef struct {
    ngx_str_t                stream_id;
    uint32_t                 pid;
    uint32_t                 index;
    uint32_t                 prog_num;
} ngx_ts_kmp_publish_t;


typedef struct {
    ngx_chain_t             *cl;
    u_char                  *pos;
    uint32_t                 size;
    u_char                   type;
} ngx_ts_kmp_avc_nalu_t;


typedef struct {
    ngx_ts_kmp_avc_nalu_t    elts[NGX_TS_KMP_MAX_FRAME_NALS];
    ngx_uint_t               nelts;
    uint32_t                 types;
} ngx_ts_kmp_avc_nalu_arr_t;


typedef struct {
    u_char                   version;
    u_char                   profile;
    u_char                   compatibility;
    u_char                   level;
    u_char                   nula_length_size;
} ngx_ts_kmp_avcc_config_t;


#include "ngx_ts_kmp_track_json.h"


static int
ngx_ts_kmp_compare_chain(u_char *ref, ngx_chain_t *cl, u_char *src_pos,
    size_t size)
{
    int         rc;
    size_t      src_left;
    ngx_buf_t  *src;

    src = cl->buf;

    for ( ;; ) {

        src_left = src->last - src_pos;
        if (size <= src_left) {
            return ngx_memcmp(ref, src_pos, size);
        }

        rc = ngx_memcmp(ref, src_pos, src_left);
        if (rc != 0) {
            return rc;
        }

        ref += src_left;
        size -= src_left;

        cl = cl->next;
        src = cl->buf;
        src_pos = src->pos;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_copy_chain(ngx_pool_t *pool, ngx_buf_t *dst, ngx_chain_t *cl,
    u_char *src_pos, size_t size)
{
    size_t      src_left;
    size_t      dst_size;
    size_t      alloc_size;
    ngx_buf_t  *src;

    dst_size = dst->end - dst->start;
    if (size > dst_size) {
        alloc_size = ngx_max(size, dst_size * 2);
        dst->start = ngx_pnalloc(pool, alloc_size);
        if (dst->start == NULL) {
            return NGX_ERROR;
        }

        dst->end = dst->start + alloc_size;
        dst->pos = dst->start;
    }

    dst->last = dst->start;

    src = cl->buf;

    for ( ;; ) {

        src_left = src->last - src_pos;
        if (size <= src_left) {
            dst->last = ngx_copy(dst->last, src_pos, size);
            break;
        }

        dst->last = ngx_copy(dst->last, src_pos, src_left);
        size -= src_left;

        cl = cl->next;
        src = cl->buf;
        src_pos = src->pos;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_write_chain(ngx_kmp_push_track_t *track,
    ngx_chain_t *cl, u_char *pos, size_t size)
{
    size_t      left;
    ngx_buf_t  *buf;

    buf = cl->buf;

    for ( ;; ) {

        left = buf->last - pos;
        if (size <= left) {
            if (ngx_kmp_push_track_write_frame_data(track, pos, size)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_ts_kmp_track_write_chain: write failed (1)");
                return NGX_ERROR;
            }

            break;
        }

        if (ngx_kmp_push_track_write_frame_data(track, pos, left)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_ts_kmp_track_write_chain: write failed (2)");
            return NGX_ERROR;
        }

        size -= left;

        cl = cl->next;
        buf = cl->buf;
        pos = buf->pos;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_handle_media_info(ngx_ts_kmp_track_t *ts_track)
{
    ngx_int_t              rc;
    ngx_kmp_push_track_t  *track;

    if (!ts_track->media_info_sent) {
        track = ts_track->track;

        rc = ngx_kmp_push_track_write_media_info(track);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_ts_kmp_track_handle_media_info: send media info failed");
            return NGX_ERROR;
        }

        ts_track->media_info_sent = 1;
    }

    if (!ts_track->published) {
        track = ts_track->track;

        if (ngx_kmp_push_track_publish(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_ts_kmp_track_handle_media_info: publish failed");
            return NGX_ERROR;
        }

        ts_track->published = 1;
    }

    return NGX_OK;
}


static void
ngx_ts_kmp_track_init_frame(ngx_ts_kmp_track_t *ts_track,
    kmp_frame_packet_t *frame, int is_key_frame, int64_t pts, int64_t dts)
{
    ngx_kmp_push_track_t  *track = ts_track->track;

    ngx_memzero(frame, sizeof(*frame));
    frame->header.packet_type = KMP_PACKET_FRAME;
    frame->header.header_size = sizeof(*frame);

    if (track->media_info.media_type == KMP_MEDIA_VIDEO) {
        if (is_key_frame) {
            frame->f.flags |= KMP_FRAME_FLAG_KEY;
        }

        frame->f.pts_delay = pts - dts;
    }

    /* created */
    frame->f.created = ngx_kmp_push_track_get_time(track);

    /* dts */
    if (!ts_track->timestamps_synced) {
        ts_track->timestamps_synced = 1;
        ts_track->timestamp = dts;
        ts_track->last_timestamp = dts;

    } else {
        /* handle 33 bit wrap around */
        ts_track->timestamp += (dts - ts_track->last_timestamp)
            & ((1LL << 33) - 1);
        ts_track->last_timestamp = dts;
    }

    track->stats.last_timestamp = ts_track->timestamp;
    frame->f.dts = ts_track->timestamp;
}


/* avc */

static ngx_int_t
ngx_ts_kmp_track_avc_handle_nalu(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_kmp_avc_nalu_t *nalu)
{
    ngx_buf_t             *dst;
    ngx_kmp_push_track_t  *track;

    switch (nalu->type) {

    case NGX_TS_AVC_NAL_SEI:
        if (ts_track->caption_tries <= 0) {
            return NGX_OK;
        }

        track = ts_track->track;
        if (ngx_ts_avc_sei_detect_cea(&track->log, nalu->cl, nalu->pos,
            nalu->size))
        {
            track->media_info.u.video.cea_captions = 1;
            ts_track->caption_tries = 0;

        } else {
            ts_track->caption_tries--;
        }

        return NGX_OK;

    case NGX_TS_AVC_NAL_SPS:
        dst = &ts_track->sps;
        break;

    case NGX_TS_AVC_NAL_PPS:
        dst = &ts_track->pps;
        break;

    default:
        return NGX_OK;
    }

    if (nalu->size == dst->last - dst->pos &&
        ngx_ts_kmp_compare_chain(dst->pos, nalu->cl, nalu->pos,
            nalu->size) == 0)
    {
        return NGX_OK;
    }

    ts_track->media_info_sent = 0;

    return ngx_ts_kmp_copy_chain(ts_track->track->pool, dst,
        nalu->cl, nalu->pos, nalu->size);
}


static ngx_int_t
ngx_ts_kmp_track_avc_init_nalu_array(ngx_ts_kmp_track_t *ts_track,
    ngx_chain_t *chain, ngx_ts_kmp_avc_nalu_arr_t *out)
{
    u_char                 *p, *pos, *last;
    int32_t                 start, offset;
    uint32_t                base;
    uint32_t                zero_count;
    ngx_chain_t            *cl;
    ngx_ts_kmp_avc_nalu_t  *nalu;

    base = 0;
    start = -1;
    zero_count = 0;
    nalu = out->elts;
    out->types = 0;

    for (cl = chain; cl; cl = cl->next) {

        pos = cl->buf->pos;
        last = cl->buf->last;
        for (p = pos; p < last; p++) {
            if (*p == 0) {
                zero_count++;
                continue;

            } else if (zero_count < 2 || *p != 1) {
                zero_count = 0;
                continue;
            }

            offset = base + p - pos;

            if (start >= 0) {
                nalu->size = offset - zero_count - start;
                if (ngx_ts_kmp_track_avc_handle_nalu(ts_track, nalu)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                nalu++;
                start = -1;
            }

            if (p + 1 >= last && cl->next == NULL) {
                break;
            }

            if (nalu >= out->elts + NGX_TS_KMP_MAX_FRAME_NALS) {
                ngx_log_error(NGX_LOG_ERR, &ts_track->track->log, 0,
                    "ngx_ts_kmp_track_avc_init_nalu_array: "
                    "nal count exceeds limit");
                return NGX_ERROR;
            }

            if (p + 1 < last) {
                nalu->cl = cl;
                nalu->pos = p + 1;

            } else {
                nalu->cl = cl->next;
                nalu->pos = cl->next->buf->pos;
            }

            nalu->type = *nalu->pos & 0x1f;
            out->types |= 1 << nalu->type;

            start = offset + 1;
            zero_count = 0;
        }

        base += last - pos;
    }

    if (start >= 0) {
        nalu->size = base - start;
        if (ngx_ts_kmp_track_avc_handle_nalu(ts_track, nalu) != NGX_OK) {
            return NGX_ERROR;
        }

        nalu++;
    }

    out->nelts = nalu - out->elts;
    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_avc_update_media_info(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_stream_t *ts)
{
    size_t                 sps_size;
    size_t                 pps_size;
    size_t                 extra_data_size;
    u_char                *p;
    ngx_str_t             *extra_data;
    ngx_ts_avc_params_t    avc_params;
    ngx_kmp_push_track_t  *track = ts_track->track;

    sps_size = ts_track->sps.last - ts_track->sps.pos;
    pps_size = ts_track->pps.last - ts_track->pps.pos;

    if (ngx_ts_avc_decode_params(&avc_params, ts,
        ts_track->sps.pos, sps_size, ts_track->pps.pos, pps_size) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_ts_kmp_track_avc_update_media_info: decode failed");
        return NGX_ERROR;
    }

    track->media_info.u.video.width = avc_params.width;
    track->media_info.u.video.height = avc_params.height;

    /* not setting bitrate / frame rate */
    track->media_info.bitrate = 0;
    track->media_info.u.video.frame_rate.num = 0;
    track->media_info.u.video.frame_rate.denom = 1;

    extra_data = &track->extra_data;

    extra_data_size = sizeof(ngx_ts_kmp_avcc_config_t)
        + 1 + 2 + sps_size      /* sps */
        + 1 + 2 + pps_size;     /* pps */

    if (ngx_kmp_push_track_alloc_extra_data(track, extra_data_size)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = extra_data->data;

    *p++ = 1;               /* version */
    *p++ = avc_params.profile_idc;
    *p++ = avc_params.constraints;
    *p++ = avc_params.level_idc;
    *p++ = 0xff;            /* nula_length_size = 4 */

    *p++ = 0xe0 | 0x01;     /* sps count */
    *p++ = (u_char) (sps_size >> 8);
    *p++ = (u_char) sps_size;
    p = ngx_copy(p, ts_track->sps.pos, sps_size);

    *p++ = 1;               /* pps count */
    *p++ = (u_char) (pps_size >> 8);
    *p++ = (u_char) pps_size;
    p = ngx_copy(p, ts_track->pps.pos, pps_size);

    extra_data->len = p - extra_data->data;

    if (extra_data->len > extra_data_size) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_ts_kmp_track_avc_update_media_info: "
            "result length %uz greater than allocated length %uz",
            extra_data->len, extra_data_size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_avc_write_frame(ngx_ts_kmp_track_t *ts_track,
    kmp_frame_packet_t *frame, ngx_ts_kmp_avc_nalu_arr_t *nalus)
{
    u_char                  len_buf[4];
    uint32_t                i;
    ngx_kmp_push_track_t   *track = ts_track->track;
    ngx_ts_kmp_avc_nalu_t  *nalu;

    if (ngx_kmp_push_track_write_frame_start(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_ts_kmp_track_avc_write_frame: start frame failed");
        return NGX_ERROR;
    }

    for (i = 0; i < nalus->nelts; i++) {

        nalu = &nalus->elts[i];
        switch (nalu->type) {

        case NGX_TS_AVC_NAL_SPS:
        case NGX_TS_AVC_NAL_PPS:
        case NGX_TS_AVC_NAL_AUD:
            continue;

        default:
            break;
        }

        ngx_ts_kmp_write_be32(len_buf, nalu->size);

        if (ngx_kmp_push_track_write_frame_data(track,
            len_buf, sizeof(len_buf)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_ts_kmp_track_avc_write_frame: write data failed");
            return NGX_ERROR;
        }

        if (ngx_ts_kmp_track_write_chain(track, nalu->cl, nalu->pos,
            nalu->size) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_kmp_push_track_write_frame_end(track, frame) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_ts_kmp_track_avc_write_frame: end frame failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_avc_pes_handler(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_handler_data_t *hd)
{
    ngx_flag_t                  is_key_frame;
    ngx_ts_es_t                *es = hd->es;
    kmp_frame_packet_t          frame;
    ngx_ts_kmp_avc_nalu_arr_t   nalus;

    if (ngx_ts_kmp_track_avc_init_nalu_array(ts_track, hd->bufs, &nalus)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (!ts_track->media_info_sent) {
        if (ts_track->sps.pos >= ts_track->sps.last ||
            ts_track->pps.pos >= ts_track->pps.last)
        {
            ngx_log_error(NGX_LOG_WARN, &ts_track->track->log, 0,
                "ngx_ts_kmp_track_avc_pes_handler: "
                "skipping frame, no sps/pps");
            return NGX_OK;
        }

        if (ngx_ts_kmp_track_avc_update_media_info(ts_track, hd->ts)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ts_kmp_track_handle_media_info(ts_track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &ts_track->track->log, 0,
                "ngx_ts_kmp_track_avc_pes_handler: handle media info failed");
            return NGX_ERROR;
        }
    }

    is_key_frame = nalus.types & (1 << NGX_TS_AVC_NAL_IDR);

    ngx_ts_kmp_track_init_frame(ts_track, &frame, is_key_frame,
        es->pts, es->dts);

    if (ngx_ts_kmp_track_avc_write_frame(ts_track, &frame, &nalus)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* aac */

static ngx_int_t
ngx_ts_kmp_track_aac_update_media_info(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_stream_t *ts, u_char *hdr)
{
    u_char                *p;
    ngx_str_t             *extra_data;
    kmp_media_info_t      *media_info;
    ngx_ts_aac_params_t    aac_params;
    ngx_kmp_push_track_t  *track;

    track = ts_track->track;

    if (ngx_ts_aac_decode_params(&aac_params, ts, hdr, NGX_TS_AAC_ADTS_LEN)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_ts_kmp_track_aac_update_media_info: decode failed");
        return NGX_ERROR;
    }

    if (ngx_memcmp(&ts_track->last_aac_params, &aac_params, sizeof(aac_params))
        == 0)
    {
        return NGX_OK;
    }

    ts_track->last_aac_params = aac_params;

    media_info = &track->media_info;

    media_info->bitrate = 0;
    media_info->u.audio.sample_rate = aac_params.freq;
    media_info->u.audio.bits_per_sample = 16;
    media_info->u.audio.channels = aac_params.chan;
    media_info->u.audio.channel_layout = aac_params.chan == 1 ?
        KMP_CH_LAYOUT_MONO : KMP_CH_LAYOUT_STEREO;

    extra_data = &ts_track->track->extra_data;
    extra_data->len = 2;

    if (ngx_kmp_push_track_alloc_extra_data(track, extra_data->len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = extra_data->data;

    p[0] = (aac_params.profile << 3)
        | (aac_params.freq_index >> 1);
    p[1] = (aac_params.freq_index << 7)
        | (aac_params.chan << 3);

    ts_track->media_info_sent = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_aac_pes_handler(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_handler_data_t *hd)
{
    size_t                 buf_left;
    u_char                *pos, *dst;
    u_char                *header;
    u_char                 header_buf[NGX_TS_AAC_ADTS_CRC_LEN];
    uint32_t               left;
    uint32_t               header_len;
    uint64_t               dts;
    ngx_buf_t             *buf;
    ngx_uint_t             index = 0;
    ngx_chain_t           *cl;
    ngx_ts_stream_t       *ts = hd->ts;
    kmp_frame_packet_t     frame;
    ngx_kmp_push_track_t  *track = ts_track->track;

    cl = hd->bufs;
    buf = cl->buf;
    pos = buf->pos;

    header_len = left = NGX_TS_AAC_ADTS_LEN;
    dst = header_buf;

    for ( ;; ) {

        /* adts header */
        for ( ;; ) {

            buf_left = buf->last - pos;
            if (buf_left < left) {
                dst = ngx_copy(dst, pos, buf_left);
                left -= buf_left;

                cl = cl->next;
                if (cl == NULL) {
                    if (dst == header_buf) {
                        return NGX_OK;
                    }

                    ngx_log_error(NGX_LOG_ERR, &track->log, 0,
                        "ngx_ts_kmp_track_aac_pes_handler: "
                        "truncated adts header");
                    return NGX_ERROR;
                }

                buf = cl->buf;
                pos = buf->pos;
                continue;
            }

            if (dst == header_buf) {
                if (!(pos[1] & 0x01) && header_len == NGX_TS_AAC_ADTS_LEN) {
                    header_len = NGX_TS_AAC_ADTS_CRC_LEN;
                    left = NGX_TS_AAC_ADTS_CRC_LEN;
                    continue;
                }

                header = pos;
                pos += left;

            } else {
                ngx_memcpy(dst, pos, left);
                pos += left;

                if (!(header_buf[1] & 0x01) &&
                    header_len == NGX_TS_AAC_ADTS_LEN)
                {
                    dst += left;
                    header_len = NGX_TS_AAC_ADTS_CRC_LEN;
                    left = NGX_TS_AAC_ADTS_CRC_LEN - NGX_TS_AAC_ADTS_LEN;
                    continue;
                }

                dst = header_buf;
                header = header_buf;
            }

            if (ngx_ts_kmp_track_aac_update_media_info(ts_track, ts, header)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ngx_ts_kmp_track_handle_media_info(ts_track) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_ts_kmp_track_aac_pes_handler: "
                    "handle media info failed");
                return NGX_ERROR;
            }

            if (ngx_kmp_push_track_write_frame_start(track) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_ts_kmp_track_aac_pes_handler: start frame failed");
                return NGX_ERROR;
            }

            left = ngx_ts_aac_adts_frame_len(header);
            if (left < header_len) {
                ngx_log_error(NGX_LOG_ERR, &track->log, 0,
                    "ngx_ts_kmp_track_aac_pes_handler: "
                    "invalid adts frame size %uD", left);
                return NGX_ERROR;
            }

            left -= header_len;

            break;
        }

        /* aac data */
        for ( ;; ) {

            buf_left = buf->last - pos;
            if (buf_left < left) {
                if (ngx_kmp_push_track_write_frame_data(track, pos, buf_left)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_ts_kmp_track_aac_pes_handler: "
                        "write data failed (1)");
                    return NGX_ERROR;
                }

                left -= buf_left;

                cl = cl->next;
                if (cl == NULL) {
                    ngx_log_error(NGX_LOG_ERR, &track->log, 0,
                        "ngx_ts_kmp_track_aac_pes_handler: "
                        "truncated adts packet");
                    return NGX_ERROR;
                }

                buf = cl->buf;
                pos = buf->pos;
                continue;
            }

            if (ngx_kmp_push_track_write_frame_data(track, pos, left)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_ts_kmp_track_aac_pes_handler: write data failed (2)");
                return NGX_ERROR;
            }

            pos += left;

            dts = hd->es->pts + NGX_TS_TIMESCALE * NGX_TS_AAC_FRAME_SAMPLES
                * index++ / track->media_info.u.audio.sample_rate;

            ngx_ts_kmp_track_init_frame(ts_track, &frame, 0, dts, dts);

            if (ngx_kmp_push_track_write_frame_end(track, &frame) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_ts_kmp_track_aac_pes_handler: end frame failed");
                return NGX_ERROR;
            }

            header_len = left = NGX_TS_AAC_ADTS_LEN;

            break;
        }
    }
}


/* main */

static ngx_int_t
ngx_ts_kmp_track_init_json_info(ngx_kmp_push_track_t *track,
    ngx_ts_kmp_publish_t *publish, ngx_ts_stream_t *ts)
{
    u_char  *p;
    size_t   size;

    size = ngx_ts_kmp_track_json_get_size(publish, ts->connection);

    p = ngx_pnalloc(track->pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    track->json_info.data = p;
    p = ngx_ts_kmp_track_json_write(p, publish, ts->connection);
    track->json_info.len = p - track->json_info.data;

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_track_init_input_id(ngx_kmp_push_track_t *track,
    ngx_ts_kmp_publish_t *publish)
{
    u_char  *p;

    p = ngx_pnalloc(track->pool, publish->stream_id.len + 1 + NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    track->input_id.data = p;
    p = ngx_copy(p, publish->stream_id.data, publish->stream_id.len);
    p = ngx_sprintf(p, "_%uD", publish->pid);
    track->input_id.len = p - track->input_id.data;

    return NGX_OK;
}


ngx_ts_kmp_track_t *
ngx_ts_kmp_track_get(ngx_ts_kmp_ctx_t *ctx, uint16_t pid)
{
    ngx_rbtree_t       *rbtree;
    ngx_rbtree_node_t  *node, *sentinel;

    rbtree = &ctx->rbtree;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        if (pid < node->key) {
            node = node->left;
            continue;
        }

        if (pid > node->key) {
            node = node->right;
            continue;
        }

        return (ngx_ts_kmp_track_t *) node;
    }

    return NULL;
}


static int32_t
ngx_ts_kmp_track_get_codec(u_char type)
{
    switch (type) {

    case NGX_TS_VIDEO_AVC:
        return KMP_CODEC_VIDEO_H264;

    case NGX_TS_AUDIO_AAC:
        return KMP_CODEC_AUDIO_AAC;

    default:
        return NGX_ERROR;
    }
}


static void
ngx_ts_kmp_track_error(void *arg)
{
    ngx_ts_kmp_ctx_t  *ctx = arg;

    ngx_log_error(NGX_LOG_NOTICE, ctx->connection->log, 0,
        "ngx_ts_kmp_track_error: called");
    ctx->error = 1;
}


ngx_int_t
ngx_ts_kmp_track_create(ngx_ts_handler_data_t *hd)
{
    int32_t                codec_id;
    ngx_uint_t             n;
    ngx_uint_t             media_type;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts = hd->ts;
    ngx_ts_program_t      *prog;
    ngx_ts_kmp_ctx_t      *ctx;
    ngx_ts_kmp_track_t    *ts_track;
    ngx_ts_kmp_publish_t   publish;
    ngx_kmp_push_track_t  *track;

    ctx = hd->data;
    prog = hd->prog;

    for (n = 0, es = prog->es; n < prog->nes; n++, es++) {

        codec_id = ngx_ts_kmp_track_get_codec(es->type);
        if (codec_id == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                "ngx_ts_kmp_track_create: invalid type %uD",
                (uint32_t) es->type);
            return NGX_ERROR;
        }

        ts_track = ngx_ts_kmp_track_get(ctx, es->pid);
        if (ts_track != NULL) {
            if (codec_id == (int32_t) ts_track->track->media_info.codec_id) {
                ngx_log_error(NGX_LOG_INFO, ts->log, 0,
                    "ngx_ts_kmp_track_create: got existing track, "
                    "pid: %uD, type: %uD",
                    (uint32_t) es->pid, (uint32_t) es->type);
                continue;
            }

            ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                "ngx_ts_kmp_track_create: track already exists, "
                "new_codec_id: %D, old_codec_id: %uD, pid: %uD",
                codec_id, ts_track->track->media_info.codec_id,
                (uint32_t) es->pid);
            return NGX_ERROR;
        }

        media_type = es->video ? KMP_MEDIA_VIDEO : KMP_MEDIA_AUDIO;

        track = ngx_kmp_push_track_create(&ctx->conf->t, media_type);
        if (track == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, ts->log, 0,
                "ngx_ts_kmp_track_create: create failed");
            return NGX_ERROR;
        }

        ts_track = ngx_pcalloc(track->pool, sizeof(ngx_ts_kmp_track_t));
        if (ts_track == NULL) {
            goto failed;
        }

        track->ctx = ctx;
        track->handler = ngx_ts_kmp_track_error;

        track->log.connection = ctx->connection->number;
        ctx->track_index[media_type]++;

        publish.stream_id = ts->header;
        publish.pid = es->pid;
        publish.prog_num = prog->number;
        publish.index = ctx->track_index[media_type];

        if (ngx_ts_kmp_track_init_json_info(track, &publish, ts) != NGX_OK) {
            goto failed;
        }

        if (ngx_ts_kmp_track_init_input_id(track, &publish) != NGX_OK) {
            goto failed;
        }

        track->media_info.codec_id = codec_id;

        ts_track->track = track;
        ts_track->caption_tries = NGX_TS_KMP_CAPTION_TRIES;
        ts_track->in.key = es->pid;
        ngx_rbtree_insert(&ctx->rbtree, &ts_track->in);
        ngx_queue_insert_tail(&ctx->tracks, &ts_track->queue);
    }

    return NGX_OK;

failed:

    ngx_kmp_push_track_detach(track, "");

    return NGX_ERROR;
}


ngx_int_t
ngx_ts_kmp_track_pes_handler(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_handler_data_t *hd)
{
    ngx_kmp_push_track_t  *track;

    track = ts_track->track;

    if (track->state == NGX_KMP_TRACK_INACTIVE) {
        return NGX_OK;
    }

    switch (track->media_info.media_type) {

    case KMP_MEDIA_VIDEO:
        return ngx_ts_kmp_track_avc_pes_handler(ts_track, hd);

    case KMP_MEDIA_AUDIO:
        return ngx_ts_kmp_track_aac_pes_handler(ts_track, hd);
    }

    return NGX_ERROR;
}
