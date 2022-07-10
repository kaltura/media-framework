#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>

#include <ngx_live_kmp.h>
#include "ngx_kmp_push_track_internal.h"
#include "ngx_kmp_push_utils.h"
#include "ngx_rtmp_kmp_track.h"

#include "ngx_rtmp_kmp_track_json.h"


#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)


/* RTMP definitions */
#define NGX_RTMP_AAC_SEQUENCE_HEADER     (0)
#define NGX_RTMP_AAC_RAW                 (1)

#define NGX_RTMP_AVC_SEQUENCE_HEADER     (0)
#define NGX_RTMP_AVC_NALU                (1)
#define NGX_RTMP_AVC_END_OF_SEQUENCE     (2)

#define NGX_RTMP_KEY_FRAME               (1)
#define NGX_RTMP_INTER_FRAME             (2)


#define NGX_RTMP_KMP_AUDIO_CODEC_BASE    (1000)


typedef struct {
    ngx_rtmp_session_t  *s;
    int64_t              timestamp;
    int32_t              last_timestamp;
    unsigned             timestamps_synced:1;
    unsigned             media_info_sent:1;
    unsigned             published:1;
} ngx_rtmp_kmp_track_ctx_t;


static ngx_str_t ngx_rtmp_kmp_media_types[KMP_MEDIA_COUNT] = {
    ngx_string("video"),
    ngx_string("audio"),
};


static void
ngx_rtmp_kmp_track_error(void *arg)
{
    ngx_rtmp_session_t        *s;
    ngx_rtmp_kmp_track_ctx_t  *ctx = arg;

    s = ctx->s;

    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
        "ngx_rtmp_kmp_track_error: called");

    ngx_rtmp_finalize_session(s);
}

static ngx_int_t
ngx_rtmp_kmp_copy(ngx_log_t *log, void *dst, u_char **src, size_t n,
    ngx_chain_t **in)
{
    size_t   pn;
    u_char  *last;

    if (*in == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_copy: end of stream (1)");
        return NGX_ERROR;
    }

    for ( ;; ) {
        last = (*in)->buf->last;

        if ((size_t) (last - *src) >= n) {
            ngx_memcpy(dst, *src, n);

            *src += n;

            while (*src == last) {
                *in = (*in)->next;
                if (!*in) {
                    break;
                }

                *src = (*in)->buf->pos;
                last = (*in)->buf->last;
            }

            return NGX_OK;
        }

        pn = last - *src;
        dst = ngx_copy(dst, *src, pn);
        n -= pn;
        *in = (*in)->next;

        if (*in == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_rtmp_kmp_copy: end of stream (2)");
            return NGX_ERROR;
        }

        *src = (*in)->buf->pos;
    }
}

static ngx_int_t
ngx_rtmp_kmp_track_set_extra_data(ngx_kmp_push_track_t *track,
    ngx_rtmp_session_t *s, ngx_chain_t *in, u_char *p, uint32_t size)
{
    size_t     alloc_size;
    ngx_int_t  rc;

    track->extra_data.len = size;

    if (size <= 0) {
        return NGX_OK;
    }

    if (size > track->extra_data_size) {

        alloc_size = ngx_max(size, track->extra_data_size * 2);
        if (track->mem_left < alloc_size) {
            ngx_log_error(NGX_LOG_ERR, &track->log, 0,
                "ngx_rtmp_kmp_track_set_extra_data: "
                "memory limit exceeded");
            ngx_kmp_push_track_set_error_reason(track, "alloc_failed");
            return NGX_ERROR;
        }

        track->extra_data.data = ngx_pnalloc(track->pool, alloc_size);
        if (track->extra_data.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_set_extra_data: alloc failed");
            ngx_kmp_push_track_set_error_reason(track, "alloc_failed");
            return NGX_ERROR;
        }

        track->extra_data_size = alloc_size;
        track->mem_left -= alloc_size;
    }

    rc = ngx_rtmp_kmp_copy(&track->log, track->extra_data.data, &p, size, &in);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_set_extra_data: "
            "failed to read extra data");
        ngx_kmp_push_track_set_error_reason(track, "rtmp_bad_data");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_kmp_track_send_media_info(ngx_kmp_push_track_t *track,
    ngx_rtmp_session_t *s)
{
    int64_t                num;
    int64_t                denom;
    kmp_media_info_t      *media_info;
    ngx_rtmp_codec_ctx_t  *codec_ctx;

    codec_ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_rtmp_kmp_track_send_media_info: failed to get codec ctx");
        return NGX_ERROR;
    }

    /* Note: media_type and timescale were set by ngx_kmp_push_track_create */

    media_info = &track->media_info;

    ngx_memzero(&media_info->u, sizeof(media_info->u));

    switch (media_info->media_type) {

    case KMP_MEDIA_VIDEO:
        /* KMP video codec ids match NGX_RTMP_VIDEO_XXX */
        media_info->codec_id = codec_ctx->video_codec_id;
        media_info->bitrate = codec_ctx->video_data_rate * 1000;

        media_info->u.video.width = codec_ctx->width;
        media_info->u.video.height = codec_ctx->height;
        media_info->u.video.cea_captions = codec_ctx->video_captions;

        ngx_kmp_push_float_to_rational(codec_ctx->frame_rate, 1000000,
            &num, &denom);
        media_info->u.video.frame_rate.num = num;
        media_info->u.video.frame_rate.denom = denom;
        break;

    case KMP_MEDIA_AUDIO:
        /* KMP audio codec ids match NGX_RTMP_AUDIO_XXX + base */
        media_info->codec_id = NGX_RTMP_KMP_AUDIO_CODEC_BASE +
            codec_ctx->audio_codec_id;
        media_info->bitrate = codec_ctx->audio_data_rate * 1000;

        media_info->u.audio.sample_rate = codec_ctx->sample_rate;
        media_info->u.audio.bits_per_sample = codec_ctx->sample_size * 8;
        media_info->u.audio.channels = codec_ctx->audio_channels;
        media_info->u.audio.channel_layout = codec_ctx->audio_channels == 1 ?
            KMP_CH_LAYOUT_MONO : KMP_CH_LAYOUT_STEREO;
        break;
    }

    /* send the updated media info */
    if (ngx_kmp_push_track_write_media_info(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_send_media_info: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_kmp_track_init_frame(ngx_kmp_push_track_t *track,
    kmp_frame_packet_t *frame, ngx_rtmp_header_t *h, ngx_chain_t **in,
    u_char **src, ngx_flag_t *sequence_header)
{
    u_char                     frame_info;
    u_char                     packet_type;
    u_char                     codec_id;
    int32_t                    pts_delay;
    uint32_t                   rtmpscale;
    ngx_int_t                  rc;
    ngx_rtmp_kmp_track_ctx_t  *ctx = track->ctx;

    struct {
        u_char  packet_type;
        u_char  comp_time[3];
    } avc_header;

    *sequence_header = 0;

    rc = ngx_rtmp_kmp_copy(&track->log, &frame_info, src, 1, in);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_init_frame: failed to read frame info");
        ngx_kmp_push_track_set_error_reason(track, "rtmp_bad_data");
        return NGX_ERROR;
    }

    rtmpscale = track->media_info.timescale / NGX_RTMP_TIMESCALE;

    ngx_memzero(frame, sizeof(*frame));
    frame->header.data_size = h->mlen - sizeof(frame_info);
    frame->header.packet_type = KMP_PACKET_FRAME;
    frame->header.header_size = sizeof(*frame);

    switch (h->type) {

    case NGX_RTMP_MSG_VIDEO:
        codec_id = frame_info & 0x0f;

        if ((frame_info >> 4) == NGX_RTMP_KEY_FRAME) {
            frame->f.flags |= KMP_FRAME_FLAG_KEY;
        }

        if (codec_id != NGX_RTMP_VIDEO_H264) {
            break;
        }

        rc = ngx_rtmp_kmp_copy(&track->log, &avc_header, src,
            sizeof(avc_header), in);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_init_frame: failed to read avc header");
            ngx_kmp_push_track_set_error_reason(track, "rtmp_bad_data");
            return NGX_ERROR;
        }

        frame->header.data_size -= sizeof(avc_header);

        if (avc_header.packet_type == NGX_RTMP_AVC_SEQUENCE_HEADER) {
            *sequence_header = 1;
        }

        pts_delay =
            (avc_header.comp_time[0] << 16) |
            (avc_header.comp_time[1] << 8) |
             avc_header.comp_time[2];

        /* sign extend */
        if (pts_delay & 0x800000) {
            pts_delay |= 0xff000000;
        }

        frame->f.pts_delay = pts_delay * rtmpscale;
        break;

    case NGX_RTMP_MSG_AUDIO:
        codec_id = frame_info >> 4;
        if (codec_id != NGX_RTMP_AUDIO_AAC) {
            break;
        }

        rc = ngx_rtmp_kmp_copy(&track->log, &packet_type, src,
            sizeof(packet_type), in);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_init_frame: failed to read aac header");
            ngx_kmp_push_track_set_error_reason(track, "rtmp_bad_data");
            return NGX_ERROR;
        }

        frame->header.data_size -= sizeof(packet_type);

        if (packet_type == NGX_RTMP_AAC_SEQUENCE_HEADER) {
            *sequence_header = 1;
        }
        break;
    }

    if (*sequence_header || frame->header.data_size <= 0) {
        return NGX_OK;
    }

    /* created */
    frame->f.created = ngx_kmp_push_track_get_time(track);

    /* dts */
    if (!ctx->timestamps_synced) {
        ctx->timestamps_synced = 1;
        ctx->timestamp = h->timestamp;
        ctx->last_timestamp = h->timestamp;

    } else {
        /* handle 32 bit wrap around */
        ctx->timestamp += (int32_t) h->timestamp - ctx->last_timestamp;
        ctx->last_timestamp = h->timestamp;
    }

    track->stats.last_timestamp = ctx->timestamp;
    frame->f.dts = ctx->timestamp * rtmpscale;

    return NGX_OK;
}

#if (NGX_DEBUG)
static size_t
ngx_rtmp_kmp_get_chain_size(ngx_chain_t *in)
{
    size_t  result = 0;

    for (; in; in = in->next) {
        result += in->buf->last - in->buf->pos;
    }

    return result;
}
#endif

ngx_int_t
ngx_rtmp_kmp_track_av(ngx_kmp_push_track_t *track, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
#if (NGX_DEBUG)
    size_t                     size;
#endif
    u_char                    *p;
    ngx_int_t                  rc;
    ngx_flag_t                 sequence_header;
    kmp_frame_packet_t         frame;
    ngx_rtmp_kmp_track_ctx_t  *ctx;

    if (track->state == NGX_KMP_TRACK_INACTIVE) {
        return NGX_OK;
    }

#if (NGX_DEBUG)
    size = ngx_rtmp_kmp_get_chain_size(in);
    if (size != h->mlen) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_rtmp_kmp_track_av: "
            "chain size %uz doesn't match packet size %uD",
            size, h->mlen);
        return NGX_ERROR;
    }
#endif

    ctx = track->ctx;
    p = in->buf->pos;

    if (ngx_rtmp_kmp_track_init_frame(track, &frame, h, &in, &p,
        &sequence_header) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_av: init frame failed");
        return NGX_ERROR;
    }

    if (sequence_header) {
        rc = ngx_rtmp_kmp_track_set_extra_data(track, ctx->s, in, p,
            frame.header.data_size);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_av: set extra data failed");
            return NGX_ERROR;
        }

        ctx->media_info_sent = 0;    /* force resend */
        return NGX_OK;
    }

    if (frame.header.data_size <= 0) {
        return NGX_OK;
    }

    if (!ctx->media_info_sent) {
        /* update and send the media info */
        rc = ngx_rtmp_kmp_track_send_media_info(track, ctx->s);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_av: send media info failed");
            return NGX_ERROR;
        }

        ctx->media_info_sent = 1;
    }

    if (!ctx->published) {
        if (ngx_kmp_push_track_publish(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_av: publish failed");
            return NGX_ERROR;
        }

        ctx->published = 1;
    }

    /* send the frame */
    if (ngx_kmp_push_track_write_frame(track, &frame, in, p) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_av: write frame failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_kmp_push_track_t *
ngx_rtmp_kmp_track_create(ngx_kmp_push_track_conf_t *conf,
    ngx_rtmp_session_t *s, ngx_rtmp_kmp_publish_t  *publish,
    ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    u_char                    *p;
    size_t                     json_len;
    size_t                     input_id_len;
    ngx_str_t                  media_type_str;
    ngx_uint_t                 media_type;
    ngx_kmp_push_track_t      *track;
    ngx_rtmp_kmp_track_ctx_t  *ctx;

    media_type = h->type == NGX_RTMP_MSG_VIDEO ? KMP_MEDIA_VIDEO :
        KMP_MEDIA_AUDIO;

    track = ngx_kmp_push_track_create(conf, media_type);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_track_create: create failed");
        return NULL;
    }

    track->log.connection = s->connection->number;

    media_type_str = ngx_rtmp_kmp_media_types[media_type];
    input_id_len = s->tc_url.len + publish->name.len +
        media_type_str.len + sizeof("//") - 1;

    json_len = ngx_rtmp_kmp_track_json_get_size(s, publish);

    ctx = ngx_palloc(track->pool, sizeof(*ctx) + input_id_len + json_len);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_create: alloc failed");
        ngx_kmp_push_track_detach(track, "create_track_failed");
        return NULL;
    }

    /* init ctx */
    ngx_memzero(ctx, sizeof(*ctx));
    ctx->s = s;

    track->ctx = ctx;
    track->handler = ngx_rtmp_kmp_track_error;

    p = (void *) (ctx + 1);

    /* set the input id */
    track->input_id.data = p;
    p = ngx_copy_str(track->input_id.data, s->tc_url);
    *p++ = '/';
    p = ngx_copy_str(p, publish->name);
    *p++ = '/';
    p = ngx_copy_str(p, media_type_str);
    track->input_id.len = p - track->input_id.data;

    /* build the json info */
    track->json_info.data = p;
    p = ngx_rtmp_kmp_track_json_write(p, s, publish);
    track->json_info.len = p - track->json_info.data;

    if (track->json_info.len > json_len) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_rtmp_kmp_track_create: "
            "json length %uz greater than allocated length %uz",
            track->json_info.len, json_len);
        ngx_kmp_push_track_detach(track, "create_track_failed");
        return NULL;
    }

    return track;
}
