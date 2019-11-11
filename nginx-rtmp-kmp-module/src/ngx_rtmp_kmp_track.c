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
} ngx_rtmp_kmp_track_ctx_t;


static ngx_str_t ngx_rtmp_kmp_media_types[KMP_MEDIA_COUNT] = {
    ngx_string("video"),
    ngx_string("audio"),
};


static size_t
ngx_rtmp_kmp_publish_get_size(ngx_kmp_push_track_t *track, void *arg)
{
    ngx_rtmp_kmp_track_create_ctx_t  *ctx = arg;
    ngx_rtmp_session_t               *s = ctx->s;
    size_t                            size = 0;

    switch (ctx->media_type) {

    case KMP_MEDIA_VIDEO:
        size = ngx_rtmp_kmp_track_video_json_get_size(s, ctx->publish,
            ctx->codec_ctx);
        break;

    case KMP_MEDIA_AUDIO:
        size = ngx_rtmp_kmp_track_audio_json_get_size(s, ctx->publish,
            ctx->codec_ctx);
        break;
    }

    return size;
}

static u_char*
ngx_rtmp_kmp_publish_write(u_char *p, ngx_kmp_push_track_t *track, void *arg)
{
    ngx_rtmp_kmp_track_create_ctx_t  *ctx = arg;
    ngx_rtmp_session_t               *s = ctx->s;

    switch (ctx->media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_rtmp_kmp_track_video_json_write(p, s, ctx->publish,
            ctx->codec_ctx);
        break;

    case KMP_MEDIA_AUDIO:
        p = ngx_rtmp_kmp_track_audio_json_write(p, s, ctx->publish,
            ctx->codec_ctx);
        break;
    }

    return p;
}

static void
ngx_rtmp_kmp_track_error(void *arg)
{
    ngx_rtmp_kmp_track_ctx_t  *ctx = arg;
    ngx_rtmp_session_t        *s = ctx->s;

    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
        "ngx_rtmp_kmp_track_error: called");

    ngx_rtmp_finalize_session(s);
}

ngx_kmp_push_track_t *
ngx_rtmp_kmp_track_create(
    ngx_kmp_push_track_conf_t *conf,
    ngx_rtmp_kmp_track_create_ctx_t *create_ctx)
{
    u_char                               *p;
    size_t                                input_id_len;
    ngx_str_t                             media_type;
    ngx_rtmp_session_t                   *s = create_ctx->s;
    ngx_kmp_push_track_t                 *track;
    ngx_rtmp_kmp_track_ctx_t             *ctx;
    ngx_kmp_push_track_publish_writer_t   writer;

    track = ngx_kmp_push_track_create(conf, create_ctx->media_type);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_track_create: create failed");
        return NULL;
    }

    track->log.connection = s->connection->number;

    media_type = ngx_rtmp_kmp_media_types[create_ctx->media_type];
    input_id_len = s->tc_url.len + create_ctx->publish->name.len +
        media_type.len + 2;

    ctx = ngx_palloc(track->pool, sizeof(*ctx) + input_id_len);
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

    /* set the input id */
    track->input_id.data = (void*)(ctx + 1);

    p = ngx_copy_str(track->input_id.data, s->tc_url);
    *p++ = '/';
    p = ngx_copy_str(p, create_ctx->publish->name);
    *p++ = '/';
    p = ngx_copy_str(p, media_type);

    track->input_id.len = p - track->input_id.data;

    /* publish */
    writer.get_size = ngx_rtmp_kmp_publish_get_size;
    writer.write = ngx_rtmp_kmp_publish_write;
    writer.arg = create_ctx;

    if (ngx_kmp_push_track_publish(track, &writer) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_create: alloc failed");
        ngx_kmp_push_track_detach(track, "publish_track_failed");
        return NULL;
    }

    return track;
}

static ngx_int_t
ngx_rtmp_kmp_track_write_media_info(ngx_kmp_push_track_t *track,
    ngx_rtmp_codec_ctx_t *codec_ctx, uint32_t extra_data_size)
{
    kmp_media_info_packet_t  media_info;
    int64_t                  num;
    int64_t                  denom;

    media_info.header.packet_type = KMP_PACKET_MEDIA_INFO;
    media_info.header.header_size = sizeof(media_info);
    media_info.header.data_size = extra_data_size;
    media_info.header.reserved = 0;

    media_info.m.media_type = track->media_type;
    media_info.m.timescale = track->timescale;

    ngx_memzero(&media_info.m.u, sizeof(media_info.m.u));

    switch (track->media_type) {

    case KMP_MEDIA_VIDEO:
        /* KMP video codec ids match NGX_RTMP_VIDEO_XXX */
        media_info.m.codec_id = codec_ctx->video_codec_id;
        media_info.m.bitrate = codec_ctx->video_data_rate * 1000;

        media_info.m.u.video.width = codec_ctx->width;
        media_info.m.u.video.height = codec_ctx->height;

        ngx_kmp_push_float_to_rational(codec_ctx->frame_rate, 1000000,
            &num, &denom);
        media_info.m.u.video.frame_rate.num = num;
        media_info.m.u.video.frame_rate.denom = denom;
        break;

    case KMP_MEDIA_AUDIO:
        /* KMP audio codec ids match NGX_RTMP_AUDIO_XXX + base */
        media_info.m.codec_id = NGX_RTMP_KMP_AUDIO_CODEC_BASE +
            codec_ctx->audio_codec_id;
        media_info.m.bitrate = codec_ctx->audio_data_rate * 1000;

        media_info.m.u.audio.sample_rate = codec_ctx->sample_rate;
        media_info.m.u.audio.bits_per_sample = codec_ctx->sample_size * 8;
        media_info.m.u.audio.channels = codec_ctx->audio_channels;
        break;
    }

    if (ngx_kmp_push_track_write(track, (u_char*)&media_info,
        sizeof(media_info)) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_write_media_info: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_kmp_copy(ngx_log_t *log, void *dst, u_char **src, size_t n,
    ngx_chain_t **in)
{
    u_char  *last;
    size_t   pn;

    if (*in == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_copy: end of stream (1)");
        return NGX_ERROR;
    }

    for ( ;; ) {
        last = (*in)->buf->last;

        if ((size_t)(last - *src) >= n) {
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
ngx_rtmp_kmp_track_init_frame(ngx_kmp_push_track_t *track,
    kmp_frame_packet_t *frame, ngx_rtmp_header_t *h, ngx_chain_t **in,
    u_char **src, ngx_flag_t *sequence_header)
{
    u_char                     frame_info;
    u_char                     packet_type;
    u_char                     codec_id;
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
        return rc;
    }

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
            return rc;
        }

        frame->header.data_size -= sizeof(avc_header);

        if (avc_header.packet_type == NGX_RTMP_AVC_SEQUENCE_HEADER) {
            *sequence_header = 1;
        }

        frame->f.pts_delay =
            ((avc_header.comp_time[0] << 16) |
            (avc_header.comp_time[1] << 8) |
            avc_header.comp_time[2]) * (track->timescale / NGX_RTMP_TIMESCALE);
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
            return rc;
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
    }
    else {
        /* handle 32 bit wrap around */
        ctx->timestamp += (int32_t)h->timestamp - ctx->last_timestamp;
        ctx->last_timestamp = h->timestamp;
    }

    frame->f.dts = ctx->timestamp * (track->timescale / NGX_RTMP_TIMESCALE);

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
    ngx_flag_t                 sequence_header;
    kmp_frame_packet_t         frame;
    ngx_rtmp_codec_ctx_t      *codec_ctx;
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
        &sequence_header) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_av: init frame failed");
        return NGX_ERROR;
    }

    if (sequence_header || !ctx->media_info_sent) {

        ctx->media_info_sent = 1;

        codec_ctx = ngx_rtmp_stream_get_module_ctx(ctx->s,
            ngx_rtmp_codec_module);
        if (codec_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, &track->log, 0,
                "ngx_rtmp_kmp_track_av: failed to get codec ctx");
            return NGX_ERROR;
        }

        if (ngx_rtmp_kmp_track_write_media_info(track, codec_ctx,
            sequence_header ? frame.header.data_size : 0)) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_av: send media info failed");
            return NGX_ERROR;
        }
    }

    if (frame.header.data_size <= 0) {
        return NGX_OK;
    }

    if (!sequence_header) {
        ngx_log_debug6(NGX_LOG_DEBUG_KMP, &track->log, 0,
            "ngx_rtmp_kmp_track_av: input: %V, created: %L, size: %uD, "
            "dts: %L, flags: %uD, ptsDelay: %uD",
            &track->input_id, frame.f.created, frame.header.data_size,
            frame.f.dts, frame.f.flags, frame.f.pts_delay);

        if (ngx_kmp_push_track_write(track, (u_char*)&frame, sizeof(frame))
            != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_rtmp_kmp_track_av: write frame header failed");
            return NGX_ERROR;
        }
    }

    if (ngx_kmp_push_track_write_chain(track, in, p) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_rtmp_kmp_track_av: write chain failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}
