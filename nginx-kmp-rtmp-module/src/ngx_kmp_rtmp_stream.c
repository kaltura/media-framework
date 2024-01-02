#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_kmp_rtmp_track.h"
#include "ngx_kmp_rtmp_upstream.h"
#include "ngx_kmp_rtmp_stream.h"


#define NGX_KMP_RTMP_STREAM_ONFI_SIZE  (sizeof("01-01-2010 00:00:00.000") - 1)


static size_t ngx_kmp_rtmp_stream_tracks_json_get_size(
    ngx_kmp_rtmp_stream_t *stream);
static u_char *ngx_kmp_rtmp_stream_tracks_json_write(u_char *p,
    ngx_kmp_rtmp_stream_t *stream);


static ngx_str_t  ngx_kmp_rtmp_media_type_names[NGX_KMP_RTMP_MEDIA_COUNT] = {
    ngx_string("video"),
    ngx_string("audio"),
};


#include "ngx_kmp_rtmp_stream_json.h"


static size_t
ngx_kmp_rtmp_stream_tracks_json_get_size(ngx_kmp_rtmp_stream_t *stream)
{
    size_t                 size;
    ngx_uint_t             i;
    ngx_kmp_rtmp_track_t  *track;

    size = sizeof("{}") - 1;

    for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
        track = stream->tracks[i];
        if (track == NULL) {
            continue;
        }

        size += sizeof(",\"\":") - 1 +
            ngx_kmp_rtmp_media_type_names[i].len +
            ngx_kmp_rtmp_track_json_get_size(track);
    }

    return size;
}


static u_char *
ngx_kmp_rtmp_stream_tracks_json_write(u_char *p, ngx_kmp_rtmp_stream_t *stream)
{
    ngx_uint_t             i;
    ngx_kmp_rtmp_track_t  *track;

    *p++ = '{';
    for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
        track = stream->tracks[i];
        if (track == NULL) {
            continue;
        }

        if (p[-1] != '{') {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_copy_str(p, ngx_kmp_rtmp_media_type_names[i]);
        *p++ = '"';

        *p++ = ':';

        p = ngx_kmp_rtmp_track_json_write(p, track);
    }

    *p++ = '}';

    return p;
}


static ngx_int_t
ngx_kmp_rtmp_stream_publish(ngx_kmp_rtmp_stream_t *stream)
{
    u_char                   *p;
    u_char                   *start;
    size_t                    size;
    size_t                    written;
    ngx_kmp_rtmp_upstream_t  *u;

    u = stream->upstream;

    size = ngx_kmp_rtmp_encoder_stream_get_size(&stream->ctx, &stream->sn.str);

    start = ngx_kmp_rtmp_upstream_get_buf(u, size);
    if (start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_stream_publish: failed to get buf");
        return NGX_ERROR;
    }

    p = ngx_kmp_rtmp_encoder_stream_write(start, &stream->ctx,
        &stream->sn.str, &u->tx_id);

    written = p - start;
    if (written != size) {
        ngx_log_error(NGX_LOG_ALERT, &stream->log, 0,
            "ngx_kmp_rtmp_stream_publish: "
            "size written %uz does not match allocated size %uz",
            written, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_stream_unpublish(ngx_kmp_rtmp_stream_t *stream)
{
    u_char                   *p;
    u_char                   *start;
    size_t                    size;
    size_t                    written;
    ngx_kmp_rtmp_upstream_t  *u;

    u = stream->upstream;

    size = ngx_kmp_rtmp_encoder_unstream_get_size(&stream->ctx,
        &stream->sn.str);

    start = ngx_kmp_rtmp_upstream_get_buf(u, size);
    if (start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_stream_unpublish: failed to get buf");
        return NGX_ERROR;
    }

    p = ngx_kmp_rtmp_encoder_unstream_write(start, &stream->ctx,
        &stream->sn.str, &u->tx_id);

    written = p - start;
    if (written != size) {
        ngx_log_error(NGX_LOG_ALERT, &stream->log, 0,
            "ngx_kmp_rtmp_stream_unpublish: "
            "size written %uz does not match allocated size %uz",
            written, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_stream_write_meta(ngx_kmp_rtmp_stream_t *stream)
{
    size_t                    size;
    size_t                    written;
    u_char                   *p;
    u_char                   *start;
    ngx_str_t                 extra_data[NGX_KMP_RTMP_MEDIA_COUNT];
    ngx_uint_t                i;
    ngx_kmp_rtmp_track_t     *track;
    ngx_kmp_rtmp_metadata_t   meta;
    ngx_kmp_rtmp_upstream_t  *u;

    ngx_log_error(NGX_LOG_INFO, &stream->log, 0,
        "ngx_kmp_rtmp_stream_write_meta: "
        "active_tracks: 0x%uxD", stream->active_tracks);

    u = stream->upstream;

    for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
        track = stream->tracks[i];
        if (track != NULL) {
            ngx_kmp_rtmp_track_get_media_info(track, &meta.mi[i],
                &extra_data[i]);

        } else {
            meta.mi[i].codec_id = KMP_CODEC_INVALID;
        }
    }

    size = ngx_kmp_rtmp_encoder_metadata_get_size(&stream->ctx, &meta);

    if (meta.mi[KMP_MEDIA_VIDEO].codec_id == KMP_CODEC_VIDEO_H264) {
        size += ngx_kmp_rtmp_encoder_avc_sequence_get_size(
            &stream->ctx, &extra_data[KMP_MEDIA_VIDEO]);
    }

    if (meta.mi[KMP_MEDIA_AUDIO].codec_id == KMP_CODEC_AUDIO_AAC) {
        size += ngx_kmp_rtmp_encoder_aac_sequence_get_size(
            &stream->ctx, &extra_data[KMP_MEDIA_AUDIO]);
    }

    start = ngx_kmp_rtmp_upstream_get_buf(u, size);
    if (start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_stream_write_meta: failed to get buf");
        return NGX_ERROR;
    }

    p = ngx_kmp_rtmp_encoder_metadata_write(start, &stream->ctx, &meta);

    if (meta.mi[KMP_MEDIA_VIDEO].codec_id == KMP_CODEC_VIDEO_H264) {
        p = ngx_kmp_rtmp_encoder_avc_sequence_write(p, &stream->ctx,
            &extra_data[KMP_MEDIA_VIDEO]);
    }

    if (meta.mi[KMP_MEDIA_AUDIO].codec_id == KMP_CODEC_AUDIO_AAC) {
        p = ngx_kmp_rtmp_encoder_aac_sequence_write(p, &stream->ctx,
            &extra_data[KMP_MEDIA_AUDIO]);
    }

    written = p - start;
    if (written != size) {
        ngx_log_error(NGX_LOG_ALERT, &stream->log, 0,
            "ngx_kmp_rtmp_stream_write_meta: "
            "size written %uz does not match allocated size %uz",
            written, size);
        return NGX_ERROR;
    }

    stream->wrote_meta = 1;

    for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
        track = stream->tracks[i];
        if (track != NULL) {
            ngx_kmp_rtmp_track_stream_ready(track);
        }
    }

    ngx_add_timer(&u->process, 0);

    return NGX_OK;
}


static void
ngx_kmp_rtmp_stream_write_meta_handler(ngx_event_t *ev)
{
    ngx_kmp_rtmp_stream_t  *stream;

    stream = ev->data;

    if (ngx_kmp_rtmp_stream_write_meta(stream) != NGX_OK) {
        ngx_kmp_rtmp_upstream_free(stream->upstream, "write_meta_failed");
    }
}


static ngx_int_t
ngx_kmp_rtmp_stream_onfi(ngx_kmp_rtmp_stream_t *stream, int64_t time)
{
    u_char                   *p;
    u_char                   *start;
    size_t                    size;
    size_t                    written;
    ngx_tm_t                  gmt;
    ngx_kmp_rtmp_onfi_t       onfi;
    ngx_kmp_rtmp_upstream_t  *u;
    u_char                    buf[NGX_KMP_RTMP_STREAM_ONFI_SIZE];

    ngx_gmtime(time / NGX_KMP_RTMP_TIMESCALE, &gmt);

    p = buf;

    onfi.date.data = p;
    p = ngx_sprintf(p, "%02d-%02d-%04d",
        gmt.ngx_tm_mday, gmt.ngx_tm_mon, gmt.ngx_tm_year);
    onfi.date.len = p - onfi.date.data;

    onfi.time.data = p;
    p = ngx_sprintf(p, "%02d:%02d:%02d.%03d",
        gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec,
        (int) (time % NGX_KMP_RTMP_TIMESCALE));
    onfi.time.len = p - onfi.time.data;

    u = stream->upstream;

    size = ngx_kmp_rtmp_encoder_onfi_get_size(&stream->ctx, &onfi);

    start = ngx_kmp_rtmp_upstream_get_buf(u, size);
    if (start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_stream_onfi: failed to get buf");
        return NGX_ERROR;
    }

    p = ngx_kmp_rtmp_encoder_onfi_write(start, &stream->ctx, &onfi);

    written = p - start;
    if (written != size) {
        ngx_log_error(NGX_LOG_ALERT, &stream->log, 0,
            "ngx_kmp_rtmp_stream_onfi: "
            "size written %uz does not match allocated size %uz",
            written, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_rtmp_stream_write_frame(ngx_kmp_rtmp_stream_t *stream,
    ngx_kmp_rtmp_frame_t *frame, uint32_t codec_id)
{
    ngx_int_t                 rc;
    ngx_kmp_rtmp_upstream_t  *u;

    u = stream->upstream;

    rc = ngx_kmp_rtmp_encoder_frame_write(&stream->ctx, frame,
        codec_id, ngx_kmp_rtmp_upstream_write, u);
    if (rc != NGX_OK) {
        return rc;
    }

    if (u->conf.onfi_period <= 0) {
        return NGX_OK;
    }

    if (frame->created < stream->last_onfi_time
        || frame->created >= stream->last_onfi_time
            + (int64_t) u->conf.onfi_period)
    {
        rc = ngx_kmp_rtmp_stream_onfi(stream, frame->created);
        if (rc != NGX_OK) {
            return rc;
        }

        stream->last_onfi_time = frame->created;
    }

    return NGX_OK;
}


void
ngx_kmp_rtmp_stream_attach_track(ngx_kmp_rtmp_stream_t *stream,
    ngx_kmp_rtmp_track_t *track, ngx_uint_t media_type)
{
    ngx_kmp_rtmp_upstream_t  *u;

    ngx_log_error(NGX_LOG_INFO, &stream->log, 0,
        "ngx_kmp_rtmp_stream_attach_track: attaching %uD", media_type);

    stream->tracks[media_type] = track;
    stream->active_tracks |= 1 << media_type;

    if (stream->wrote_meta) {
        return;
    }

    if (stream->active_tracks == NGX_KMP_RTMP_MEDIA_MASK) {
        ngx_add_timer(&stream->write_meta, 0);
        return;
    }

    u = stream->upstream;
    ngx_add_timer(&stream->write_meta, u->conf.write_meta_timeout);
}


void
ngx_kmp_rtmp_stream_detach_track(ngx_kmp_rtmp_stream_t *stream,
    ngx_uint_t media_type)
{
    ngx_kmp_rtmp_upstream_t  *u;

    ngx_log_error(NGX_LOG_INFO, &stream->log, 0,
        "ngx_kmp_rtmp_stream_detach_track: detaching %uD", media_type);

    stream->active_tracks &= ~(1 << media_type);

    if (stream->active_tracks != 0) {
        return;
    }

    u = stream->upstream;

    if (stream->write_meta.timer_set) {
        ngx_del_timer(&stream->write_meta);
    }

    if (ngx_kmp_rtmp_stream_unpublish(stream) != NGX_OK) {
        ngx_kmp_rtmp_upstream_free(u, "unpublish_stream_failed");
        return;
    }

    ngx_rbtree_delete(&u->streams.rbtree, &stream->sn.node);
    ngx_queue_remove(&stream->queue);

    /* TODO: reuse stream/track pointers */

    ngx_kmp_rtmp_upstream_stream_removed(u);
}


static u_char *
ngx_kmp_rtmp_stream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                   *p;
    ngx_kmp_rtmp_stream_t    *stream;
    ngx_kmp_rtmp_upstream_t  *u;

    stream = log->data;
    u = stream->upstream;

    p = ngx_snprintf(buf, len, ", upstream: %V, stream: %V",
        &u->sn.str, &stream->sn.str);
    buf = p;

    return buf;
}


static ngx_kmp_rtmp_stream_t *
ngx_kmp_rtmp_stream_get(ngx_kmp_rtmp_upstream_t *u, ngx_str_t *name)
{
    uint32_t  hash;

    hash = ngx_crc32_short(name->data, name->len);

    return (ngx_kmp_rtmp_stream_t *) ngx_str_rbtree_lookup(
        &u->streams.rbtree, name, hash);
}


static ngx_kmp_rtmp_stream_t *
ngx_kmp_rtmp_stream_create(ngx_kmp_rtmp_upstream_t *u, ngx_str_t *name)
{
    uint32_t                hash;
    ngx_kmp_rtmp_stream_t  *stream;

    stream = ngx_palloc(u->pool, sizeof(*stream) + name->len);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_stream_create: alloc failed");
        return NULL;
    }

    ngx_memzero(stream, sizeof(*stream));

    stream->sn.str.data = (void *) (stream + 1);
    stream->sn.str.len = name->len;
    ngx_memcpy(stream->sn.str.data, name->data, name->len);

    hash = ngx_crc32_short(name->data, name->len);
    stream->sn.node.key = hash;

    stream->id_escape = ngx_json_str_get_escape(name);

    stream->log = u->log;

    stream->log.handler = ngx_kmp_rtmp_stream_log_error;
    stream->log.data = stream;
    stream->log.action = NULL;

    stream->created = ngx_current_msec;
    stream->upstream = u;

    /* Note: assuming remote server allocates stream ids incrementally,
        starting from 1 */

    u->last_msid++;

    stream->ctx.log = &stream->log;
    stream->ctx.chunk_size = u->conf.chunk_size;
    stream->ctx.msid = u->last_msid;
    stream->ctx.csid = 3 + stream->ctx.msid;    /* csid < 3 are reserved */

    stream->write_meta.handler = ngx_kmp_rtmp_stream_write_meta_handler;
    stream->write_meta.data = stream;
    stream->write_meta.log = &stream->log;

    ngx_rbtree_insert(&u->streams.rbtree, &stream->sn.node);
    ngx_queue_insert_tail(&u->streams.queue, &stream->queue);

    if (ngx_kmp_rtmp_stream_publish(stream) != NGX_OK) {
        return NULL;
    }

    ngx_log_error(NGX_LOG_INFO, &stream->log, 0,
        "ngx_kmp_rtmp_stream_create: created %p", stream);

    return stream;
}


ngx_kmp_rtmp_stream_t *
ngx_kmp_rtmp_stream_get_or_create(ngx_kmp_rtmp_upstream_t *u, ngx_str_t *name)
{
    ngx_kmp_rtmp_stream_t  *stream;

    stream = ngx_kmp_rtmp_stream_get(u, name);
    if (stream != NULL) {
        return stream;
    }

    return ngx_kmp_rtmp_stream_create(u, name);
}


void
ngx_kmp_rtmp_stream_free(ngx_kmp_rtmp_stream_t *stream)
{
    ngx_uint_t             i;
    ngx_kmp_rtmp_track_t  *track;

    ngx_log_error(NGX_LOG_INFO, &stream->log, 0,
        "ngx_kmp_rtmp_stream_free: called");

    for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
        track = stream->tracks[i];
        if (track == NULL) {
            continue;
        }

        ngx_kmp_rtmp_track_free(track);
    }

    if (stream->write_meta.timer_set) {
        ngx_del_timer(&stream->write_meta);
    }
}
