#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_kmp_rtmp_encoder.h"
#include "ngx_kmp_rtmp_upstream.h"
#include "ngx_kmp_rtmp_stream.h"
#include "ngx_kmp_rtmp_track.h"


#define NGX_KMP_RTMP_MAX_FRAME_COUNT     (16384)

/* sizeof(ngx_kmp_rtmp_frame_part_t) == 1024 */
#define NGX_KMP_RTMP_FRAME_PART_COUNT    (21)

#define NGX_KMP_RTMP_FRAME_READY_MARGIN  (50)
#define NGX_KMP_RTMP_LAZY_DELAY          (100)


#define ngx_kmp_rtmp_rescale_time(time, cur_scale, new_scale)                \
    ((((uint64_t) (time)) * (new_scale) + (cur_scale) / 2) / (cur_scale))

#ifndef ngx_rbtree_data
#define ngx_rbtree_data(node, type, link)                                    \
    (type *) ((u_char *) (node) - offsetof(type, link))
#endif


typedef struct ngx_kmp_rtmp_frame_part_s  ngx_kmp_rtmp_frame_part_t;

struct ngx_kmp_rtmp_frame_part_s {
    ngx_kmp_rtmp_frame_part_t  *next;
    ngx_uint_t                  nelts;

    ngx_kmp_rtmp_frame_t        elts[NGX_KMP_RTMP_FRAME_PART_COUNT];
};


typedef struct {
    ngx_pool_t                 *pool;
    size_t                     *mem_left;

    ngx_kmp_rtmp_frame_part_t  *part;
    ngx_kmp_rtmp_frame_part_t  *last;
    ngx_kmp_rtmp_frame_part_t  *free;

    ngx_uint_t                  offset;
    ngx_uint_t                  count;
} ngx_kmp_rtmp_frame_list_t;


struct ngx_kmp_rtmp_track_s {
    ngx_rbtree_node_t           dts_node;
    ngx_rbtree_node_t           added_node;

    ngx_log_t                   log;
    ngx_kmp_rtmp_stream_t      *stream;
    ngx_kmp_rtmp_upstream_t    *upstream;

    ngx_kmp_in_ctx_t           *input;
    ngx_buf_queue_t             buf_queue;

    uint32_t                    media_type;
    kmp_media_info_t            media_info;
    ngx_str_t                   extra_data;
    size_t                      extra_data_size;

    ngx_kmp_rtmp_frame_list_t   frames;
};


#include "ngx_kmp_rtmp_track_json.h"


/* frame list */

static ngx_kmp_rtmp_frame_part_t *
ngx_kmp_rtmp_frame_list_alloc_part(ngx_kmp_rtmp_frame_list_t *list)
{
    ngx_kmp_rtmp_frame_part_t  *part;

    if (*list->mem_left < sizeof(*part)) {
        ngx_log_error(NGX_LOG_ERR, list->pool->log, 0,
            "ngx_kmp_rtmp_frame_list_alloc_part: memory limit exceeded");
        return NULL;
    }

    *list->mem_left -= sizeof(*part);

    part = ngx_palloc(list->pool, sizeof(*part));
    if (part == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, list->pool->log, 0,
            "ngx_kmp_rtmp_frame_list_alloc_part: alloc failed");
        return NULL;
    }

    return part;
}


static ngx_int_t
ngx_kmp_rtmp_frame_list_init(ngx_kmp_rtmp_frame_list_t *list, ngx_pool_t *pool,
    size_t *mem_left)
{
    ngx_kmp_rtmp_frame_part_t  *part;

    list->pool = pool;
    list->mem_left = mem_left;

    part = ngx_kmp_rtmp_frame_list_alloc_part(list);
    if (part == NULL) {
        return NGX_ERROR;
    }

    part->nelts = 0;
    part->next = NULL;

    list->last = list->part = part;

    return NGX_OK;
}


#if (NGX_DEBUG)
static void
ngx_kmp_rtmp_frame_list_validate(ngx_kmp_rtmp_frame_list_t *list)
{
    ngx_uint_t                  count;
    ngx_kmp_rtmp_frame_part_t  *part;

    part = list->part;

    if (list->offset > part->nelts) {
        ngx_log_error(NGX_LOG_ALERT, list->pool->log, 0,
            "ngx_kmp_rtmp_frame_list_validate: "
            "invalid offset %ui", list->offset);
        ngx_debug_point();
    }

    count = 0;

    for ( ;; ) {

        if (part->nelts > NGX_KMP_RTMP_FRAME_PART_COUNT) {
            ngx_log_error(NGX_LOG_ALERT, list->pool->log, 0,
                "ngx_kmp_rtmp_frame_list_validate: "
                "invalid part count %ui (1)", part->nelts);
            ngx_debug_point();
        }

        count += part->nelts;

        if (part->next == NULL) {
            break;
        }

        part = part->next;

        if (part->nelts <= 0) {
            ngx_log_error(NGX_LOG_ALERT, list->pool->log, 0,
                "ngx_kmp_rtmp_frame_list_validate: "
                "invalid part count %ui (2)", part->nelts);
            ngx_debug_point();
        }
    }

    if (list->last != part) {
        ngx_log_error(NGX_LOG_ALERT, list->pool->log, 0,
            "ngx_kmp_rtmp_frame_list_validate: invalid last part");
        ngx_debug_point();
    }

    count -= list->offset;
    if (list->count != count) {
        ngx_log_error(NGX_LOG_ALERT, list->pool->log, 0,
            "ngx_kmp_rtmp_frame_list_validate: "
            "invalid count %ui expected %ui", list->count, count);
        ngx_debug_point();
    }
}
#else
#define ngx_kmp_rtmp_frame_list_validate(list)
#endif


static ngx_kmp_rtmp_frame_t *
ngx_kmp_rtmp_frame_list_push(ngx_kmp_rtmp_frame_list_t *list)
{
    ngx_kmp_rtmp_frame_t       *frame;
    ngx_kmp_rtmp_frame_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_KMP_RTMP_FRAME_PART_COUNT) {

        last = list->free;
        if (last == NULL) {
            last = ngx_kmp_rtmp_frame_list_alloc_part(list);
            if (last == NULL) {
                return NULL;
            }

        } else {
            list->free = last->next;
        }

        last->nelts = 0;
        last->next = NULL;

        list->last->next = last;
        list->last = last;
    }

    frame = &last->elts[last->nelts];
    last->nelts++;

    list->count++;

    ngx_kmp_rtmp_frame_list_validate(list);

    return frame;
}


static void
ngx_kmp_rtmp_frame_list_pop(ngx_kmp_rtmp_frame_list_t *list)
{
    ngx_kmp_rtmp_frame_part_t  *part;

    list->count--;

    list->offset++;
    if (list->offset < NGX_KMP_RTMP_FRAME_PART_COUNT) {
        goto done;
    }

    list->offset = 0;

    part = list->part;
    if (part->next == NULL) {
        part->nelts = 0;
        goto done;
    }

    list->part = part->next;

    part->next = list->free;
    list->free = part;

done:

    ngx_kmp_rtmp_frame_list_validate(list);
}


static ngx_kmp_rtmp_frame_t *
ngx_kmp_rtmp_frame_list_head(ngx_kmp_rtmp_frame_list_t *list)
{
    return list->part->elts + list->offset;
}


/* track */

static ngx_buf_chain_t *
ngx_kmp_rtmp_track_alloc_chain(void *data)
{
    ngx_kmp_rtmp_track_t  *track;

    track = data;

    return ngx_kmp_rtmp_upstream_alloc_chain(track->upstream);
}


static void
ngx_kmp_rtmp_track_free_chain_list(void *data, ngx_buf_chain_t *head,
    ngx_buf_chain_t *tail)
{
    ngx_kmp_rtmp_track_t  *track;

    track = data;

    ngx_kmp_rtmp_upstream_free_chain_list(track->upstream, head, tail);
}


static ngx_int_t
ngx_kmp_rtmp_track_get_input_buf(void *data, ngx_buf_t *b)
{
    u_char                *p;
    ngx_kmp_rtmp_track_t  *track;

    track = data;

    p = ngx_buf_queue_get(&track->buf_queue);
    if (p == NULL) {
        ngx_kmp_rtmp_upstream_finalize(track->upstream);
        return NGX_ERROR;
    }

    b->start = p;
    b->end = p + track->buf_queue.used_size;

    b->pos = b->last = p;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_validate_media_info(ngx_log_t *log, kmp_media_info_t *media_info)
{
    switch (media_info->media_type) {

    case KMP_MEDIA_VIDEO:
        switch (media_info->codec_id) {

        case KMP_CODEC_VIDEO_H264:
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_kmp_rtmp_validate_media_info: "
                "invalid video codec %uD", media_info->codec_id);
            return NGX_ERROR;
        }

        break;

    case KMP_MEDIA_AUDIO:
        switch (media_info->codec_id) {

        case KMP_CODEC_AUDIO_AAC:
        case KMP_CODEC_AUDIO_MP3:
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_kmp_rtmp_validate_media_info: "
                "invalid audio codec %uD", media_info->codec_id);
            return NGX_ERROR;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_rtmp_validate_media_info: "
            "invalid media type %uD", media_info->media_type);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_track_alloc_extra_data(ngx_kmp_rtmp_track_t *track, size_t size)
{
    ngx_kmp_rtmp_upstream_t  *u;

    if (track->extra_data_size >= size) {
        return NGX_OK;
    }

    if (size < track->extra_data_size * 2) {
        size = track->extra_data_size * 2;
    }

    u = track->upstream;

    if (u->mem_left < size) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_rtmp_track_alloc_extra_data: memory limit exceeded");
        return NGX_ERROR;
    }

    u->mem_left -= size;

    track->extra_data.data = ngx_pnalloc(u->pool, size);
    if (track->extra_data.data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_rtmp_track_alloc_extra_data: alloc failed");
        return NGX_ERROR;
    }

    track->extra_data_size = size;

    return NGX_OK;
}


void
ngx_kmp_rtmp_track_get_media_info(ngx_kmp_rtmp_track_t *track,
    kmp_media_info_t *mi, ngx_str_t *extra_data)
{
    *mi = track->media_info;
    *extra_data = track->extra_data;
}


static ngx_int_t
ngx_kmp_rtmp_track_add_media_info(void *data, ngx_kmp_in_evt_media_info_t *evt)
{
    ngx_kmp_rtmp_track_t  *track;

    track = data;

    if (evt->media_info.media_type != track->media_type) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_rtmp_track_add_media_info: "
            "media type %uD doesn't match track %uD",
            evt->media_info.media_type, track->media_type);
        return NGX_ERROR;
    }

    if (ngx_kmp_rtmp_validate_media_info(&track->log, &evt->media_info)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_kmp_rtmp_encoder_update_media_info(&track->stream->ctx,
        &evt->media_info);

    track->media_info = evt->media_info;
    track->extra_data.len = evt->extra_data_size;

    if (evt->extra_data_size <= 0) {
        return NGX_OK;
    }

    if (ngx_kmp_rtmp_track_alloc_extra_data(track, evt->extra_data_size)
        != NGX_OK)
    {
        goto fatal;
    }

    if (ngx_buf_chain_copy(&evt->extra_data, track->extra_data.data,
        evt->extra_data_size) == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_kmp_rtmp_track_add_media_info: failed to copy extra data");
        goto fatal;
    }

    return NGX_OK;

fatal:

    ngx_kmp_rtmp_upstream_finalize(track->upstream);
    return NGX_ABORT;
}


static ngx_int_t
ngx_kmp_rtmp_track_add_frame(void *data, ngx_kmp_in_evt_frame_t *evt)
{
    int64_t                   dts, pts, created;
    uint32_t                  timescale;
    ngx_uint_t                count;
    ngx_kmp_rtmp_frame_t     *frame;
    ngx_kmp_rtmp_track_t     *track;
    ngx_kmp_rtmp_stream_t    *stream;
    ngx_kmp_rtmp_upstream_t  *u;

    track = data;
    count = track->frames.count;

    if (count >= NGX_KMP_RTMP_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_rtmp_track_add_frame: pending frame count exceeds limit");
        return NGX_ERROR;
    }

    frame = ngx_kmp_rtmp_frame_list_push(&track->frames);
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_rtmp_track_add_frame: push failed");
        ngx_kmp_rtmp_upstream_finalize(track->upstream);
        return NGX_ABORT;
    }

    timescale = track->media_info.timescale;

    dts = ngx_kmp_rtmp_rescale_time(evt->frame.dts, timescale,
        NGX_KMP_RTMP_TIMESCALE);
    pts = ngx_kmp_rtmp_rescale_time(evt->frame.dts + evt->frame.pts_delay,
        timescale, NGX_KMP_RTMP_TIMESCALE);
    created = ngx_kmp_rtmp_rescale_time(evt->frame.created, timescale,
        NGX_KMP_RTMP_TIMESCALE);

    frame->added = ngx_current_msec;
    frame->created = created;
    frame->dts = dts;
    frame->pts_delay = pts - dts;
    frame->flags = evt->frame.flags;
    frame->size = evt->size;
    frame->data = evt->data_head;

    if (count > 0) {
        return NGX_OK;
    }

    track->dts_node.key = frame->dts;
    track->added_node.key = frame->added;

    stream = track->stream;
    if (!stream->wrote_meta) {
        return NGX_OK;
    }

    u = stream->upstream;

    ngx_rbtree_insert(&u->tracks.dts_rbtree, &track->dts_node);
    ngx_rbtree_insert(&u->tracks.added_rbtree, &track->added_node);

    ngx_add_timer(&u->process, 0);

    return NGX_OK;
}


static void
ngx_kmp_rtmp_track_close(ngx_kmp_rtmp_track_t *track)
{
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_close: called");

    ngx_kmp_rtmp_stream_detach_track(track->stream, track->media_type);

    ngx_buf_queue_delete(&track->buf_queue);
}


static ngx_int_t
ngx_kmp_rtmp_track_write_frame(ngx_kmp_rtmp_track_t *track)
{
    ngx_int_t                 rc;
    ngx_msec_int_t            diff;
    ngx_kmp_rtmp_frame_t     *frame;
    ngx_kmp_rtmp_stream_t    *stream;
    ngx_kmp_rtmp_upstream_t  *u;

    stream = track->stream;
    u = track->upstream;

    frame = ngx_kmp_rtmp_frame_list_head(&track->frames);

    ngx_log_debug7(NGX_LOG_DEBUG_STREAM, &track->log, 0,
        "ngx_kmp_rtmp_track_write_frame: stream: %V, media_type: %uD, "
        "created: %L, size: %uD, dts: %L, flags: 0x%uxD, ptsDelay: %uD",
        &stream->sn.str, track->media_type, frame->created,
        frame->size, frame->dts, frame->flags, frame->pts_delay);

    rc = ngx_kmp_rtmp_stream_write_frame(stream, frame,
        track->media_info.codec_id);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_rtmp_track_write_frame: write failed");
        return rc;
    }

    ngx_buf_queue_free(&track->buf_queue, frame->data->data);

    ngx_kmp_rtmp_upstream_free_chain_list(u, frame->data, NULL);
    ngx_kmp_rtmp_frame_list_pop(&track->frames);

    ngx_rbtree_delete(&u->tracks.dts_rbtree, &track->dts_node);

    if (track->frames.count <= 0) {
        ngx_rbtree_delete(&u->tracks.added_rbtree, &track->added_node);

        if (track->input == NULL) {
            ngx_kmp_rtmp_track_close(track);
        }

        return NGX_OK;
    }

    frame = ngx_kmp_rtmp_frame_list_head(&track->frames);

    track->dts_node.key = frame->dts;
    ngx_rbtree_insert(&u->tracks.dts_rbtree, &track->dts_node);

    /* avoid delete/insert to rbtree if new added time is close enough */
    diff = frame->added - track->added_node.key;
    if (ngx_abs(diff) > NGX_KMP_RTMP_LAZY_DELAY) {
        ngx_rbtree_delete(&u->tracks.added_rbtree, &track->added_node);

        track->added_node.key = frame->added;
        ngx_rbtree_insert(&u->tracks.added_rbtree, &track->added_node);
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_rtmp_track_process_frame(ngx_rbtree_node_t *node, ngx_msec_t *timer)
{
    ngx_msec_t                frame_ready;
    ngx_kmp_rtmp_frame_t     *frame;
    ngx_kmp_rtmp_track_t     *track;
    ngx_kmp_rtmp_upstream_t  *u;

    track = ngx_rbtree_data(node, ngx_kmp_rtmp_track_t, dts_node);

    u = track->upstream;

    frame = ngx_kmp_rtmp_frame_list_head(&track->frames);

    frame_ready = frame->added + u->conf.min_process_delay;
    if (frame_ready > ngx_current_msec + NGX_KMP_RTMP_FRAME_READY_MARGIN) {
        *timer = frame_ready - ngx_current_msec;

        ngx_log_debug5(NGX_LOG_DEBUG_CORE, &track->log, 0,
            "ngx_kmp_rtmp_track_process_frame: delaying frame, "
            "added: %M, current: %M, wait: %M, stream: %V, media_type: %uD",
            frame->added, ngx_current_msec, *timer,
            &track->stream->sn.str, track->media_type);

        return NGX_DONE;
    }

    return ngx_kmp_rtmp_track_write_frame(track);
}


ngx_int_t
ngx_kmp_rtmp_track_process_expired(ngx_rbtree_node_t *node)
{
    ngx_kmp_rtmp_track_t     *track;
    ngx_kmp_rtmp_frame_t     *frame;
    ngx_kmp_rtmp_upstream_t  *u;

    track = ngx_rbtree_data(node, ngx_kmp_rtmp_track_t, added_node);

    u = track->upstream;

    frame = ngx_kmp_rtmp_frame_list_head(&track->frames);

    if (ngx_current_msec < frame->added + u->conf.max_process_delay) {
        return NGX_DONE;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, &track->log, 0,
        "ngx_kmp_rtmp_track_process_expired: writing expired frame, "
        "added: %M, current: %M, stream: %V, media_type: %uD",
        frame->added, ngx_current_msec,
        &track->stream->sn.str, track->media_type);

    return ngx_kmp_rtmp_track_write_frame(track);
}


void
ngx_kmp_rtmp_track_stream_ready(ngx_kmp_rtmp_track_t *track)
{
    ngx_kmp_rtmp_upstream_t  *u;

    if (track->frames.count > 0) {
        u = track->upstream;
        ngx_rbtree_insert(&u->tracks.dts_rbtree, &track->dts_node);
        ngx_rbtree_insert(&u->tracks.added_rbtree, &track->added_node);
    }
}


static void
ngx_kmp_rtmp_track_remove_pending_frames(ngx_kmp_rtmp_track_t *track)
{
    ngx_kmp_rtmp_frame_t     *frame;
    ngx_kmp_rtmp_upstream_t  *u;

    if (track->frames.count <= 0) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_remove_pending_frames: "
        "dropping %ui pending frames", track->frames.count);

    u = track->upstream;

    while (track->frames.count > 0) {
        frame = ngx_kmp_rtmp_frame_list_head(&track->frames);
        ngx_kmp_rtmp_upstream_free_chain_list(u, frame->data, NULL);
        ngx_kmp_rtmp_frame_list_pop(&track->frames);
    }

    if (track->stream->wrote_meta) {
        ngx_rbtree_delete(&u->tracks.dts_rbtree, &track->dts_node);
        ngx_rbtree_delete(&u->tracks.added_rbtree, &track->added_node);
    }
}


static void
ngx_kmp_rtmp_track_end_stream(void *data)
{
    ngx_kmp_rtmp_track_t  *track;

    track = data;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_end_stream: got end of stream");
}


static void
ngx_kmp_rtmp_track_disconnected(ngx_kmp_in_ctx_t *ctx)
{
    ngx_kmp_rtmp_track_t  *track;

    track = ctx->data;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_disconnected: called");

    track->input = NULL;

    if (track->frames.count <= 0) {
        ngx_kmp_rtmp_track_close(track);
    }
}


static u_char *
ngx_kmp_rtmp_track_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                   *p;
    ngx_kmp_rtmp_track_t     *track;
    ngx_kmp_rtmp_stream_t    *stream;
    ngx_kmp_rtmp_upstream_t  *u;

    track = log->data;
    stream = track->stream;
    u = stream->upstream;

    p = ngx_snprintf(buf, len, ", upstream: %V, stream: %V, media_type: %uD",
        &u->sn.str, &stream->sn.str, track->media_type);
    buf = p;

    return buf;
}


static ngx_kmp_rtmp_track_t *
ngx_kmp_rtmp_track_create(ngx_kmp_rtmp_stream_t *stream, uint32_t media_type)
{
    ngx_kmp_rtmp_track_t    *track;
    ngx_kmp_rtmp_upstream_t *u;

    u = stream->upstream;

    track = ngx_pcalloc(u->pool, sizeof(*track));
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_track_create: alloc failed");
        return NULL;
    }

    if (ngx_kmp_rtmp_frame_list_init(&track->frames, u->pool, &u->mem_left)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &stream->log, 0,
            "ngx_kmp_rtmp_track_create: init frame list failed");
        return NULL;
    }

    track->log = stream->log;

    track->log.handler = ngx_kmp_rtmp_track_log_error;
    track->log.data = track;
    track->log.action = NULL;

    track->stream = stream;
    track->upstream = u;

    track->media_type = media_type;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_create: created %p", track);

    return track;
}


ngx_int_t
ngx_kmp_rtmp_track_connect(ngx_kmp_rtmp_track_connect_t *connect)
{
    size_t                        mem_used;
    uint32_t                      media_type;
    ngx_int_t                     rc;
    ngx_str_t                     name;
    ngx_pool_t                   *temp_pool;
    ngx_kmp_in_ctx_t             *input;
    ngx_kmp_rtmp_track_t         *track;
    ngx_kmp_rtmp_stream_t        *stream;
    ngx_kmp_rtmp_upstream_t      *u;
    ngx_kmp_in_evt_media_info_t  *mi;

    temp_pool = connect->temp_pool;
    mi = connect->media_info;

    if (ngx_kmp_rtmp_validate_media_info(temp_pool->log, &mi->media_info)) {
        return NGX_ERROR;
    }

    rc = ngx_kmp_rtmp_upstream_get_or_create(temp_pool, connect->conf,
        connect->value, &u, &name);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_track_connect: failed to get upstream");
        return rc;
    }

    stream = ngx_kmp_rtmp_stream_get_or_create(u, &name);
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_track_connect: failed to get stream");
        goto fatal;
    }

    media_type = mi->media_info.media_type;
    track = stream->tracks[media_type];
    if (track != NULL) {

        if (track->input != NULL) {
            ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
                "ngx_kmp_rtmp_track_connect: track already connected, "
                "upstream: %V, stream: %V, media_type: %uD",
                &u->sn.str, &stream->sn.str, media_type);
            return NGX_ERROR;
        }

        ngx_kmp_rtmp_track_remove_pending_frames(track);

        ngx_buf_queue_delete(&track->buf_queue);

    } else {

        if (stream->wrote_meta) {
            ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
                "ngx_kmp_rtmp_track_connect: stream meta already sent, "
                "upstream: %V, stream: %V, media_type: %uD",
                &u->sn.str, &stream->sn.str, media_type);
            return NGX_ERROR;
        }

        track = ngx_kmp_rtmp_track_create(stream, media_type);
        if (track == NULL) {
            goto fatal;
        }
    }

    rc = ngx_kmp_rtmp_track_add_media_info(track, mi);
    if (rc != NGX_OK) {
        return rc;
    }

    mem_used = ngx_buf_queue_mem_used(connect->buf_queue);
    if (u->mem_left < mem_used) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_track_connect: "
            "used memory %uz overflows upstream memory left %uz",
            mem_used, u->mem_left);
        goto fatal;
    }

    u->mem_left -= mem_used;

    track->buf_queue = *connect->buf_queue;
    track->buf_queue.log = &track->log;
    track->buf_queue.mem_left = &u->mem_left;

    input = connect->input;

    input->alloc_chain = ngx_kmp_rtmp_track_alloc_chain;
    input->free_chain_list = ngx_kmp_rtmp_track_free_chain_list;
    input->get_input_buf = ngx_kmp_rtmp_track_get_input_buf;

    input->media_info = ngx_kmp_rtmp_track_add_media_info;
    input->frame = ngx_kmp_rtmp_track_add_frame;
    input->end_stream = ngx_kmp_rtmp_track_end_stream;

    input->disconnected = ngx_kmp_rtmp_track_disconnected;

    input->data = track;
    track->input = input;

    ngx_kmp_rtmp_stream_attach_track(stream, track, media_type);

    connect->track = track;

    return NGX_OK;

fatal:

    ngx_kmp_rtmp_upstream_finalize(u);
    return NGX_ABORT;
}


void
ngx_kmp_rtmp_track_free(ngx_kmp_rtmp_track_t *track)
{
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_rtmp_track_free: called");

    if (track->input != NULL) {
        track->input->disconnect(track->input, NGX_OK);
    }

    ngx_buf_queue_delete(&track->buf_queue);
}


ngx_int_t
ngx_kmp_rtmp_track_disconnect_by_num(ngx_kmp_rtmp_upstream_t *u,
    ngx_uint_t connection)
{
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_kmp_rtmp_track_t   *track;
    ngx_kmp_rtmp_stream_t  *stream;

    for (q = ngx_queue_head(&u->streams.queue);
        q != ngx_queue_sentinel(&u->streams.queue);
        q = ngx_queue_next(q))
    {
        stream = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);

        for (i = 0; i < NGX_KMP_RTMP_MEDIA_COUNT; i++) {
            track = stream->tracks[i];
            if (track == NULL || track->input == NULL
                || track->input->connection->number != connection)
            {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, &track->log, 0,
                "ngx_kmp_rtmp_track_disconnect_by_num: disconnecting");

            track->input->disconnect(track->input, NGX_OK);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
