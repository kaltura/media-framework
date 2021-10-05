#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_media_info.h"
#include "ngx_live_input_bufs.h"
#include "ngx_live_segmenter.h"
#include "ngx_live_timeline.h"
#include "ngx_live_notif.h"
#include "persist/ngx_live_persist_internal.h"
#include "ngx_live_filler.h"
#include "ngx_live_filler_json.h"


#define NGX_LIVE_FILLER_MAX_SEGMENTS            128

#define NGX_LIVE_PERSIST_TYPE_FILLER            (0x726c6c66)    /* fllr */

#define NGX_LIVE_FILLER_PERSIST_BLOCK           (0x726c6c66)    /* fllr */

#define NGX_LIVE_FILLER_PERSIST_BLOCK_TRACK     (0x6b746c66)    /* fltk */


/* Note: the data chains of all segments in a track are connected in a cycle */

typedef struct {
    int32_t                            pts_delay;
    uint32_t                           duration;
    ngx_list_t                         frames;        /* ngx_live_frame_t */
    ngx_uint_t                         frame_count;

    ngx_buf_chain_t                   *data_head;
    ngx_buf_chain_t                   *data_tail;
    size_t                             data_size;
} ngx_live_filler_segment_t;


typedef struct {
    ngx_live_persist_file_conf_t       file;
} ngx_live_filler_preset_conf_t;


typedef struct {
    ngx_json_str_t                     channel_id;
    ngx_json_str_t                     preset_name;
    ngx_json_str_t                     timeline_id;
} ngx_live_filler_source_t;

typedef struct {
    ngx_pool_t                        *pool;
    ngx_live_filler_source_t           source;

    ngx_live_persist_read_file_ctx_t  *read_ctx;

    uint32_t                           count;
    uint32_t                          *durations;
    uint64_t                           cycle_duration;
    ngx_queue_t                        queue;

    uint32_t                           last_media_type_mask;
} ngx_live_filler_channel_ctx_t;

typedef struct {
    ngx_queue_t                        queue;
    ngx_pool_t                        *pool;
    ngx_live_track_t                  *track;
    ngx_live_filler_segment_t         *segments;
    uint32_t                           bitrate;
} ngx_live_filler_track_ctx_t;


typedef struct {
    ngx_list_part_t                   *part;
    ngx_live_frame_t                  *cur;
    ngx_live_frame_t                  *last;
} ngx_live_filler_frame_iter_t;

typedef struct {
    ngx_buf_chain_t                   *chain;
    size_t                             offset;
} ngx_live_filler_data_iter_t;

typedef struct {
    ngx_live_track_t                  *track;
    int64_t                            start_pts;
    int64_t                            end_pts;

    uint32_t                           frame_count;
    int64_t                            start_dts;
    ngx_live_filler_data_iter_t        data_iter;
    size_t                             data_size;
} ngx_live_filler_serve_ctx_t;


typedef struct {
    ngx_live_timeline_t               *timeline;
    ngx_live_segment_cleanup_t        *cln;
} ngx_live_filler_write_ctx_t;


typedef struct {
    int64_t                            time;
    uint32_t                           count;
    uint32_t                           index;
    uint32_t                          *durations;
    unsigned                           got_media_info:1;
} ngx_live_filler_read_ctx_t;


static size_t ngx_live_filler_channel_json_get_size(void *obj);
static u_char *ngx_live_filler_channel_json_write(u_char *p, void *obj);

static ngx_int_t ngx_live_filler_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_filler_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_filler_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_filler_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_filler_set_channel(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value);

static ngx_int_t ngx_live_filler_post_json(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value);


static ngx_command_t  ngx_live_filler_commands[] = {
    { ngx_string("persist_filler_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_filler_preset_conf_t, file.path),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_filler_module_ctx = {
    ngx_live_filler_preconfiguration,       /* preconfiguration */
    ngx_live_filler_postconfiguration,      /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_live_filler_create_preset_conf,     /* create preset configuration */
    ngx_live_filler_merge_preset_conf,      /* merge preset configuration */
};

ngx_module_t  ngx_live_filler_module = {
    NGX_MODULE_V1,
    &ngx_live_filler_module_ctx,            /* module context */
    ngx_live_filler_commands,               /* module directives */
    NGX_LIVE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_live_json_cmd_t  ngx_live_filler_dyn_cmds[] = {

    { ngx_string("filler"), NGX_JSON_OBJECT,
      ngx_live_filler_set_channel },

    { ngx_null_string, NGX_JSON_NULL,
      ngx_live_filler_post_json },

      ngx_live_null_json_cmd
};

static ngx_live_json_writer_def_t  ngx_live_filler_json_writers[] = {
    { { ngx_live_filler_channel_json_get_size,
        ngx_live_filler_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};

static ngx_live_persist_file_type_t  ngx_live_filler_file_type = {
    NGX_LIVE_PERSIST_TYPE_FILLER, NGX_LIVE_PERSIST_CTX_FILLER_MAIN, 0
};


/* frame iterator */

static ngx_inline void
ngx_live_filler_frame_iter_init(ngx_live_filler_frame_iter_t *iter,
    ngx_live_filler_segment_t *segment)
{
    iter->part = &segment->frames.part;
    iter->cur = iter->part->elts;
    iter->last = iter->cur + iter->part->nelts;
}

static ngx_inline ngx_live_frame_t *
ngx_live_filler_frame_iter_get(ngx_live_filler_frame_iter_t *iter)
{
    ngx_live_frame_t  *frame;

    if (iter->cur >= iter->last) {

        if (iter->part->next == NULL) {
            return NULL;
        }

        iter->part = iter->part->next;
        iter->cur = iter->part->elts;
        iter->last = iter->cur + iter->part->nelts;
    }

    frame = iter->cur;
    iter->cur++;

    return frame;
}

static ngx_int_t
ngx_live_filler_frame_iter_skip(ngx_live_filler_frame_iter_t *iter,
    int64_t target, int64_t *pts, size_t *size)
{
    ngx_live_frame_t  *cur;

    *size = 0;
    while (*pts < target) {

        cur = ngx_live_filler_frame_iter_get(iter);
        if (cur == NULL) {
            return NGX_ERROR;
        }

        *pts += cur->duration;
        *size += cur->size;
    }

    return NGX_OK;
}


/* data iterator */

static void
ngx_live_filler_data_iter_init(ngx_live_filler_data_iter_t *iter,
    ngx_live_filler_segment_t *segment)
{
    iter->chain = segment->data_head;
    iter->offset = 0;
}

static void
ngx_live_filler_data_iter_skip(ngx_live_filler_data_iter_t *iter, size_t left)
{
    size_t            size;
    size_t            offset;
    ngx_buf_chain_t  *chain;

    chain = iter->chain;
    offset = iter->offset;

    size = chain->size - offset;

    for ( ;; ) {

        if (size > left) {
            offset += left;
            break;
        }

        left -= size;

        chain = chain->next;
        offset = 0;

        size = chain->size;
    }

    iter->chain = chain;
    iter->offset = offset;
}

static ngx_int_t
ngx_live_filler_data_iter_write(ngx_live_filler_data_iter_t *iter,
    ngx_persist_write_ctx_t *write_ctx, size_t size)
{
    return ngx_persist_write_append_buf_chain_n(write_ctx,
        iter->chain, iter->offset, size);
}


/* fill */

static void
ngx_live_filler_set_last_media_types(ngx_live_channel_t *channel,
    uint32_t media_type_mask)
{
    ngx_queue_t                    *q;
    ngx_live_track_t               *cur_track;
    ngx_live_filler_track_ctx_t    *cur_ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        /* update has_last_segment */

        if (!(media_type_mask & (1 << cur_track->media_type))) {

            if (!cur_track->has_last_segment) {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_filler_set_last_media_types: track removed");

            cur_track->last_segment_bitrate = 0;
            cur_track->has_last_segment = 0;

        } else {

            if (cur_track->has_last_segment) {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_filler_set_last_media_types: track added");

            cur_track->last_segment_bitrate = cur_ctx->bitrate;
            cur_track->has_last_segment = 1;
        }
    }

    cctx->last_media_type_mask = media_type_mask;
}


static uint32_t
ngx_live_filler_video_get_segment_index(ngx_live_filler_channel_ctx_t *cctx,
    int64_t pts)
{
    int64_t   cur;
    int64_t   diff;
    int64_t   min_diff;
    uint32_t  i, index;

    pts %= cctx->cycle_duration;

    index = 0;
    min_diff = pts;     /* == ngx_abs_diff(cur, pts) */

    cur = 0;
    for (i = 0; i < cctx->count; i++) {
        cur += cctx->durations[i];

        diff = ngx_abs_diff(cur, pts);
        if (diff < min_diff) {
            index = i + 1;
            min_diff = diff;
        }
    }

    return index < cctx->count ? index : 0;
}

ngx_int_t
ngx_live_filler_fill(ngx_live_channel_t *channel, uint32_t media_type_mask,
    int64_t start_pts, uint32_t min_duration, uint32_t max_duration,
    uint32_t *fill_duration)
{
    uint32_t                        index;
    uint32_t                        duration;
    uint32_t                        cur_duration;
    uint32_t                        next_duration;
    uint32_t                        initial_index;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return NGX_DONE;
    }

    media_type_mask &= channel->filler_media_types;

    if (cctx->last_media_type_mask != media_type_mask) {
        ngx_live_filler_set_last_media_types(channel, media_type_mask);
    }

    if (media_type_mask == 0) {
        return NGX_DONE;
    }

    if (!(media_type_mask & (1 << KMP_MEDIA_VIDEO))) {
        return NGX_OK;
    }

    initial_index = ngx_live_filler_video_get_segment_index(cctx, start_pts);

    duration = 0;
    index = initial_index;

    for ( ;; ) {

        cur_duration = cctx->durations[index];
        next_duration = duration + cur_duration;

        if (duration >= min_duration &&
            ngx_abs_diff(next_duration, *fill_duration) >
            ngx_abs_diff(duration, *fill_duration))
        {
            *fill_duration = duration;
            break;
        }

        index++;
        if (index >= cctx->count) {
            index = 0;
        }

        if (next_duration >= max_duration) {
            *fill_duration = max_duration;
            break;
        }

        duration = next_duration;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_filler_fill: "
        "pts: %L, min_duration: %uD, max_duration: %uD, "
        "duration: %uD, index: %uD..%uD",
        start_pts, min_duration, max_duration,
        *fill_duration, initial_index, index);

    return NGX_OK;
}


/* serve */

static ngx_int_t
ngx_live_filler_serve_write_frames(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_filler_serve_ctx_t *sctx, ngx_live_filler_frame_iter_t *iter,
    uint64_t *duration)
{
    ngx_live_frame_t  *cur;

    for ( ;; ) {

        cur = ngx_live_filler_frame_iter_get(iter);
        if (cur == NULL) {
            break;
        }

        if (ngx_persist_write(write_ctx, cur, sizeof(*cur)) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
                "ngx_live_filler_serve_write_frames: write failed");
            return NGX_ERROR;
        }

        sctx->frame_count++;
        if (sctx->frame_count > NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
            ngx_log_error(NGX_LOG_ERR, ngx_persist_write_log(write_ctx), 0,
                "ngx_live_filler_serve_write_frames: frame count too big");
            return NGX_ERROR;
        }

        sctx->data_size += cur->size;

        if (*duration <= cur->duration) {
            return NGX_DONE;
        }

        *duration -= cur->duration;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_serve_video(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_filler_serve_ctx_t *sctx)
{
    int64_t                         cur_pts;
    int64_t                         end_pts;
    uint32_t                        index;
    uint32_t                        duration;
    uint64_t                        write_duration;
    ngx_int_t                       rc;
    ngx_live_track_t               *track;
    ngx_live_filler_segment_t      *segment;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_frame_iter_t    iter;
    ngx_live_filler_channel_ctx_t  *cctx;

    track = sctx->track;
    cur_pts = sctx->start_pts;
    end_pts = sctx->end_pts;

    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_filler_module);

    index = ngx_live_filler_video_get_segment_index(cctx, cur_pts);
    segment = &ctx->segments[index];

    ngx_live_filler_data_iter_init(&sctx->data_iter, segment);
    sctx->start_dts = cur_pts - segment->pts_delay;

    while (cur_pts < end_pts) {

        ngx_live_filler_frame_iter_init(&iter, segment);

        duration = cctx->durations[index];
        if (cur_pts + duration > end_pts) {

            write_duration = end_pts - cur_pts;
            rc = ngx_live_filler_serve_write_frames(write_ctx, sctx, &iter,
                &write_duration);
            if (rc != NGX_OK && rc != NGX_DONE) {
                ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx),
                    0, "ngx_live_filler_serve_video: write failed (1)");
                return NGX_ERROR;
            }

            break;
        }

        write_duration = LLONG_MAX;
        if (ngx_live_filler_serve_write_frames(write_ctx, sctx, &iter,
            &write_duration) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
                "ngx_live_filler_serve_video: write failed (2)");
            return NGX_ERROR;
        }

        cur_pts += duration;

        index++;
        if (index >= cctx->count) {
            index = 0;
        }

        segment = &ctx->segments[index];
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_audio_get_segment_index(ngx_live_track_t *track,
    uint32_t *index, int64_t *pts)
{
    int64_t                         cur, next;
    uint32_t                        i;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_filler_module);

    cur = (*pts / cctx->cycle_duration) * cctx->cycle_duration;

    for (i = 0; ; i++) {

        if (i >= cctx->count) {
            return NGX_ERROR;
        }

        next = cur + ctx->segments[i].duration;
        if (*pts >= cur && *pts < next) {
            break;
        }

        cur = next;
    }

    *index = i;
    *pts = cur;

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_serve_audio_write_frames(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_filler_serve_ctx_t *sctx, ngx_live_filler_frame_iter_t *iter,
    uint32_t index, uint64_t duration)
{
    ngx_int_t                       rc;
    ngx_live_track_t               *track;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    track = sctx->track;
    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_filler_module);

    for ( ;; ) {

        rc = ngx_live_filler_serve_write_frames(write_ctx, sctx, iter,
            &duration);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            return NGX_OK;

        default:
            return NGX_ERROR;
        }

        index++;
        if (index >= cctx->count) {
            index = 0;
        }

        ngx_live_filler_frame_iter_init(iter, &ctx->segments[index]);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_serve_audio(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_filler_serve_ctx_t *sctx)
{
    size_t                         skip_size;
    int64_t                        pts;
    int64_t                        start_pts, end_pts;
    uint32_t                       index;
    ngx_live_track_t              *track;
    ngx_live_filler_segment_t     *segment;
    ngx_live_filler_track_ctx_t   *ctx;
    ngx_live_filler_frame_iter_t   iter;

    track = sctx->track;
    start_pts = sctx->start_pts;

    pts = start_pts;
    if (ngx_live_filler_audio_get_segment_index(track, &index, &pts)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ALERT, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_audio: "
            "segment index not found, track: %V, pts: %L",
            &track->sn.str, start_pts);
        return NGX_ERROR;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);

    segment = &ctx->segments[index];
    ngx_live_filler_frame_iter_init(&iter, segment);

    if (ngx_live_filler_frame_iter_skip(&iter, start_pts, &pts, &skip_size)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ALERT, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_audio: "
            "failed to skip to initial frame, pts: %L", start_pts);
        return NGX_ERROR;
    }

    end_pts = sctx->end_pts;
    if (end_pts < pts) {
        ngx_log_error(NGX_LOG_ERR, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_audio: "
            "no frames, start: %L, end: %L, pts: %L", start_pts, end_pts, pts);
        return NGX_ERROR;
    }

    if (ngx_live_filler_serve_audio_write_frames(write_ctx, sctx, &iter, index,
        end_pts - pts) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_audio: write failed");
        return NGX_ERROR;
    }

    ngx_live_filler_data_iter_init(&sctx->data_iter, segment);
    ngx_live_filler_data_iter_skip(&sctx->data_iter, skip_size);
    sctx->start_dts = pts;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_serve_write_frame_list(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_track_t             *track;
    ngx_live_filler_serve_ctx_t  *sctx = obj;

    track = sctx->track;
    switch (track->media_type) {

    case KMP_MEDIA_VIDEO:
        if (ngx_live_filler_serve_video(write_ctx, sctx) != NGX_OK) {
            return NGX_ERROR;
        }
        break;

    case KMP_MEDIA_AUDIO:
        if (ngx_live_filler_serve_audio(write_ctx, sctx) != NGX_OK) {
            return NGX_ERROR;
        }
        break;
    }

    if (sctx->frame_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_write_frame_list: "
            "no frames, track: %V", &track->sn.str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_serve_write_frame_data(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_filler_serve_ctx_t  *sctx = obj;

    /* Note: no need to send segment_index & ptr for filler lock,
        since the filler content was linked to the original track */

    if (ngx_live_input_bufs_lock_cleanup(ngx_persist_write_pool(write_ctx),
        sctx->track, 0, NULL) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_write_frame_data: lock failed");
        return NGX_ERROR;
    }

    if (ngx_live_filler_data_iter_write(&sctx->data_iter, write_ctx,
        sctx->data_size) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_write_frame_data: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_serve_segment(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_live_channel_t                 *channel;
    ngx_persist_write_marker_t          marker;
    ngx_live_filler_serve_ctx_t         sctx;
    ngx_live_filler_channel_ctx_t      *cctx;
    ngx_live_persist_segment_header_t   header;

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_segment: filler not set up");
        return NGX_ERROR;
    }

    ngx_memzero(&sctx, sizeof(sctx));
    sctx.track = track;

    if (ngx_live_timelines_get_segment_time(channel, segment_index,
        &sctx.start_pts, &sctx.end_pts) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_segment: "
            "failed to get segment time, index: %uD", segment_index);
        return NGX_ERROR;
    }

    if (ngx_persist_write_block_open(write_ctx, NGX_KSMP_BLOCK_SEGMENT)
            != NGX_OK ||
        ngx_persist_write_reserve(write_ctx, sizeof(header), &marker)
            != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_FILLER_HEADER, &sctx) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_FILLER_DATA, &sctx) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_segment: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);     /* segment */

    header.track_id = track->in.key;
    header.index = segment_index;
    header.frame_count = sctx.frame_count;
    header.start_dts = sctx.start_dts;
    header.reserved = 0;

    ngx_persist_write_marker_write(&marker, &header, sizeof(header));

    return NGX_OK;
}

ngx_int_t
ngx_live_filler_serve_segments(ngx_pool_t *pool, ngx_array_t *track_refs,
    uint32_t segment_index, ngx_chain_t ***last, size_t *size)
{
    size_t                     write_size;
    ngx_uint_t                 i, n;
    ngx_chain_t              **chain;
    ngx_live_track_t          *cur_track;
    ngx_live_track_ref_t      *refs;
    ngx_persist_write_ctx_t   *write_ctx;

    write_ctx = NULL;

    refs = track_refs->elts;
    n = track_refs->nelts;
    for (i = n; i > 0; i--) {

        cur_track = refs[i - 1].track;
        if (cur_track == NULL || cur_track->type != ngx_live_track_type_filler)
        {
            continue;
        }

        if (write_ctx == NULL) {
            write_ctx = ngx_persist_write_init(pool, 0, 0);
            if (write_ctx == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx),
                    0, "ngx_live_filler_serve_segments: write init failed");
                return NGX_ERROR;
            }
        }

        if (ngx_live_filler_serve_segment(write_ctx, cur_track, segment_index)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
                "ngx_live_filler_serve_segments: "
                "serve failed, track: %V", &cur_track->sn.str);
            return NGX_ERROR;
        }

        ngx_memmove(&refs[i - 1], &refs[i], (n - i) * sizeof(refs[0]));
        n--;
    }

    if (write_ctx == NULL) {
        return NGX_DONE;
    }

    track_refs->nelts = n;

    chain = *last;

    *chain = ngx_persist_write_close(write_ctx, &write_size, last);
    if (*chain == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
            "ngx_live_filler_serve_segments: close failed");
        return NGX_ERROR;
    }

    *size += write_size;

    return NGX_OK;
}


/* setup */

static ngx_int_t
ngx_live_filler_setup_copy_frames(ngx_live_filler_segment_t *dst_segment,
    ngx_live_segment_t *src_segment, uint32_t initial_pts_delay,
    ngx_flag_t is_last, uint64_t duration, ngx_log_t *log)
{
    ngx_list_part_t   *part;
    ngx_live_frame_t  *dst;
    ngx_live_frame_t  *cur, *last;

    dst = NULL;
    dst_segment->frame_count = 0;
    dst_segment->data_size = 0;

    part = &src_segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    for ( ;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->pts_delay >= duration + initial_pts_delay) {
            break;
        }

        dst = ngx_list_push(&dst_segment->frames);
        if (dst == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_copy_frames: add frame failed");
            return NGX_ERROR;
        }

        *dst = *cur;
        dst_segment->frame_count++;
        dst_segment->data_size += dst->size;

        if (dst->duration >= duration) {
            dst->duration = duration;
            duration = 0;
            break;
        }

        duration -= dst->duration;
    }

    if (is_last) {
        if (dst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_copy_frames: last segment empty");
            return NGX_ERROR;
        }

        dst->duration += duration;

    } else if (cur < last || part->next != NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup_copy_frames: incomplete segment");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_setup_copy_chains(ngx_live_filler_track_ctx_t *ctx,
    ngx_live_filler_segment_t *dst_segment, ngx_live_segment_t *src_segment,
    ngx_log_t *log)
{
    size_t            size;
    ngx_buf_chain_t  *src;
    ngx_buf_chain_t  *dst, **last_dst;

    size = dst_segment->data_size;
    last_dst = &dst_segment->data_head;

    for (src = src_segment->data_head; ; src = src->next) {

        dst = ngx_palloc(ctx->pool, sizeof(*dst));
        if (dst == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_copy_chains: alloc chain failed");
            return NGX_ERROR;
        }

        *last_dst = dst;
        last_dst = &dst->next;

        dst->data = src->data;

        if (src->size >= size) {
            dst->size = size;
            break;
        }

        dst->size = src->size;
        size -= dst->size;
    }

    *last_dst = NULL;
    dst_segment->data_tail = dst;

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_setup_track_segments(ngx_live_track_t *dst_track,
    ngx_live_track_t *src_track, ngx_live_timeline_t *timeline, ngx_log_t *log)
{
    size_t                          total_size;
    int64_t                         timeline_pts;
    uint32_t                        i;
    uint32_t                        segment_index;
    uint32_t                        initial_pts_delay;
    uint64_t                        duration;
    ngx_int_t                       rc;
    ngx_flag_t                      is_last;
    ngx_queue_t                    *q;
    ngx_live_frame_t               *first_frame;
    ngx_live_period_t              *period;
    ngx_live_channel_t             *dst_channel;
    ngx_live_segment_t             *src_segment;
    ngx_live_filler_segment_t      *dst_segment;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    dst_channel = dst_track->channel;
    ctx = ngx_live_get_module_ctx(dst_track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(dst_channel, ngx_live_filler_module);

    ngx_live_input_bufs_link(dst_track, src_track);

    ctx->segments = ngx_palloc(ctx->pool, sizeof(ctx->segments[0]) *
        cctx->count);
    if (ctx->segments == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track_segments: alloc segments failed");
        return NGX_ERROR;
    }

    q = ngx_queue_head(&timeline->periods);
    period = ngx_queue_data(q, ngx_live_period_t, queue);

    segment_index = period->node.key;
    timeline_pts = period->time;

    duration = cctx->cycle_duration;
    total_size = 0;

    /* suppress warning */
    initial_pts_delay = 0;

    for (i = 0 ;; i++) {

        src_segment = ngx_live_segment_cache_get(src_track, segment_index);
        if (src_segment == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_track_segments: "
                "failed to get segment %uD, track: %V",
                segment_index, &src_track->sn.str);
            return NGX_ERROR;
        }

        /* copy the frames */
        dst_segment = &ctx->segments[i];
        if (ngx_list_init(&dst_segment->frames, ctx->pool, 10,
            sizeof(ngx_live_frame_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_track_segments: "
                "init frame list failed");
            return NGX_ERROR;
        }

        if (i == 0) {
            first_frame = src_segment->frames.part.elts;
            initial_pts_delay = first_frame[0].pts_delay;
        }

        is_last = i + 1 >= cctx->count;

        rc = ngx_live_filler_setup_copy_frames(dst_segment, src_segment,
            initial_pts_delay, is_last, duration, log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_track_segments: copy frames failed");
            return rc;
        }

        /* copy the data chains */
        rc = ngx_live_filler_setup_copy_chains(ctx, dst_segment, src_segment,
            log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_track_segments: copy chains failed");
            return rc;
        }

        total_size += dst_segment->data_size;

        if (i > 0) {
            dst_segment[-1].data_tail->next = dst_segment->data_head;
        }

        dst_segment->pts_delay = timeline_pts - src_segment->start_dts;

        if (is_last) {
            dst_segment->duration = duration;
            break;
        }

        dst_segment->duration = src_segment->end_dts - src_segment->start_dts;

        /* move to next segment */
        duration -= dst_segment->duration;
        segment_index++;
        timeline_pts += cctx->durations[i];
    }

    dst_segment->data_tail->next = ctx->segments[0].data_head;

    ctx->bitrate = (total_size * 8 * dst_channel->timescale)
        / cctx->cycle_duration;
    if (ctx->bitrate <= 0) {
        ctx->bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
    }

    return NGX_OK;
}

static void
ngx_live_filler_setup_free_tracks(ngx_live_channel_t *channel)
{
    ngx_queue_t       *q;
    ngx_live_track_t  *cur_track;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue); )
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        q = ngx_queue_next(q);      /* track may be freed */

        if (cur_track->type != ngx_live_track_type_filler) {
            continue;
        }

        ngx_live_track_free(cur_track);
    }
}

static ngx_int_t
ngx_live_filler_setup_track(ngx_live_channel_t *dst,
    ngx_live_track_t *src_track, ngx_live_timeline_t *timeline, ngx_log_t *log)
{
    ngx_int_t                       rc;
    ngx_live_track_t               *dst_track;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    /* create the track */
    rc = ngx_live_track_create(dst, &src_track->sn.str,
        NGX_LIVE_INVALID_TRACK_ID, src_track->media_type, log, &dst_track);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_EXISTS:
        if (dst_track->type != ngx_live_track_type_filler) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_track: "
                "track \"%V\" already exists in channel \"%V\"",
                &src_track->sn.str, &dst->sn.str);
            return NGX_ERROR;
        }

        if (ngx_live_media_info_queue_get_last(dst_track) != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_track: "
                "track \"%V\" already has media info", &src_track->sn.str);
            return NGX_ERROR;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: create track failed %i", rc);
        return NGX_ERROR;
    }

    dst_track->type = ngx_live_track_type_filler;

    ctx = ngx_live_get_module_ctx(dst_track, ngx_live_filler_module);

    if (ctx->pool != NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_filler_setup_track: track \"%V\" already initialized",
            &dst_track->sn.str);
        return NGX_ERROR;
    }

    ctx->pool = ngx_create_pool(1024, &dst_track->log);
    if (ctx->pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: create pool failed");
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(dst, ngx_live_filler_module);

    ctx->track = dst_track;

    ngx_queue_insert_tail(&cctx->queue, &ctx->queue);
    dst->filler_media_types |= 1 << dst_track->media_type;

    /* copy the media info */
    rc = ngx_live_media_info_queue_copy_last(dst_track, src_track,
        dst->filler_start_index);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: failed to copy media info");
        return NGX_ERROR;
    }

    /* create the segments */
    rc = ngx_live_filler_setup_track_segments(dst_track, src_track,
        timeline, log);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: create segments failed");
        return rc;
    }

    return NGX_OK;
}

static uint64_t
ngx_live_filler_setup_get_cycle_duration(ngx_live_channel_t *src,
    uint32_t segment_index, uint32_t count, ngx_log_t *log)
{
    int64_t              start_dts;
    uint32_t             last_segment_index;
    uint64_t             cur_duration;
    uint64_t             duration[KMP_MEDIA_COUNT];
    ngx_queue_t         *q;
    ngx_live_track_t    *src_track;
    ngx_live_segment_t  *src_segment;

    ngx_memzero(duration, sizeof(duration));

    last_segment_index = segment_index + count - 1;

    /* find max duration per media type */
    for (q = ngx_queue_head(&src->tracks.queue);
        q != ngx_queue_sentinel(&src->tracks.queue);
        q = ngx_queue_next(q))
    {
        src_track = ngx_queue_data(q, ngx_live_track_t, queue);

        src_segment = ngx_live_segment_cache_get(src_track, segment_index);
        if (src_segment == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_get_cycle_duration: "
                "failed to get segment %uD (1), track: %V",
                segment_index, &src_track->sn.str);
            return 0;
        }

        start_dts = src_segment->start_dts;

        if (count > 1) {
            src_segment = ngx_live_segment_cache_get(src_track,
                last_segment_index);
            if (src_segment == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_live_filler_setup_get_cycle_duration: "
                    "failed to get segment %uD (2), track: %V",
                    last_segment_index, &src_track->sn.str);
                return 0;
            }
        }

        cur_duration = src_segment->end_dts - start_dts;

        if (duration[src_track->media_type] < cur_duration) {
            duration[src_track->media_type] = cur_duration;
        }
    }

    /* prefer to use the audio duration - changing the duration of audio
        frames is problematic */
    if (duration[KMP_MEDIA_AUDIO] > 0) {
        return duration[KMP_MEDIA_AUDIO];

    } else if (duration[KMP_MEDIA_VIDEO] > 0) {
        return duration[KMP_MEDIA_VIDEO];
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0,
        "ngx_live_filler_setup_get_cycle_duration: "
        "failed to get cycle duration");
    return 0;
}

static void
ngx_live_filler_setup_get_durations(ngx_live_filler_channel_ctx_t *cctx,
    ngx_live_timeline_t *timeline)
{
    int64_t                   delta;
    int32_t                   index, count;
    uint64_t                  duration;
    uint32_t                 *cur, *end;
    ngx_queue_t              *q;
    ngx_live_period_t        *period;
    ngx_live_segment_iter_t   iter;

    /* get the segment durations */
    q = ngx_queue_head(&timeline->periods);
    period = ngx_queue_data(q, ngx_live_period_t, queue);

    iter = period->segment_iter;
    duration = 0;

    cur = cctx->durations;
    end = cur + cctx->count;
    for (; cur < end; cur++) {
        *cur = ngx_live_segment_iter_get_one(&iter);
        duration += *cur;
    }

    /* adjust the durations to match the cycle duration */
    delta = cctx->cycle_duration - duration;
    count = cctx->count;

    for (index = 0; index < count; index++) {
        cctx->durations[index] += (delta * (index + 1)) / count -
            (delta * index) / count;
    }
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_filler_setup_validate_segment(ngx_live_filler_segment_t *segment,
    ngx_log_t *log)
{
    size_t             data_size;
    size_t             frames_size;
    uint32_t           duration;
    ngx_buf_chain_t   *data;
    ngx_list_part_t   *part;
    ngx_live_frame_t  *cur, *last;

    /* get the total size and duration of the frames */
    duration = 0;
    frames_size = 0;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    for ( ;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        duration += cur->duration;
        frames_size += cur->size;
    }

    if (segment->duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_filler_setup_validate_segment: "
            "invalid segment duration %uD expected %uD",
            segment->duration, duration);
        ngx_debug_point();
    }

    /* make sure data head/tail match the frames size */
    data_size = 0;
    data = segment->data_head;

    for ( ;; ) {

        data_size += data->size;
        if (data_size >= frames_size) {
            break;
        }

        data = data->next;
    }

    if (data_size != frames_size) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_filler_setup_validate_segment: "
            "data size %uz doesn't match frames size %uz",
            data_size, frames_size);
        ngx_debug_point();
    }

    if (segment->data_tail != data) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_filler_setup_validate_segment: data tail mismatch");
        ngx_debug_point();
    }
}

static void
ngx_live_filler_setup_validate(ngx_live_channel_t *channel)
{
    uint32_t                        i;
    uint32_t                        filler_media_types;
    uint64_t                        duration;
    ngx_queue_t                    *q;
    ngx_buf_chain_t                *prev_data;
    ngx_live_track_t               *cur_track;
    ngx_live_filler_segment_t      *cur_segment;
    ngx_live_filler_track_ctx_t    *cur_ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    duration = 0;
    for (i = 0; i < cctx->count; i++) {
        duration += cctx->durations[i];
    }

    if (cctx->cycle_duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_filler_setup_validate: "
            "invalid cycle duration %uL expected %uL",
            cctx->cycle_duration, duration);
        ngx_debug_point();
    }

    filler_media_types = 0;
    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        duration = 0;
        prev_data = cur_ctx->segments[cctx->count - 1].data_tail;
        for (i = 0; i < cctx->count; i++) {
            cur_segment = &cur_ctx->segments[i];

            if (prev_data->next != cur_segment->data_head) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_filler_setup_validate: "
                    "segment data not connected to prev segment");
                ngx_debug_point();
            }

            ngx_live_filler_setup_validate_segment(cur_segment,
                &cur_track->log);

            duration += cur_segment->duration;

            prev_data = cur_segment->data_tail;
        }

        if (duration != cctx->cycle_duration) {
            ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                "ngx_live_filler_setup_validate: "
                "track duration %uL doesn't match cycle duration %uL",
                duration, cctx->cycle_duration);
            ngx_debug_point();
        }

        filler_media_types |= (1 << cur_track->media_type);
    }

    if (channel->filler_media_types != filler_media_types) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_filler_setup_validate: "
            "invalid channel media types mask 0x%uxD expected 0x%uxD",
            channel->filler_media_types, filler_media_types);
        ngx_debug_point();
    }
}
#else
#define ngx_live_filler_setup_validate(channel)
#endif

static void
ngx_live_filler_setup_free_unused_tracks(ngx_live_channel_t *channel)
{
    ngx_queue_t                  *q;
    ngx_live_track_t             *cur_track;
    ngx_live_filler_track_ctx_t  *cur_ctx;

    /* Note: filler tracks may be unused if they were saved on the channel
        using the filler, but later removed from the filler channel itself */

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue); )
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        q = ngx_queue_next(q);      /* track may be freed */

        if (cur_track->type != ngx_live_track_type_filler) {
            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_filler_module);
        if (cur_ctx->pool != NULL) {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
            "ngx_live_filler_setup_free_unused_tracks: freeing track");

        ngx_live_track_free(cur_track);
    }
}

static ngx_int_t
ngx_live_filler_setup(ngx_live_channel_t *dst, ngx_live_channel_t *src,
    ngx_live_timeline_t *timeline, ngx_log_t *log)
{
    u_char                         *p;
    ngx_queue_t                    *q;
    ngx_live_track_t               *src_track;
    ngx_live_period_t              *period;
    ngx_live_filler_channel_ctx_t  *cctx;

    if (timeline->period_count != 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup: "
            "input timeline must have a single period, id: %V, count: %uD",
            &timeline->sn.str, timeline->period_count);
        return NGX_ERROR;
    }

    if (timeline->segment_count > NGX_LIVE_FILLER_MAX_SEGMENTS) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup: segment count %uD too big",
            timeline->segment_count);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(dst, ngx_live_filler_module);

    cctx->count = timeline->segment_count;

    p = ngx_palloc(cctx->pool, cctx->count * sizeof(cctx->durations[0]));
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup: alloc failed");
        goto failed;
    }

    cctx->durations = (void *) p;

    q = ngx_queue_head(&timeline->periods);
    period = ngx_queue_data(q, ngx_live_period_t, queue);

    cctx->cycle_duration = ngx_live_filler_setup_get_cycle_duration(src,
        period->node.key, cctx->count, log);
    if (cctx->cycle_duration <= 0) {
        goto failed;
    }

    ngx_live_filler_setup_get_durations(cctx, timeline);

    for (q = ngx_queue_head(&src->tracks.queue);
        q != ngx_queue_sentinel(&src->tracks.queue);
        q = ngx_queue_next(q))
    {
        src_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (ngx_live_filler_setup_track(dst, src_track, timeline, log)
            != NGX_OK)
        {
            goto failed;
        }
    }

    ngx_live_filler_setup_free_unused_tracks(dst);

    ngx_live_filler_setup_validate(dst);

    return NGX_OK;

failed:

    ngx_live_filler_setup_free_tracks(dst);

    cctx->count = 0;
    cctx->durations = NULL;
    cctx->cycle_duration = 0;

    return NGX_ERROR;
}


/* json cmd */

static ngx_int_t
ngx_live_filler_source_set(ngx_live_channel_t *channel,
    ngx_live_filler_source_t *new, uint32_t filler_start_index, ngx_log_t *log)
{
    u_char                         *p;
    ngx_pool_t                     *pool;
    ngx_live_filler_source_t       *cur;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    if (cctx->pool != NULL) {
        cur = &cctx->source;

        if (cur->channel_id.s.len != new->channel_id.s.len ||
            ngx_memcmp(cur->channel_id.s.data, new->channel_id.s.data,
                new->channel_id.s.len) != 0 ||
            cur->timeline_id.s.len != new->timeline_id.s.len ||
            ngx_memcmp(cur->timeline_id.s.data, new->timeline_id.s.data,
                new->timeline_id.s.len) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "ngx_live_filler_source_set: "
                "attempt to change filler from \"%V:%V\" to \"%V:%V\"",
                &cur->channel_id.s, &cur->timeline_id.s,
                &new->channel_id.s, &new->timeline_id.s);
        }

        return NGX_OK;
    }

    pool = ngx_create_pool(1024, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_source_set: create pool failed");
        return NGX_ERROR;
    }

    p = ngx_palloc(pool, new->channel_id.s.len + new->preset_name.s.len +
        new->timeline_id.s.len);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_source_set: alloc failed");
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    cctx->pool = pool;

    cur = &cctx->source;

    cur->channel_id.s.data = p;
    cur->channel_id.s.len = new->channel_id.s.len;
    p = ngx_copy(p, new->channel_id.s.data, new->channel_id.s.len);
    ngx_json_str_set_escape(&cur->channel_id);

    cur->preset_name.s.data = p;
    cur->preset_name.s.len = new->preset_name.s.len;
    p = ngx_copy(p, new->preset_name.s.data, new->preset_name.s.len);
    ngx_json_str_set_escape(&cur->preset_name);

    cur->timeline_id.s.data = p;
    cur->timeline_id.s.len = new->timeline_id.s.len;
    p = ngx_copy(p, new->timeline_id.s.data, new->timeline_id.s.len);
    ngx_json_str_set_escape(&cur->timeline_id);

    channel->filler_start_index = filler_start_index;

    return NGX_OK;
}

static void
ngx_live_filler_source_unset(ngx_live_channel_t *channel)
{
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return;
    }

    ngx_destroy_pool(cctx->pool);
    cctx->pool = NULL;

    ngx_memzero(&cctx->source, sizeof(cctx->source));
}

static void
ngx_live_filler_write_handler(void *arg, ngx_int_t rc)
{
    void                               *data;
    ngx_live_json_cmds_ctx_t           *jctx;
    ngx_live_json_cmds_handler_pt       handler;
    ngx_live_persist_write_file_ctx_t  *ctx = arg;

    jctx = (void *) ctx->scope;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_write_handler: write failed %i", rc);

    } else {
        ngx_log_error(NGX_LOG_INFO, jctx->pool->log, 0,
            "ngx_live_filler_write_handler: write success");
    }

    handler = jctx->handler;
    data = jctx->data;

    ngx_live_persist_write_file_destroy(ctx);

    handler(data, rc);
}

static void
ngx_live_filler_write_cancel(void *arg)
{
    ngx_live_channel_t                 *channel;
    ngx_live_persist_write_file_ctx_t  *write_ctx = arg;

    channel = write_ctx->channel;

    ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
        "ngx_live_filler_write_cancel: cancelling write request");

    ngx_live_filler_write_handler(write_ctx, NGX_HTTP_CONFLICT);
}

static ngx_int_t
ngx_live_filler_write_file(ngx_live_json_cmds_ctx_t *jctx,
    ngx_str_t *timeline_id)
{
    ngx_live_channel_t                 *channel;
    ngx_live_timeline_t                *timeline;
    ngx_live_filler_write_ctx_t         ctx;
    ngx_live_filler_preset_conf_t      *fpcf;
    ngx_live_persist_write_file_ctx_t  *write_ctx;

    channel = jctx->obj;

    fpcf = ngx_live_get_module_preset_conf(channel, ngx_live_filler_module);
    if (fpcf->file.path == NULL) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_filler_write_file: "
            "missing \"persist_filler_path\" directive");
        return NGX_ERROR;
    }

    timeline = ngx_live_timeline_get(channel, timeline_id);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_filler_write_file: "
            "unknown timeline \"%V\" in channel \"%V\"",
            timeline_id, &channel->sn.str);
        return NGX_ERROR;
    }

    if (timeline->period_count != 1) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_filler_write_file: "
            "timeline must have a single period, actual: %uD",
            timeline->period_count);
        return NGX_ERROR;
    }

    ctx.timeline = timeline;
    ctx.cln = NULL;

    write_ctx = ngx_live_persist_write_file(channel, &fpcf->file,
        &ngx_live_filler_file_type, ngx_live_filler_write_handler, &ctx,
        jctx, sizeof(*jctx));
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_write_file: write failed");
        return NGX_ERROR;
    }

    ctx.cln->handler = ngx_live_filler_write_cancel;
    ctx.cln->data = write_ctx;

    /* Note: if the channel is freed, the segment index module will call
        ngx_live_filler_write_cancel, which will free the pool */

    return NGX_AGAIN;
}

static ngx_int_t
ngx_live_filler_read_create_segments(ngx_live_channel_t *channel,
    ngx_live_filler_read_ctx_t *ctx)
{
    int64_t   time;
    uint32_t  i;
    uint32_t  cur;

    time = ctx->time;

    for (i = 0; i < ctx->count; i++) {
        cur = ctx->durations[i];

        if (ngx_live_timelines_add_segment(channel, time, cur, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_filler_read_create_segments: add segment failed");
            return NGX_ERROR;
        }

        time += cur;

        channel->next_segment_index++;
    }

    channel->last_segment_created = ngx_time();

    return NGX_OK;
}

static void
ngx_live_filler_read_handler(void *data, ngx_int_t rc,
    ngx_buf_t *response)
{
    ngx_str_t                          buf;
    ngx_pool_cleanup_t                *cln;
    ngx_live_channel_t                *channel;
    ngx_live_filler_read_ctx_t         ctx;
    ngx_live_filler_channel_ctx_t     *cctx;
    ngx_live_filler_preset_conf_t     *fpcf;
    ngx_live_persist_read_file_ctx_t  *read_ctx = data;

    channel = read_ctx->channel;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    cctx->read_ctx = NULL;

    /* read_ctx will be freed, make sure the cleanup handler won't run */
    cln = read_ctx->cln;
    if (cln) {
        cln->handler = NULL;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_read_handler: "
            "read failed %i, path: %V", rc, &read_ctx->path);
        goto failed;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_filler_read_handler: read success");

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    fpcf = ngx_live_get_module_preset_conf(channel, ngx_live_filler_module);

    ngx_memzero(&ctx, sizeof(ctx));

    rc = ngx_live_persist_read_parse(channel, &buf,
        &ngx_live_filler_file_type, fpcf->file.max_size, &ctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_read_handler: "
            "parse failed %i, path: %V", rc, &read_ctx->path);
        goto failed;
    }

    if (channel->tracks.count <= 0) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_filler_read_handler: no tracks created, path: %V",
            &read_ctx->path);
        goto failed;
    }

    rc = ngx_live_filler_read_create_segments(channel, &ctx);
    if (rc != NGX_OK) {
        goto failed;
    }

    ngx_destroy_pool(read_ctx->pool);

    channel->read_time = ngx_time();
    channel->blocked--;

    if (channel->blocked <= 0) {
        ngx_live_notif_publish(channel, NGX_LIVE_NOTIF_CHANNEL_READY, NGX_OK);
    }

    return;

failed:

    ngx_destroy_pool(read_ctx->pool);

    ngx_live_notif_publish(channel, NGX_LIVE_NOTIF_CHANNEL_READY, rc);

    /* Note: channel free calls all subscribers with error */
    ngx_live_channel_free(channel, ngx_live_free_read_failed);
}

static ngx_live_channel_t *
ngx_live_filler_read_file(ngx_live_json_cmds_ctx_t *jctx,
    ngx_str_t *channel_id, ngx_str_t *preset)
{
    ngx_int_t                       rc;
    ngx_live_channel_t             *channel;
    ngx_pool_cleanup_t             *cln;
    ngx_live_conf_ctx_t            *conf_ctx;
    ngx_live_filler_channel_ctx_t  *cctx;
    ngx_live_filler_preset_conf_t  *fpcf;

    conf_ctx = ngx_live_core_get_preset_conf((ngx_cycle_t *) ngx_cycle,
        preset);
    if (conf_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_filler_read_file: unknown preset \"%V\"", preset);
        return NULL;
    }

    fpcf = ngx_live_get_module_preset_conf(conf_ctx, ngx_live_filler_module);
    if (fpcf->file.path == NULL) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_filler_read_file: "
            "filler not found and persistence is not enabled");
        return NULL;
    }

    cln = ngx_pool_cleanup_add(jctx->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_read_file: cleanup add failed");
        return NULL;
    }

    rc = ngx_live_channel_create(channel_id, conf_ctx, jctx->pool, &channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_read_file: create channel failed %i", rc);
        return NULL;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    cctx->read_ctx = ngx_live_persist_read_file(channel, cln, &fpcf->file,
        ngx_live_filler_read_handler, NULL, 0);
    if (cctx->read_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_read_file: read file failed");
        ngx_live_channel_free(channel, ngx_live_free_read_failed);
        return NULL;
    }

    channel->blocked++;

    return channel;
}

static void
ngx_live_filler_ready_handler(void *arg, ngx_int_t rc)
{
    ngx_live_channel_t        *channel;
    ngx_live_json_cmds_ctx_t  *jctx = arg;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_ready_handler: notif failed %i", rc);

    } else {
        ngx_log_error(NGX_LOG_INFO, jctx->pool->log, 0,
            "ngx_live_filler_ready_handler: notif success");
    }

    channel = jctx->obj;

    channel->blocked--;

    if (rc != NGX_OK) {
        ngx_live_filler_source_unset(channel);
    }

    jctx->handler(jctx->data, rc);
}

static ngx_int_t
ngx_live_filler_wait_ready(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_channel_t *dst, ngx_live_channel_t *src)
{
    ngx_pool_cleanup_t        *cln;
    ngx_live_notif_sub_t      *sub;
    ngx_live_json_cmds_ctx_t  *jctx_copy;

    cln = ngx_pool_cleanup_add(jctx->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_wait_ready: cleanup add failed");
        return NGX_ERROR;
    }

    jctx_copy = ngx_palloc(jctx->pool, sizeof(*jctx_copy));
    if (jctx_copy == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
            "ngx_live_filler_wait_ready: alloc failed");
        return NGX_ERROR;
    }

    *jctx_copy = *jctx;

    sub = ngx_live_notif_subscribe(src, NGX_LIVE_NOTIF_CHANNEL_READY, dst,
        cln);

    sub->handler = ngx_live_filler_ready_handler;
    sub->data = jctx_copy;

    dst->blocked++;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_live_filler_set_channel(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value)
{
    ngx_log_t                 *log;
    ngx_live_channel_t        *dst;
    ngx_live_filler_json_t     json;
    ngx_live_filler_source_t   source;

    if (value->v.obj.nelts <= 0) {
        return NGX_OK;
    }

    log = jctx->pool->log;
    dst = jctx->obj;

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(jctx->pool, &value->v.obj, ngx_live_filler_json,
        ngx_array_entries(ngx_live_filler_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_set_channel: failed to parse json");
        return NGX_ERROR;
    }

    if (json.save == 1) {
        if (json.timeline_id.data == NGX_JSON_UNSET_PTR) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_set_channel: missing mandatory params (1)");
            return NGX_ERROR;
        }

        value->v.obj.nelts = 0;     /* prevent loop */

        return ngx_live_filler_write_file(jctx, &json.timeline_id);
    }

    if (json.channel_id.data == NGX_JSON_UNSET_PTR ||
        json.preset.data == NGX_JSON_UNSET_PTR ||
        json.timeline_id.data == NGX_JSON_UNSET_PTR)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_set_channel: missing mandatory params (2)");
        return NGX_ERROR;
    }

    /* Note: no need to set 'escape' */
    source.channel_id.s = json.channel_id;
    source.preset_name.s = json.preset;
    source.timeline_id.s = json.timeline_id;

    return ngx_live_filler_source_set(dst, &source, dst->next_segment_index,
        log);
}

static ngx_int_t
ngx_live_filler_post_json(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value)
{
    ngx_str_t                       channel_id;
    ngx_pool_t                     *pool = jctx->pool;
    ngx_live_channel_t             *dst = jctx->obj;
    ngx_live_channel_t             *src;
    ngx_live_timeline_t            *src_timeline;
    ngx_live_filler_channel_ctx_t  *cctx;

    /* Note: filler setup is done in 'post json' and not in 'set channel'
        in order to support reading the filler source from setup file */

    cctx = ngx_live_get_module_ctx(dst, ngx_live_filler_module);
    if (cctx->pool == NULL || cctx->count > 0) {
        /* no source set / already set up */
        return NGX_OK;
    }

    channel_id = cctx->source.channel_id.s;

    src = ngx_live_channel_get(&channel_id);
    if (src == NULL) {
        src = ngx_live_filler_read_file(jctx, &channel_id,
            &cctx->source.preset_name.s);
        if (src == NULL) {
            goto failed;
        }
    }

    if (src->blocked) {
        if (ngx_live_filler_wait_ready(jctx, dst, src) != NGX_AGAIN) {
            goto failed;
        }

        return NGX_AGAIN;
    }

    src_timeline = ngx_live_timeline_get(src, &cctx->source.timeline_id.s);
    if (src_timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_filler_post_json: "
            "unknown timeline \"%V\" in channel \"%V\"",
            &cctx->source.timeline_id, &channel_id);
        goto failed;
    }

    if (ngx_live_filler_setup(dst, src, src_timeline, pool->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_filler_post_json: setup failed");
        goto failed;
    }

    ngx_log_error(NGX_LOG_INFO, &dst->log, 0,
        "ngx_live_filler_post_json: using channel \"%V\" as filler",
        &channel_id);

    return NGX_OK;

failed:

    ngx_live_filler_source_unset(dst);

    return NGX_ERROR;
}


/* persist */

static ngx_int_t
ngx_live_filler_write_setup(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_wstream_t                  *ws;
    ngx_live_channel_t             *channel = obj;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return NGX_OK;
    }

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_FILLER_PERSIST_BLOCK) != NGX_OK ||
        ngx_wstream_str(ws, &cctx->source.channel_id.s) != NGX_OK ||
        ngx_wstream_str(ws, &cctx->source.preset_name.s) != NGX_OK ||
        ngx_wstream_str(ws, &cctx->source.timeline_id.s) != NGX_OK ||
        ngx_persist_write(write_ctx, &channel->filler_start_index,
            sizeof(channel->filler_start_index)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_write_setup: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_read_setup(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                        filler_start_index;
    ngx_live_channel_t             *channel = obj;
    ngx_live_filler_source_t        source;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool != NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_setup: channel \"%V\" already has a filler",
            &channel->sn.str);
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &source.channel_id.s) != NGX_OK ||
        ngx_mem_rstream_str_get(rs, &source.preset_name.s) != NGX_OK ||
        ngx_mem_rstream_str_get(rs, &source.timeline_id.s) != NGX_OK ||
        ngx_mem_rstream_read(rs, &filler_start_index,
            sizeof(filler_start_index)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_setup: read failed");
        return NGX_BAD_DATA;
    }

    return ngx_live_filler_source_set(channel, &source, filler_start_index,
        rs->log);
}


static ngx_int_t
ngx_live_filler_write_frame_list(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_segment_t  *segment = obj;

    return ngx_persist_write_list_data(write_ctx, &segment->frames);
}

static ngx_int_t
ngx_live_filler_read_frame_list(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t            rc;
    ngx_live_segment_t  *segment = obj;

    if (segment->frames.part.nelts != 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_frame_list: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_mem_rstream_read_list(rs, &segment->frames, segment->frame_count);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_frame_list: read failed");
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_write_frame_data(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_segment_t  *segment = obj;

    return ngx_persist_write_append_buf_chain(write_ctx, segment->data_head);
}

static ngx_int_t
ngx_live_filler_read_frame_data(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_str_t            data;
    ngx_live_segment_t  *segment = obj;

    if (segment->data_head != NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_frame_data: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    if (data.len <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_frame_data: empty frame data");
        return NGX_BAD_DATA;
    }

    segment->data_head = ngx_live_input_bufs_read_chain(segment->track,
        &data, &segment->data_tail);
    if (segment->data_head == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_frame_data: read failed");
        return NGX_ERROR;
    }

    segment->data_size = data.len;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_write_segment(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_segment_t *segment)
{
    ngx_live_track_t                   *track = segment->track;
    ngx_live_persist_segment_header_t   sp;

    sp.track_id = track->in.key;
    sp.index = segment->node.key;
    sp.frame_count = segment->frame_count;
    sp.start_dts = segment->start_dts;
    sp.reserved = 0;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_PERSIST_BLOCK_SEGMENT) != NGX_OK ||
        ngx_persist_write(write_ctx, &sp, sizeof(sp)) != NGX_OK ||
        ngx_live_persist_write_blocks(track->channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_FILLER_SEGMENT, segment) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_filler_write_segment: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_write_segments(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    uint32_t                      last_index;
    uint32_t                      segment_index;
    ngx_pool_t                   *pool;
    ngx_queue_t                  *q;
    ngx_live_track_t             *track = obj;
    ngx_live_period_t            *period;
    ngx_live_channel_t           *channel;
    ngx_live_segment_t           *segment;
    ngx_live_segment_index_t     *index;
    ngx_live_filler_write_ctx_t  *ctx;

    ctx = ngx_persist_write_ctx(write_ctx);

    q = ngx_queue_head(&ctx->timeline->periods);
    period = ngx_queue_data(q, ngx_live_period_t, queue);

    segment_index = period->node.key;

    if (ctx->cln == NULL) {
        channel = track->channel;

        index = ngx_live_segment_index_get(channel, segment_index);
        if (index == NULL) {
            ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
                "ngx_live_filler_write_segments: "
                "failed to get index %ui", segment_index);
            return NGX_ERROR;
        }

        pool = ngx_persist_write_pool(write_ctx);

        ctx->cln = ngx_live_segment_index_cleanup_add(pool, index,
            channel->tracks.count);
        if (ctx->cln == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_filler_write_segments: "
                "add cleanup item failed");
            return NGX_ERROR;
        }
    }

    for (last_index = segment_index + period->segment_count;
        segment_index < last_index;
        segment_index++)
    {
        segment = ngx_live_segment_cache_get(track, segment_index);
        if (segment == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_filler_write_segments: "
                "failed to get segment %uD", segment_index);
            return NGX_ERROR;
        }

        if (segment_index == period->node.key) {
            if (ngx_live_segment_index_lock(ctx->cln, segment) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_filler_write_segments: lock segment failed");
                return NGX_ERROR;
            }
        }

        if (ngx_live_filler_write_segment(write_ctx, segment) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_live_filler_read_get_frames_info(ngx_live_segment_t *segment,
    size_t *size, int64_t *duration)
{
    ngx_list_part_t   *part;
    ngx_live_frame_t  *cur, *last;

    *size = 0;
    *duration = 0;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    for (;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        *size += cur->size;
        *duration += cur->duration;
    }
}

static ngx_int_t
ngx_live_filler_read_segment(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    size_t                              size;
    int64_t                             duration;
    ngx_int_t                           rc;
    ngx_live_track_t                   *track = obj;
    ngx_live_segment_t                 *segment;
    ngx_live_filler_read_ctx_t         *ctx;
    ngx_live_persist_segment_header_t  *sp;

    sp = ngx_mem_rstream_get_ptr(rs, sizeof(*sp));
    if (sp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_segment: read header failed");
        return NGX_BAD_DATA;
    }

    if (sp->frame_count <= 0 ||
        sp->frame_count > NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_segment: invalid frame count %uD",
            sp->frame_count);
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ctx = ngx_mem_rstream_scope(rs);

    segment = ngx_live_segment_cache_create(track, ctx->index);
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_segment: create segment failed");
        return NGX_ERROR;
    }

    segment->frame_count = sp->frame_count;

    rc = ngx_live_persist_read_blocks(track->channel,
        NGX_LIVE_PERSIST_CTX_FILLER_SEGMENT, rs, segment);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_segment: read blocks failed");
        return rc;
    }

    if (segment->frames.part.nelts == 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_segment: missing frame list");
        return NGX_BAD_DATA;
    }

    if (segment->data_head == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_segment: missing frame data");
        return NGX_BAD_DATA;
    }

    rc = ngx_live_media_info_pending_create_segment(track, ctx->index);
    if (rc != NGX_OK) {
        if (rc != NGX_DONE) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_filler_read_segment: create media info failed");
            return NGX_ERROR;
        }

        if (ctx->index == 0) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_filler_read_segment: missing media info (1)");
            return NGX_BAD_DATA;
        }
    }

    segment->media_info = ngx_live_media_info_queue_get_last(track);
    if (segment->media_info == NULL) {
        ngx_log_error(NGX_LOG_ALERT, rs->log, 0,
            "ngx_live_filler_read_segment: missing media info (2)");
        return NGX_BAD_DATA;
    }

    ngx_live_filler_read_get_frames_info(segment, &size, &duration);

    if (size != segment->data_size) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_segment: "
            "frames size %uz different than data size %uz",
            size, segment->data_size);
        return NGX_BAD_DATA;
    }

    segment->start_dts = sp->start_dts;
    segment->end_dts = segment->start_dts + duration;

    track->has_last_segment = 1;
    ngx_live_segment_cache_finalize(segment);

    ctx->index++;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_write_media_info(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_track_t       *track = obj;
    ngx_live_media_info_t  *media_info;

    media_info = ngx_live_media_info_queue_get_last(track);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_filler_write_media_info: "
            "failed to get media info");
        return NGX_ERROR;
    }

    if (ngx_live_media_info_write(write_ctx, NULL, media_info) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_read_media_info(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                    rc;
    ngx_str_t                    data;
    ngx_buf_chain_t              chain;
    kmp_media_info_t            *media_info;
    ngx_live_track_t            *track = obj;
    ngx_live_filler_read_ctx_t  *ctx;

    ctx = ngx_mem_rstream_scope(rs);
    if (ctx->got_media_info) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_media_info: duplicate block");
        return NGX_BAD_DATA;
    }

    media_info = ngx_mem_rstream_get_ptr(rs, sizeof(*media_info));
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_media_info: read media info failed");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    chain.data = data.data;
    chain.size = data.len;
    chain.next = NULL;

    rc = ngx_live_media_info_pending_add(track, media_info,
        &chain, chain.size, 0);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_media_info: media info add failed");
        return rc;
    }

    ctx->got_media_info = 1;

    return rc;
}


static ngx_int_t
ngx_live_filler_write_tracks(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    uint32_t             media_type;
    ngx_queue_t         *q;
    ngx_wstream_t       *ws;
    ngx_live_track_t    *cur_track;
    ngx_live_channel_t  *channel = obj;

    ws = ngx_persist_write_stream(write_ctx);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        media_type = cur_track->media_type;

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_wstream_str(ws, &cur_track->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &media_type, sizeof(media_type))
                != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_FILLER_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_filler_write_tracks: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_read_track(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                     media_type;
    ngx_int_t                    rc;
    ngx_str_t                    id;
    ngx_log_t                   *orig_log;
    ngx_live_track_t            *track;
    ngx_live_channel_t          *channel = obj;
    ngx_live_filler_read_ctx_t  *ctx;

    ctx = ngx_mem_rstream_scope(rs);
    if (ctx->count <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_track: timeline was not read");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK ||
        ngx_mem_rstream_read(rs, &media_type, sizeof(media_type)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_track: read failed");
        return NGX_BAD_DATA;
    }

    rc = ngx_live_track_create(channel, &id, NGX_LIVE_INVALID_TRACK_ID,
        media_type, rs->log, &track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_track: "
            "create failed %i, track: %V", rc, &id);

        if (rc == NGX_EXISTS || rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    orig_log = rs->log;
    rs->log = &track->log;

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ctx->index = 0;
    ctx->got_media_info = 0;

    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_FILLER_TRACK, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_track: read blocks failed");
        return rc;
    }

    if (ctx->index != ctx->count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_track: "
            "segment count mismatch, expected: %uD, actual: %uD",
            ctx->count, ctx->index);
        return NGX_BAD_DATA;
    }

    rs->log = orig_log;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_write_timeline(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    uint32_t                      i;
    uint32_t                      duration;
    ngx_queue_t                  *q;
    ngx_wstream_t                *ws;
    ngx_live_period_t            *period;
    ngx_live_timeline_t          *timeline;
    ngx_live_segment_iter_t       iter;
    ngx_live_filler_write_ctx_t  *ctx;

    ctx = ngx_persist_write_ctx(write_ctx);
    timeline = ctx->timeline;

    q = ngx_queue_head(&timeline->periods);
    period = ngx_queue_data(q, ngx_live_period_t, queue);

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_wstream_str(ws, &timeline->sn.str) != NGX_OK ||
        ngx_persist_write(write_ctx, &period->time, sizeof(period->time))
            != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_filler_write_timeline: write failed (1)");
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    iter = period->segment_iter;
    for (i = 0; i < period->segment_count; i++) {
        duration = ngx_live_segment_iter_get_one(&iter);

        if (ngx_persist_write(write_ctx, &duration, sizeof(duration))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
                "ngx_live_filler_write_timeline: write failed (2)");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_read_timeline(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                           rc;
    ngx_str_t                           id;
    ngx_str_t                           durations;
    ngx_live_channel_t                 *channel = obj;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_conf_t            conf;
    ngx_live_filler_read_ctx_t         *ctx;
    ngx_live_timeline_manifest_conf_t   manifest_conf;

    ctx = ngx_mem_rstream_scope(rs);
    if (ctx->count > 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_timeline: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK ||
        ngx_mem_rstream_read(rs, &ctx->time, sizeof(ctx->time)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_timeline: read failed");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_live_timeline_conf_default(&conf, &manifest_conf);

    rc = ngx_live_timeline_create(channel, &id, &conf, &manifest_conf, rs->log,
        &timeline);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_timeline: create failed %i", rc);

        if (rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    ngx_mem_rstream_get_left(rs, &durations);

    ctx->count = durations.len / sizeof(ctx->durations[0]);
    if (ctx->count <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_timeline: no segments");
        return NGX_BAD_DATA;
    }

    if (ctx->count > NGX_LIVE_FILLER_MAX_SEGMENTS) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_filler_read_timeline: invalid segment count %uD",
            ctx->count);
        return NGX_BAD_DATA;
    }

    ctx->durations = (void *) durations.data;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_write_channel(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_channel_t           *channel = obj;
    ngx_live_filler_write_ctx_t  *ctx;

    ctx = ngx_persist_write_ctx(write_ctx);

    if (ngx_live_persist_write_channel_header(write_ctx, channel) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_FILLER_CHANNEL, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_write_channel: write failed");
        return NGX_ERROR;
    }

    if (ctx->cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_filler_write_channel: no segments written");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_read_channel(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t            rc;
    ngx_live_channel_t  *channel = obj;

    rc = ngx_live_persist_read_channel_header(channel, rs);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_FILLER_CHANNEL, rs, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_filler_read_channel: read blocks failed");
        return rc;
    }

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_filler_blocks[] = {
    /*
     * persist data:
     *   ngx_str_t  channel_id;
     *   ngx_str_t  preset_name;
     *   ngx_str_t  timeline_id;
     *   uint32_t   filler_start_index;
     */
    { NGX_LIVE_FILLER_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_filler_write_setup,
      ngx_live_filler_read_setup },

    /*
     * persist header:
     *   ngx_str_t  id;
     *   ngx_str_t  opaquep;
     */
    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_FILLER_MAIN,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_write_channel,
      ngx_live_filler_read_channel },

    /*
     * persist header:
     *   ngx_str_t  id;
     *   int64_t    time;
     *
     * persist data:
     *   uint32_t  duration[];
     */
    { NGX_LIVE_PERSIST_BLOCK_TIMELINE, NGX_LIVE_PERSIST_CTX_FILLER_CHANNEL,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_write_timeline,
      ngx_live_filler_read_timeline },

    /*
     * persist header:
     *   ngx_str_t  id;
     *   uint32_t   media_type;
     */
    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_FILLER_CHANNEL, 0,
      ngx_live_filler_write_tracks,
      ngx_live_filler_read_track },

    /*
     * persist header:
     *   kmp_media_info_t  kmp;
     */
    { NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO, NGX_LIVE_PERSIST_CTX_FILLER_TRACK, 0,
      ngx_live_filler_write_media_info,
      ngx_live_filler_read_media_info },

    /*
     * persist header:
     *   ngx_live_persist_segment_header_t  sp;
     */
    { NGX_LIVE_PERSIST_BLOCK_SEGMENT, NGX_LIVE_PERSIST_CTX_FILLER_TRACK, 0,
      ngx_live_filler_write_segments,
      ngx_live_filler_read_segment },

    /*
     * persist data:
     *   ngx_live_frame_t  frame[];
     */
    { NGX_LIVE_PERSIST_BLOCK_FRAME_LIST, NGX_LIVE_PERSIST_CTX_FILLER_SEGMENT,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_write_frame_list,
      ngx_live_filler_read_frame_list },

    { NGX_LIVE_PERSIST_BLOCK_FRAME_DATA, NGX_LIVE_PERSIST_CTX_FILLER_SEGMENT,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_write_frame_data,
      ngx_live_filler_read_frame_data },

    /*
     * persist data:
     *   ngx_ksmp_frame_t  frame[];
     */
    { NGX_KSMP_BLOCK_FRAME_LIST,
      NGX_LIVE_PERSIST_CTX_SERVE_FILLER_HEADER,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_serve_write_frame_list, NULL },

    { NGX_KSMP_BLOCK_FRAME_DATA,
      NGX_LIVE_PERSIST_CTX_SERVE_FILLER_DATA,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_filler_serve_write_frame_data, NULL },

    ngx_null_persist_block
};


/* main */

static ngx_int_t
ngx_live_filler_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_channel_init: alloc ctx failed");
        return NGX_ERROR;
    }

    ngx_queue_init(&cctx->queue);

    ngx_live_set_ctx(channel, cctx, ngx_live_filler_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    if (cctx->read_ctx != NULL) {
        ngx_live_filler_read_handler(cctx->read_ctx, NGX_HTTP_CONFLICT, NULL);
    }

    if (cctx->pool != NULL) {
        ngx_destroy_pool(cctx->pool);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_channel_read(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return NGX_OK;
    }

    ngx_live_filler_set_last_media_types(channel,
        channel->filler_media_types & ~channel->last_segment_media_types);

    return NGX_OK;
}

static void
ngx_live_filler_recalc_media_type_mask(ngx_live_channel_t *channel)
{
    ngx_queue_t                    *q;
    ngx_live_filler_track_ctx_t    *cur_ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    channel->filler_media_types = 0;

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);

        channel->filler_media_types |= (1 << cur_ctx->track->media_type);
    }
}

static ngx_int_t
ngx_live_filler_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_filler_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);
    if (ctx->pool == NULL) {
        /* not a filler track / failed to initialize */
        return NGX_OK;
    }

    ngx_queue_remove(&ctx->queue);

    ngx_live_filler_recalc_media_type_mask(track->channel);

    ngx_destroy_pool(ctx->pool);

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_track_channel_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_filler_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_filler_module);

    if (ctx->pool) {
        ngx_destroy_pool(ctx->pool);
    }

    return NGX_OK;
}

static size_t
ngx_live_filler_channel_json_get_size(void *obj)
{
    ngx_live_channel_t             *channel = obj;
    ngx_live_filler_source_t       *src;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return 0;
    }

    src = &cctx->source;

    return sizeof("\"filler\":{\"channel_id\":\"") - 1 +
        ngx_json_str_get_size(&src->channel_id) +
        sizeof("\",\"timeline_id\":\"") - 1 +
        ngx_json_str_get_size(&src->timeline_id) +
        sizeof("\",\"segments\":") - 1 +
        NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_filler_channel_json_write(u_char *p, void *obj)
{
    ngx_live_channel_t             *channel = obj;
    ngx_live_filler_source_t       *src;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);
    if (cctx->pool == NULL) {
        return p;
    }

    src = &cctx->source;

    p = ngx_copy_fix(p, "\"filler\":{\"channel_id\":\"");
    p = ngx_json_str_write(p, &src->channel_id);
    p = ngx_copy_fix(p, "\",\"timeline_id\":\"");
    p = ngx_json_str_write(p, &src->timeline_id);
    p = ngx_copy_fix(p, "\",\"segments\":");
    p = ngx_sprintf(p, "%uD", cctx->count);
    *p++ = '}';

    return p;
}

static ngx_int_t
ngx_live_filler_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_json_cmds_add_multi(cf, ngx_live_filler_dyn_cmds,
        NGX_LIVE_JSON_CTX_CHANNEL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_persist_add_blocks(cf, ngx_live_filler_blocks) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf, ngx_live_filler_json_writers)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t  ngx_live_filler_channel_events[] = {
    { ngx_live_filler_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_filler_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_filler_channel_read, NGX_LIVE_EVENT_CHANNEL_READ },
      ngx_live_null_event
};

static ngx_live_track_event_t    ngx_live_filler_track_events[] = {
    { ngx_live_filler_track_free,         NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_filler_track_channel_free, NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },
      ngx_live_null_event
};

static ngx_int_t
ngx_live_filler_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf, ngx_live_filler_channel_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf, ngx_live_filler_track_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_live_filler_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_filler_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_filler_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->file.max_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_live_filler_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_filler_preset_conf_t   *prev = parent;
    ngx_live_filler_preset_conf_t   *conf = child;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_persist_module);

    if (ppcf->store == NULL) {
        conf->file.path = NULL;

    } else if (conf->file.path == NULL) {
        conf->file.path = prev->file.path;
    }

    ngx_conf_merge_size_value(conf->file.max_size,
                              prev->file.max_size, 5 * 1024 * 1024);

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_filler_module,
        sizeof(ngx_live_filler_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
