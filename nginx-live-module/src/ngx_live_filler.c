#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_media_info.h"
#include "ngx_live_timeline.h"
#include "ngx_live_filler.h"


/* Note: the data chains of all segments in a track are connected in a cycle */

typedef struct {
    ngx_list_t                     frames;        /* input_frame_t */
    ngx_buf_chain_t               *data_head;
    ngx_buf_chain_t               *data_tail;
    int32_t                        pts_delay;
} ngx_live_filler_segment_t;


typedef struct {
    ngx_list_part_t               *part;
    input_frame_t                 *cur;
    input_frame_t                 *last;
    uint32_t                       dts_offset;
} ngx_live_filler_frame_iter_t;


typedef struct {
    ngx_buf_chain_t               *chain;
    size_t                         offset;
} ngx_live_filler_data_iter_t;


typedef struct {
    ngx_queue_t                    queue;
    ngx_pool_t                    *pool;
    ngx_live_track_t              *track;
    ngx_live_filler_segment_t     *segments;

    ngx_live_filler_frame_iter_t   frame_iter;
    ngx_live_filler_data_iter_t    data_iter;
} ngx_live_filler_track_ctx_t;

typedef struct {
    ngx_queue_t                    queue;
    uint32_t                       count;
    uint32_t                      *durations;

    uint32_t                       index;
    uint32_t                       dts_offset;
    uint32_t                       last_media_type_mask;
    int64_t                        last_pts;
    unsigned                       reset:1;
} ngx_live_filler_channel_ctx_t;


static ngx_int_t ngx_live_filler_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_filler_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_live_filler_set_channel(void *ctx,
    ngx_live_json_command_t *cmd, ngx_json_value_t *value, ngx_log_t *log);

static ngx_live_module_t  ngx_live_filler_module_ctx = {
    ngx_live_filler_preconfiguration,       /* preconfiguration */
    ngx_live_filler_postconfiguration,      /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create preset configuration */
    NULL,                                   /* merge preset configuration */
};

ngx_module_t  ngx_live_filler_module = {
    NGX_MODULE_V1,
    &ngx_live_filler_module_ctx,            /* module context */
    NULL,                                   /* module directives */
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


enum {
    FILLER_PARAM_CHANNEL_ID,
    FILLER_PARAM_TIMELINE_ID,
    FILLER_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_live_filler_params[] = {
    { vod_string("channel_id"),  NGX_JSON_STRING, FILLER_PARAM_CHANNEL_ID },
    { vod_string("timeline_id"), NGX_JSON_STRING, FILLER_PARAM_TIMELINE_ID },
    { vod_null_string, 0, 0 }
};


static ngx_live_json_command_t  ngx_live_filler_dyn_cmds[] = {

    { ngx_string("filler"), NGX_JSON_OBJECT,
      ngx_live_filler_set_channel },

      ngx_live_null_json_command
};


static void
ngx_live_filler_frame_iter_init(ngx_live_filler_frame_iter_t *iter,
    ngx_live_filler_segment_t *segment)
{
    iter->part = &segment->frames.part;
    iter->cur = iter->part->elts;
    iter->last = iter->cur + iter->part->nelts;
    iter->dts_offset = 0;
}

static input_frame_t *
ngx_live_filler_frame_iter_get(ngx_live_filler_frame_iter_t *iter)
{
    input_frame_t  *frame;

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
    iter->dts_offset += frame->duration;

    return frame;
}

static void
ngx_live_filler_frame_iter_unget(ngx_live_filler_frame_iter_t *iter)
{
    iter->cur--;
    iter->dts_offset -= iter->cur->duration;
}


static void
ngx_live_filler_data_iter_init(ngx_live_filler_data_iter_t *iter,
    ngx_live_filler_segment_t *segment)
{
    iter->chain = segment->data_head;
    iter->offset = 0;
}

static ngx_int_t
ngx_live_filler_data_iter_copy(ngx_live_channel_t *channel,
    ngx_live_filler_data_iter_t *iter, ngx_live_segment_t *segment,
    ngx_log_t *log)
{
    size_t            left;
    ngx_buf_chain_t  *dst;
    ngx_buf_chain_t  *src;
    ngx_buf_chain_t  *last;

    /* Note: handling first chain seperately as it may have an offset */
    dst = ngx_live_channel_buf_chain_alloc(channel);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_data_iter_copy: alloc chain failed (1)");
        return NGX_ERROR;
    }

    segment->data_head = dst;

    src = iter->chain;

    dst->data = src->data + iter->offset;
    dst->size = src->size - iter->offset;

    left = segment->data_size;

    for ( ;; ) {

        if (dst->size > left) {
            dst->size = left;
            iter->offset = dst->data + dst->size - src->data;
            break;
        }

        src = src->next;

        left -= dst->size;
        if (left <= 0) {
            iter->offset = 0;
            break;
        }

        last = dst;

        dst = ngx_live_channel_buf_chain_alloc(channel);
        if (dst == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_data_iter_copy: alloc chain failed (2)");
            segment->data_tail = last;      /* required for segment free */
            return NGX_ERROR;
        }

        dst->data = src->data;
        dst->size = src->size;

        last->next = dst;
    }

    iter->chain = src;

    dst->next = NULL;
    segment->data_tail = dst;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_track_fill(ngx_live_track_t *track, uint32_t segment_count,
    uint32_t last_segment_duration)
{
    uint32_t                        i;
    uint32_t                        max_pts;
    uint32_t                        dts_offset;
    media_info_t                   *media_info;
    input_frame_t                  *src, *dst;
    kmp_media_info_t               *kmp_media_info;
    ngx_live_channel_t             *channel;
    ngx_live_segment_t             *segment;
    ngx_live_filler_segment_t      *fs;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    media_info = ngx_live_media_info_queue_get_last(track, &kmp_media_info);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_filler_track_fill: failed to get media info");
        return NGX_ERROR;
    }

    channel = track->channel;
    segment = ngx_live_segment_cache_create(track,
        channel->next_segment_index);
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_filler_track_fill: create segment failed");
        return NGX_ERROR;
    }

    segment->media_info = media_info;
    segment->kmp_media_info = kmp_media_info;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    fs = &ctx->segments[cctx->index];

    if (cctx->reset) {
        ngx_live_filler_frame_iter_init(&ctx->frame_iter, fs);
        ngx_live_filler_data_iter_init(&ctx->data_iter, fs);
    }

    segment->end_dts = cctx->last_pts - fs->pts_delay;
    segment->start_dts = segment->end_dts + ctx->frame_iter.dts_offset;

    /* full segments */
    for (i = 0; i < segment_count; ) {

        for (;;) {

            src = ngx_live_filler_frame_iter_get(&ctx->frame_iter);
            if (src == NULL) {
                break;
            }

            dst = ngx_list_push(&segment->frames);
            if (dst == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_filler_track_fill: push frame failed");
                goto error;
            }

            *dst = *src;

            segment->data_size += dst->size;
            segment->frame_count++;
        }

        segment->end_dts += ctx->frame_iter.dts_offset;

        i++;

        fs = &ctx->segments[(cctx->index + i) % cctx->count];
        ngx_live_filler_frame_iter_init(&ctx->frame_iter, fs);
    }

    /* partial segment */
    if (last_segment_duration > ctx->frame_iter.dts_offset) {

        src = fs->frames.part.elts;
        max_pts = last_segment_duration + src->pts_delay;

        for ( ;; ) {

            dts_offset = ctx->frame_iter.dts_offset;

            src = ngx_live_filler_frame_iter_get(&ctx->frame_iter);
            if (src == NULL) {
                break;
            }

            if (dts_offset + src->pts_delay > max_pts) {
                ngx_live_filler_frame_iter_unget(&ctx->frame_iter);
                break;
            }

            dst = ngx_list_push(&segment->frames);
            if (dst == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_filler_track_fill: push frame failed");
                goto error;
            }

            *dst = *src;

            segment->data_size += dst->size;
            segment->frame_count++;
        }

        segment->end_dts += ctx->frame_iter.dts_offset;
    }

    if (segment->frame_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_filler_track_fill: empty segment");
        ngx_live_segment_cache_free(track, segment);
        return NGX_ABORT;
    }

    if (ngx_live_filler_data_iter_copy(channel, &ctx->data_iter, segment,
        &track->log) != NGX_OK) {
        goto error;
    }

    ngx_live_segment_cache_validate(segment);

    return NGX_OK;

error:

    ngx_live_segment_cache_free(track, segment);
    return NGX_ERROR;
}

static void
ngx_live_filler_align_to_next(ngx_live_filler_channel_ctx_t *cctx,
    ngx_flag_t update_last_pts)
{
    ngx_queue_t                  *q;
    ngx_live_track_t             *cur_track;
    ngx_live_filler_track_ctx_t  *cur_ctx;

    cctx->index++;
    if (cctx->index >= cctx->count) {
        cctx->index = 0;
    }

    cctx->dts_offset = 0;

    if (!update_last_pts) {
        return;
    }

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        if (!cur_track->has_last_segment) {
            continue;
        }

        cctx->last_pts += cur_ctx->frame_iter.dts_offset;
        break;
    }
}

ngx_int_t
ngx_live_filler_fill(ngx_live_channel_t *channel, uint32_t media_type_mask,
    int64_t start_pts, ngx_flag_t force_new_period, uint32_t min_duration,
    uint32_t max_duration, uint32_t *fill_duration)
{
    int64_t                         last_pts;
    uint32_t                        index;
    uint32_t                        duration;
    uint32_t                        dts_offset;
    uint32_t                        cur_duration;
    uint32_t                        next_duration;
    uint32_t                        segment_count;
    ngx_int_t                       rc;
    ngx_flag_t                      last_pts_reset;
    ngx_queue_t                    *q;
    ngx_live_track_t               *cur_track;
    ngx_live_filler_track_ctx_t    *cur_ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_filler_module);

    media_type_mask &= channel->filler_media_types;

    if (media_type_mask == 0) {

        /* nothing to fill */
        if (cctx->last_media_type_mask == 0) {
            return NGX_DONE;
        }

        /* clear 'has last segment' on all filler tracks */
        for (q = ngx_queue_head(&cctx->queue);
            q != ngx_queue_sentinel(&cctx->queue);
            q = ngx_queue_next(q))
        {
            cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
            cur_track = cur_ctx->track;

            if (cur_track->has_last_segment) {
                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_filler_fill: track removed (1)");

                cur_track->has_last_segment = 0;
                channel->last_modified = ngx_time();
            }
        }

        cctx->last_media_type_mask = 0;

        return NGX_DONE;
    }

    if (!cctx->last_media_type_mask || force_new_period) {
        cctx->last_pts = start_pts;
        last_pts_reset = 1;

    } else {
        last_pts_reset = 0;
    }

    /* reset the iterator when -
        1. there is video and we are not aligned to segment
        2. tracks are being added - reset required to align all tracks */
    if ((cctx->dts_offset > 0 && (media_type_mask & KMP_MEDIA_VIDEO)) ||
        (media_type_mask & ~cctx->last_media_type_mask))
    {
        /* when filling video, must align to segment boundary */
        if (cctx->dts_offset > 0) {
            ngx_live_filler_align_to_next(cctx, !last_pts_reset);
        }

        cctx->reset = 1;
    }

    /* get the number of input segments */
    duration = 0;
    segment_count = 0;
    index = cctx->index;
    dts_offset = cctx->dts_offset;
    last_pts = cctx->last_pts;

    for ( ;; ) {

        cur_duration = cctx->durations[index];
        next_duration = duration + cur_duration - dts_offset;

        if (duration >= min_duration &&
            ngx_abs_diff(next_duration, *fill_duration) >
            ngx_abs_diff(duration, *fill_duration))
        {
            *fill_duration = duration;
            break;
        }

        if (next_duration > max_duration) {
            dts_offset += max_duration - duration;
            *fill_duration = max_duration;
            break;
        }

        segment_count++;
        last_pts += cur_duration;

        index++;
        if (index >= cctx->count) {
            index = 0;
        }
        dts_offset = 0;

        duration = next_duration;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_filler_fill: filler segment count %uD, dts offset %uD",
        segment_count, dts_offset);

    /* fill all relevant tracks */
    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        if (!(media_type_mask & (1 << cur_track->media_type))) {
            continue;
        }

        rc = ngx_live_filler_track_fill(cur_track, segment_count, dts_offset);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_ABORT:
            ngx_live_segment_cache_free_by_index(channel,
                channel->next_segment_index);
            cctx->reset = 1;
            cctx->dts_offset = 0;
            /* fall through */

        default:
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_filler_fill: fill track failed %i", rc);
            return rc;
        }
    }

    /* update has_last_segment */
    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        if (!(media_type_mask & (1 << cur_track->media_type))) {

            if (!cur_track->has_last_segment) {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_filler_fill: track removed (2)");

            cur_track->has_last_segment = 0;

        } else {

            if (cur_track->has_last_segment) {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_filler_fill: track added");

            cur_track->has_last_segment = 1;
        }

        channel->last_modified = ngx_time();
    }

    /* update channel ctx */
    cctx->last_media_type_mask = media_type_mask;
    cctx->index = index;
    cctx->dts_offset = dts_offset;
    cctx->last_pts = last_pts;
    cctx->reset = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_setup_copy_frames(ngx_live_filler_segment_t *dst_segment,
    ngx_live_segment_t *src_segment, uint32_t initial_pts_delay,
    ngx_flag_t is_last, uint64_t duration, size_t *data_size, ngx_log_t *log)
{
    input_frame_t    *dst;
    input_frame_t    *cur, *last;
    ngx_list_part_t  *part;

    dst = NULL;
    *data_size = 0;

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
        *data_size += dst->size;

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
    size_t size, ngx_log_t *log)
{
    ngx_buf_chain_t  *src;
    ngx_buf_chain_t  *dst, **last_dst;

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
    ngx_live_track_t *src_track, ngx_live_timeline_t *timeline,
    uint64_t duration, ngx_log_t *log)
{
    size_t                          data_size;
    int64_t                         timeline_pts;
    uint32_t                        i;
    uint32_t                        segment_index;
    uint32_t                        initial_pts_delay;
    ngx_int_t                       rc;
    ngx_flag_t                      is_last;
    input_frame_t                  *first_frame;
    ngx_live_segment_t             *src_segment;
    ngx_live_filler_segment_t      *dst_segment;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(dst_track, ngx_live_filler_module);
    cctx = ngx_live_get_module_ctx(dst_track->channel, ngx_live_filler_module);

    ngx_live_input_bufs_link(dst_track, src_track);

    ctx->segments = ngx_palloc(ctx->pool, sizeof(ctx->segments[0]) *
        cctx->count);
    if (ctx->segments == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track_segments: alloc segments failed");
        return NGX_ERROR;
    }

    segment_index = timeline->head_period->node.key;
    timeline_pts = timeline->head_period->time;

    for (i = 0 ;; i++) {

        src_segment = ngx_live_segment_cache_get(src_track, segment_index);
        if (src_segment == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_filler_setup_track_segments: "
                "failed to get segment %uD", segment_index);
            return NGX_ERROR;
        }

        /* copy the frames */
        dst_segment = &ctx->segments[i];
        if (ngx_list_init(&dst_segment->frames, ctx->pool, 10,
            sizeof(input_frame_t)) != NGX_OK)
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
            initial_pts_delay, is_last, duration, &data_size, log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_track_segments: copy frames failed");
            return rc;
        }

        dst_segment->pts_delay = timeline_pts - src_segment->start_dts;

        /* copy the data chains */
        rc = ngx_live_filler_setup_copy_chains(ctx, dst_segment, src_segment,
            data_size, log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_filler_setup_track_segments: copy chains failed");
            return rc;
        }

        if (i > 0) {
            dst_segment[-1].data_tail->next = dst_segment->data_head;
        }

        if (is_last) {
            break;
        }

        /* move to next segment */
        duration -= src_segment->end_dts - src_segment->start_dts;
        segment_index++;
        timeline_pts += cctx->durations[i];
    }

    dst_segment->data_tail->next = ctx->segments[0].data_head;

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_setup_track(ngx_live_channel_t *dst,
    ngx_live_track_t *src_track, ngx_live_timeline_t *timeline,
    uint64_t duration, ngx_log_t *log)
{
    ngx_int_t                       rc;
    ngx_live_track_t               *dst_track;
    ngx_live_filler_track_ctx_t    *ctx;
    ngx_live_filler_channel_ctx_t  *cctx;

    /* create the track */
    rc = ngx_live_track_create(dst, &src_track->sn.str, src_track->media_type,
        log, &dst_track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: create track failed %i", rc);
        return NGX_ERROR;
    }

    dst_track->type = ngx_live_track_type_filler;

    ctx = ngx_live_track_get_module_ctx(dst_track, ngx_live_filler_module);

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
    rc = ngx_live_media_info_queue_copy_last(dst_track, src_track, 0);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup_track: failed to copy media info");
        return NGX_ERROR;
    }

    /* create the segments */
    rc = ngx_live_filler_setup_track_segments(dst_track, src_track,
        timeline, duration, log);
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
                "failed to get segment %uD (1)", segment_index);
            return 0;
        }

        start_dts = src_segment->start_dts;

        if (count > 1) {
            src_segment = ngx_live_segment_cache_get(src_track,
                last_segment_index);
            if (src_segment == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_live_filler_setup_get_cycle_duration: "
                    "failed to get segment %uD (2)", last_segment_index);
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
ngx_live_filler_get_durations(ngx_live_filler_channel_ctx_t *cctx,
    ngx_live_timeline_t *timeline, uint64_t cycle_duration)
{
    int64_t                       delta;
    int32_t                       index, count;
    uint64_t                      duration;
    uint32_t                     *cur, *end;
    ngx_live_segment_iterator_t   iterator;

    /* get the segment durations */
    iterator = timeline->head_period->segment_iterator;
    duration = 0;

    cur = cctx->durations;
    end = cur + cctx->count;
    for (; cur < end; cur++) {
        ngx_live_segment_iterator_get_one(&iterator, cur);
        duration += *cur;
    }

    /* adjust the durations to match the cycle duration */
    delta = cycle_duration - duration;
    count = cctx->count;

    for (index = 0; index < count; index++) {
        cctx->durations[index] += (delta * (index + 1)) / count -
            (delta * index) / count;
    }
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_filler_setup_validate_segment(ngx_live_filler_segment_t *segment,
    uint64_t *duration, ngx_log_t *log)
{
    uint32_t          data_size;
    uint32_t          frames_size;
    input_frame_t    *cur, *last;
    ngx_buf_chain_t  *data;
    ngx_list_part_t  *part;

    /* get the total size and duration of the frames */
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

        *duration += cur->duration;
        frames_size += cur->size;
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
            "data size %uD doesn't match frames size %uD",
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
    uint64_t                        cur_duration;
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

    filler_media_types = 0;
    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur_ctx = ngx_queue_data(q, ngx_live_filler_track_ctx_t, queue);
        cur_track = cur_ctx->track;

        cur_duration = 0;
        prev_data = cur_ctx->segments[cctx->count - 1].data_tail;
        for (i = 0; i < cctx->count; i++) {
            cur_segment = &cur_ctx->segments[i];

            if (prev_data->next != cur_segment->data_head) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_filler_setup_validate: "
                    "segment data not connected to prev segment");
                ngx_debug_point();
            }

            ngx_live_filler_setup_validate_segment(cur_segment, &cur_duration,
                &cur_track->log);

            prev_data = cur_segment->data_tail;
        }

        if (cur_duration != duration) {
            ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                "ngx_live_filler_setup_validate: "
                "track duration %uL doesn't match timeline duration %uL",
                cur_duration, duration);
            ngx_debug_point();
        }

        filler_media_types |= (1 << cur_track->media_type);
    }

    if (filler_media_types != channel->filler_media_types) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_filler_setup_validate: "
            "invalid channel media types 0x%uxD expected 0x%uxD",
            channel->filler_media_types, filler_media_types);
        ngx_debug_point();
    }
}
#else
#define ngx_live_filler_setup_validate(channel)
#endif

static ngx_int_t
ngx_live_filler_setup(ngx_live_channel_t *dst, ngx_live_channel_t *src,
    ngx_live_timeline_t *timeline, ngx_log_t *log)
{
    uint64_t                        duration;
    ngx_queue_t                    *q;
    ngx_live_track_t               *src_track;
    ngx_live_filler_channel_ctx_t  *cctx;

    if (timeline->head_period == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup: timeline \"%V\" has no periods",
            &timeline->sn.str);
        return NGX_ERROR;
    }

    if (timeline->head_period != timeline->last_period) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup: timeline \"%V\" has multiple periods",
            &timeline->sn.str);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(dst, ngx_live_filler_module);

    if (cctx->count > 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_setup: channel \"%V\" already has a filler",
            &dst->sn.str);
        return NGX_ERROR;
    }

    cctx->count = timeline->segment_count;
    cctx->durations = ngx_palloc(dst->pool, cctx->count *
        sizeof(cctx->durations[0]));
    if (cctx->durations == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_setup: failed to allocate durations array");
        return NGX_ERROR;
    }

    duration = ngx_live_filler_setup_get_cycle_duration(src,
        timeline->head_period->node.key, cctx->count, log);
    if (duration <= 0) {
        return NGX_ERROR;
    }

    ngx_live_filler_get_durations(cctx, timeline, duration);

    for (q = ngx_queue_head(&src->tracks.queue);
        q != ngx_queue_sentinel(&src->tracks.queue);
        q = ngx_queue_next(q))
    {
        src_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (ngx_live_filler_setup_track(dst, src_track, timeline, duration,
            log) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_live_filler_setup_validate(dst);

    return NGX_OK;
}


static ngx_int_t
ngx_live_filler_set_channel(void *ctx, ngx_live_json_command_t *cmd,
    ngx_json_value_t *value, ngx_log_t *log)
{
    ngx_str_t             channel_id;
    ngx_str_t             timeline_id;
    ngx_json_value_t     *values[FILLER_PARAM_COUNT];
    ngx_live_channel_t   *dst = ctx;
    ngx_live_channel_t   *src;
    ngx_live_timeline_t  *src_timeline;

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&value->v.obj, ngx_live_filler_params, values);

    if (values[FILLER_PARAM_CHANNEL_ID] == NULL ||
        values[FILLER_PARAM_TIMELINE_ID] == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_set_channel: missing mandatory params");
        return NGX_ERROR;
    }

    channel_id = values[FILLER_PARAM_CHANNEL_ID]->v.str;
    src = ngx_live_channel_get(&channel_id);
    if (src == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_set_channel: unknown channel \"%V\"",
            &channel_id);
        return NGX_ERROR;
    }

    timeline_id = values[FILLER_PARAM_TIMELINE_ID]->v.str;
    src_timeline = ngx_live_timeline_get(src, &timeline_id);
    if (src_timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_filler_set_channel: "
            "unknown timeline \"%V\" in channel \"%V\"",
            &timeline_id, &channel_id);
        return NGX_ERROR;
    }

    if (ngx_live_filler_setup(dst, src, src_timeline, log) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_filler_set_channel: setup failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, &dst->log, 0,
        "ngx_live_filler_set_channel: using channel \"%V\" as filler",
        &channel_id);

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size)
{
    ngx_live_filler_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_filler_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_filler_module);

    ngx_live_reserve_track_ctx_size(channel, ngx_live_filler_module,
        sizeof(ngx_live_filler_track_ctx_t), track_ctx_size);

    ngx_queue_init(&cctx->queue);

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
ngx_live_filler_track_free(ngx_live_track_t *track)
{
    ngx_live_filler_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_filler_module);
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
ngx_live_filler_track_channel_free(ngx_live_track_t *track)
{
    ngx_live_filler_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_filler_module);

    if (ctx->pool) {
        ngx_destroy_pool(ctx->pool);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_preconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_command_t  *cmd, *c;

    for (c = ngx_live_filler_dyn_cmds; c->name.len; c++) {
        cmd = ngx_live_json_commands_add(cf, &c->name,
            NGX_LIVE_JSON_CTX_CHANNEL);
        if (cmd == NULL) {
            return NGX_ERROR;
        }

        cmd->set_handler = c->set_handler;
        cmd->type = c->type;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_filler_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_track_handler_pt         *th;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_filler_channel_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_filler_track_free;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_CHANNEL_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_filler_track_channel_free;

    return NGX_OK;
}
