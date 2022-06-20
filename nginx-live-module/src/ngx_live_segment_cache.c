#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_media_info.h"
#include "ngx_live_segmenter.h"
#include "ngx_live_timeline.h"
#include "persist/ngx_live_persist_internal.h"


#define NGX_LIVE_SEGMENT_CACHE_MAX_BITRATE  (64 * 1024 * 1024)


typedef struct {
    ngx_queue_t             queue;
    ngx_rbtree_t            rbtree;
    ngx_rbtree_node_t       sentinel;
    uint32_t                count;
    uint32_t                parts;
} ngx_live_segment_cache_track_ctx_t;


static ngx_int_t ngx_live_segment_cache_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_segment_cache_postconfiguration(ngx_conf_t *cf);

static char *ngx_live_segment_cache_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_live_module_t  ngx_live_segment_cache_module_ctx = {
    ngx_live_segment_cache_preconfiguration,  /* preconfiguration */
    ngx_live_segment_cache_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    ngx_live_segment_cache_merge_preset_conf, /* merge preset configuration */
};


ngx_module_t  ngx_live_segment_cache_module = {
    NGX_MODULE_V1,
    &ngx_live_segment_cache_module_ctx,       /* module context */
    NULL,                                     /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_live_serve_segment_pt  ngx_live_next_serve;
ngx_live_serve_segment_pt         ngx_live_serve_segment = NULL;

static ngx_str_t  ngx_live_segment_cache_source_name = ngx_string("cache");


ngx_live_segment_t *
ngx_live_segment_cache_create(ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_uint_t                           n;
    ngx_pool_t                          *pool;
    ngx_live_channel_t                  *channel;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    pool = ngx_create_pool(1024, &track->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_create: create pool failed");
        return NULL;
    }

    segment = ngx_pcalloc(pool, sizeof(*segment));
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_create: allocate segment failed");
        goto error;
    }

    if (ngx_list_init(&segment->frames, pool, 10, sizeof(ngx_live_frame_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_create: init list failed");
        goto error;
    }

    channel = track->channel;
    if (channel->part_duration > 0) {
        n = ngx_ceil_div(channel->segment_duration, channel->part_duration);

    } else {
        n = 1;
    }

    if (ngx_array_init(&segment->parts, pool, n,
        sizeof(ngx_live_segment_part_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_create: init array failed");
        goto error;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    segment->node.key = segment_index;
    segment->track_id = track->in.key;
    segment->track = track;
    segment->pool = pool;

    ngx_rbtree_insert(&ctx->rbtree, &segment->node);
    ngx_queue_insert_tail(&ctx->queue, &segment->queue);
    ctx->count++;

    return segment;

error:

    ngx_destroy_pool(pool);
    return NULL;
}

static void
ngx_live_segment_cache_destroy(ngx_live_segment_t *segment)
{
    ngx_buf_chain_t     *data_tail;
    ngx_live_channel_t  *channel;

    if (segment->ready) {
        data_tail = segment->data_tail;

    } else {
        data_tail = ngx_buf_chain_terminate(segment->data_head,
            segment->data_size);
    }

    if (data_tail != NULL) {
        channel = segment->track->channel;
        ngx_live_channel_buf_chain_free_list(channel, segment->data_head,
            data_tail);
    }

    ngx_destroy_pool(segment->pool);
}

void
ngx_live_segment_cache_free(ngx_live_segment_t *segment)
{
    ngx_live_track_t                    *track;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    track = segment->track;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    ctx->count--;
    ctx->parts -= segment->parts.nelts;

    ngx_queue_remove(&segment->queue);
    ngx_rbtree_delete(&ctx->rbtree, &segment->node);

    ngx_live_segment_cache_destroy(segment);
}


#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_segment_cache_validate_parts(ngx_live_segment_t *segment)
{
    size_t                    data_size;
    int64_t                   dts;
    ngx_uint_t                i, j, n;
    ngx_buf_chain_t          *data;
    ngx_list_part_t          *part;
    ngx_live_frame_t         *cur, *last;
    ngx_live_segment_part_t  *sp, *parts;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    data = segment->data_head;
    dts = segment->start_dts;

    parts = segment->parts.elts;
    n = segment->parts.nelts;
    for (i = 0; i < n; i++) {

        sp = &parts[i];
        if (sp->frame_count <= 0) {
            /* gap part */
            continue;
        }

        if (sp->start_dts != dts) {
            ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                "ngx_live_segment_cache_validate_parts: "
                "invalid start dts %L expected %L", sp->start_dts, dts);
            ngx_debug_point();
        }

        if (sp->data_head != data) {
            ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                "ngx_live_segment_cache_validate_parts: "
                "data head mismatch");
            ngx_debug_point();
        }

        data_size = 0;
        for (j = 0; j < sp->frame_count; j++) {

            if (cur >= last) {
                if (part->next == NULL) {
                    ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                        "ngx_live_segment_cache_validate_parts: "
                        "frame list overflow");
                    ngx_debug_point();
                    break;
                }

                part = part->next;
                cur = part->elts;
                last = cur + part->nelts;
            }

            if (j == 0) {
                if (sp->frame != cur) {
                    ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                        "ngx_live_segment_cache_validate_parts: "
                        "frame mismatch");
                    ngx_debug_point();
                }

                if (sp->frame_part != part) {
                    ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                        "ngx_live_segment_cache_validate_parts: "
                        "frame part mismatch");
                    ngx_debug_point();
                }
            }

            dts += cur->duration;
            data_size += cur->size;

            cur++;
        }

        if (sp->data_size != data_size) {
            ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
                "ngx_live_segment_cache_validate_parts: "
                "invalid part data size %uz expected %uz",
                sp->data_size, data_size);
            ngx_debug_point();
        }

        while (data_size > 0) {
            data_size -= data->size;
            data = data->next;
        }
    }

    if (cur < last || part->next != NULL) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate_parts: "
            "trailing frames after last part");
        ngx_debug_point();
    }
}

static void
ngx_live_segment_cache_validate(ngx_live_segment_t *segment)
{
    size_t             data_size;
    size_t             frames_size;
    int64_t            end_dts;
    uint32_t           frame_count;
    ngx_uint_t         i;
    ngx_buf_chain_t   *data;
    ngx_list_part_t   *part;
    ngx_live_frame_t  *frames;

    /* get the chain size, and validate data_tail */
    data_size = 0;
    data = segment->data_head;

    for ( ;; ) {

        data_size += data->size;
        if (data->next == NULL) {
            break;
        }

        data = data->next;
    }

    if (segment->data_size != data_size) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "invalid segment data size %uz expected %uz",
            segment->data_size, data_size);
        ngx_debug_point();
    }

    if (segment->data_tail != data) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: data tail mismatch");
        ngx_debug_point();
    }

    /* get the frames size */
    frame_count = 0;
    frames_size = 0;
    end_dts = segment->start_dts;

    part = &segment->frames.part;
    frames = part->elts;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            frames = part->elts;
            i = 0;
        }

        frame_count++;
        frames_size += frames[i].size;
        end_dts += frames[i].duration;
    }

    if (segment->frame_count != frame_count) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "invalid segment frame count %uD expected %uD",
            segment->frame_count, frame_count);
        ngx_debug_point();
    }

    if (segment->end_dts != end_dts) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "invalid segment end dts %L expected %L",
            segment->end_dts, end_dts);
        ngx_debug_point();
    }

    if (data_size != frames_size) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "data size %uz doesn't match frames size %uz",
            data_size, frames_size);
        ngx_debug_point();
    }

    if (segment->parts.nelts > 0) {
        ngx_live_segment_cache_validate_parts(segment);
    }
}
#else
#define ngx_live_segment_cache_validate(segment)
#endif

void
ngx_live_segment_cache_shift_dts(ngx_live_segment_t *segment, uint32_t shift)
{
    ngx_uint_t         i;
    ngx_list_part_t   *part;
    ngx_live_frame_t  *frames;

    part = &segment->frames.part;
    frames = part->elts;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            frames = part->elts;
            i = 0;
        }

        frames[i].pts_delay += shift;
    }

    segment->start_dts -= shift;
    segment->end_dts -= shift;
}

void
ngx_live_segment_cache_finalize(ngx_live_segment_t *segment, uint32_t *bitrate)
{
    int64_t              min_duration;
    uint64_t             segment_bitrate;
    ngx_live_track_t    *track;
    ngx_live_channel_t  *channel;

    track = segment->track;
    channel = track->channel;

    segment->ready = 1;

    /* calculate bitrate only for segments with duration > .25 sec */
    min_duration = channel->timescale / 4;
    if (segment->end_dts > segment->start_dts + min_duration) {

        segment_bitrate =
            (segment->data_size * 8 * channel->timescale) /
            (segment->end_dts - segment->start_dts);

        if (segment_bitrate <= 0 ||
            segment_bitrate >= NGX_LIVE_SEGMENT_CACHE_MAX_BITRATE)
        {
            segment_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
        }

        ngx_live_media_info_update_stats(segment, segment_bitrate);

    } else {
        segment_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
    }

    *bitrate = segment_bitrate;

    ngx_log_debug6(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_segment_cache_finalize: "
        "created segment %ui, frames: %ui, size: %uz, "
        "duration: %L, bitrate: %uL, track: %V",
        segment->node.key, segment->frame_count, segment->data_size,
        segment->end_dts - segment->start_dts,
        segment_bitrate, &track->sn.str);

    ngx_live_segment_cache_validate(segment);
}


ngx_live_segment_part_t *
ngx_live_segment_part_push(ngx_live_segment_t *segment)
{
    ngx_live_track_t                    *track;
    ngx_live_segment_part_t             *part;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    track = segment->track;

    part = ngx_array_push(&segment->parts);
    if (part == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_part_push: push failed");
        return NULL;
    }

    ngx_memzero(part, sizeof(*part));

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    ctx->parts++;

    return part;
}


static ngx_live_segment_t *
ngx_live_segment_cache_get_internal(ngx_live_track_t *track,
    uint32_t segment_index)
{
    ngx_rbtree_t                        *rbtree;
    ngx_rbtree_node_t                   *node;
    ngx_rbtree_node_t                   *sentinel;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    rbtree = &ctx->rbtree;
    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (segment_index < node->key) {
            node = node->left;
            continue;
        }

        if (segment_index > node->key) {
            node = node->right;
            continue;
        }

        return (ngx_live_segment_t *) node;
    }

    return NULL;
}


ngx_live_segment_t *
ngx_live_segment_cache_get(ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_live_segment_t  *segment;

    segment = ngx_live_segment_cache_get_internal(track, segment_index);
    if (segment == NULL || !segment->ready) {
        return NULL;
    }

    return segment;
}


uint32_t
ngx_live_segment_cache_get_last_part(ngx_live_track_t *track,
    uint32_t segment_index)
{
    ngx_uint_t                n;
    ngx_uint_t                ignore_count;
    ngx_live_segment_t       *segment;
    ngx_live_segment_part_t  *parts;

    segment = ngx_live_segment_cache_get_internal(track, segment_index);
    if (segment == NULL || segment->parts.nelts <= 0) {
        return NGX_LIVE_INVALID_PART_INDEX;
    }

    parts = segment->parts.elts;
    n = segment->parts.nelts;

    ignore_count = parts[n - 1].duration <= 0;
    if (n <= ignore_count) {
        return NGX_LIVE_INVALID_PART_INDEX;
    }

    return n - 1 - ignore_count;
}


ngx_flag_t
ngx_live_segment_cache_is_pending_part(ngx_live_track_t *track,
    uint32_t segment_index, uint32_t part_index)
{
    ngx_uint_t                           n;
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_part_t             *parts;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    q = ngx_queue_last(&ctx->queue);
    if (q == ngx_queue_sentinel(&ctx->queue)) {
        return 0;
    }

    segment = ngx_queue_data(q, ngx_live_segment_t, queue);
    if (segment->node.key != segment_index) {
        return 0;
    }

    n = segment->parts.nelts;
    if (n <= 0 || n - 1 != part_index) {
        return 0;
    }

    parts = segment->parts.elts;
    if (parts[part_index].duration > 0) {
        return 0;
    }

    return 1;
}


void
ngx_live_segment_cache_free_input_bufs(ngx_live_track_t *track)
{
    u_char                              *ptr;
    uint32_t                             segment_index;
    ngx_queue_t                         *head;
    ngx_live_channel_t                  *channel;
    ngx_live_segment_t                  *first;
    ngx_live_core_preset_conf_t         *cpcf;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);
    if (!ngx_queue_empty(&ctx->queue)) {
        head = ngx_queue_head(&ctx->queue);
        first = ngx_queue_data(head, ngx_live_segment_t, queue);

        segment_index = first->node.key;
        ptr = first->data_head->data;

    } else {
        channel = track->channel;
        cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

        cpcf->segmenter.get_min_used(track, &segment_index, &ptr);
    }

    ngx_live_input_bufs_set_min_used(track, segment_index, ptr);
}

void
ngx_live_segment_cache_free_by_index(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_queue_t         *q;
    ngx_live_track_t    *cur_track;
    ngx_live_segment_t  *segment;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segment_cache_free_by_index: index: %uD", segment_index);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        segment = ngx_live_segment_cache_get(cur_track, segment_index);
        if (segment == NULL) {
            continue;
        }

        ngx_live_segment_cache_free(segment);

        ngx_live_segment_cache_free_input_bufs(cur_track);
    }
}


static ngx_int_t
ngx_live_segment_cache_write_frame_list(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_list_part_t                part;
    ngx_list_part_t               *frame_part;
    ngx_live_frame_t              *frames, *last_frame;
    ngx_live_segment_write_ctx_t  *ctx = obj;

    frame_part = ctx->part.frame_part;
    frames = frame_part->elts;
    last_frame = frames + frame_part->nelts;

    part.elts = ctx->part.frame;
    part.nelts = last_frame - ctx->part.frame;
    part.next = frame_part->next;

    if (ngx_persist_write_list_data_n(write_ctx, &part, ctx->part.frame_count,
        sizeof(ngx_live_frame_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_cache_write_frame_data(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_segment_write_ctx_t  *ctx = obj;

    if (ngx_persist_write_append_buf_chain_n(write_ctx, ctx->part.data_head,
        ctx->data_offset, ctx->part.data_size) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_part_write_serve(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                          duration;
    ngx_uint_t                        i, n;
    ngx_live_track_t                 *track;
    ngx_live_segment_t               *segment = obj;
    ngx_live_segment_part_t          *parts, *part;
    ngx_ksmp_segment_parts_header_t   header;

    track = segment->track;

    header.segment_index = segment->node.key;

    if (ngx_persist_write(write_ctx, &header, sizeof(header)) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_part_write_serve: write header failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    parts = segment->parts.elts;
    n = segment->parts.nelts;

    if (parts[n - 1].duration <= 0) {
        n--;
    }

    for (i = 0; i < n; i++) {
        part = &parts[i];

        duration = part->duration;

        if (part->frame_count <= 0) {
            duration |= NGX_KSMP_PART_GAP;

        } else if (track->media_type == KMP_MEDIA_VIDEO
            && part->frame->key_frame)
        {
            duration |= NGX_KSMP_PART_INDEPENDENT;
        }

        if (ngx_persist_write(write_ctx, &duration, sizeof(duration))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segment_part_write_serve: write failed (1)");
            return NGX_ERROR;
        }
    }

    if (n < segment->parts.nelts) {
        duration = NGX_KSMP_PART_PRELOAD_HINT;

        if (ngx_persist_write(write_ctx, &duration, sizeof(duration))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segment_part_write_serve: write failed (2)");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_part_list_write_serve(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                         *q;
    ngx_queue_t                         *pq, *prev;
    ngx_live_track_t                    *track = obj;
    ngx_live_period_t                   *period;
    ngx_live_segment_t                  *segment;
    ngx_live_channel_t                  *channel;
    ngx_live_timeline_t                 *timeline;
    ngx_persist_write_marker_t           marker;
    ngx_ksmp_track_parts_header_t        header;
    ngx_live_persist_serve_scope_t      *scope;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_SEGMENT_PARTS)) {
        return NGX_OK;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    /* find the first segment with parts */

    q = ngx_queue_head(&ctx->queue);
    for ( ;; ) {

        if (q == ngx_queue_sentinel(&ctx->queue)) {
            return NGX_OK;
        }

        segment = ngx_queue_data(q, ngx_live_segment_t, queue);
        if (segment->parts.nelts > 0) {
            break;
        }

        q = ngx_queue_next(q);
    }

    /* skip periods that start after the segment
        (assume it's near the end of the timeline) */

    timeline = scope->timeline;
    pq = ngx_queue_last(&timeline->periods);
    for ( ;; ) {

        period = ngx_queue_data(pq, ngx_live_period_t, queue);
        if (period->node.key <= segment->node.key) {
            break;
        }

        prev = ngx_queue_prev(pq);
        if (prev == ngx_queue_sentinel(&timeline->periods)) {
            break;
        }

        pq = prev;
    }

    channel = track->channel;
    header.count = 0;

    for ( ;; ) {

        if (segment->node.key >= period->node.key + period->segment_count) {

            /* move to the next period */

            pq = ngx_queue_next(pq);
            if (pq == ngx_queue_sentinel(&timeline->periods)) {
                goto done;
            }

            period = ngx_queue_data(pq, ngx_live_period_t, queue);
            continue;
        }

        if (segment->node.key > scope->max_index) {
            goto done;
        }

        if (segment->node.key >= period->node.key) {

            /* write the parts of the segment */

            if (header.count <= 0) {
                if (ngx_persist_write_block_open(write_ctx,
                        NGX_KSMP_BLOCK_TRACK_PARTS) != NGX_OK ||
                    ngx_persist_write_reserve(write_ctx, sizeof(header),
                        &marker) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_live_segment_part_list_write_serve: "
                        "write failed");
                    return NGX_ERROR;
                }

                ngx_persist_write_block_set_header(write_ctx, 0);
            }

            if (ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_PARTS, segment) != NGX_OK)
            {
                return NGX_ERROR;
            }

            header.count++;
        }

        /* move to the next segment with parts */

        do {
            q = ngx_queue_next(q);
            if (q == ngx_queue_sentinel(&ctx->queue)) {
                goto done;
            }

            segment = ngx_queue_data(q, ngx_live_segment_t, queue);
        } while (segment->parts.nelts <= 0);
    }

done:

    if (header.count <= 0) {
        return NGX_OK;
    }

    ngx_persist_write_marker_write(&marker, &header, sizeof(header));

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}


static void
ngx_live_segment_write_init_ctx_closest_key(ngx_live_segment_write_ctx_t *ctx,
    int64_t time)
{
    size_t               offset;
    int64_t              dts, pts;
    int64_t              min_diff, cur_diff;
    ngx_list_part_t     *part;
    ngx_live_frame_t    *cur, *last;
    ngx_live_segment_t  *segment = ctx->segment;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    dts = segment->start_dts;
    offset = 0;

    pts = dts + cur->pts_delay;
    min_diff = ngx_abs_diff(pts, time);

    ctx->part.start_dts = dts;
    ctx->part.frame = cur;
    ctx->part.frame_part = part;
    ctx->part.frame_count = 1;
    ctx->part.data_size = cur->size;
    ctx->data_offset = 0;

    for ( ;; ) {

        dts += cur->duration;
        offset += cur->size;
        cur++;

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (!cur->key_frame) {
            continue;
        }

        pts = dts + cur->pts_delay;
        cur_diff = ngx_abs_diff(pts, time);
        if (cur_diff >= min_diff) {
            continue;
        }

        min_diff = cur_diff;

        ctx->part.start_dts = dts;
        ctx->part.frame = cur;
        ctx->part.frame_part = part;
        ctx->part.data_size = cur->size;
        ctx->data_offset = offset;
    }

    ctx->part.data_head = segment->data_head;

    if (ctx->data_offset > 0) {
        ctx->part.data_head = ngx_buf_chain_seek(ctx->part.data_head,
            &ctx->data_offset);
    }
}

static void
ngx_live_segment_write_init_ctx_min_gop(ngx_live_segment_write_ctx_t *ctx,
    int64_t time)
{
    size_t               offset;
    size_t               key_offset;
    int64_t              key_dts;
    int64_t              max_pts;
    int64_t              dts, pts;
    int64_t              min_diff, cur_diff;
    ngx_uint_t           count;
    ngx_flag_t           last_used;
    ngx_list_part_t     *part;
    ngx_list_part_t     *key_part;
    ngx_live_frame_t    *key_frame;
    ngx_live_frame_t    *cur, *last;
    ngx_live_segment_t  *segment = ctx->segment;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    dts = segment->start_dts;
    offset = 0;
    count = 1;

    key_frame = cur;
    key_part = part;
    key_dts = dts;
    key_offset = 0;

    pts = dts + cur->pts_delay;

    max_pts = pts;
    min_diff = ngx_abs_diff(pts, time);

    ctx->part.start_dts = dts;
    ctx->part.frame = cur;
    ctx->part.frame_part = part;
    ctx->part.frame_count = 1;
    ctx->part.data_size = cur->size;

    last_used = 1;

    for ( ;; ) {

        if (pts > max_pts) {
            max_pts = pts;
        }

        dts += cur->duration;
        offset += cur->size;
        count++;
        cur++;

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->key_frame) {
            key_frame = cur;
            key_part = part;
            key_dts = dts;
            key_offset = offset;
            count = 1;
        }

        pts = dts + cur->pts_delay;
        cur_diff = ngx_abs_diff(pts, time);

        /* if the current frame has a pts smaller than the max, it means it's
            a B frame, if the last frame was used, must take this one too */

        if (cur_diff >= min_diff && (!last_used || pts >= max_pts)) {
            last_used = 0;
            continue;
        }

        min_diff = ngx_min(cur_diff, min_diff);

        ctx->part.start_dts = key_dts;
        ctx->part.frame = key_frame;
        ctx->part.frame_part = key_part;
        ctx->part.frame_count = count;
        ctx->part.data_size = offset + cur->size - key_offset;
        ctx->data_offset = key_offset;

        last_used = 1;
    }

    ctx->part.data_head = segment->data_head;

    if (ctx->data_offset > 0) {
        ctx->part.data_head = ngx_buf_chain_seek(ctx->part.data_head,
            &ctx->data_offset);
    }
}


void
ngx_live_segment_write_init_ctx(ngx_live_segment_write_ctx_t *ctx,
    ngx_live_segment_t *segment, uint32_t part_index, uint32_t flags,
    int64_t time)
{
    ngx_live_segment_part_t  *part;

    ctx->segment = segment;
    ctx->part_sequence = 0;
    ctx->data_offset = 0;

    if (part_index != NGX_LIVE_INVALID_PART_INDEX) {
        ctx->part_sequence = segment->part_sequence + part_index;

        part = segment->parts.elts;
        part += part_index;

        ctx->part = *part;

    } else if (flags & NGX_KSMP_FLAG_MEDIA_CLOSEST_KEY) {
        ngx_live_segment_write_init_ctx_closest_key(ctx, time);

    } else if (flags & NGX_KSMP_FLAG_MEDIA_MIN_GOP) {
        ngx_live_segment_write_init_ctx_min_gop(ctx, time);

    } else {
        ctx->part.start_dts = segment->start_dts;

        ctx->part.frame = segment->frames.part.elts;
        ctx->part.frame_part = &segment->frames.part;
        ctx->part.frame_count = segment->frame_count;

        ctx->part.data_head = segment->data_head;
        ctx->part.data_size = segment->data_size;
    }
}


ngx_int_t
ngx_live_segment_cache_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_segment_write_ctx_t *ctx, ngx_live_persist_main_conf_t *pmcf,
    ngx_live_segment_cleanup_t *cln, uint32_t *header_size)
{
    size_t                              start;
    ngx_live_segment_t                 *segment;
    ngx_live_persist_segment_header_t   header;

    /* segment header */
    start = ngx_persist_write_get_size(write_ctx);

    segment = ctx->segment;

    header.track_id = segment->track_id;
    header.index = segment->node.key;
    header.frame_count = ctx->part.frame_count;
    header.part_sequence = ctx->part_sequence;
    header.start_dts = ctx->part.start_dts;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_SEGMENT) != NGX_OK ||
        ngx_persist_write(write_ctx, &header, sizeof(header)) != NGX_OK ||
        ngx_live_persist_write_blocks_internal(pmcf, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER, ctx) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, segment->pool->log, 0,
            "ngx_live_segment_cache_write: write failed (1)");
        return NGX_ERROR;
    }

    *header_size = ngx_persist_write_get_size(write_ctx) - start;

    /* segment data */
    if (ngx_live_persist_write_blocks_internal(pmcf, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA, ctx) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, segment->pool->log, 0,
            "ngx_live_segment_cache_write: write failed (2)");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);     /* segment */

    /* lock the segment data */
    if (cln != NULL) {
        if (ngx_live_segment_index_lock(cln, segment) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, segment->pool->log, 0,
                "ngx_live_segment_cache_write: lock segment failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_cache_serve(ngx_live_segment_serve_req_t *req)
{
    uint32_t                       ignore;
    uint32_t                       part_index;
    uint32_t                       segment_index;
    ngx_pool_t                    *pool;
    ngx_live_channel_t            *channel;
    ngx_live_segment_t            *segment;
    ngx_live_track_ref_t          *cur, *last;
    ngx_live_segment_part_t       *parts;
    ngx_persist_write_ctx_t       *write_ctx;
    ngx_live_segment_index_t      *index;
    ngx_live_segment_cleanup_t    *cln;
    ngx_live_segment_write_ctx_t   sctx;
    ngx_live_persist_main_conf_t  *pmcf;

    pool = req->pool;
    channel = req->channel;
    segment_index = req->segment_index;
    part_index = req->part_index;

    index = ngx_live_segment_index_get(channel, segment_index);
    if (index == NULL) {
        if (ngx_live_next_serve != NULL) {
            return ngx_live_next_serve(req);
        }

        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_serve: "
            "segment %uD not found", segment_index);
        return NGX_OK;
    }

    cln = ngx_live_segment_index_cleanup_add(pool, index, req->track_count);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_serve: cleanup add failed");
        return NGX_ERROR;
    }

    cln->handler = req->writer.cleanup;
    cln->data = req->writer.arg;

    write_ctx = NULL;

    last = req->tracks + req->track_count;
    for (cur = req->tracks; cur < last; cur++) {

        if (cur->track == NULL) {
            if (ngx_live_next_serve != NULL) {
                return ngx_live_next_serve(req);
            }

            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_live_segment_cache_serve: "
                "segment %uD refers to a missing track id %uD",
                segment_index, cur->id);
            return NGX_ERROR;
        }

        segment = ngx_live_segment_cache_get_internal(cur->track,
            segment_index);
        if (segment == NULL) {
            continue;
        }

        if (part_index != NGX_LIVE_INVALID_PART_INDEX) {
            if (part_index >= segment->parts.nelts) {
                continue;
            }

            if (part_index == segment->parts.nelts - 1 && !segment->ready) {
                continue;
            }

            parts = segment->parts.elts;
            if (parts[part_index].frame_count <= 0) {
                /* gap part */
                continue;
            }

        } else if (!segment->ready) {
            continue;
        }

        if (write_ctx == NULL) {
            write_ctx = ngx_persist_write_init(req->pool, 0, 0);
            if (write_ctx == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_live_segment_cache_serve: write init failed");
                return NGX_ERROR;
            }
        }

        ngx_live_segment_write_init_ctx(&sctx, segment, part_index,
            req->flags, req->time);

        pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

        if (ngx_live_segment_cache_write(write_ctx, &sctx, pmcf, cln, &ignore)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_serve: write segment failed");
            return NGX_ERROR;
        }
    }

    if (write_ctx == NULL) {
        if (part_index != NGX_LIVE_INVALID_PART_INDEX) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_serve: "
                "segment %uD part %uD not found on any track",
                segment_index, part_index);

        } else {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_serve: "
                "segment %uD not found on any track", segment_index);
        }

        return NGX_OK;
    }

    req->chain = ngx_persist_write_close(write_ctx, &req->size, NULL);
    if (req->chain == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_serve: write close failed");
        return NGX_ERROR;
    }

    req->source = ngx_live_segment_cache_source_name;
    return NGX_OK;
}


static size_t
ngx_live_segment_cache_track_json_get_size(void *obj)
{
    return sizeof("\"segment_cache\":{\"count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"parts\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"min_index\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"max_index\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_segment_cache_track_json_write(u_char *p, void *obj)
{
    ngx_queue_t                         *q;
    ngx_live_track_t                    *track = obj;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    p = ngx_copy_fix(p, "\"segment_cache\":{\"count\":");
    p = ngx_sprintf(p, "%uD", ctx->count);

    p = ngx_copy_fix(p, ",\"parts\":");
    p = ngx_sprintf(p, "%uD", ctx->parts);

    if (!ngx_queue_empty(&ctx->queue)) {

        q = ngx_queue_head(&ctx->queue);
        segment = ngx_queue_data(q, ngx_live_segment_t, queue);
        p = ngx_copy_fix(p, ",\"min_index\":");
        p = ngx_sprintf(p, "%uD", (uint32_t) segment->node.key);

        q = ngx_queue_last(&ctx->queue);
        segment = ngx_queue_data(q, ngx_live_segment_t, queue);
        p = ngx_copy_fix(p, ",\"max_index\":");
        p = ngx_sprintf(p, "%uD", (uint32_t) segment->node.key);
    }
    *p++ = '}';

    return p;
}


static ngx_int_t
ngx_live_segment_cache_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    q = ngx_queue_head(&ctx->queue);
    if (q == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }

    while (q != ngx_queue_sentinel(&ctx->queue)) {

        segment = ngx_queue_data(q, ngx_live_segment_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_segment_cache_destroy(segment);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_track_channel_free(ngx_live_track_t *track, void *ectx)
{
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);

    q = ngx_queue_head(&ctx->queue);
    while (q != ngx_queue_sentinel(&ctx->queue)) {

        segment = ngx_queue_data(q, ngx_live_segment_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_destroy_pool(segment->pool);
    }

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_segment_cache_blocks[] = {
    /*
     * persist data:
     *   ngx_ksmp_frame_t  frame[];
     */
    { NGX_KSMP_BLOCK_FRAME_LIST, NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_segment_cache_write_frame_list, NULL },

    { NGX_KSMP_BLOCK_FRAME_DATA, NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_segment_cache_write_frame_data, NULL },

    /*
     * persist header:
     *   ngx_ksmp_track_parts_header_t  header;
     */
    { NGX_KSMP_BLOCK_TRACK_PARTS, NGX_LIVE_PERSIST_CTX_SERVE_TRACK, 0,
      ngx_live_segment_part_list_write_serve, NULL },

    /*
     * persist header:
     *   ngx_ksmp_segment_parts_header_t  header;
     *
     * persist data:
     *   uint32_t  duration[];
     */
    { NGX_KSMP_BLOCK_SEGMENT_PARTS, NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_PARTS,
      NGX_PERSIST_FLAG_SINGLE, ngx_live_segment_part_write_serve, NULL },

    /*
     * persist header:
     *   ngx_ksmp_segment_header_t  header;
     */
    { NGX_KSMP_BLOCK_SEGMENT, NGX_LIVE_PERSIST_CTX_SERVE_MAIN, 0,
      NULL, NULL },

      ngx_null_persist_block
};

static ngx_int_t
ngx_live_segment_cache_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_segment_cache_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_track_event_t      ngx_live_segment_cache_track_events[] = {
    { ngx_live_segment_cache_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_segment_cache_track_free, NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_segment_cache_track_channel_free,
        NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_segment_cache_json_writers[] = {
    { { ngx_live_segment_cache_track_json_get_size,
        ngx_live_segment_cache_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_segment_cache_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_track_events_add(cf,
        ngx_live_segment_cache_track_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_segment_cache_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_live_next_serve = ngx_live_serve_segment;
    ngx_live_serve_segment = ngx_live_segment_cache_serve;

    return NGX_OK;
}

static char *
ngx_live_segment_cache_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_segment_cache_module,
        sizeof(ngx_live_segment_cache_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
