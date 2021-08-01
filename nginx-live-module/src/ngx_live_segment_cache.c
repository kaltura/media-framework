#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_media_info.h"
#include "ngx_live_segmenter.h"
#include "persist/ngx_live_persist_internal.h"


#define NGX_LIVE_SEGMENT_CACHE_MAX_BITRATE  (64 * 1024 * 1024)


typedef struct {
    ngx_queue_t             queue;
    ngx_rbtree_t            rbtree;
    ngx_rbtree_node_t       sentinel;
    uint32_t                count;
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
    ngx_pool_t                            *pool;
    ngx_live_segment_t                    *segment;
    ngx_live_segment_cache_track_ctx_t    *ctx;

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
    ngx_live_channel_t  *channel;

    if (segment->data_tail != NULL) {
        channel = segment->track->channel;
        ngx_live_channel_buf_chain_free_list(channel, segment->data_head,
            segment->data_tail);
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
    ngx_queue_remove(&segment->queue);
    ngx_rbtree_delete(&ctx->rbtree, &segment->node);

    ngx_live_segment_cache_destroy(segment);
}

#if (NGX_LIVE_VALIDATIONS)
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

    if (segment->data_size != data_size) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "invalid segment data size %uz expected %uz",
            segment->data_size, data_size);
        ngx_debug_point();
    }

    if (data_size != frames_size) {
        ngx_log_error(NGX_LOG_ALERT, segment->pool->log, 0,
            "ngx_live_segment_cache_validate: "
            "data size %uz doesn't match frames size %uz",
            data_size, frames_size);
        ngx_debug_point();
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
ngx_live_segment_cache_finalize(ngx_live_segment_t *segment)
{
    int64_t                       min_duration;
    uint64_t                      last_segment_bitrate;
    ngx_live_track_t             *track;
    ngx_live_core_preset_conf_t  *cpcf;

    track = segment->track;
    cpcf = ngx_live_get_module_preset_conf(track->channel,
        ngx_live_core_module);

    /* calculate bitrate only for segments with duration > .25 sec */
    min_duration = cpcf->timescale / 4;
    if (segment->end_dts > segment->start_dts + min_duration) {

        last_segment_bitrate =
            (segment->data_size * 8 * cpcf->timescale) /
            (segment->end_dts - segment->start_dts);

        if (last_segment_bitrate > 0 &&
            last_segment_bitrate < NGX_LIVE_SEGMENT_CACHE_MAX_BITRATE)
        {
            track->last_segment_bitrate = last_segment_bitrate;

            ngx_live_media_info_update_bitrate(track);

        } else {
            track->last_segment_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
        }

    } else {
        track->last_segment_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_segment_cache_finalize: "
        "created segment %ui, frames: %ui, size: %uz, duration: %L, track: %V",
        segment->node.key, segment->frame_count, segment->data_size,
        segment->end_dts - segment->start_dts, &track->sn.str);

    ngx_live_segment_cache_validate(segment);
}

ngx_live_segment_t *
ngx_live_segment_cache_get(ngx_live_track_t *track, uint32_t segment_index)
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

void
ngx_live_segment_cache_free_input_bufs(ngx_live_track_t *track)
{
    u_char                              *ptr;
    uint32_t                             segment_index;
    ngx_queue_t                         *head;
    ngx_live_segment_t                  *first;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_cache_module);
    if (!ngx_queue_empty(&ctx->queue)) {
        head = ngx_queue_head(&ctx->queue);
        first = ngx_queue_data(head, ngx_live_segment_t, queue);

        segment_index = first->node.key;
        ptr = first->data_head->data;

    } else {
        ngx_live_segmenter_get_min_used(track, &segment_index, &ptr);
    }

    ngx_live_input_bufs_set_min_used(track, segment_index, ptr);
}

void
ngx_live_segment_cache_free_by_index(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_segment_t                    *segment;

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
    ngx_live_segment_write_ctx_t  *ctx = obj;

    if (ngx_persist_write_list_data_n(write_ctx, &ctx->part, ctx->count,
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
    size_t                         offset;
    ngx_buf_chain_t               *head;
    ngx_live_segment_write_ctx_t  *ctx = obj;

    offset = ctx->offset;
    head = ctx->segment->data_head;

    if (offset > 0) {
        head = ngx_buf_chain_seek(head, &offset);
    }

    if (ngx_persist_write_append_buf_chain_n(write_ctx, head, offset,
        ctx->size) != NGX_OK)
    {
        return NGX_ERROR;
    }

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

    ctx->part.elts = cur;
    ctx->part.nelts = 1;
    ctx->part.next = NULL;
    ctx->count = 1;
    ctx->offset = 0;
    ctx->size = cur->size;
    ctx->start_dts = dts;

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

        ctx->part.elts = cur;
        ctx->offset = offset;
        ctx->size = cur->size;
        ctx->start_dts = dts;
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
    ngx_list_part_t      key_part;
    ngx_live_frame_t    *cur, *last;
    ngx_live_segment_t  *segment = ctx->segment;

    part = &segment->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    dts = segment->start_dts;
    offset = 0;
    count = 1;

    key_part = *part;
    key_dts = dts;
    key_offset = 0;

    pts = dts + cur->pts_delay;

    max_pts = pts;
    min_diff = ngx_abs_diff(pts, time);

    ctx->part = *part;
    ctx->count = 1;
    ctx->start_dts = dts;
    ctx->offset = 0;
    ctx->size = cur->size;

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
            key_part.elts = cur;
            key_part.nelts = last - cur;
            key_part.next = part->next;
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

        ctx->part = key_part;
        ctx->count = count;
        ctx->start_dts = key_dts;
        ctx->offset = key_offset;
        ctx->size = offset + cur->size - key_offset;

        last_used = 1;
    }
}


void
ngx_live_segment_write_init_ctx(ngx_live_segment_write_ctx_t *ctx,
    ngx_live_segment_t *segment, uint32_t flags, int64_t time)
{
    ctx->segment = segment;

    if (flags & NGX_KSMP_FLAG_MEDIA_CLOSEST_KEY) {
        ngx_live_segment_write_init_ctx_closest_key(ctx, time);

    } else if (flags & NGX_KSMP_FLAG_MEDIA_MIN_GOP) {
        ngx_live_segment_write_init_ctx_min_gop(ctx, time);

    } else {
        ctx->part = segment->frames.part;
        ctx->count = segment->frame_count;
        ctx->start_dts = segment->start_dts;
        ctx->offset = 0;
        ctx->size = segment->data_size;
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
    header.frame_count = ctx->count;
    header.start_dts = ctx->start_dts;
    header.reserved = 0;

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
    uint32_t                       segment_index;
    ngx_pool_t                    *pool;
    ngx_live_channel_t            *channel;
    ngx_live_segment_t            *segment;
    ngx_live_track_ref_t          *cur, *last;
    ngx_persist_write_ctx_t       *write_ctx;
    ngx_live_segment_index_t      *index;
    ngx_live_segment_cleanup_t    *cln;
    ngx_live_segment_write_ctx_t   sctx;
    ngx_live_persist_main_conf_t  *pmcf;

    pool = req->pool;
    channel = req->channel;
    segment_index = req->segment_index;

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

        segment = ngx_live_segment_cache_get(cur->track, segment_index);
        if (segment == NULL) {
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

        ngx_live_segment_write_init_ctx(&sctx, segment, req->flags, req->time);

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
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_serve: "
            "segment %uD not found on any track", segment_index);
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
