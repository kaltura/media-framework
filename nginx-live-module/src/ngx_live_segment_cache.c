#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_media_info.h"
#include "ngx_live_segmenter.h"


#define NGX_MAX_INT32_BIT  31

#define NGX_LIVE_SEGMENT_CACHE_MAX_BITRATE  (64 * 1024 * 1024)


typedef struct {
    ngx_queue_t             queue;
    ngx_rbtree_t            rbtree;
    ngx_rbtree_node_t       sentinel;
    uint32_t                count;
} ngx_live_segment_cache_track_ctx_t;

typedef struct {
    size_t                  frame_left;
    ngx_buf_chain_t        *chain;
    u_char                 *pos;
} ngx_live_segment_cache_source_state_t;


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


static ngx_live_read_segment_pt  ngx_live_next_read;
ngx_live_read_segment_pt         ngx_live_read_segment = NULL;

static ngx_live_copy_segment_pt  ngx_live_next_copy;
ngx_live_copy_segment_pt         ngx_live_copy_segment = NULL;

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
ngx_live_segment_cache_source_init(ngx_pool_t *pool, ngx_buf_chain_t *chain,
    void **result)
{
    ngx_live_segment_cache_source_state_t  *state;

    state = ngx_palloc(pool, sizeof(*state));
    if (state == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, pool->log, 0,
            "ngx_live_segment_cache_source_init: alloc failed");
        return NGX_ERROR;
    }

    state->chain = chain;
    state->pos = chain->data;

    *result = state;

    return NGX_OK;
}

static vod_status_t
ngx_live_segment_cache_source_start_frame(void *ctx, ngx_live_frame_t *frame)
{
    ngx_live_segment_cache_source_state_t  *state = ctx;

    state->frame_left = frame->size;

    return VOD_OK;
}

static vod_status_t
ngx_live_segment_cache_source_read(void *ctx, u_char **buffer, uint32_t *size,
    bool_t *frame_done)
{
    size_t                                  chain_left;
    ngx_buf_chain_t                        *chain;
    ngx_live_segment_cache_source_state_t  *state = ctx;

    *buffer = state->pos;

    chain = state->chain;
    chain_left = chain->data + chain->size - state->pos;

    if (state->frame_left >= chain_left) {
        *size = chain_left;

        state->frame_left -= chain_left;
        *frame_done = state->frame_left <= 0;

        chain = chain->next;
        if (chain) {
            state->chain = chain;
            state->pos = chain->data;
        }

    } else {
        *size = state->frame_left;

        state->frame_left = 0;
        *frame_done = 1;

        state->pos += *size;
    }

    return VOD_OK;
}

static frames_source_t  ngx_live_segment_cache_source = {
    ngx_live_segment_cache_source_start_frame,
    ngx_live_segment_cache_source_read,
};


static ngx_int_t
ngx_live_segment_cache_read(ngx_live_segment_read_req_t *req)
{
    uint32_t                     segment_index;
    ngx_flag_t                   found;
    ngx_pool_t                  *pool;
    media_segment_t             *result;
    ngx_live_channel_t          *channel;
    ngx_live_segment_t          *segment;
    ngx_live_track_ref_t        *cur, *last;
    media_segment_track_t       *dest_track;
    ngx_live_segment_index_t    *index;
    ngx_live_segment_cleanup_t  *cln;

    pool = req->pool;
    result = req->segment;
    channel = req->channel;
    segment_index = result->segment_index;

    index = ngx_live_segment_index_get(channel, segment_index);
    if (index == NULL) {
        if (ngx_live_next_read != NULL) {
            return ngx_live_next_read(req);
        }

        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_read: "
            "segment %uD not found", segment_index);
        return NGX_ABORT;
    }

    if (req->flags & NGX_LIVE_READ_FLAG_LOCK_DATA) {

        cln = ngx_live_segment_index_cleanup_add(pool, index,
            result->track_count);
        if (cln == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_read: cleanup add failed");
            return NGX_ERROR;
        }

        cln->handler = req->cleanup;
        cln->data = req->arg;

    } else {
        cln = NULL;
    }

    found = 0;

    last = req->tracks + result->track_count;
    for (cur = req->tracks, dest_track = result->tracks;
        cur < last;
        cur++, dest_track++)
    {
        if (cur->track == NULL) {
            if (ngx_live_next_read != NULL) {
                return ngx_live_next_read(req);
            }

            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_live_segment_cache_read: "
                "segment %uD refers to a missing track id %uD",
                segment_index, cur->id);
            return NGX_ERROR;
        }

        segment = ngx_live_segment_cache_get(cur->track, segment_index);
        if (segment == NULL) {
            continue;
        }

        if (ngx_live_segment_cache_source_init(pool, segment->data_head,
            &dest_track->frames_source_context) != VOD_OK)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_LIVE, pool->log, 0,
                "ngx_live_segment_cache_read: "
                "frame source init failed");
            return NGX_ERROR;
        }

        if (cln != NULL &&
            ngx_live_segment_index_lock(cln, segment) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_read: lock segment failed");
            return NGX_ERROR;
        }

        dest_track->frames_source = &ngx_live_segment_cache_source;

        /* Note: copying only the frames part since dest is immutable */
        dest_track->frames.part = segment->frames.part;
        dest_track->frame_count = segment->frame_count;
        dest_track->start_dts = segment->start_dts;

        found = 1;
    }

    if (!found) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_read: "
            "segment %uD not found on any track", segment_index);
        return NGX_ABORT;
    }

    result->source = ngx_live_segment_cache_source_name;
    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_cache_write_frame_list(ngx_persist_write_ctx_t *write_data,
    void *obj)
{
    ngx_live_segment_t  *segment = obj;

    if (ngx_persist_write_list_data(write_data, &segment->frames)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_cache_write_frame_data(ngx_persist_write_ctx_t *write_data,
    void *obj)
{
    ngx_live_segment_t  *segment = obj;

    if (ngx_persist_write_append_buf_chain(write_data, segment->data_head)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_segment_cache_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_segment_t *segment, ngx_live_segment_cleanup_t *cln,
    uint32_t *header_size)
{
    size_t                              start;
    ngx_live_track_t                   *track;
    ngx_live_channel_t                 *channel;
    ngx_live_persist_segment_header_t   header;

    track = segment->track;
    channel = track->channel;

    /* segment header */
    start = ngx_persist_write_get_size(write_ctx);

    header.track_id = segment->track->in.key;
    header.segment_index = segment->node.key;
    header.frame_count = segment->frame_count;
    header.start_dts = segment->start_dts;
    header.reserved = 0;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_SEGMENT) != NGX_OK ||
        ngx_persist_write(write_ctx, &header, sizeof(header)) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER, segment) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_write: write failed (1)");
        return NGX_ERROR;
    }

    *header_size = ngx_persist_write_get_size(write_ctx) - start;

    /* segment data */
    if (ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA, segment) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_write: write failed (2)");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);     /* segment */

    /* lock the segment data */
    if (ngx_live_segment_index_lock(cln, segment) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_write: lock segment failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_segment_cache_copy(ngx_live_segment_copy_req_t *req)
{
    uint32_t                     ignore;
    uint32_t                     segment_index;
    ngx_pool_t                  *pool;
    ngx_live_segment_t          *segment;
    ngx_live_track_ref_t        *cur, *last;
    ngx_persist_write_ctx_t     *write_ctx;
    ngx_live_segment_index_t    *index;
    ngx_live_segment_cleanup_t  *cln;

    pool = req->pool;
    segment_index = req->segment_index;

    index = ngx_live_segment_index_get(req->channel, segment_index);
    if (index == NULL) {
        if (ngx_live_next_copy != NULL) {
            return ngx_live_next_copy(req);
        }

        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_copy: "
            "segment %uD not found", segment_index);
        return NGX_OK;
    }

    cln = ngx_live_segment_index_cleanup_add(pool, index, req->track_count);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_copy: cleanup add failed");
        return NGX_ERROR;
    }

    cln->handler = req->writer.cleanup;
    cln->data = req->writer.arg;

    write_ctx = NULL;

    last = req->tracks + req->track_count;
    for (cur = req->tracks; cur < last; cur++) {

        if (cur->track == NULL) {
            if (ngx_live_next_copy != NULL) {
                return ngx_live_next_copy(req);
            }

            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_live_segment_cache_copy: "
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
                    "ngx_live_segment_cache_copy: write init failed");
                return NGX_ERROR;
            }
        }

        if (ngx_live_segment_cache_write(write_ctx, segment, cln, &ignore)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_copy: write segment failed");
            return NGX_ERROR;
        }
    }

    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_copy: "
            "segment %uD not found on any track", segment_index);
        return NGX_OK;
    }

    req->chain = ngx_persist_write_close(write_ctx, &req->size);
    if (req->chain == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_copy: write close failed");
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
    { NGX_KSMP_BLOCK_FRAME_LIST,
      NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_segment_cache_write_frame_list, NULL },

    { NGX_KSMP_BLOCK_FRAME_DATA,
      NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_segment_cache_write_frame_data, NULL },

    /*
     * persist header:
     *   ngx_ksmp_segment_header_t  header;
     */
    { NGX_KSMP_BLOCK_SEGMENT, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
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

    ngx_live_next_read = ngx_live_read_segment;
    ngx_live_read_segment = ngx_live_segment_cache_read;

    ngx_live_next_copy = ngx_live_copy_segment;
    ngx_live_copy_segment = ngx_live_segment_cache_copy;

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
