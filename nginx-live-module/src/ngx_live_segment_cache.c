#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_media_info.h"
#include "ngx_live_segmenter.h"


#define NGX_MAX_INT32_BIT  31


typedef struct {
    ngx_queue_t             queue;
    ngx_rbtree_t            tree;
    ngx_rbtree_node_t       sentinel;
    uint32_t                count;
} ngx_live_segment_cache_track_ctx_t;

typedef struct {
    uint32_t                segment_mask_base;
    uint32_t                segment_mask;
} ngx_live_segment_cache_channel_ctx_t;

typedef struct {
    size_t                  frame_left;
    ngx_buf_chain_t        *chain;
} ngx_live_segment_cache_source_state_t;


static ngx_int_t ngx_live_segment_cache_postconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_segment_cache_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_segment_cache_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    NULL,                                     /* merge preset configuration */
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

static ngx_str_t  ngx_live_segment_cache_source_name = ngx_string("cache");


ngx_live_segment_t *
ngx_live_segment_cache_create(ngx_live_track_t *track, uint32_t segment_index)
{
    uint32_t                               segment_mask_base;
    ngx_pool_t                            *pool;
    ngx_live_segment_t                    *segment;
    ngx_live_segment_cache_track_ctx_t    *ctx;
    ngx_live_segment_cache_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(track->channel,
        ngx_live_segment_cache_module);

    if (segment_index < cctx->segment_mask_base) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segment_cache_create: "
            "segment index %uD smaller than base %uD",
            segment_index, cctx->segment_mask_base);
        return NULL;
    }

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

    if (ngx_list_init(&segment->frames, pool, 10, sizeof(input_frame_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_cache_create: init list failed");
        goto error;
    }

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    segment->node.key = segment_index;
    segment->track = track;
    segment->pool = pool;

    ngx_rbtree_insert(&ctx->tree, &segment->node);
    ngx_queue_insert_tail(&ctx->queue, &segment->queue);
    ctx->count++;

    if (segment_index > cctx->segment_mask_base + NGX_MAX_INT32_BIT) {
        segment_mask_base = segment_index - NGX_MAX_INT32_BIT;
        cctx->segment_mask >>= segment_mask_base - cctx->segment_mask_base;
        cctx->segment_mask_base = segment_mask_base;
    }

    cctx->segment_mask |= 1 << (segment_index - cctx->segment_mask_base);

    return segment;

error:

    ngx_destroy_pool(pool);
    return NULL;
}

static void
ngx_live_segment_cache_destroy(ngx_live_channel_t *channel,
    ngx_live_segment_t *segment)
{
    if (segment->data_tail != NULL) {
        ngx_live_channel_buf_chain_free_list(channel, segment->data_head,
            segment->data_tail);
    }

    ngx_destroy_pool(segment->pool);
}

void
ngx_live_segment_cache_free(ngx_live_track_t *track,
    ngx_live_segment_t *segment)
{
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    ctx->count--;
    ngx_queue_remove(&segment->queue);
    ngx_rbtree_delete(&ctx->tree, &segment->node);

    ngx_live_segment_cache_destroy(track->channel, segment);
}

ngx_live_segment_t *
ngx_live_segment_cache_get(ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_rbtree_t                        *rbtree;
    ngx_rbtree_node_t                   *node;
    ngx_rbtree_node_t                   *sentinel;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    rbtree = &ctx->tree;
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

        return (ngx_live_segment_t*) node;
    }

    return NULL;
}

ngx_live_input_bufs_lock_t *
ngx_live_segment_cache_lock_data(ngx_live_segment_t *segment)
{
    return ngx_live_input_bufs_lock(segment->track, segment->node.key,
        segment->data_head->data);
}

static void
ngx_live_segment_cache_free_input_bufs(ngx_live_track_t *track)
{
    u_char                              *ptr;
    uint32_t                             segment_index;
    ngx_queue_t                         *head;
    ngx_live_segment_t                  *first;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);
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
    ngx_live_segment_cache_channel_ctx_t  *cctx;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        segment = ngx_live_segment_cache_get(cur_track, segment_index);
        if (segment == NULL) {
            continue;
        }

        ngx_live_segment_cache_free(cur_track, segment);

        ngx_live_segment_cache_free_input_bufs(cur_track);
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_cache_module);

    if (segment_index - cctx->segment_mask_base <= NGX_MAX_INT32_BIT) {
        cctx->segment_mask &=
            ~(1 << (segment_index - cctx->segment_mask_base));
    }
}

static void
ngx_live_segment_cache_track_free_old(ngx_live_track_t *track,
    uint32_t min_segment_index)
{
    ngx_flag_t                           free;
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    free = 0;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);
    while (!ngx_queue_empty(&ctx->queue)) {

        q = ngx_queue_head(&ctx->queue);
        segment = ngx_queue_data(q, ngx_live_segment_t, queue);
        if (segment->node.key >= min_segment_index) {
            break;
        }

        free = 1;
        ngx_live_segment_cache_free(track, segment);
    }

    if (free) {
        ngx_live_segment_cache_free_input_bufs(track);
    }
}

void
ngx_live_segment_cache_free_old(ngx_live_channel_t *channel,
    uint32_t min_segment_index)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_segment_cache_channel_ctx_t  *cctx;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        ngx_live_segment_cache_track_free_old(cur_track, min_segment_index);
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_cache_module);

    if (min_segment_index > cctx->segment_mask_base) {
        cctx->segment_mask >>= min_segment_index - cctx->segment_mask_base;
        cctx->segment_mask_base = min_segment_index;
    }
}

#if (NGX_LIVE_VALIDATIONS)
void
ngx_live_segment_cache_validate(ngx_live_segment_t *segment)
{
    size_t            data_size;
    size_t            frames_size;
    int64_t           end_dts;
    uint32_t          frame_count;
    ngx_uint_t        i;
    input_frame_t    *frames;
    ngx_buf_chain_t  *data;
    ngx_list_part_t  *part;

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
#endif


static ngx_int_t
ngx_live_segment_cache_source_init(
    ngx_pool_t *pool,
    ngx_buf_chain_t *chain,
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

    *result = state;

    return NGX_OK;
}

static vod_status_t
ngx_live_segment_cache_source_start_frame(void *ctx, input_frame_t *frame)
{
    ngx_live_segment_cache_source_state_t  *state = ctx;

    state->frame_left = frame->size;

    return VOD_OK;
}

static vod_status_t
ngx_live_segment_cache_source_read(void *ctx, u_char **buffer, uint32_t *size,
    bool_t *frame_done)
{
    ngx_buf_chain_t                        *chain;
    ngx_live_segment_cache_source_state_t  *state = ctx;

    chain = state->chain;
    state->chain = chain->next;
    state->frame_left -= chain->size;

    *buffer = chain->data;
    *size = chain->size;
    *frame_done = state->frame_left <= 0;

    return VOD_OK;
}

static frames_source_t  ngx_live_segment_cache_source = {
    ngx_live_segment_cache_source_start_frame,
    ngx_live_segment_cache_source_read,
};


static void
ngx_live_segment_cache_release_locks(void *data)
{
    ngx_live_input_bufs_lock_t  **cur;
    ngx_live_input_bufs_lock_t  **end;

    for (cur = data, end = cur + KMP_MEDIA_COUNT; cur < end; cur++) {
        if (*cur == NULL) {
            break;
        }

        ngx_live_input_bufs_unlock(*cur);
    }
}

static ngx_int_t
ngx_live_segment_cache_read(ngx_live_segment_read_req_t *req)
{
    uint32_t                               segment_index;
    ngx_flag_t                             found;
    ngx_pool_t                            *pool;
    media_segment_t                       *result;
    ngx_pool_cleanup_t                    *cln;
    ngx_live_segment_t                    *segment;
    ngx_live_track_ref_t                  *cur, *last;
    media_segment_track_t                 *dest_track;
    ngx_live_input_bufs_lock_t           **locks;
    ngx_live_segment_cache_channel_ctx_t  *cctx;

    pool = req->pool;

    if (req->flags & NGX_LIVE_READ_FLAG_LOCK_DATA) {
        cln = ngx_pool_cleanup_add(pool, sizeof(*locks) * KMP_MEDIA_COUNT);
        if (cln == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_segment_cache_read: failed to add cleanup item");
            return NGX_ERROR;
        }

        cln->handler = ngx_live_segment_cache_release_locks;

        locks = cln->data;
        ngx_memzero(locks, sizeof(*locks) * KMP_MEDIA_COUNT);

    } else {
        locks = NULL;
    }

    result = req->segment;
    segment_index = result->segment_index;
    found = 0;

    last = req->tracks + req->track_count;
    for (cur = req->tracks, dest_track = result->tracks;
        cur < last;
        cur++, dest_track++)
    {
        if (cur->track == NULL) {
            if (ngx_live_next_read != NULL) {
                goto next;
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

        if (locks != NULL) {
            *locks = ngx_live_segment_cache_lock_data(segment);
            if (*locks == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_live_segment_cache_read: lock segment failed");
                return NGX_ERROR;
            }
            locks++;
        }

        dest_track->frames_source = &ngx_live_segment_cache_source;

        /* Note: copying only the frames part since dest is immutable */
        dest_track->frames.part = segment->frames.part;
        dest_track->frame_count = segment->frame_count;
        dest_track->start_dts = segment->start_dts;

        found = 1;
    }

    if (found) {
        result->source = ngx_live_segment_cache_source_name;
        return NGX_OK;
    }

    if (ngx_live_next_read == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_read: "
            "segment %uD not found on any track (1)", segment_index);
        return NGX_ABORT;
    }

    cctx = ngx_live_get_module_ctx(req->channel,
        ngx_live_segment_cache_module);

    /* if we have the segment in mask, no need to forward to the next reader.
        this can happen when requesting a single media type that does not exist
        in this segment */
    if (segment_index - cctx->segment_mask_base <= NGX_MAX_INT32_BIT &&
        cctx->segment_mask & (1 << (segment_index - cctx->segment_mask_base)))
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_cache_read: "
            "segment %uD not found on any track (2)", segment_index);
        return NGX_ABORT;
    }

next:

    return ngx_live_next_read(req);
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

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

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
ngx_live_segment_cache_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size)
{
    ngx_live_segment_cache_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_cache_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_segment_cache_module);

    ngx_live_reserve_track_ctx_size(channel, ngx_live_segment_cache_module,
        sizeof(ngx_live_segment_cache_track_ctx_t), track_ctx_size);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_track_init(ngx_live_track_t *track)
{
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    ngx_rbtree_init(&ctx->tree, &ctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_track_free(ngx_live_track_t *track)
{
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    q = ngx_queue_head(&ctx->queue);
    if (q == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }

    for (; q != ngx_queue_sentinel(&ctx->queue); q = ngx_queue_next(q)) {

        segment = ngx_queue_data(q, ngx_live_segment_t, queue);

        ngx_live_segment_cache_destroy(track->channel, segment);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_track_channel_free(ngx_live_track_t *track)
{
    ngx_queue_t                         *q;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_cache_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segment_cache_module);

    for (q = ngx_queue_head(&ctx->queue);
        q != ngx_queue_sentinel(&ctx->queue);
        q = ngx_queue_next(q))
    {
        segment = ngx_queue_data(q, ngx_live_segment_t, queue);

        ngx_destroy_pool(segment->pool);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_cache_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_writer_t            *writer;
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_track_handler_pt         *th;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_segment_cache_channel_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_INIT]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segment_cache_track_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segment_cache_track_free;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_CHANNEL_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segment_cache_track_channel_free;

    writer = ngx_array_push(&cmcf->json_writers[NGX_LIVE_JSON_CTX_TRACK]);
    if (writer == NULL) {
        return NGX_ERROR;
    }
    writer->get_size = ngx_live_segment_cache_track_json_get_size;
    writer->write = ngx_live_segment_cache_track_json_write;

    ngx_live_next_read = ngx_live_read_segment;
    ngx_live_read_segment = ngx_live_segment_cache_read;

    return NGX_OK;
}
