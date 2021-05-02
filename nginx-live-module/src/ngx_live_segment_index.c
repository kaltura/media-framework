#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_timeline.h"


enum {
    NGX_LIVE_BP_SEGMENT_INDEX,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    ngx_uint_t                      force_memory_segments;
    ngx_uint_t                      bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_segment_index_preset_conf_t;


typedef enum {
    ngx_live_segment_persist_none,
    ngx_live_segment_persist_ok,
    ngx_live_segment_persist_error,
} ngx_live_segment_persist_e;

struct ngx_live_segment_index_s {
    ngx_rbtree_node_t               node;       /* key = segment_index */
    ngx_queue_t                     queue;      /* all queue */
    ngx_queue_t                     pqueue;     /* pending / done queues */

    ngx_queue_t                     cleanup;
    ngx_live_segment_persist_e      persist;
    ngx_live_persist_snap_t        *snap;
    unsigned                        free:1;
};


typedef struct {
    ngx_queue_t                     all;
    ngx_queue_t                     pending;
    ngx_queue_t                     done;
    ngx_rbtree_t                    rbtree;
    ngx_rbtree_node_t               sentinel;
    uint32_t                        last_segment_index;
    unsigned                        no_free:1;
} ngx_live_segment_index_channel_ctx_t;


static void *ngx_live_segment_index_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_segment_index_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_live_segment_index_postconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_segment_index_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_segment_index_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_segment_index_create_preset_conf,/* create preset configuration */
    ngx_live_segment_index_merge_preset_conf, /* merge preset configuration */
};


static ngx_command_t  ngx_live_segment_index_commands[] = {
    { ngx_string("force_memory_segments"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segment_index_preset_conf_t, force_memory_segments),
      NULL },

      ngx_null_command
};

ngx_module_t  ngx_live_segment_index_module = {
    NGX_MODULE_V1,
    &ngx_live_segment_index_module_ctx,       /* module context */
    ngx_live_segment_index_commands,          /* module directives */
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


static void
ngx_live_segment_index_free(ngx_live_channel_t *channel,
    ngx_live_segment_index_t *index, uint32_t *truncate)
{
    ngx_live_segment_index_channel_ctx_t  *cctx;
    ngx_live_segment_index_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);
    if (cctx->no_free) {
        return;
    }

    if (!index->free) {
        index->free = 1;

        ngx_live_segment_cache_free_by_index(channel, index->node.key);

        if (index->persist != ngx_live_segment_persist_ok) {
            *truncate = index->node.key;
        }
    }

    if (index->snap != NULL) {
        index->snap->close(index->snap, ngx_live_persist_snap_close_ack);
        index->snap = NULL;
    }

    if (!ngx_queue_empty(&index->cleanup)) {
        return;
    }

    ngx_rbtree_delete(&cctx->rbtree, &index->node);
    ngx_queue_remove(&index->queue);
    ngx_queue_remove(&index->pqueue);

    spcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_index_module);

    ngx_block_pool_free(channel->block_pool,
        spcf->bp_idx[NGX_LIVE_BP_SEGMENT_INDEX], index);
}

static void
ngx_live_segment_index_free_non_forced(ngx_live_channel_t *channel)
{
    uint32_t                               truncate;
    ngx_uint_t                             limit;
    ngx_queue_t                           *q;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;
    ngx_live_segment_index_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    spcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_index_module);

    if (cctx->last_segment_index < spcf->force_memory_segments) {
        return;
    }
    limit = cctx->last_segment_index - spcf->force_memory_segments;

    truncate = 0;

    q = ngx_queue_head(&cctx->done);
    while (q != ngx_queue_sentinel(&cctx->done)) {

        index = ngx_queue_data(q, ngx_live_segment_index_t, pqueue);
        if (index->node.key > limit) {
            break;
        }

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_segment_index_free(channel, index, &truncate);
    }

    if (truncate) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_index_free_non_forced: "
            "truncating timelines, index: %uD", truncate);

        ngx_live_timelines_truncate(channel, truncate);
    }
}

ngx_int_t
ngx_live_segment_index_create(ngx_live_channel_t *channel, ngx_flag_t exists)
{
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;
    ngx_live_segment_index_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    if (!exists) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_segment_index_create: "
            "no active timeline, freeing segment");

        ngx_live_segment_cache_free_by_index(channel,
            channel->next_segment_index);
        goto done;
    }

    spcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_index_module);

    index = ngx_block_pool_calloc(channel->block_pool,
        spcf->bp_idx[NGX_LIVE_BP_SEGMENT_INDEX]);
    if (index == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_index_create: alloc failed");
        return NGX_ERROR;
    }

    index->snap = ngx_live_persist_snap_create(channel);
    if (index->snap == NGX_LIVE_PERSIST_INVALID_SNAP) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_index_create: create snap failed");
        return NGX_ERROR;
    }

    index->node.key = channel->next_segment_index;
    ngx_queue_init(&index->cleanup);

    ngx_rbtree_insert(&cctx->rbtree, &index->node);
    ngx_queue_insert_tail(&cctx->all, &index->queue);
    ngx_queue_insert_tail(&cctx->pending, &index->pqueue);

done:

    cctx->last_segment_index = channel->next_segment_index;

    ngx_live_segment_index_free_non_forced(channel);

    if (channel->snapshots <= 0) {
        ngx_live_channel_ack_frames(channel);
    }

    return NGX_OK;
}

ngx_live_segment_index_t *
ngx_live_segment_index_get(ngx_live_channel_t *channel, uint32_t segment_index)
{
    ngx_rbtree_t                          *rbtree;
    ngx_rbtree_node_t                     *node, *sentinel;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    rbtree = &cctx->rbtree;

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

        index = (ngx_live_segment_index_t *) node;

        return index->free ? NULL : index;
    }

    return NULL;
}

static ngx_live_segment_index_t *
ngx_live_segment_index_get_first(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_queue_t                           *q;
    ngx_rbtree_t                          *rbtree;
    ngx_rbtree_node_t                     *next;
    ngx_rbtree_node_t                     *node, *sentinel;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    rbtree = &cctx->rbtree;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    if (node == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        if (segment_index < node->key) {
            next = node->left;
            if (next != sentinel) {
                node = next;
                continue;
            }

            return (ngx_live_segment_index_t *) node;

        } else if (segment_index > node->key) {
            next = node->right;
            if (next != sentinel) {
                node = next;
                continue;
            }

            index = (ngx_live_segment_index_t *) node;

            q = ngx_queue_next(&index->queue);
            if (q == ngx_queue_sentinel(&cctx->all)) {
                return NULL;
            }

            return ngx_queue_data(q, ngx_live_segment_index_t, queue);

        } else {
            return (ngx_live_segment_index_t *) node;
        }
    }
}

static ngx_queue_t *
ngx_live_segment_index_get_insert_pos(ngx_queue_t *queue,
    uint32_t segment_index)
{
    ngx_queue_t               *q;
    ngx_live_segment_index_t  *cur;

    for (q = ngx_queue_last(queue);
        q != ngx_queue_sentinel(queue);
        q = ngx_queue_prev(q))
    {
        cur = ngx_queue_data(q, ngx_live_segment_index_t, pqueue);
        if (cur->node.key < segment_index) {
            break;
        }
    }

    return ngx_queue_next(q);
}

void
ngx_live_segment_index_persisted(ngx_live_channel_t *channel,
    uint32_t min_segment_index, uint32_t max_segment_index, ngx_int_t rc)
{
    ngx_flag_t                             inherited;
    ngx_queue_t                           *q;
    ngx_queue_t                           *ins;
    ngx_live_persist_snap_t               *snap;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_t              *pending;
    ngx_live_segment_persist_e             persist;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    /* Note: may not find the first index when a dvr bucket is saved,
        and some segment indexes contained in it did not exist */

    index = ngx_live_segment_index_get_first(channel, min_segment_index);
    if (index == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segment_index_persisted: "
            "index not found, min: %uD", min_segment_index);
        return;
    }

    if (index->node.key >= max_segment_index) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segment_index_persisted: "
            "index not in range, index: %ui, min: %uD, max: %uD",
            index->node.key, min_segment_index, max_segment_index);
        return;
    }

    if (index->persist != ngx_live_segment_persist_none) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segment_index_persisted: "
            "already called for segment %ui", index->node.key);
        ngx_debug_point();
        return;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    q = ngx_queue_prev(&index->pqueue);
    if (q != ngx_queue_sentinel(&cctx->pending)) {
        pending = ngx_queue_data(q, ngx_live_segment_index_t, pqueue);

    } else {
        pending = NULL;
    }

    snap = NULL;

    ins = ngx_live_segment_index_get_insert_pos(&cctx->done, index->node.key);

    q = &index->queue;
    persist = rc == NGX_OK ? ngx_live_segment_persist_ok :
        ngx_live_segment_persist_error;

    for ( ;; ) {

        index->persist = persist;

        /* move from pending queue to done */
        ngx_queue_remove(&index->pqueue);
        ngx_queue_insert_before(ins, &index->pqueue);

        if (index->snap != NULL) {
            if (snap != NULL) {
                snap->close(snap, ngx_live_persist_snap_close_free);
            }
            snap = index->snap;
            index->snap = NULL;
        }

        q = ngx_queue_next(q);
        if (q == ngx_queue_sentinel(&cctx->all)) {
            break;
        }

        index = ngx_queue_data(q, ngx_live_segment_index_t, queue);
        if (index->node.key >= max_segment_index) {
            break;
        }
    }

    ngx_live_segment_index_free_non_forced(channel);

    if (snap == NULL) {
        return;
    }

    inherited = snap->scope.max_index >= max_segment_index;
    if (rc != NGX_OK && !inherited) {
        /* Note: it is possible that there is some pending segment before
            this one, but since this one failed, we just ack it */
        snap->close(snap, ngx_live_persist_snap_close_ack);
        return;
    }

    if (pending != NULL) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_segment_index_persisted: "
            "ownership of snapshot %uD passed to %ui",
            snap->scope.max_index, pending->node.key);

        if (pending->snap != NULL) {
            pending->snap->close(pending->snap,
                ngx_live_persist_snap_close_free);
        }
        pending->snap = snap;
        return;
    }

    snap->close(snap, ngx_live_persist_snap_close_write);
}

static void
ngx_live_segment_index_cleanup(ngx_live_segment_index_t *index)
{
    ngx_queue_t                 *q;
    ngx_live_segment_cleanup_t  *cln;

    q = ngx_queue_head(&index->cleanup);
    while (q != ngx_queue_sentinel(&index->cleanup)) {

        cln = ngx_queue_data(q, ngx_live_segment_cleanup_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        if (cln->handler) {
            cln->handler(cln->data);
        }
    }
}

static ngx_int_t
ngx_live_segment_index_watermark(ngx_live_channel_t *channel, void *ectx)
{
    uint32_t                               truncate;
    ngx_uint_t                             level;
    ngx_queue_t                           *q;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    channel->mem_watermark_events++;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    truncate = 0;
    level = NGX_LOG_NOTICE;

    q = ngx_queue_head(&cctx->all);
    while (q != ngx_queue_sentinel(&cctx->all)) {

        if (channel->mem_left >= channel->mem_low_watermark) {
            break;
        }

        index = ngx_queue_data(q, ngx_live_segment_index_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        /* Note: need to disable free, since cleanup handlers call 'persisted'
            which in turn calls 'free', and may release index/q */
        cctx->no_free = 1;
        ngx_live_segment_index_cleanup(index);
        cctx->no_free = 0;

        if (!ngx_queue_empty(&index->cleanup)) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_segment_index_watermark: cleanup queue not empty");
            break;
        }

        if (!index->free && index->persist == ngx_live_segment_persist_none) {
            level = NGX_LOG_ERR;
        }

        ngx_live_segment_index_free(channel, index, &truncate);
    }

    if (truncate) {
        ngx_log_error(level, &channel->log, 0,
            "ngx_live_segment_index_watermark: "
            "truncating timelines, index: %uD", truncate);

        ngx_live_timelines_truncate(channel, truncate);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_index_segment_free(ngx_live_channel_t *channel, void *ectx)
{
    uint32_t                               ignore;
    uint32_t                               min_segment_index;
    ngx_queue_t                           *q;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    min_segment_index = (uintptr_t) ectx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);

    q = ngx_queue_head(&cctx->all);
    while (q != ngx_queue_sentinel(&cctx->all)) {

        index = ngx_queue_data(q, ngx_live_segment_index_t, queue);

        if (index->node.key >= min_segment_index) {
            break;
        }

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_segment_index_free(channel, index, &ignore);
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_segment_index_lock(ngx_live_segment_cleanup_t *cln,
    ngx_live_segment_t *segment)
{
    ngx_live_input_bufs_lock_t  *lock;

    lock = ngx_live_input_bufs_lock(segment->track, segment->node.key,
        segment->data_head->data);
    if (lock == NULL) {
        return NGX_ERROR;
    }

    *cln->locks_end++ = lock;

    return NGX_OK;
}

static void
ngx_live_segment_index_unlock(void *data)
{
    ngx_live_segment_cleanup_t   *cln = data;
    ngx_live_input_bufs_lock_t  **cur;

    for (cur = cln->locks; cur < cln->locks_end; cur++) {
        ngx_live_input_bufs_unlock(*cur);
    }

    ngx_queue_remove(&cln->queue);
}

ngx_live_segment_cleanup_t *
ngx_live_segment_index_cleanup_add(ngx_pool_t *pool,
    ngx_live_segment_index_t *index, uint32_t max_locks)
{
    ngx_pool_cleanup_t           *cln;
    ngx_live_segment_cleanup_t   *result;
    ngx_live_input_bufs_lock_t  **locks;

    cln = ngx_pool_cleanup_add(pool, sizeof(*result) +
        sizeof(*locks) * max_locks);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_segment_index_cleanup_add: failed to add cleanup item");
        return NULL;
    }

    result = cln->data;
    locks = (void *) (result + 1);

    result->handler = NULL;
    result->data = NULL;
    result->locks = locks;
    result->locks_end = locks;

    cln->handler = ngx_live_segment_index_unlock;
    cln->data = result;

    ngx_queue_insert_tail(&index->cleanup, &result->queue);

    return result;
}

static ngx_int_t
ngx_live_segment_index_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_segment_index_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_index_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&cctx->all);
    ngx_queue_init(&cctx->pending);
    ngx_queue_init(&cctx->done);

    ngx_live_set_ctx(channel, cctx, ngx_live_segment_index_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_index_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                           *q;
    ngx_live_segment_index_t              *index;
    ngx_live_segment_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_index_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    /* Note: should not try to free segments when the channel is freed since
        the segment cache module may have already freed everything */
    cctx->no_free = 1;

    q = ngx_queue_head(&cctx->all);
    while (q != ngx_queue_sentinel(&cctx->all)) {

        index = ngx_queue_data(q, ngx_live_segment_index_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_segment_index_cleanup(index);

        if (!ngx_queue_empty(&index->cleanup)) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_segment_index_channel_free: "
                "cleanup queue not empty");
        }

        if (index->snap != NULL) {
            index->snap->close(index->snap, ngx_live_persist_snap_close_free);
        }
    }

    return NGX_OK;
}

static void *
ngx_live_segment_index_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_segment_index_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_segment_index_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->force_memory_segments = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_segment_index_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_segment_index_preset_conf_t  *prev = parent;
    ngx_live_segment_index_preset_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->force_memory_segments,
                              prev->force_memory_segments, 5);

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_SEGMENT_INDEX],
        sizeof(ngx_live_segment_index_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t  ngx_live_segment_index_channel_events[] = {
    { ngx_live_segment_index_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_segment_index_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_segment_index_segment_free,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE },
    { ngx_live_segment_index_watermark, NGX_LIVE_EVENT_CHANNEL_WATERMARK },
      ngx_live_null_event
};

static ngx_int_t
ngx_live_segment_index_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_segment_index_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
