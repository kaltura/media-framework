#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_notif_segment.h"
#include "ngx_live_timeline.h"


typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
} ngx_live_notif_segment_track_ctx_t;

typedef struct {
    ngx_queue_t        queue;
} ngx_live_notif_segment_channel_ctx_t;


static ngx_int_t ngx_live_notif_segment_postconfiguration(ngx_conf_t *cf);
static char *ngx_live_notif_segment_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_live_module_t  ngx_live_notif_segment_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_notif_segment_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    ngx_live_notif_segment_merge_preset_conf, /* merge preset configuration */
};

ngx_module_t  ngx_live_notif_segment_module = {
    NGX_MODULE_V1,
    &ngx_live_notif_segment_module_ctx,       /* module context */
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


static void
ngx_live_notif_segment_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_live_notif_segment_sub_t   *n, *t;

    for ( ;; ) {

        n = (ngx_live_notif_segment_sub_t *) node;
        t = (ngx_live_notif_segment_sub_t *) temp;

        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else {
            p = (n->part_index < t->part_index) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_live_notif_segment_detach(void *data)
{
    ngx_live_notif_segment_sub_t        *sub = data;
    ngx_live_notif_segment_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(sub->track, ngx_live_notif_segment_module);

    ngx_rbtree_delete(&ctx->rbtree, &sub->node);
    ngx_queue_remove(&sub->queue);
}


ngx_live_notif_segment_sub_t *
ngx_live_notif_segment_subscribe(ngx_pool_t *pool, ngx_live_track_t *track,
    ngx_live_timeline_t *timeline, uint32_t segment_index, uint32_t part_index)
{
    ngx_pool_cleanup_t                    *cln;
    ngx_live_channel_t                    *channel;
    ngx_live_notif_segment_sub_t          *sub;
    ngx_live_notif_segment_track_ctx_t    *ctx;
    ngx_live_notif_segment_channel_ctx_t  *cctx;

    cln = ngx_pool_cleanup_add(pool, sizeof(*sub));
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_notif_segment_subscribe: cleanup add failed");
        return NULL;
    }

    cln->handler = ngx_live_notif_segment_detach;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_notif_segment_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_notif_segment_module);

    sub = cln->data;

    sub->node.key = segment_index;
    sub->part_index = part_index;
    sub->track = track;
    sub->timeline_int_id = timeline->int_id;
    sub->cln = cln;

    ngx_rbtree_insert(&ctx->rbtree, &sub->node);
    ngx_queue_insert_tail(&cctx->queue, &sub->queue);

    ngx_log_error(NGX_LOG_INFO, pool->log, 0,
        "ngx_live_notif_segment_subscribe: "
        "sub: %p, track: %V, timeline: %V, segment: %uD, part: %uD",
        sub, &track->sn.str, &timeline->sn.str, segment_index, part_index);

    return sub;
}


void
ngx_live_notif_segment_publish(ngx_live_track_t *track, uint32_t segment_index,
    uint32_t part_index, ngx_int_t rc)
{
    ngx_rbtree_t                        *rbtree;
    ngx_rbtree_node_t                   *node, *root, *sentinel;
    ngx_live_notif_segment_sub_t        *sub;
    ngx_live_notif_segment_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_notif_segment_module);

    rbtree = &ctx->rbtree;
    sentinel = &ctx->sentinel;

    for ( ;; ) {
        root = rbtree->root;

        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);
        if (node->key > segment_index) {
            break;
        }

        sub = (void *) node;
        if (node->key == segment_index && sub->part_index > part_index) {
            break;
        }

        ngx_live_notif_segment_detach(sub);
        sub->cln->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_notif_segment_publish: "
            "calling handler %i, sub: %p", rc, sub);

        sub->handler(sub->data, rc);
    }
}


void
ngx_live_notif_segment_publish_timeline(ngx_live_timeline_t *timeline,
    ngx_int_t rc)
{
    ngx_queue_t                           *q;
    ngx_live_channel_t                    *channel;
    ngx_live_notif_segment_sub_t          *sub;
    ngx_live_notif_segment_channel_ctx_t  *cctx;

    channel = timeline->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_notif_segment_module);

    /* Note: this can be optimized by moving the queue from channel to
        timeline, however, the assumption is that it doesn't happen too often
        and there won't be too many subscribers, so not worth the trouble */

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue); )
    {
        sub = ngx_queue_data(q, ngx_live_notif_segment_sub_t, queue);
        q = ngx_queue_next(q);  /* sub may be freed */

        if (sub->timeline_int_id != timeline->int_id) {
            continue;
        }

        ngx_live_notif_segment_detach(sub);
        sub->cln->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, &timeline->log, 0,
            "ngx_live_notif_segment_publish_timeline: "
            "calling handler %i, sub: %p", rc, sub);

        sub->handler(sub->data, rc);
    }
}


static ngx_int_t
ngx_live_notif_segment_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_notif_segment_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_notif_segment_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_notif_segment_module);

    ngx_queue_init(&cctx->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_live_notif_segment_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_notif_segment_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_notif_segment_module);

    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel,
        ngx_live_notif_segment_insert_value);

    return NGX_OK;
}


static ngx_int_t
ngx_live_notif_segment_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_notif_segment_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_notif_segment_module);
    if (ctx->rbtree.sentinel == NULL) {
        return NGX_OK;      /* failed to initialize */
    }

    ngx_live_notif_segment_publish(track, NGX_LIVE_INVALID_SEGMENT_INDEX,
        NGX_LIVE_INVALID_PART_INDEX, NGX_ABORT);

    return NGX_OK;
}


static ngx_live_channel_event_t  ngx_live_notif_segment_channel_events[] = {
    { ngx_live_notif_segment_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },

      ngx_live_null_event
};

static ngx_live_track_event_t    ngx_live_notif_segment_track_events[] = {
    { ngx_live_notif_segment_track_init,   NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_notif_segment_track_free,   NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_notif_segment_track_free,   NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_int_t
ngx_live_notif_segment_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_notif_segment_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf, ngx_live_notif_segment_track_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_live_notif_segment_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_notif_segment_module,
        sizeof(ngx_live_notif_segment_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
