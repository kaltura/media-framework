#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_info.h"
#include "ngx_live_timeline.h"


#define NGX_LIVE_SEGMENT_INFO_PERSIST_BLOCK  NGX_KSMP_BLOCK_SEGMENT_INFO

/* sizeof ngx_live_segment_info_node_t = 1024 */
#define NGX_LIVE_SEGMENT_INFO_NODE_ELTS    (120)

#define NGX_LIVE_SEGMENT_INFO_FREE_PERIOD  (32)

enum {
    NGX_LIVE_BP_SEGMENT_INFO_NODE,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    ngx_flag_t                     gaps;
    ngx_flag_t                     bitrate;
    ngx_uint_t                     bitrate_lower_bound;
    ngx_uint_t                     bitrate_upper_bound;
    ngx_uint_t                     bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_segment_info_preset_conf_t;


struct ngx_live_segment_info_node_s {
    ngx_rbtree_node_t              node;        /* key = segment_index */
    ngx_queue_t                    queue;
    ngx_uint_t                     nelts;
    ngx_live_segment_info_elt_t    elts[NGX_LIVE_SEGMENT_INFO_NODE_ELTS];
};

typedef struct {
    ngx_rbtree_t                   rbtree;
    ngx_rbtree_node_t              sentinel;
    ngx_queue_t                    queue;
    uint64_t                       last_segment_bitrate;    /* bitrate * 100 */
    uint32_t                       initial_bitrate;
    uint32_t                       last_segment_index;
} ngx_live_segment_info_track_ctx_t;

typedef struct {
    uint32_t                       min_free_index;
} ngx_live_segment_info_channel_ctx_t;


static ngx_int_t ngx_live_segment_info_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_segment_info_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_segment_info_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_segment_info_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_live_segment_info_commands[] = {

    { ngx_string("segment_info_gaps"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segment_info_preset_conf_t, gaps),
      NULL },

    { ngx_string("segment_info_bitrate"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segment_info_preset_conf_t, bitrate),
      NULL },

    { ngx_string("segment_info_bitrate_lower_bound"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segment_info_preset_conf_t, bitrate_lower_bound),
      NULL },

    { ngx_string("segment_info_bitrate_upper_bound"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segment_info_preset_conf_t, bitrate_upper_bound),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_segment_info_module_ctx = {
    ngx_live_segment_info_preconfiguration,   /* preconfiguration */
    ngx_live_segment_info_postconfiguration,  /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_segment_info_create_preset_conf, /* create preset configuration */
    ngx_live_segment_info_merge_preset_conf,  /* merge preset configuration */
};

ngx_module_t  ngx_live_segment_info_module = {
    NGX_MODULE_V1,
    &ngx_live_segment_info_module_ctx,        /* module context */
    ngx_live_segment_info_commands,           /* module directives */
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


static ngx_live_segment_info_elt_t *
ngx_live_segment_info_push(ngx_live_channel_t *channel, uint32_t segment_index,
    ngx_live_segment_info_track_ctx_t *ctx)
{
    ngx_queue_t                          *q;
    ngx_live_segment_info_elt_t          *elt;
    ngx_live_segment_info_node_t         *last;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    q = ngx_queue_last(&ctx->queue);
    if (q != ngx_queue_sentinel(&ctx->queue)) {

        last = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);

        if (last->nelts < NGX_LIVE_SEGMENT_INFO_NODE_ELTS) {

            elt = &last->elts[last->nelts];
            last->nelts++;

            elt->index = segment_index;
            return elt;
        }
    }

    sipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_info_module);

    last = ngx_block_pool_alloc(channel->block_pool,
        sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE]);
    if (last == NULL) {
        return NULL;
    }

    last->node.key = segment_index;

    ngx_queue_insert_tail(&ctx->queue, &last->queue);
    ngx_rbtree_insert(&ctx->rbtree, &last->node);

    elt = &last->elts[0];
    last->nelts = 1;

    elt->index = segment_index;
    return elt;
}


static ngx_int_t
ngx_live_segment_info_track_segment_created(ngx_live_track_t *track,
    void *ectx)
{
    uint64_t                              cur;
    uint64_t                              last;
    ngx_live_channel_t                   *channel;
    ngx_live_segment_info_elt_t          *elt;
    ngx_live_track_segment_info_t        *info;
    ngx_live_segment_info_track_ctx_t    *ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    channel = track->channel;

    sipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_info_module);
    if (!sipcf->bitrate && !sipcf->gaps) {
        return NGX_OK;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);
    info = ectx;

    ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_segment_info_track_segment_created: "
        "index: %uD, bitrate: %uD, track: %V",
        info->segment_index, info->bitrate, &track->sn.str);

    if (ctx->last_segment_index >= info->segment_index
        && ctx->last_segment_index != NGX_LIVE_INVALID_SEGMENT_INDEX)
    {
        return NGX_OK;
    }

    ctx->last_segment_index = info->segment_index;

    cur = info->bitrate;
    if (cur) {
        if (!sipcf->bitrate) {
            cur = NGX_LIVE_SEGMENT_NO_BITRATE;
        }

    } else {
        if (!sipcf->gaps) {
            return NGX_OK;
        }
    }

    last = ctx->last_segment_bitrate;
    if (last >= cur * sipcf->bitrate_lower_bound &&
        last <= cur * sipcf->bitrate_upper_bound)
    {
        return NGX_OK;
    }

    elt = ngx_live_segment_info_push(channel, info->segment_index, ctx);
    if (elt == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segment_info_track_segment_created: push failed");
        return NGX_ERROR;
    }

    elt->bitrate = cur;

    ctx->last_segment_bitrate = cur * 100;

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_info_segment_created(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                    *q;
    ngx_live_track_t               *cur_track;
    ngx_live_track_segment_info_t   info;

    info.segment_index = channel->next_segment_index;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        info.bitrate = cur_track->last_segment_bitrate;

        if (ngx_live_segment_info_track_segment_created(cur_track, &info)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_track_copy(ngx_live_track_t *dst, void *ectx)
{
    ngx_queue_t                          *q;
    ngx_live_track_t                     *src = ectx;
    ngx_live_channel_t                   *dst_channel;
    ngx_live_segment_info_node_t         *src_node;
    ngx_live_segment_info_node_t         *dst_node;
    ngx_live_segment_info_track_ctx_t    *src_ctx;
    ngx_live_segment_info_track_ctx_t    *dst_ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    src_ctx = ngx_live_get_module_ctx(src, ngx_live_segment_info_module);
    dst_ctx = ngx_live_get_module_ctx(dst, ngx_live_segment_info_module);

    dst_channel = dst->channel;
    sipcf = ngx_live_get_module_preset_conf(dst_channel,
        ngx_live_segment_info_module);

    for (q = ngx_queue_head(&src_ctx->queue);
        q != ngx_queue_sentinel(&src_ctx->queue);
        q = ngx_queue_next(q))
    {
        dst_node = ngx_block_pool_alloc(dst_channel->block_pool,
            sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE]);
        if (dst_node == NULL) {
            return NGX_ERROR;
        }

        src_node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);

        dst_node->node.key = src_node->node.key;
        dst_node->nelts = src_node->nelts;
        ngx_memcpy(dst_node->elts, src_node->elts,
            sizeof(src_node->elts[0]) * src_node->nelts);

        ngx_queue_insert_tail(&dst_ctx->queue, &dst_node->queue);
        ngx_rbtree_insert(&dst_ctx->rbtree, &dst_node->node);
    }

    dst_ctx->last_segment_bitrate = src_ctx->last_segment_bitrate;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_track_segment_free(ngx_live_track_t *track,
    uint32_t min_segment_index)
{
    ngx_queue_t                          *q, *next;
    ngx_live_channel_t                   *channel;
    ngx_live_segment_info_node_t         *next_node;
    ngx_live_segment_info_node_t         *node;
    ngx_live_segment_info_track_ctx_t    *ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);
    sipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_info_module);

    q = ngx_queue_head(&ctx->queue);
    for ( ;; ) {

        next = ngx_queue_next(q);
        if (next == ngx_queue_sentinel(&ctx->queue)) {
            break;
        }

        next_node = ngx_queue_data(next, ngx_live_segment_info_node_t, queue);
        if (min_segment_index < next_node->node.key) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);
        ngx_queue_remove(q);
        ngx_rbtree_delete(&ctx->rbtree, &node->node);

        ngx_block_pool_free(channel->block_pool,
            sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE], node);

        q = next;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_segment_free(ngx_live_channel_t *channel, void *ectx)
{
    uint32_t                              min_segment_index = (uintptr_t) ectx;
    ngx_queue_t                          *q;
    ngx_live_track_t                     *cur_track;
    ngx_live_segment_info_channel_ctx_t  *cctx;

    /* no need to look for nodes to free on each segment */
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segment_info_module);

    if (min_segment_index < cctx->min_free_index) {
        return NGX_OK;
    }

    cctx->min_free_index = min_segment_index +
        NGX_LIVE_SEGMENT_INFO_FREE_PERIOD;

    /* free unused segment info nodes */
    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        ngx_live_segment_info_track_segment_free(cur_track,
            min_segment_index);
    }

    return NGX_OK;
}

static ngx_live_segment_info_node_t *
ngx_live_segment_info_lookup(ngx_live_segment_info_track_ctx_t *ctx,
    uint32_t segment_index)
{
    ngx_queue_t                   *prev;
    ngx_rbtree_t                  *rbtree;
    ngx_rbtree_node_t             *rbnode;
    ngx_rbtree_node_t             *sentinel;
    ngx_rbtree_node_t             *next_node;
    ngx_live_segment_info_node_t  *node;

    rbtree = &ctx->rbtree;
    rbnode = rbtree->root;
    sentinel = rbtree->sentinel;

    if (rbnode == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        next_node = (segment_index < rbnode->key) ? rbnode->left :
            rbnode->right;
        if (next_node == sentinel) {
            break;
        }

        rbnode = next_node;
    }

    node = (ngx_live_segment_info_node_t *) rbnode;
    if (segment_index < node->node.key) {

        /* Note: since we don't know the end index of each node, it is possible
            that we made a wrong right turn, in that case, we need to go back
            one node */
        prev = ngx_queue_prev(&node->queue);
        if (prev == ngx_queue_sentinel(&ctx->queue)) {
            return node;
        }

        node = ngx_queue_data(prev, ngx_live_segment_info_node_t, queue);
    }

    return node;
}

ngx_flag_t
ngx_live_segment_info_segment_exists(ngx_live_track_t *track, uint32_t start,
    uint32_t end)
{
    ngx_queue_t                        *q;
    ngx_live_segment_info_elt_t        *cur, *last;
    ngx_live_segment_info_node_t       *node;
    ngx_live_segment_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);

    if (ctx->initial_bitrate != 0) {
        /* gap tracking not enabled */
        return 1;
    }

    node = ngx_live_segment_info_lookup(ctx, start);
    if (node == NULL) {
        return 0;
    }

    cur = &node->elts[0];
    last = &node->elts[node->nelts];

    /* TODO: use binary search */

    /* skip irrelevant elts */
    while (cur + 1 < last && cur[1].index <= start) {
        cur++;
    }

    for ( ;; ) {

        for (; cur < last; cur++) {

            if (cur->index >= end) {
                return 0;
            }

            if (cur->bitrate != 0) {
                return 1;
            }
        }

        q = ngx_queue_next(&node->queue);
        if (q == ngx_queue_sentinel(&ctx->queue)) {
            return 0;
        }

        node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);

        cur = &node->elts[0];
        last = &node->elts[node->nelts];
    }
}

ngx_flag_t
ngx_live_segment_info_timeline_exists(ngx_live_track_t *track,
    ngx_live_timeline_t *timeline)
{
    uint32_t            start, end;
    ngx_queue_t        *q;
    ngx_live_period_t  *period;

    for (q = ngx_queue_head(&timeline->periods);
        q != ngx_queue_sentinel(&timeline->periods);
        q = ngx_queue_next(q))
    {
        period = ngx_queue_data(q, ngx_live_period_t, queue);

        start = period->node.key;
        end = start + period->segment_count;

        if (ngx_live_segment_info_segment_exists(track, start, end)) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_live_segment_info_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_segment_info_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_info_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_segment_info_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_segment_info_track_ctx_t    *ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);

    sipcf = ngx_live_get_module_preset_conf(track->channel,
        ngx_live_segment_info_module);

    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->queue);

    if (!sipcf->gaps) {
        ctx->initial_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE;
        ctx->last_segment_bitrate = NGX_LIVE_SEGMENT_NO_BITRATE * 100;
    }

    ctx->last_segment_index = NGX_LIVE_INVALID_SEGMENT_INDEX;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_queue_t                          *q;
    ngx_live_channel_t                   *channel;
    ngx_live_segment_info_node_t         *node;
    ngx_live_segment_info_track_ctx_t    *ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);

    q = ngx_queue_head(&ctx->queue);
    if (q == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }

    channel = track->channel;
    sipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_info_module);

    while (q != ngx_queue_sentinel(&ctx->queue)) {

        node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_block_pool_free(channel->block_pool,
            sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE], node);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_write_index(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                        *q;
    ngx_live_track_t                   *track = obj;
    ngx_live_persist_snap_t            *snap;
    ngx_live_segment_info_elt_t        *first, *last;
    ngx_live_segment_info_node_t       *node;
    ngx_live_segment_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);
    snap = ngx_persist_write_ctx(write_ctx);

    node = ngx_live_segment_info_lookup(ctx, snap->scope.min_index);
    if (node == NULL) {
        return NGX_OK;
    }

    q = &node->queue;

    first = &node->elts[0];
    last = &node->elts[node->nelts];

    /* trim the left side */
    while (first + 1 < last && first[1].index <= snap->scope.min_index) {
        first++;
    }

    if (ngx_persist_write_block_open(write_ctx,
        NGX_LIVE_SEGMENT_INFO_PERSIST_BLOCK) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    for ( ;; ) {

        /* trim the right side */
        for ( ;; ) {
            if (last[-1].index <= snap->scope.max_index) {
                break;
            }

            last--;

            if (first >= last) {
                goto done;
            }
        }

        if (ngx_persist_write_append(write_ctx, first,
            (u_char *) last - (u_char *) first) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segment_info_write_index: append failed");
            return NGX_ERROR;
        }

        q = ngx_queue_next(q);
        if (q == ngx_queue_sentinel(&ctx->queue)) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);

        first = &node->elts[0];
        last = &node->elts[node->nelts];
    }

done:

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_info_read_index(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                              count;
    uint32_t                              min_index;
    ngx_str_t                             data;
    ngx_live_track_t                     *track = obj;
    ngx_live_channel_t                   *channel;
    ngx_live_segment_info_elt_t          *dst, *dst_end;
    ngx_live_segment_info_elt_t          *src, *src_end;
    ngx_live_segment_info_node_t         *last;
    ngx_live_persist_index_scope_t       *scope;
    ngx_live_segment_info_track_ctx_t    *ctx;
    ngx_live_segment_info_preset_conf_t  *sipcf;

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &data);

    count = data.len / sizeof(*src);
    if (count <= 0) {
        return NGX_OK;
    }

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);
    sipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_segment_info_module);
    scope = ngx_mem_rstream_scope(rs);

    min_index = scope->min_index;

    src = (void *) data.data;
    src_end = src + count;

    if (!ngx_queue_empty(&ctx->queue)) {

        /* append to existing node */
        last = ngx_queue_data(ngx_queue_last(&ctx->queue),
            ngx_live_segment_info_node_t, queue);

        dst = last->elts + last->nelts;
        if (dst[-1].index >= min_index) {
            /* can happen due to duplicate block */
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_segment_info_read_index: "
                "last index %uD exceeds min index %uD",
                dst[-1].index, min_index);
            return NGX_BAD_DATA;
        }

        dst_end = last->elts + NGX_LIVE_SEGMENT_INFO_NODE_ELTS;

        for (; src < src_end && dst < dst_end; src++) {
            if (src->index < min_index) {
                if ((u_char *) src != data.data) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_info_read_index: "
                        "segment index %uD less than min segment index %uD",
                        src->index, min_index);
                    return NGX_BAD_DATA;
                }

                continue;
            }

            if (src->index > scope->max_index) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_info_read_index: "
                    "segment index %uD greater than max segment index %uD",
                    src->index, scope->max_index);
                return NGX_BAD_DATA;
            }

            min_index = src->index + 1;

            *dst++ = *src;
        }

        last->nelts = dst - last->elts;
    }

    /* create new nodes */
    while (src < src_end) {

        last = ngx_block_pool_alloc(channel->block_pool,
            sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE]);
        if (last == NULL) {
            return NGX_ERROR;
        }

        dst = last->elts;
        dst_end = last->elts + NGX_LIVE_SEGMENT_INFO_NODE_ELTS;

        for (; src < src_end && dst < dst_end; src++) {
            if (src->index < min_index) {
                if ((u_char *) src != data.data) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_info_read_index: "
                        "segment index %uD less than min segment index %uD",
                        src->index, min_index);
                    return NGX_BAD_DATA;
                }

                if (!ngx_queue_empty(&ctx->queue)) {
                    continue;
                }
            }

            if (src->index > scope->max_index) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_info_read_index: "
                    "segment index %uD greater than max segment index %uD",
                    src->index, scope->max_index);
                return NGX_BAD_DATA;
            }

            min_index = src->index + 1;

            *dst++ = *src;
        }

        last->nelts = dst - last->elts;

        if (last->nelts > 0) {
            last->node.key = last->elts[0].index;
            ngx_queue_insert_tail(&ctx->queue, &last->queue);
            ngx_rbtree_insert(&ctx->rbtree, &last->node);

        } else {
            ngx_block_pool_free(channel->block_pool,
                sipcf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE], last);
        }
    }

    last = ngx_queue_data(ngx_queue_last(&ctx->queue),
        ngx_live_segment_info_node_t, queue);

    ctx->last_segment_bitrate = last->elts[last->nelts - 1].bitrate * 100;

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_info_write_serve(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                        *q;
    ngx_live_track_t                   *track;
    ngx_live_segment_info_elt_t         elt;
    ngx_live_segment_info_elt_t        *first, *last;
    ngx_live_segment_info_node_t       *node;
    ngx_live_persist_serve_scope_t     *scope;
    ngx_live_segment_info_track_ctx_t  *ctx;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_SEGMENT_INFO)) {
        return NGX_OK;
    }

    track = obj;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segment_info_module);

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_SEGMENT_INFO) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    /* TODO: save only the minimum according to the manifest timeline in scope,
        and scope->segment_index (need to save one node before each period). */

    q = ngx_queue_head(&ctx->queue);
    if (q == ngx_queue_sentinel(&ctx->queue)) {
        elt.index = 0;
        elt.bitrate = ctx->initial_bitrate;

        if (ngx_persist_write(write_ctx, &elt, sizeof(elt)) != NGX_OK) {
            return NGX_ERROR;
        }

        goto done;
    }

    node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);
    if (node->elts[0].index > 0) {
        elt.index = 0;
        elt.bitrate = ctx->initial_bitrate;

        if (ngx_persist_write(write_ctx, &elt, sizeof(elt)) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    for ( ;; ) {
        first = &node->elts[0];
        last = &node->elts[node->nelts];

        if (ngx_persist_write_append(write_ctx, first,
            (u_char *) last - (u_char *) first) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segment_info_write_serve: append failed");
            return NGX_ERROR;
        }

        q = ngx_queue_next(q);
        if (q == ngx_queue_sentinel(&ctx->queue)) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_segment_info_node_t, queue);
    }

done:

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_segment_info_blocks[] = {
    /*
     * persist data:
     *   ngx_live_segment_info_elt_t  info[];
     */
    { NGX_LIVE_SEGMENT_INFO_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_INDEX_TRACK, 0,
      ngx_live_segment_info_write_index,
      ngx_live_segment_info_read_index },

    /*
     * persist data:
     *   ngx_ksmp_segment_info_elt_t  info[];
     */
    { NGX_KSMP_BLOCK_SEGMENT_INFO, NGX_LIVE_PERSIST_CTX_SERVE_TRACK, 0,
      ngx_live_segment_info_write_serve, NULL },

    ngx_null_persist_block
};

static ngx_int_t
ngx_live_segment_info_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_segment_info_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_live_channel_event_t  ngx_live_segment_info_channel_events[] = {
    { ngx_live_segment_info_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_segment_info_segment_created,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_CREATED },
    { ngx_live_segment_info_segment_free,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE },

      ngx_live_null_event
};

static ngx_live_track_event_t    ngx_live_segment_info_track_events[] = {
    { ngx_live_segment_info_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_segment_info_track_free, NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_segment_info_track_copy, NGX_LIVE_EVENT_TRACK_COPY },
    { ngx_live_segment_info_track_segment_created,
        NGX_LIVE_EVENT_TRACK_SEGMENT_CREATED },

      ngx_live_null_event
};

static ngx_int_t
ngx_live_segment_info_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_segment_info_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf,
        ngx_live_segment_info_track_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_live_segment_info_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_segment_info_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_segment_info_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->gaps = NGX_CONF_UNSET;
    conf->bitrate = NGX_CONF_UNSET;
    conf->bitrate_lower_bound = NGX_CONF_UNSET_UINT;
    conf->bitrate_upper_bound = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_segment_info_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_segment_info_preset_conf_t  *prev = parent;
    ngx_live_segment_info_preset_conf_t  *conf = child;

    ngx_conf_merge_value(conf->gaps,
                         prev->gaps, 1);

    ngx_conf_merge_value(conf->bitrate,
                         prev->bitrate, 0);

    ngx_conf_merge_uint_value(conf->bitrate_lower_bound,
                              prev->bitrate_lower_bound, 90);

    ngx_conf_merge_uint_value(conf->bitrate_upper_bound,
                              prev->bitrate_upper_bound, 110);

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_SEGMENT_INFO_NODE],
        sizeof(ngx_live_segment_info_node_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_segment_info_module,
        sizeof(ngx_live_segment_info_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
