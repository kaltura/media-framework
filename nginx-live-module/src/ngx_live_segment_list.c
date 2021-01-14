#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_segment_list.h"


/* sizeof ngx_live_segment_list_node_t = 1024 */
#define NGX_LIVE_SEGMENT_LIST_NODE_ELTS             (118)


#define NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD  (0x64706c73)    /* slpd */


enum {
    NGX_LIVE_BP_SEGMENT_LIST_NODE,

    NGX_LIVE_BP_COUNT
};


struct ngx_live_segment_list_node_s {
    ngx_rbtree_node_t           node;        /* key = segment_index */
    ngx_queue_t                 queue;
    int64_t                     time;
    uint32_t                    last_segment_index;
    uint32_t                    period_index;
    ngx_uint_t                  nelts;
    ngx_live_segment_repeat_t   elts[NGX_LIVE_SEGMENT_LIST_NODE_ELTS];
};


/* used for persist */
typedef struct {
    int64_t                     time;
    uint32_t                    segment_index;
    uint32_t                    padding;
} ngx_live_segment_list_period_t;


ngx_int_t
ngx_live_segment_list_init(ngx_live_channel_t *channel,
    ngx_live_segment_list_t *segment_list)
{
    size_t  block_sizes[NGX_LIVE_BP_COUNT];

    ngx_rbtree_init(&segment_list->rbtree, &segment_list->sentinel,
        ngx_rbtree_insert_value);
    ngx_queue_init(&segment_list->queue);

    block_sizes[NGX_LIVE_BP_SEGMENT_LIST_NODE] =
        sizeof(ngx_live_segment_list_node_t);

    segment_list->block_pool = ngx_live_channel_create_block_pool(channel,
        block_sizes, NGX_LIVE_BP_COUNT);
    if (segment_list->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segment_list_init: create pool failed");
        return NGX_ERROR;
    }

    segment_list->log = &channel->log;

    /* other fields are assumed to be initialized to 0 */

    return NGX_OK;
}

ngx_int_t
ngx_live_segment_list_add(ngx_live_segment_list_t *segment_list,
    uint32_t segment_index, int64_t time, uint32_t duration)
{
    uint32_t                       period_index;
    ngx_live_segment_repeat_t     *last_elt;
    ngx_live_segment_list_node_t  *last;

    if (!ngx_queue_empty(&segment_list->queue)) {

        last = ngx_queue_data(ngx_queue_last(&segment_list->queue),
            ngx_live_segment_list_node_t, queue);

        period_index = last->period_index;

        if (time == segment_list->last_time &&
            segment_index == last->last_segment_index + 1)
        {
            last_elt = &last->elts[last->nelts - 1];
            if (last_elt->duration == duration) {
                last_elt->repeat_count++;
                goto add;
            }

            if (last->nelts < NGX_LIVE_SEGMENT_LIST_NODE_ELTS) {

                last_elt = &last->elts[last->nelts];
                last->nelts++;

                last_elt->duration = duration;
                last_elt->repeat_count = 1;
                goto add;
            }

        } else {
            period_index++;
        }

    } else {
        period_index = 0;
    }

    last = ngx_block_pool_alloc(segment_list->block_pool,
        NGX_LIVE_BP_SEGMENT_LIST_NODE);
    if (last == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
            "ngx_live_segment_list_add: alloc failed");
        return NGX_ERROR;
    }

    last->node.key = segment_index;
    last->time = time;
    last->period_index = period_index;
    last->nelts = 1;
    last->elts[0].duration = duration;
    last->elts[0].repeat_count = 1;

    ngx_queue_insert_tail(&segment_list->queue, &last->queue);
    ngx_rbtree_insert(&segment_list->rbtree, &last->node);

add:

    last->last_segment_index = segment_index;
    segment_list->last_time = time + duration;

    return NGX_OK;
}

void
ngx_live_segment_list_free_nodes(ngx_live_segment_list_t *segment_list,
    uint32_t min_segment_index)
{
    ngx_queue_t                   *q, *next;
    ngx_live_segment_list_node_t  *node;
    ngx_live_segment_list_node_t  *next_node;

    q = ngx_queue_head(&segment_list->queue);
    for ( ;; ) {

        next = ngx_queue_next(q);
        if (next == ngx_queue_sentinel(&segment_list->queue)) {
            break;
        }

        next_node = ngx_queue_data(next, ngx_live_segment_list_node_t, queue);

        /* Note: when next_node->node.key == min_segment_index the
            the current node doesn't have any used segments, but there may
            still be iterators pointing to it, so it should not be freed */

        if (min_segment_index <= next_node->node.key) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);
        ngx_queue_remove(q);
        ngx_rbtree_delete(&segment_list->rbtree, &node->node);

        ngx_block_pool_free(segment_list->block_pool,
            NGX_LIVE_BP_SEGMENT_LIST_NODE, node);

        q = next;
    }
}

ngx_int_t
ngx_live_segment_list_get_segment_time(ngx_live_segment_list_t *segment_list,
    uint32_t segment_index, int64_t *result)
{
    ngx_live_segment_iter_t  ignore;

    return ngx_live_segment_iter_init(segment_list, &ignore, segment_index, 1,
        result);
}


ngx_int_t
ngx_live_segment_list_get_closest_segment(
    ngx_live_segment_list_t *segment_list, int64_t time,
    uint32_t *segment_index, int64_t *segment_time,
    ngx_live_segment_iter_t *iter)
{
    int64_t                        elt_duration;
    ngx_queue_t                   *prev;
    ngx_rbtree_t                  *rbtree;
    ngx_rbtree_node_t             *rbnode;
    ngx_rbtree_node_t             *sentinel;
    ngx_rbtree_node_t             *next_node;
    ngx_live_segment_repeat_t     *elt;
    ngx_live_segment_repeat_t     *last;
    ngx_live_segment_list_node_t  *node;

    rbtree = &segment_list->rbtree;
    rbnode = rbtree->root;
    sentinel = rbtree->sentinel;

    if (rbnode == sentinel) {
        return NGX_ERROR;
    }

    for ( ;; ) {

        node = (ngx_live_segment_list_node_t *) rbnode;
        next_node = (time < node->time) ? rbnode->left : rbnode->right;
        if (next_node == sentinel) {
            break;
        }

        rbnode = next_node;
    }

    if (time < node->time)
    {
        /* Note: since we don't know the end index of each node, it is possible
            that we made a wrong right turn, in that case, we need to go back
            one node */
        prev = ngx_queue_prev(&node->queue);
        if (prev == ngx_queue_sentinel(&segment_list->queue)) {
            return NGX_ERROR;
        }

        node = ngx_queue_data(prev, ngx_live_segment_list_node_t, queue);
    }

    *segment_index = node->node.key;
    *segment_time = node->time;

    for (elt = node->elts, last = elt + node->nelts; elt < last; elt++) {

        elt_duration = (int64_t) elt->repeat_count * elt->duration;

        if (time >= *segment_time + elt_duration) {
            *segment_index += elt->repeat_count;
            *segment_time += elt_duration;
            continue;
        }

        iter->node = node;
        iter->elt = elt;
        iter->offset = (time - *segment_time + elt->duration / 2) /
            elt->duration;

        *segment_index += iter->offset;
        *segment_time += (int64_t) iter->offset * elt->duration;

        return NGX_OK;
    }

    return NGX_ERROR;
}

ngx_int_t
ngx_live_segment_list_get_period_end_time(
    ngx_live_segment_list_t *segment_list, ngx_live_segment_iter_t *start_iter,
    uint32_t last_index, int64_t *end_time)
{
    int64_t                  time;
    uint32_t                 duration;
    ngx_live_segment_iter_t  end_iter;

    if (ngx_live_segment_iter_init(segment_list, &end_iter, last_index, 1,
        &time) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, segment_list->log, 0,
            "ngx_live_segment_list_get_period_end_time: "
            "last segment %uD not found", last_index);
        return NGX_ERROR;
    }

    ngx_live_segment_iter_get_one(&end_iter, &duration);

    if (start_iter->node->period_index != end_iter.node->period_index) {
        ngx_log_error(NGX_LOG_ERR, segment_list->log, 0,
            "ngx_live_segment_list_get_period_end_time: "
            "first and last indexes are in different periods");
        return NGX_ERROR;
    }

    *end_time = time + duration;

    return NGX_OK;
}


static ngx_int_t
ngx_live_segment_list_write_node_part(ngx_live_segment_iter_t *iter,
    uint32_t segment_index, ngx_live_persist_write_ctx_t *write_ctx)
{
    uint32_t                    max_index;
    uint32_t                    next_index;
    ngx_live_persist_snap_t    *snap;
    ngx_live_segment_repeat_t   elt;
    ngx_live_segment_repeat_t  *cur, *last;

    snap = ngx_live_persist_write_ctx(write_ctx);

    max_index = snap->scope.max_index + 1;

    cur = iter->elt;
    last = iter->node->elts + iter->node->nelts;

    elt.duration = cur->duration;
    elt.repeat_count = cur->repeat_count - iter->offset;

    for ( ;; ) {

        next_index = segment_index + elt.repeat_count;

        if (next_index >= max_index) {
            elt.repeat_count = max_index - segment_index;
            return ngx_live_persist_write(write_ctx, &elt, sizeof(elt));
        }

        if (ngx_live_persist_write(write_ctx, &elt, sizeof(elt)) != NGX_OK) {
            return NGX_ERROR;
        }

        cur++;
        if (cur >= last) {
            break;
        }

        segment_index = next_index;
        elt = *cur;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_segment_list_write_index(ngx_live_segment_list_t *segment_list,
    ngx_live_persist_write_ctx_t *write_ctx)
{
    uint32_t                         period_index;
    ngx_flag_t                       in_block;
    ngx_queue_t                     *q;
    ngx_live_persist_snap_t         *snap;
    ngx_live_segment_iter_t          iter;
    ngx_live_segment_list_node_t    *node;
    ngx_live_segment_list_period_t   period;

    snap = ngx_live_persist_write_ctx(write_ctx);

    period.padding = 0;

    if (snap->scope.min_index > 0) {

        period.segment_index = snap->scope.min_index;

        if (ngx_live_segment_iter_init(segment_list, &iter,
            period.segment_index, 0, &period.time) != NGX_OK)
        {
            /* no segments after min_index */
            return NGX_OK;
        }

        if (period.segment_index < iter.node->node.key) {

            period.segment_index = iter.node->node.key;
            if (period.segment_index > snap->scope.max_index) {
                return NGX_OK;
            }
        }

        if (ngx_live_persist_write_block_open(write_ctx,
                NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD) != NGX_OK ||
            ngx_live_persist_write(write_ctx, &period, sizeof(period))
                != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                "ngx_live_segment_list_write_index: "
                "start period failed (1)");
            return NGX_ERROR;
        }

        ngx_live_persist_write_block_set_header(write_ctx, 0);

        if (ngx_live_segment_list_write_node_part(&iter, period.segment_index,
            write_ctx) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                "ngx_live_segment_list_write_index: write part failed (1)");
            return NGX_ERROR;
        }

        in_block = 1;
        period_index = iter.node->period_index;
        q = ngx_queue_next(&iter.node->queue);

    } else {
        in_block = 0;
        period_index = 0;
        q = ngx_queue_head(&segment_list->queue);
    }

    for (;
        q != ngx_queue_sentinel(&segment_list->queue);
        q = ngx_queue_next(q))
    {
        node = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        if (node->node.key > snap->scope.max_index) {
            break;
        }

        if (!in_block || node->period_index != period_index) {

            if (in_block) {
                ngx_live_persist_write_block_close(write_ctx);

            } else {
                in_block = 1;
            }

            period.time = node->time;
            period.segment_index = node->node.key;

            if (ngx_live_persist_write_block_open(write_ctx,
                    NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD) != NGX_OK ||
                ngx_live_persist_write(write_ctx, &period, sizeof(period))
                    != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                    "ngx_live_segment_list_write_index: "
                    "start period failed (2)");
                return NGX_ERROR;
            }

            ngx_live_persist_write_block_set_header(write_ctx, 0);

            period_index = node->period_index;
        }

        if (node->last_segment_index > snap->scope.max_index) {

            iter.node = node;
            iter.elt = node->elts;
            iter.offset = 0;

            if (ngx_live_segment_list_write_node_part(&iter, node->node.key,
                write_ctx) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                    "ngx_live_segment_list_write_index: write part failed");
                return NGX_ERROR;
            }

            break;
        }

        if (ngx_live_persist_write_append(write_ctx, node->elts,
            node->nelts * sizeof(node->elts[0])) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                "ngx_live_segment_list_write_index: append failed (2)");
            return NGX_ERROR;
        }
    }

    if (in_block) {
        ngx_live_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segment_list_read_period(ngx_live_segment_list_t *segment_list,
    ngx_mem_rstream_t *rs, ngx_live_persist_block_header_t *block,
    ngx_flag_t is_first)
{
    uint32_t                         period_index;
    uint32_t                         left;
    uint32_t                         count;
    uint32_t                         max_index;
    ngx_str_t                        data;
    ngx_live_segment_repeat_t       *cur;
    ngx_live_segment_repeat_t       *next;
    ngx_live_segment_repeat_t       *dst;
    ngx_live_segment_list_node_t    *last = NULL;
    ngx_live_persist_index_scope_t  *scope;
    ngx_live_segment_list_period_t   period;

    if (ngx_mem_rstream_read(rs, &period, sizeof(period)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_segment_list_read_period: read failed");
        return NGX_BAD_DATA;
    }

    scope = ngx_mem_rstream_scope(rs);

    if (period.segment_index < scope->min_index ||
        period.segment_index > scope->max_index)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_segment_list_read_period: "
            "segment index %uD outside scope %uD..%uD",
            period.segment_index, scope->min_index, scope->max_index);
        return NGX_BAD_DATA;
    }

    if (ngx_live_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    left = data.len / sizeof(*cur);
    if (left <= 0) {
        return NGX_OK;
    }

    cur = (void *) data.data;

    max_index = scope->max_index + 1;

    if (!ngx_queue_empty(&segment_list->queue)) {

        last = ngx_queue_data(ngx_queue_last(&segment_list->queue),
            ngx_live_segment_list_node_t, queue);

        period_index = last->period_index;

        if (is_first && last->last_segment_index >= scope->min_index) {
            /* can happen due to duplicate block */
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_segment_list_read_period: "
                "last index %uD exceeds min index %uD",
                last->last_segment_index, scope->min_index);
            return NGX_BAD_DATA;
        }

        if (period.time < segment_list->last_time) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_segment_list_read_period: "
                "period time %L less than last period time %L",
                period.time, segment_list->last_time);
            return NGX_BAD_DATA;
        }

        if (period.time == segment_list->last_time &&
            period.segment_index == last->last_segment_index + 1)
        {
            dst = &last->elts[last->nelts - 1];
            if (dst->duration == cur->duration) {
                if (cur->repeat_count <= 0) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "zero repeat count (1)");
                    return NGX_BAD_DATA;
                }

                if (cur->repeat_count > max_index - period.segment_index) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "invalid repeat count %uD (1), index: %uD",
                        cur->repeat_count, period.segment_index);
                    return NGX_BAD_DATA;
                }

                dst->repeat_count += cur->repeat_count;

                period.segment_index += cur->repeat_count;
                period.time += (int64_t) cur->duration * cur->repeat_count;

                cur++;
                left--;
            }

            dst++;

            count = NGX_LIVE_SEGMENT_LIST_NODE_ELTS - last->nelts;
            if (count > left) {
                count = left;
            }

            last->nelts += count;
            next = cur + count;

            for (; cur < next; cur++) {
                if (cur->repeat_count <= 0) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "zero repeat count (2)");
                    return NGX_BAD_DATA;
                }

                if (cur->repeat_count > max_index - period.segment_index) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "invalid repeat count %uD (2), index: %uD",
                        cur->repeat_count, period.segment_index);
                    return NGX_BAD_DATA;
                }

                *dst++ = *cur;

                period.segment_index += cur->repeat_count;
                period.time += (int64_t) cur->duration * cur->repeat_count;
            }

            left -= count;

            last->last_segment_index = period.segment_index - 1;

        } else {
            period_index++;
        }

    } else {
        period_index = 0;
    }

    while (left > 0) {

        last = ngx_block_pool_alloc(segment_list->block_pool,
            NGX_LIVE_BP_SEGMENT_LIST_NODE);
        if (last == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_segment_list_read_period: alloc failed (1)");
            return NGX_ERROR;
        }

        last->node.key = period.segment_index;
        last->time = period.time;
        last->period_index = period_index;

        dst = last->elts;

        last->nelts = ngx_min(left, NGX_LIVE_SEGMENT_LIST_NODE_ELTS);
        next = cur + last->nelts;

        for (; cur < next; cur++) {
            if (cur->repeat_count <= 0) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_list_read_period: "
                    "zero repeat count (3)");
                return NGX_BAD_DATA;
            }

            if (cur->repeat_count > max_index - period.segment_index) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_list_read_period: "
                    "invalid repeat count %uD (3), index: %uD",
                    cur->repeat_count, period.segment_index);
                return NGX_BAD_DATA;
            }

            *dst++ = *cur;

            period.segment_index += cur->repeat_count;
            period.time += (int64_t) cur->duration * cur->repeat_count;
        }

        left -= last->nelts;

        last->last_segment_index = period.segment_index - 1;

        ngx_queue_insert_tail(&segment_list->queue, &last->queue);
        ngx_rbtree_insert(&segment_list->rbtree, &last->node);
    }

    segment_list->last_time = period.time;

    return NGX_OK;
}

ngx_int_t
ngx_live_segment_list_read_index(ngx_live_segment_list_t *segment_list,
    ngx_mem_rstream_t *rs, ngx_live_persist_block_header_t *block)
{
    ngx_int_t          rc;
    ngx_flag_t         is_first;
    ngx_mem_rstream_t  block_rs;

    if (ngx_live_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    is_first = 1;

    while (!ngx_mem_rstream_eof(rs)) {

        block = ngx_live_persist_read_block(rs, &block_rs);
        if (block == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_segment_list_read_index: read block failed");
            return NGX_BAD_DATA;
        }

        if (block->id != NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD) {
            continue;
        }

        rc = ngx_live_segment_list_read_period(segment_list, &block_rs, block,
            is_first);
        if (rc != NGX_OK) {
            return rc;
        }

        is_first = 0;
    }

    return NGX_OK;
}


size_t
ngx_live_segment_list_json_get_size(ngx_live_segment_list_t *segment_list)
{
    size_t  result;

    result = sizeof("{}") - 1;

    if (!ngx_queue_empty(&segment_list->queue)) {
        result += sizeof("\"min_index\":") - 1 + NGX_INT32_LEN +
            sizeof(",\"max_index\":") - 1 + NGX_INT32_LEN;
    }

    return result;
}

u_char *
ngx_live_segment_list_json_write(u_char *p,
    ngx_live_segment_list_t *segment_list)
{
    ngx_queue_t                   *q;
    ngx_live_segment_list_node_t  *last;
    ngx_live_segment_list_node_t  *first;

    *p++ = '{';

    if (!ngx_queue_empty(&segment_list->queue)) {

        q = ngx_queue_head(&segment_list->queue);
        first = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        q = ngx_queue_last(&segment_list->queue);
        last = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        p = ngx_copy_fix(p, "\"min_index\":");
        p = ngx_sprintf(p, "%uD", (uint32_t) first->node.key);

        p = ngx_copy_fix(p, ",\"max_index\":");
        p = ngx_sprintf(p, "%uD", last->last_segment_index);
    }

    *p++ = '}';

    return p;
}


ngx_int_t
ngx_live_segment_iter_init(ngx_live_segment_list_t *segment_list,
    ngx_live_segment_iter_t *iter, uint32_t segment_index, ngx_flag_t strict,
    int64_t *segment_time)
{
    int64_t                        time;
    uint32_t                       left;
    ngx_queue_t                   *q;
    ngx_rbtree_t                  *rbtree;
    ngx_rbtree_node_t             *rbnode;
    ngx_rbtree_node_t             *sentinel;
    ngx_rbtree_node_t             *next_node;
    ngx_live_segment_repeat_t     *elt;
    ngx_live_segment_repeat_t     *last;
    ngx_live_segment_list_node_t  *node;

    rbtree = &segment_list->rbtree;
    rbnode = rbtree->root;
    sentinel = rbtree->sentinel;

    if (rbnode == sentinel) {
        return NGX_ERROR;
    }

    for ( ;; ) {

        node = (ngx_live_segment_list_node_t *) rbnode;

        if (segment_index < rbnode->key) {

            next_node = rbnode->left;
            if (next_node != sentinel) {
                rbnode = next_node;
                continue;
            }

        } else if (segment_index > node->last_segment_index) {

            next_node = rbnode->right;
            if (next_node != sentinel) {
                rbnode = next_node;
                continue;
            }

            q = ngx_queue_next(&node->queue);
            if (q == ngx_queue_sentinel(&segment_list->queue)) {
                return NGX_ERROR;
            }

            node = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        } else {
            break;
        }

        /* node is the first node following segment_index */

        if (strict) {
            return NGX_ERROR;
        }

        iter->node = node;
        iter->elt = node->elts;
        iter->offset = 0;

        *segment_time = node->time;
        return NGX_OK;
    }

    /* segment_index is within node */

    left = segment_index - node->node.key;
    time = node->time;

    for (elt = node->elts, last = elt + node->nelts; ; elt++) {

        if (elt >= last) {
            ngx_log_error(NGX_LOG_ALERT, segment_list->log, 0,
                "ngx_live_segment_iter_init: segment %uD not in node %ui..%uD",
                segment_index, node->node.key, node->last_segment_index);
            return NGX_ERROR;
        }

        if (left < elt->repeat_count) {
            break;
        }

        left -= elt->repeat_count;
        time += (int64_t) elt->repeat_count * elt->duration;
    }

    iter->node = node;
    iter->elt = elt;
    iter->offset = left;

    *segment_time = time + (int64_t) left * elt->duration;
    return NGX_OK;
}

void
ngx_live_segment_iter_last(ngx_live_segment_list_t *segment_list,
    ngx_live_segment_iter_t *iter)
{
    ngx_queue_t                   *q;
    ngx_live_segment_list_node_t  *last;

    /* Note: must not be called when empty */
    q = ngx_queue_last(&segment_list->queue);
    last = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);
    iter->node = last;
    iter->elt = &last->elts[last->nelts - 1];
    iter->offset = iter->elt->repeat_count - 1;
}

static void
ngx_live_segment_iter_move_next(ngx_live_segment_iter_t *iter)
{
    ngx_queue_t  *next;

    if (iter->offset < iter->elt->repeat_count) {
        return;
    }

    iter->elt++;
    iter->offset = 0;

    if (iter->elt < iter->node->elts + iter->node->nelts) {
        return;
    }

    next = ngx_queue_next(&iter->node->queue);
    iter->node = ngx_queue_data(next, ngx_live_segment_list_node_t, queue);
    iter->elt = iter->node->elts;
}

void
ngx_live_segment_iter_get_one(ngx_live_segment_iter_t *iter,
    uint32_t *duration)
{
    ngx_live_segment_iter_move_next(iter);

    *duration = iter->elt->duration;
    iter->offset++;
}

void
ngx_live_segment_iter_get_element(ngx_live_segment_iter_t *iter,
    ngx_live_segment_repeat_t *segment_duration)
{
    ngx_live_segment_repeat_t  *elt;

    ngx_live_segment_iter_move_next(iter);

    elt = iter->elt;
    segment_duration->duration = elt->duration;
    segment_duration->repeat_count = elt->repeat_count - iter->offset;
    iter->offset = elt->repeat_count;
}
