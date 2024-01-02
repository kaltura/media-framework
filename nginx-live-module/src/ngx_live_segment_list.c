#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_segment_list.h"


/* sizeof ngx_live_segment_list_node_t = 1024 */
#define NGX_LIVE_SEGMENT_LIST_NODE_ELTS             (118)


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


size_t
ngx_live_segment_list_get_node_size(void)
{
    return sizeof(ngx_live_segment_list_node_t);
}


ngx_int_t
ngx_live_segment_list_init(ngx_live_channel_t *channel, ngx_uint_t bp_idx,
    ngx_live_segment_list_t *segment_list)
{
    ngx_rbtree_init(&segment_list->rbtree, &segment_list->sentinel,
        ngx_rbtree_insert_value);
    ngx_queue_init(&segment_list->queue);

    segment_list->block_pool = channel->block_pool;
    segment_list->bp_idx = bp_idx;

    segment_list->log = &channel->log;

    /* other fields are assumed to be initialized to 0 */

    return NGX_OK;
}


ngx_int_t
ngx_live_segment_list_add(ngx_live_segment_list_t *segment_list,
    uint32_t segment_index, int64_t time, uint32_t duration)
{
    uint32_t                       period_index;
    ngx_queue_t                   *q;
    ngx_live_segment_repeat_t     *last_elt;
    ngx_live_segment_list_node_t  *last;

    q = ngx_queue_last(&segment_list->queue);
    if (q != ngx_queue_sentinel(&segment_list->queue)) {

        last = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        if (time == segment_list->last_time &&
            segment_index == last->last_segment_index + 1)
        {
            last_elt = &last->elts[last->nelts - 1];
            if (last_elt->duration == duration) {
                last_elt->count++;
                goto add;
            }

            if (last->nelts < NGX_LIVE_SEGMENT_LIST_NODE_ELTS) {

                last_elt = &last->elts[last->nelts];
                last->nelts++;

                last_elt->duration = duration;
                last_elt->count = 1;

                segment_list->elt_count++;
                goto add;
            }

            period_index = last->period_index;

        } else {
            period_index = last->period_index + 1;
        }

    } else {
        period_index = 0;
    }

    last = ngx_block_pool_alloc(segment_list->block_pool,
        segment_list->bp_idx);
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
    last->elts[0].count = 1;

    ngx_queue_insert_tail(&segment_list->queue, &last->queue);
    ngx_rbtree_insert(&segment_list->rbtree, &last->node);

    segment_list->node_count++;
    segment_list->elt_count++;

add:

    last->last_segment_index = segment_index;
    segment_list->last_time = time + duration;

    segment_list->segment_count++;

    return NGX_OK;
}


ngx_int_t
ngx_live_segment_list_update_last(ngx_live_segment_list_t *segment_list,
    uint32_t duration)
{
    ngx_queue_t                   *q;
    ngx_live_segment_repeat_t     *last_elt;
    ngx_live_segment_list_node_t  *last, *prev;

    q = ngx_queue_last(&segment_list->queue);
    if (q == ngx_queue_sentinel(&segment_list->queue)) {
        ngx_log_error(NGX_LOG_ALERT, segment_list->log, 0,
            "ngx_live_segment_list_update_last: empty list");
        return NGX_ERROR;
    }

    last = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

    last_elt = &last->elts[last->nelts - 1];
    if (last_elt->count != 1) {
        ngx_log_error(NGX_LOG_ALERT, segment_list->log, 0,
            "ngx_live_segment_list_update_last: "
            "unexpected last count %uD", last_elt->count);
        return NGX_ERROR;
    }

    if (last_elt->duration != NGX_LIVE_PENDING_SEGMENT_DURATION) {
        ngx_log_error(NGX_LOG_ALERT, segment_list->log, 0,
            "ngx_live_segment_list_update_last: "
            "unexpected last duration %uD", last_elt->duration);
        return NGX_ERROR;
    }

    segment_list->last_time += duration;

    if (last->nelts >= 2) {
        if (last_elt[-1].duration != duration) {
            goto use_new;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, segment_list->log, 0,
            "ngx_live_segment_list_update_last: incrementing previous count");

        last_elt[-1].count++;
        last->nelts--;

        segment_list->elt_count--;

        return NGX_OK;
    }

    q = ngx_queue_prev(q);
    if (q == ngx_queue_sentinel(&segment_list->queue)) {
        goto use_new;
    }

    prev = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);
    if (prev->period_index != last->period_index
        || prev->elts[prev->nelts - 1].duration != duration)
    {
        goto use_new;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_LIVE, segment_list->log, 0,
        "ngx_live_segment_list_update_last: "
        "reverting new node and incrementing previous count");

    prev->elts[prev->nelts - 1].count++;
    prev->last_segment_index = last->last_segment_index;

    segment_list->node_count--;
    segment_list->elt_count -= last->nelts;

    ngx_queue_remove(&last->queue);
    ngx_rbtree_delete(&segment_list->rbtree, &last->node);

    ngx_block_pool_free(segment_list->block_pool, segment_list->bp_idx, last);

    return NGX_OK;

use_new:

    ngx_log_debug0(NGX_LOG_DEBUG_LIVE, segment_list->log, 0,
        "ngx_live_segment_list_update_last: using new element");

    last_elt->duration = duration;
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

        segment_list->node_count--;
        segment_list->elt_count -= node->nelts;
        segment_list->segment_count -= node->last_segment_index + 1
            - node->node.key;

        ngx_queue_remove(q);
        ngx_rbtree_delete(&segment_list->rbtree, &node->node);

        ngx_block_pool_free(segment_list->block_pool, segment_list->bp_idx,
            node);

        q = next;
    }
}


ngx_int_t
ngx_live_segment_list_get_segment_index(
    ngx_live_segment_list_t *segment_list, int64_t time,
    ngx_live_get_segment_mode_e mode, uint32_t *segment_index,
    int64_t *segment_time, ngx_live_segment_iter_t *iter)
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
        if (time < node->time) {
            next_node = rbnode->left;
            if (next_node != sentinel) {
                goto next;
            }

            /* Note: since we don't know the end index of each node, it is
                possible that we made a wrong right turn, in that case, we
                need to go back one node */

            prev = ngx_queue_prev(&node->queue);
            if (prev == ngx_queue_sentinel(&segment_list->queue)) {
                return NGX_ERROR;
            }

            node = ngx_queue_data(prev, ngx_live_segment_list_node_t, queue);

        } else {
            next_node = rbnode->right;
            if (next_node != sentinel) {
                goto next;
            }
        }

        break;

    next:

        rbnode = next_node;
    }

    *segment_index = node->node.key;
    *segment_time = node->time;

    for (elt = node->elts, last = elt + node->nelts; elt < last; elt++) {

        elt_duration = (int64_t) elt->count * elt->duration;

        if (time >= *segment_time + elt_duration) {
            *segment_index += elt->count;
            *segment_time += elt_duration;
            continue;
        }

        iter->node = node;
        iter->elt = elt;

        if (mode == ngx_live_get_segment_mode_closest) {
            time += elt->duration / 2;
        }

        iter->offset = (time - *segment_time) / elt->duration;

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

    duration = ngx_live_segment_iter_get_one(&end_iter);

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
    uint32_t segment_index, ngx_persist_write_ctx_t *write_ctx)
{
    uint32_t                    max_index;
    uint32_t                    next_index;
    ngx_live_persist_snap_t    *snap;
    ngx_live_segment_repeat_t   elt;
    ngx_live_segment_repeat_t  *cur, *last;

    snap = ngx_persist_write_ctx(write_ctx);

    max_index = snap->scope.max_index + 1;

    cur = iter->elt;
    last = iter->node->elts + iter->node->nelts;

    elt.duration = cur->duration;
    elt.count = cur->count - iter->offset;

    for ( ;; ) {

        next_index = segment_index + elt.count;

        if (next_index >= max_index) {
            elt.count = max_index - segment_index;
            return ngx_persist_write(write_ctx, &elt, sizeof(elt));
        }

        if (ngx_persist_write(write_ctx, &elt, sizeof(elt)) != NGX_OK) {
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
ngx_live_segment_list_write_periods(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                         period_index;
    ngx_flag_t                       in_block;
    ngx_queue_t                     *q;
    ngx_live_persist_snap_t         *snap;
    ngx_live_segment_iter_t          iter;
    ngx_live_segment_list_t         *segment_list = obj;
    ngx_live_segment_list_node_t    *node;
    ngx_live_segment_list_period_t   period;

    snap = ngx_persist_write_ctx(write_ctx);

    period.padding = 0;

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

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD) != NGX_OK ||
        ngx_persist_write(write_ctx, &period, sizeof(period))
            != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
            "ngx_live_segment_list_write_periods: "
            "start period failed (1)");
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    if (ngx_live_segment_list_write_node_part(&iter, period.segment_index,
        write_ctx) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
            "ngx_live_segment_list_write_periods: write part failed (1)");
        return NGX_ERROR;
    }

    in_block = 1;
    period_index = iter.node->period_index;
    q = ngx_queue_next(&iter.node->queue);

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
                ngx_persist_write_block_close(write_ctx);

            } else {
                in_block = 1;
            }

            period.time = node->time;
            period.segment_index = node->node.key;

            if (ngx_persist_write_block_open(write_ctx,
                    NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD) != NGX_OK ||
                ngx_persist_write(write_ctx, &period, sizeof(period))
                    != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                    "ngx_live_segment_list_write_periods: "
                    "start period failed (2)");
                return NGX_ERROR;
            }

            ngx_persist_write_block_set_header(write_ctx, 0);

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
                    "ngx_live_segment_list_write_periods: write part failed");
                return NGX_ERROR;
            }

            break;
        }

        if (ngx_persist_write_append(write_ctx, node->elts,
            node->nelts * sizeof(node->elts[0])) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, segment_list->log, 0,
                "ngx_live_segment_list_write_periods: append failed (2)");
            return NGX_ERROR;
        }
    }

    if (in_block) {
        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_segment_list_read_period(ngx_persist_block_hdr_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    u_char                          *p, *next;
    int64_t                          time;
    uint32_t                         period_index;
    uint32_t                         left;
    uint32_t                         count;
    uint32_t                         max_index;
    uint32_t                         segment_index;
    ngx_str_t                        data;
    ngx_live_segment_list_t         *segment_list = obj;
    ngx_live_segment_repeat_t        cur;
    ngx_live_segment_repeat_t       *dst;
    ngx_live_segment_list_node_t    *last;
    ngx_live_persist_index_scope_t  *scope;
    ngx_live_segment_list_period_t   period;

    if (ngx_mem_rstream_read(rs, &period, sizeof(period)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_segment_list_read_period: read failed");
        return NGX_BAD_DATA;
    }

    time = period.time;
    segment_index = period.segment_index;

    scope = ngx_mem_rstream_scope(rs);

    if (segment_index < scope->min_index || segment_index > scope->max_index) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_segment_list_read_period: "
            "segment index %uD outside scope %uD..%uD",
            segment_index, scope->min_index, scope->max_index);
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    left = data.len / sizeof(cur);
    if (left <= 0) {
        return NGX_OK;
    }

    segment_list->elt_count += left;

    p = data.data;

    max_index = scope->max_index + 1;

    if (!ngx_queue_empty(&segment_list->queue)) {

        last = ngx_queue_data(ngx_queue_last(&segment_list->queue),
            ngx_live_segment_list_node_t, queue);

        period_index = last->period_index;

        if (segment_list->is_first &&
            last->last_segment_index >= scope->min_index)
        {
            /* can happen due to duplicate block */
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_segment_list_read_period: "
                "last index %uD exceeds min index %uD",
                last->last_segment_index, scope->min_index);
            return NGX_BAD_DATA;
        }

        if (time < segment_list->last_time) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_segment_list_read_period: "
                "period time %L less than last period time %L",
                time, segment_list->last_time);
            return NGX_BAD_DATA;
        }

        if (time == segment_list->last_time &&
            segment_index == last->last_segment_index + 1)
        {
            ngx_memcpy(&cur, p, sizeof(cur));
            dst = &last->elts[last->nelts - 1];
            if (dst->duration == cur.duration) {
                if (cur.count <= 0) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "zero repeat count (1)");
                    return NGX_BAD_DATA;
                }

                if (cur.count > max_index - segment_index) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "invalid repeat count %uD (1), index: %uD",
                        cur.count, segment_index);
                    return NGX_BAD_DATA;
                }

                dst->count += cur.count;

                segment_index += cur.count;
                time += (int64_t) cur.duration * cur.count;

                p += sizeof(cur);
                left--;

                segment_list->elt_count--;
            }

            dst++;

            count = NGX_LIVE_SEGMENT_LIST_NODE_ELTS - last->nelts;
            if (count > left) {
                count = left;
            }

            last->nelts += count;
            next = p + sizeof(cur) * count;

            for (; p < next; p += sizeof(cur)) {
                ngx_memcpy(&cur, p, sizeof(cur));

                if (cur.count <= 0) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "zero repeat count (2)");
                    return NGX_BAD_DATA;
                }

                if (cur.count > max_index - segment_index) {
                    ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                        "ngx_live_segment_list_read_period: "
                        "invalid repeat count %uD (2), index: %uD",
                        cur.count, segment_index);
                    return NGX_BAD_DATA;
                }

                *dst++ = cur;

                segment_index += cur.count;
                time += (int64_t) cur.duration * cur.count;
            }

            left -= count;

            last->last_segment_index = segment_index - 1;

        } else {
            period_index++;
        }

    } else {
        period_index = 0;
    }

    while (left > 0) {

        last = ngx_block_pool_alloc(segment_list->block_pool,
            segment_list->bp_idx);
        if (last == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_segment_list_read_period: alloc failed");
            return NGX_ERROR;
        }

        last->node.key = segment_index;
        last->time = time;
        last->period_index = period_index;

        dst = last->elts;

        last->nelts = ngx_min(left, NGX_LIVE_SEGMENT_LIST_NODE_ELTS);
        next = p + sizeof(cur) * last->nelts;

        for (; p < next; p += sizeof(cur)) {
            ngx_memcpy(&cur, p, sizeof(cur));

            if (cur.count <= 0) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_list_read_period: "
                    "zero repeat count (3)");
                return NGX_BAD_DATA;
            }

            if (cur.count > max_index - segment_index) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_segment_list_read_period: "
                    "invalid repeat count %uD (3), index: %uD",
                    cur.count, segment_index);
                return NGX_BAD_DATA;
            }

            *dst++ = cur;

            segment_index += cur.count;
            time += (int64_t) cur.duration * cur.count;
        }

        left -= last->nelts;

        last->last_segment_index = segment_index - 1;

        ngx_queue_insert_tail(&segment_list->queue, &last->queue);
        ngx_rbtree_insert(&segment_list->rbtree, &last->node);

        segment_list->node_count++;
    }

    segment_list->last_time = time;
    segment_list->is_first = 0;

    segment_list->segment_count += segment_index - period.segment_index;

    return NGX_OK;
}


size_t
ngx_live_segment_list_json_get_size(ngx_live_segment_list_t *segment_list)
{
    size_t  result;

    result = sizeof("{}") - 1
        + sizeof("\"node_count\":") - 1 + NGX_INT32_LEN
        + sizeof(",\"elt_count\":") - 1 + NGX_INT32_LEN
        + sizeof(",\"segment_count\":") - 1 + NGX_INT32_LEN;

    if (!ngx_queue_empty(&segment_list->queue)) {
        result += sizeof(",\"min_index\":") - 1 + NGX_INT32_LEN
            + sizeof(",\"max_index\":") - 1 + NGX_INT32_LEN;
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

    p = ngx_copy_fix(p, "\"node_count\":");
    p = ngx_sprintf(p, "%uD", segment_list->node_count);

    p = ngx_copy_fix(p, ",\"elt_count\":");
    p = ngx_sprintf(p, "%uD", segment_list->elt_count);

    p = ngx_copy_fix(p, ",\"segment_count\":");
    p = ngx_sprintf(p, "%uD", segment_list->segment_count);

    if (!ngx_queue_empty(&segment_list->queue)) {

        q = ngx_queue_head(&segment_list->queue);
        first = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        q = ngx_queue_last(&segment_list->queue);
        last = ngx_queue_data(q, ngx_live_segment_list_node_t, queue);

        p = ngx_copy_fix(p, ",\"min_index\":");
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

        if (left < elt->count) {
            break;
        }

        left -= elt->count;
        time += (int64_t) elt->count * elt->duration;
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
    iter->offset = iter->elt->count - 1;
}


static void
ngx_live_segment_iter_move_next(ngx_live_segment_iter_t *iter)
{
    ngx_queue_t  *next;

    if (iter->offset < iter->elt->count) {
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


uint32_t
ngx_live_segment_iter_peek(ngx_live_segment_iter_t *iter)
{
    ngx_live_segment_iter_move_next(iter);

    return iter->elt->duration;
}


uint32_t
ngx_live_segment_iter_get_one(ngx_live_segment_iter_t *iter)
{
    ngx_live_segment_iter_move_next(iter);

    iter->offset++;

    return iter->elt->duration;
}


void
ngx_live_segment_iter_get_element(ngx_live_segment_iter_t *iter,
    ngx_live_segment_repeat_t *sd)
{
    ngx_live_segment_repeat_t  *elt;

    ngx_live_segment_iter_move_next(iter);

    elt = iter->elt;
    sd->duration = elt->duration;
    sd->count = elt->count - iter->offset;
    iter->offset = elt->count;
}
