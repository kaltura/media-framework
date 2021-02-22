#ifndef _NGX_LIVE_SEGMENT_LIST_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


#define NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK         (0x74736c73)    /* slst */

#define NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD  (0x64706c73)    /* slpd */


typedef struct ngx_live_segment_list_node_s  ngx_live_segment_list_node_t;


typedef struct {
    uint32_t                       repeat_count;
    uint32_t                       duration;
} ngx_live_segment_repeat_t;

typedef struct {
    ngx_rbtree_t                   rbtree;
    ngx_rbtree_node_t              sentinel;
    ngx_queue_t                    queue;

    ngx_block_pool_t              *block_pool;
    ngx_uint_t                     bp_idx;
    ngx_log_t                     *log;

    int64_t                        last_time;
    unsigned                       is_first:1;      /* temp during read */
} ngx_live_segment_list_t;

typedef struct {
    ngx_live_segment_list_node_t  *node;
    ngx_live_segment_repeat_t     *elt;
    uint32_t                       offset;
} ngx_live_segment_iter_t;


size_t ngx_live_segment_list_get_node_size();

ngx_int_t ngx_live_segment_list_init(ngx_live_channel_t *channel,
    ngx_uint_t bp_idx, ngx_live_segment_list_t *segment_list);

ngx_int_t ngx_live_segment_list_add(ngx_live_segment_list_t *segment_list,
    uint32_t segment_index, int64_t time, uint32_t duration);

ngx_int_t ngx_live_segment_list_get_segment_time(
    ngx_live_segment_list_t *segment_list, uint32_t segment_index,
    int64_t *result);

ngx_int_t ngx_live_segment_list_get_closest_segment(
    ngx_live_segment_list_t *segment_list, int64_t time,
    uint32_t *segment_index, int64_t *segment_time,
    ngx_live_segment_iter_t *iter);

ngx_int_t ngx_live_segment_list_get_period_end_time(
    ngx_live_segment_list_t *segment_list, ngx_live_segment_iter_t *start_iter,
    uint32_t last_index, int64_t *end_time);

void ngx_live_segment_list_free_nodes(ngx_live_segment_list_t *segment_list,
    uint32_t min_segment_index);


ngx_int_t ngx_live_segment_list_write_periods(
    ngx_live_persist_write_ctx_t *write_ctx, void *obj);

ngx_int_t ngx_live_segment_list_read_period(
    ngx_live_persist_block_header_t *block, ngx_mem_rstream_t *rs, void *obj);


size_t ngx_live_segment_list_json_get_size(
    ngx_live_segment_list_t *segment_list);

u_char *ngx_live_segment_list_json_write(u_char *p,
    ngx_live_segment_list_t *segment_list);


ngx_int_t ngx_live_segment_iter_init(ngx_live_segment_list_t *segment_list,
    ngx_live_segment_iter_t *iter, uint32_t segment_index, ngx_flag_t strict,
    int64_t *segment_time);

void ngx_live_segment_iter_last(ngx_live_segment_list_t *segment_list,
    ngx_live_segment_iter_t *iter);

void ngx_live_segment_iter_get_one(ngx_live_segment_iter_t *iter,
    uint32_t *duration);

void ngx_live_segment_iter_get_element(ngx_live_segment_iter_t *iter,
    ngx_live_segment_repeat_t *segment_duration);

#endif /* _NGX_LIVE_SEGMENT_LIST_H_INCLUDED_ */
