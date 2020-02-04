#ifndef _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_buf_chain.h"
#include "ngx_live_input_bufs.h"


#define NGX_LIVE_READ_FLAG_LOCK_DATA  (0x01)


typedef struct {
    ngx_rbtree_node_t       node;
    ngx_queue_t             queue;

    ngx_live_track_t       *track;
    ngx_pool_t             *pool;

    media_info_t           *media_info;
    kmp_media_info_t       *kmp_media_info;

    ngx_list_t              frames;        /* input_frame_t */
    ngx_uint_t              frame_count;
    int64_t                 start_dts;
    int64_t                 end_dts;

    ngx_buf_chain_t        *data_head;
    ngx_buf_chain_t        *data_tail;
    size_t                  data_size;
} ngx_live_segment_t;


typedef void (*ngx_live_read_segment_callback_pt)(void *arg, ngx_int_t rc);

typedef struct {
    uint32_t                            id;
    ngx_live_track_t                   *track;
} ngx_live_track_ref_t;

typedef struct {
    ngx_pool_t                         *pool;
    ngx_live_channel_t                 *channel;
    ngx_live_track_ref_t               *tracks;
    uint32_t                            track_count;
    uint32_t                            flags;
    media_segment_t                    *segment;
    ngx_live_read_segment_callback_pt   callback;
    void                               *arg;
} ngx_live_segment_read_req_t;

/*
 * NGX_OK - operation completed synchronously
 * NGX_DONE - started asynchronous read, the callback will be called once done
 * NGX_ABORT - no tracks were found
 * NGX_ERROR - error
*/

typedef ngx_int_t (*ngx_live_read_segment_pt)(
    ngx_live_segment_read_req_t *req);


ngx_live_segment_t *ngx_live_segment_cache_create(ngx_live_track_t *track,
    uint32_t segment_index);

void ngx_live_segment_cache_free(ngx_live_track_t *track,
    ngx_live_segment_t *segment);

ngx_live_segment_t *ngx_live_segment_cache_get(ngx_live_track_t *track,
    uint32_t segment_index);

void ngx_live_segment_cache_free_old(ngx_live_channel_t *channel,
    uint32_t min_segment_index);

void ngx_live_segment_cache_free_by_index(ngx_live_channel_t *channel,
    uint32_t segment_index);

ngx_live_input_bufs_lock_t *ngx_live_segment_cache_lock_data(
    ngx_live_segment_t *segment);

#if (NGX_LIVE_VALIDATIONS)
void ngx_live_segment_cache_validate(ngx_live_segment_t *segment);
#else
#define ngx_live_segment_cache_validate(segment)
#endif


extern ngx_live_read_segment_pt  ngx_live_read_segment;

#endif /* _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_ */
