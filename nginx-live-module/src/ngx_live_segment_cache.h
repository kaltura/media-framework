#ifndef _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_buf_chain.h>
#include "ngx_live.h"
#include "media/media_format.h"


#define NGX_LIVE_READ_FLAG_LOCK_DATA  (0x01)


struct ngx_live_segment_s {
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
};


typedef void (*ngx_live_segment_cleanup_pt)(void *data);

typedef void (*ngx_live_read_segment_callback_pt)(void *arg, ngx_int_t rc);


typedef ngx_int_t (*ngx_live_copy_segment_set_size_pt)(void *arg, size_t size);

typedef ngx_int_t (*ngx_live_copy_segment_write_pt)(void *arg,
    ngx_chain_t *cl);

typedef void (*ngx_live_copy_segment_close_pt)(void *arg, ngx_int_t rc);


typedef struct {
    uint32_t                            id;
    ngx_live_track_t                   *track;
} ngx_live_track_ref_t;

typedef struct {
    ngx_pool_t                         *pool;
    ngx_live_channel_t                 *channel;
    ngx_live_track_ref_t               *tracks;
    uint32_t                            flags;
    media_segment_t                    *segment;
    ngx_live_read_segment_callback_pt   callback;
    ngx_live_segment_cleanup_pt         cleanup;
    void                               *arg;
} ngx_live_segment_read_req_t;


typedef struct {
    ngx_live_copy_segment_set_size_pt   set_size;
    ngx_live_copy_segment_write_pt      write;
    ngx_live_copy_segment_close_pt      close;
    ngx_live_segment_cleanup_pt         cleanup;
    void                               *arg;
} ngx_live_segment_writer_t;


typedef struct {
    ngx_pool_t                         *pool;
    ngx_live_channel_t                 *channel;
    ngx_live_track_ref_t               *tracks;
    uint32_t                            track_count;
    uint32_t                            segment_index;
    ngx_live_segment_writer_t           writer;

    size_t                              size;
    ngx_chain_t                        *chain;
    ngx_str_t                           source;
} ngx_live_segment_copy_req_t;


/*
 * NGX_OK - operation completed synchronously
 * NGX_DONE - started asynchronous read, the callback will be called once done
 * NGX_ABORT - no tracks were found
 * NGX_ERROR - error
 */

typedef ngx_int_t (*ngx_live_read_segment_pt)(
    ngx_live_segment_read_req_t *req);

typedef ngx_int_t (*ngx_live_copy_segment_pt)(
    ngx_live_segment_copy_req_t *req);

ngx_live_segment_t *ngx_live_segment_cache_create(ngx_live_track_t *track,
    uint32_t segment_index);

void ngx_live_segment_cache_free(ngx_live_segment_t *segment);

void ngx_live_segment_cache_free_by_index(ngx_live_channel_t *channel,
    uint32_t segment_index);

void ngx_live_segment_cache_shift_dts(ngx_live_segment_t *segment,
    uint32_t shift);

void ngx_live_segment_cache_finalize(ngx_live_segment_t *segment);

ngx_live_segment_t *ngx_live_segment_cache_get(ngx_live_track_t *track,
    uint32_t segment_index);

ngx_int_t ngx_live_segment_cache_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_segment_t *segment, ngx_live_segment_cleanup_t *cln,
    uint32_t *header_size);

void ngx_live_segment_cache_free_input_bufs(ngx_live_track_t *track);


extern ngx_live_read_segment_pt  ngx_live_read_segment;

extern ngx_live_copy_segment_pt  ngx_live_copy_segment;

#endif /* _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_ */
