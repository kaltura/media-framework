#ifndef _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_buf_chain.h>
#include "ngx_live.h"


#define NGX_LIVE_READ_FLAG_LOCK_DATA  (0x01)


struct ngx_live_segment_s {
    ngx_rbtree_node_t         node;
    ngx_queue_t               queue;

    ngx_live_track_t         *track;
    uint32_t                  track_id;
    uint32_t                  part_sequence;
    ngx_pool_t               *pool;

    ngx_live_media_info_t    *media_info;

    ngx_list_t                frames;       /* ngx_live_frame_t */
    ngx_uint_t                frame_count;
    int64_t                   start_dts;
    int64_t                   end_dts;

    ngx_buf_chain_t          *data_head;
    ngx_buf_chain_t          *data_tail;
    size_t                    data_size;

    ngx_array_t               parts;        /* ngx_live_segment_part_t */

    unsigned                  ready:1;
};


typedef struct {
    int64_t                   start_dts;
    uint32_t                  duration;     /* != sum(frame->duration) */

    ngx_live_frame_t         *frame;
    ngx_list_part_t          *frame_part;   /* ngx_live_frame_t */
    ngx_uint_t                frame_count;

    ngx_buf_chain_t          *data_head;
    size_t                    data_size;
} ngx_live_segment_part_t;


typedef struct {
    ngx_live_segment_t       *segment;
    ngx_live_segment_part_t   part;
    uint32_t                  part_sequence;
    size_t                    data_offset;
} ngx_live_segment_write_ctx_t;


typedef void (*ngx_live_segment_cleanup_pt)(void *data);


typedef ngx_int_t (*ngx_live_serve_segment_set_size_pt)(void *arg,
    size_t size);

typedef ngx_int_t (*ngx_live_serve_segment_write_pt)(void *arg,
    ngx_chain_t *cl);

/*
 * NGX_DECLINED - file not found
 * NGX_BAD_DATA - error parsing media file
 * NGX_ERROR - internal error
 */
typedef void (*ngx_live_serve_segment_close_pt)(void *arg, ngx_int_t rc);


typedef struct {
    uint32_t                             id;
    ngx_live_track_t                    *track;
} ngx_live_track_ref_t;


typedef struct {
    ngx_live_serve_segment_set_size_pt   set_size;
    ngx_live_serve_segment_write_pt      write;
    ngx_live_serve_segment_close_pt      close;
    ngx_live_segment_cleanup_pt          cleanup;
    void                                *arg;
} ngx_live_segment_writer_t;


typedef struct {
    ngx_pool_t                          *pool;
    ngx_live_channel_t                  *channel;
    ngx_live_track_ref_t                *tracks;
    uint32_t                             track_count;
    uint32_t                             flags;
    uint32_t                             segment_index;
    uint32_t                             part_index;
    int64_t                              time;
    ngx_live_segment_writer_t            writer;

    size_t                               size;
    ngx_chain_t                         *chain;
    ngx_str_t                            source;
} ngx_live_segment_serve_req_t;


/*
 * NGX_OK - operation completed synchronously (incl. no segments found)
 * NGX_DONE - started asynchronous read, the callback will be called once done
 * NGX_ERROR - error
 */
typedef ngx_int_t (*ngx_live_serve_segment_pt)(
    ngx_live_segment_serve_req_t *req);


ngx_live_segment_t *ngx_live_segment_cache_create(ngx_live_track_t *track,
    uint32_t segment_index);

void ngx_live_segment_cache_free(ngx_live_segment_t *segment);

void ngx_live_segment_cache_free_by_index(ngx_live_channel_t *channel,
    uint32_t segment_index);

void ngx_live_segment_cache_shift_dts(ngx_live_segment_t *segment,
    uint32_t shift);

void ngx_live_segment_cache_finalize(ngx_live_segment_t *segment,
    uint32_t *bitrate);


ngx_live_segment_part_t *ngx_live_segment_part_push(
    ngx_live_segment_t *segment);


ngx_live_segment_t *ngx_live_segment_cache_get(ngx_live_track_t *track,
    uint32_t segment_index);

uint32_t ngx_live_segment_cache_get_last_part(ngx_live_track_t *track,
    uint32_t segment_index);

ngx_flag_t ngx_live_segment_cache_is_pending_part(ngx_live_track_t *track,
    uint32_t segment_index, uint32_t part_index);

void ngx_live_segment_write_init_ctx(ngx_live_segment_write_ctx_t *ctx,
    ngx_live_segment_t *segment, uint32_t part_index, uint32_t flags,
    int64_t time);

ngx_int_t ngx_live_segment_cache_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_segment_write_ctx_t *ctx, ngx_live_persist_main_conf_t *pmcf,
    ngx_live_segment_cleanup_t *cln, uint32_t *header_size);

void ngx_live_segment_cache_free_input_bufs(ngx_live_track_t *track);


extern ngx_live_serve_segment_pt  ngx_live_serve_segment;

#endif /* _NGX_LIVE_SEGMENT_CACHE_H_INCLUDED_ */
