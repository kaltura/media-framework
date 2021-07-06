#ifndef _NGX_LIVE_PERSIST_H_INCLUDED_
#define _NGX_LIVE_PERSIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_persist.h>
#include "ngx_live_store.h"


/* block ids */
#define NGX_LIVE_PERSIST_BLOCK_CHANNEL           NGX_KSMP_BLOCK_CHANNEL
#define NGX_LIVE_PERSIST_BLOCK_TIMELINE          NGX_KSMP_BLOCK_TIMELINE
#define NGX_LIVE_PERSIST_BLOCK_VARIANT           NGX_KSMP_BLOCK_VARIANT
#define NGX_LIVE_PERSIST_BLOCK_TRACK             NGX_KSMP_BLOCK_TRACK
#define NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO        NGX_KSMP_BLOCK_MEDIA_INFO
#define NGX_LIVE_PERSIST_BLOCK_SEGMENT           NGX_KSMP_BLOCK_SEGMENT
#define NGX_LIVE_PERSIST_BLOCK_FRAME_LIST        NGX_KSMP_BLOCK_FRAME_LIST
#define NGX_LIVE_PERSIST_BLOCK_FRAME_DATA        NGX_KSMP_BLOCK_FRAME_DATA

#define NGX_LIVE_PERSIST_INVALID_SNAP  ((void *) -1)


enum {
    NGX_LIVE_PERSIST_CTX_SETUP_MAIN = 0,
    NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL,
    NGX_LIVE_PERSIST_CTX_SETUP_TRACK,

    NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
    NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL,
    NGX_LIVE_PERSIST_CTX_INDEX_TRACK,
    NGX_LIVE_PERSIST_CTX_INDEX_TIMELINE,
    NGX_LIVE_PERSIST_CTX_INDEX_SEGMENT_LIST,
    NGX_LIVE_PERSIST_CTX_INDEX_MEDIA_INFO,

    NGX_LIVE_PERSIST_CTX_MEDIA_MAIN,
    NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_DATA,

    NGX_LIVE_PERSIST_CTX_SERVE_MAIN,
    NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL,
    NGX_LIVE_PERSIST_CTX_SERVE_TRACK,
    NGX_LIVE_PERSIST_CTX_SERVE_TIMELINE,
    NGX_LIVE_PERSIST_CTX_SERVE_MEDIA_INFO,
    NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER,
    NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA,
    NGX_LIVE_PERSIST_CTX_SERVE_FILLER_HEADER,
    NGX_LIVE_PERSIST_CTX_SERVE_FILLER_DATA,

    NGX_LIVE_PERSIST_CTX_FILLER_MAIN,
    NGX_LIVE_PERSIST_CTX_FILLER_CHANNEL,
    NGX_LIVE_PERSIST_CTX_FILLER_TRACK,
    NGX_LIVE_PERSIST_CTX_FILLER_SEGMENT,

    NGX_LIVE_PERSIST_CTX_COUNT
};


typedef enum {
    ngx_live_persist_snap_close_free,
    ngx_live_persist_snap_close_ack,
    ngx_live_persist_snap_close_write,
} ngx_live_persist_snap_close_action_e;


typedef ngx_ksmp_segment_header_t  ngx_live_persist_segment_header_t;


typedef struct {
    ngx_uint_t                        file;
} ngx_live_persist_scope_t;


typedef struct {
    ngx_live_persist_scope_t          base;
    uint32_t                          min_index;
    uint32_t                          max_index;
} ngx_live_persist_index_scope_t;


typedef struct {
    ngx_live_channel_t               *channel;
    uint32_t                          max_track_id;
    ngx_live_persist_index_scope_t    scope;
    void                            (*close)(void *snap,
                                ngx_live_persist_snap_close_action_e action);
} ngx_live_persist_snap_t;


typedef struct {
    ngx_live_persist_snap_t           base;     /* must be first */
    ngx_pool_t                       *pool;
    void                            **ctx;
    ngx_live_persist_snap_t          *frames_snap;
} ngx_live_persist_snap_index_t;


typedef struct {
    ngx_live_channel_t               *channel;
    ngx_live_timeline_t              *timeline;
    ngx_ksmp_channel_header_t         header;
    ngx_live_variant_t              **variants;
    ngx_array_t                      *track_refs;   /* ngx_live_track_ref_t */
    uint32_t                          segment_index;
    uint32_t                          flags;
    int64_t                           correction;
    ngx_uint_t                        media_info_count;
} ngx_live_persist_serve_scope_t;


char *ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store);


ngx_int_t ngx_live_persist_add_blocks(ngx_conf_t *cf,
    ngx_persist_block_t *blocks);


ngx_int_t ngx_live_persist_read_blocks(ngx_live_channel_t *channel,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj);

ngx_int_t ngx_live_persist_write_blocks(ngx_live_channel_t *channel,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj);


ngx_live_persist_snap_t *ngx_live_persist_snap_create(
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_H_INCLUDED_ */
