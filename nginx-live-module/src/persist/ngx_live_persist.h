#ifndef _NGX_LIVE_PERSIST_H_INCLUDED_
#define _NGX_LIVE_PERSIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_write.h"
#include "ngx_live_persist_read.h"
#include "ngx_live_store.h"


#define NGX_LIVE_PERSIST_FLAG_SINGLE  (0x01)


#define ngx_live_null_persist_block   { 0, 0, 0, NULL, NULL }


enum {
    NGX_LIVE_PERSIST_CTX_SETUP_MAIN = 0,
    NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL,
    NGX_LIVE_PERSIST_CTX_SETUP_TRACK,

    NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
    NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL,
    NGX_LIVE_PERSIST_CTX_INDEX_TRACK,

    NGX_LIVE_PERSIST_CTX_MEDIA_MAIN,
    NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_DATA,

    NGX_LIVE_PERSIST_CTX_COUNT
};


typedef enum {
    ngx_live_persist_snap_close_free,
    ngx_live_persist_snap_close_ack,
    ngx_live_persist_snap_close_write,
} ngx_live_persist_snap_close_action_e;


typedef struct {
    uint32_t     id;
    uint32_t     ctx;
    uint32_t     flags;

    ngx_int_t  (*write)(ngx_live_persist_write_ctx_t *write_ctx, void *obj);

    /*
     * NGX_BAD_DATA - data error
     * NGX_ERROR    - alloc/other error
     */

    ngx_int_t  (*read)(ngx_live_persist_block_header_t *block,
        ngx_mem_rstream_t *rs, void *obj);
} ngx_live_persist_block_t;


typedef struct {
    uint32_t     min_index;
    uint32_t     max_index;
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


typedef void (*ngx_live_persist_read_handler_pt)(void *arg, ngx_int_t rc);


char *ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store);


ngx_int_t ngx_ngx_live_persist_add_block(ngx_conf_t *cf,
    ngx_live_persist_block_t *block);

ngx_int_t ngx_ngx_live_persist_add_blocks(ngx_conf_t *cf,
    ngx_live_persist_block_t *blocks);


ngx_int_t ngx_live_persist_read(ngx_live_channel_t *channel,
    ngx_pool_t *handler_pool, ngx_live_persist_read_handler_pt handler,
    void *data);


ngx_live_persist_snap_t *ngx_live_persist_snap_create(
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_H_INCLUDED_ */
