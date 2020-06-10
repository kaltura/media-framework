#ifndef _NGX_LIVE_PERSIST_H_INCLUDED_
#define _NGX_LIVE_PERSIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_write.h"
#include "ngx_live_persist_read.h"
#include "ngx_live_store.h"


#define NGX_LIVE_PERSIST_FLAG_SINGLE  (0x01)


enum {
    NGX_LIVE_PERSIST_CTX_MAIN = 0,
    NGX_LIVE_PERSIST_CTX_CHANNEL,
    NGX_LIVE_PERSIST_CTX_TRACK,

    NGX_LIVE_PERSIST_CTX_COUNT
};


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


typedef void (*ngx_live_persist_read_handler_pt)(void *arg, ngx_int_t rc);


ngx_live_store_t *ngx_live_persist_get_store(ngx_live_channel_t *channel);

char *ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store);


ngx_int_t ngx_ngx_live_persist_add_block(ngx_conf_t *cf,
    ngx_live_persist_block_t *block);

ngx_int_t ngx_ngx_live_persist_add_blocks(ngx_conf_t *cf,
    ngx_live_persist_block_t *blocks);


ngx_int_t ngx_live_persist_read(ngx_live_channel_t *channel,
    ngx_pool_t *handler_pool, ngx_live_persist_read_handler_pt handler,
    void *data);

#endif /* _NGX_LIVE_PERSIST_H_INCLUDED_ */
