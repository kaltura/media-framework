#ifndef _NGX_PERSIST_H_INCLUDED_
#define _NGX_PERSIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_persist_read.h"
#include "ngx_persist_write.h"


#define NGX_PERSIST_FLAG_SINGLE  (0x01)

#define ngx_null_persist_block   { 0, 0, 0, NULL, NULL }


typedef struct ngx_persist_conf_s  ngx_persist_conf_t;


typedef struct {
    uint32_t     id;
    uint32_t     ctx;
    uint32_t     flags;

    ngx_int_t  (*write)(ngx_persist_write_ctx_t *write_ctx, void *obj);

    /*
     * NGX_BAD_DATA - data error
     * NGX_ERROR    - alloc/other error
     */

    ngx_int_t  (*read)(ngx_persist_block_hdr_t *header,
        ngx_mem_rstream_t *rs, void *obj);
} ngx_persist_block_t;


ngx_persist_conf_t *ngx_persist_conf_create(ngx_conf_t *cf,
    ngx_uint_t ctx_count);

ngx_int_t ngx_persist_conf_add_blocks(ngx_conf_t *cf, ngx_persist_conf_t *conf,
    ngx_persist_block_t *blocks);

ngx_int_t ngx_persist_conf_init(ngx_conf_t *cf, ngx_persist_conf_t *conf);


ngx_int_t ngx_persist_conf_write_blocks(ngx_persist_conf_t *conf,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj);

ngx_int_t ngx_persist_conf_read_blocks(ngx_persist_conf_t *conf,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj);

#endif /* _NGX_PERSIST_H_INCLUDED_ */
