#ifndef _NGX_PERSIST_WRITE_H_INCLUDED_
#define _NGX_PERSIST_WRITE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_wstream.h>
#include "ngx_persist_format.h"
#include "ngx_buf_chain.h"


#define ngx_persist_write_stream(c)  (&((ngx_persist_write_base_t *) (c))->ws)

#define ngx_persist_write_ctx(c)     (((ngx_persist_write_base_t *) (c))->ctx)

#define ngx_persist_write_vctx(c)    (((ngx_persist_write_base_t *) (c))->vctx)

#define ngx_persist_write_log(c)     (ngx_persist_write_pool(c)->log)


typedef struct ngx_persist_write_ctx_s  ngx_persist_write_ctx_t;


typedef struct {
    ngx_wstream_t   ws;
    void           *ctx;
    void           *vctx;
} ngx_persist_write_base_t;


typedef struct {
    size_t          size;
    ngx_chain_t   **next;
    ngx_buf_t      *buf;
    u_char         *pos;
} ngx_persist_write_marker_t;


ngx_persist_write_ctx_t *ngx_persist_write_init(ngx_pool_t *pool,
    uint32_t type, int comp_level);

ngx_chain_t *ngx_persist_write_close(ngx_persist_write_ctx_t *ctx,
    size_t *size, ngx_chain_t ***last);

ngx_int_t ngx_persist_write_chain(ngx_persist_write_ctx_t *ctx1,
    ngx_persist_write_ctx_t *ctx2);

ngx_pool_t *ngx_persist_write_pool(ngx_persist_write_ctx_t *ctx);

size_t ngx_persist_write_get_size(ngx_persist_write_ctx_t *ctx);


/* copy functions */
ngx_int_t ngx_persist_write(ngx_persist_write_ctx_t *ctx,
    void *buf, size_t size);

ngx_int_t ngx_persist_write_list_data(ngx_persist_write_ctx_t *ctx,
    ngx_list_t *list);

ngx_int_t ngx_persist_write_list_data_n(ngx_persist_write_ctx_t *ctx,
    ngx_list_part_t *part, ngx_uint_t count, size_t size);

ngx_int_t ngx_persist_write_reserve(ngx_persist_write_ctx_t *ctx, size_t size,
    ngx_persist_write_marker_t *marker);

void ngx_persist_write_marker_write(ngx_persist_write_marker_t *marker,
    void *buf, size_t size);

/* no copy functions - original buffer must remain valid! */
ngx_int_t ngx_persist_write_append(ngx_persist_write_ctx_t *ctx,
    void *buf, size_t size);

ngx_int_t ngx_persist_write_append_buf_chain(
    ngx_persist_write_ctx_t *ctx, ngx_buf_chain_t *chain);

ngx_int_t ngx_persist_write_append_buf_chain_n(ngx_persist_write_ctx_t *ctx,
    ngx_buf_chain_t *chain, size_t offset, size_t size);

/* block functions */
ngx_int_t ngx_persist_write_block_open(ngx_persist_write_ctx_t *ctx,
    uint32_t id);

void ngx_persist_write_block_set_header(ngx_persist_write_ctx_t *ctx,
    uint32_t flags);

void ngx_persist_write_block_close(ngx_persist_write_ctx_t *ctx);

ngx_int_t ngx_persist_write_block(ngx_persist_write_ctx_t *ctx,
    ngx_persist_block_header_t *header, void *buf, size_t size);

#endif /* _NGX_PERSIST_WRITE_H_INCLUDED_ */
