#ifndef _ngx_live_store_http_H_INCLUDED_
#define _ngx_live_store_http_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


/* read */

typedef ngx_int_t (*ngx_live_store_http_create_read_pt)(ngx_pool_t *pool,
    void *ctx, ngx_str_t *host, ngx_str_t *uri, off_t range_start,
    off_t range_end, ngx_buf_t **result);

void *ngx_live_store_http_read_init(ngx_live_store_read_request_t *request,
    ngx_url_t *url, ngx_live_store_http_create_read_pt create,
    void *create_data, ngx_live_store_stats_t *stats);

ngx_int_t ngx_live_store_http_read(void *ctx, off_t offset, size_t size);


/* write */

ngx_int_t ngx_live_store_http_write(ngx_live_store_write_request_t *request,
    ngx_url_t *url, ngx_chain_t *headers, ngx_chain_t *body,
    ngx_live_store_stats_t *stats);

#endif /* _ngx_live_store_http_H_INCLUDED_ */
