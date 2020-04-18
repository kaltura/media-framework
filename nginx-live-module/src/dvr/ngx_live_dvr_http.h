#ifndef _NGX_LIVE_DVR_HTTP_H_INCLUDED_
#define _NGX_LIVE_DVR_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_dvr.h"


/* read */

typedef ngx_int_t (*ngx_live_dvr_http_create_read_pt)(ngx_pool_t *pool,
    void *ctx, ngx_str_t *host, ngx_str_t *uri, off_t range_start,
    off_t range_end, ngx_buf_t **result);

void *ngx_live_dvr_http_read_init(ngx_live_dvr_read_request_t *request,
    ngx_url_t *url, ngx_live_dvr_http_create_read_pt create,
    void *create_data);

ngx_int_t ngx_live_dvr_http_read(void *ctx, off_t offset, size_t size);


/* write */

void *ngx_live_dvr_http_save(ngx_live_dvr_save_request_t *request,
    ngx_url_t *url, ngx_chain_t *headers, ngx_chain_t *body);

void ngx_live_dvr_http_cancel_save(void *data);

#endif /* _NGX_LIVE_DVR_HTTP_H_INCLUDED_ */
