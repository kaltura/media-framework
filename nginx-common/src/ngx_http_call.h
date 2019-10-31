#ifndef _NGX_HTTP_CALL_H_INCLUDED_
#define _NGX_HTTP_CALL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HTTP_CALL_ERROR         1
#define NGX_HTTP_CALL_BAD_GATEWAY   2
#define NGX_HTTP_CALL_TIME_OUT      3


typedef struct ngx_http_call_ctx_s ngx_http_call_ctx_t;

typedef ngx_chain_t *(*ngx_http_call_create_pt)(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body);

typedef ngx_int_t (*ngx_http_call_handle_pt)(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body);

typedef struct {
    ngx_url_t                      *url;
    ngx_http_call_create_pt         create;
    ngx_http_call_handle_pt         handle;
    ngx_pool_t                     *handler_pool;
    void                           *arg;
    size_t                          argsize;
    size_t                          buffer_size;
    ngx_msec_t                      timeout;
    ngx_msec_t                      read_timeout;
    ngx_msec_t                      retry_interval;
    ngx_buf_t                      *response;
} ngx_http_call_init_t;


ngx_http_call_ctx_t *ngx_http_call_create(ngx_http_call_init_t *ci);

void ngx_http_call_cancel(ngx_http_call_ctx_t *ctx);

#endif /* _NGX_HTTP_CALL_H_INCLUDED_ */
