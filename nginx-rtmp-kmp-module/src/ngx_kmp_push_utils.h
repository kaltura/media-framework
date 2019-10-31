#ifndef _NGX_KMP_PUSH_UTILS_H_INCLUDED_
#define _NGX_KMP_PUSH_UTILS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_json_parser.h>


#define NGX_LOG_DEBUG_KMP NGX_LOG_DEBUG_CORE


ngx_chain_t *ngx_kmp_push_alloc_chain_temp_buf(ngx_pool_t *pool, size_t size);

ngx_chain_t *ngx_kmp_push_alloc_chain_buf(ngx_pool_t *pool, void *pos,
    void *last);

#if 0
ngx_chain_t *ngx_kmp_push_copy_chain(ngx_pool_t *pool, ngx_chain_t *src);
#endif

ngx_chain_t *ngx_kmp_push_format_json_http_request(ngx_pool_t *pool,
    ngx_str_t *host, ngx_str_t *uri, ngx_chain_t *body);

ngx_int_t ngx_kmp_push_parse_json_response(ngx_pool_t *pool, ngx_log_t *log,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body,
    ngx_json_value_t *json);

void ngx_kmp_push_float_to_rational(double f, int64_t md, int64_t *num,
    int64_t *denom);

#endif /* _NGX_KMP_PUSH_UTILS_H_INCLUDED_ */
