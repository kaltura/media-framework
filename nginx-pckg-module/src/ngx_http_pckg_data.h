#ifndef _NGX_HTTP_PCKG_DATA_H_INCLUDED_
#define _NGX_HTTP_PCKG_DATA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t  id;
    ngx_str_t  value;
    ngx_str_t  uri;
    ngx_str_t  lang;
} ngx_pckg_data_value_t;


/*
 * NGX_BAD_DATA - invalid data json
 * NGX_ERROR - alloc error
 */
ngx_int_t ngx_http_pckg_data_init(ngx_http_request_t *r, ngx_array_t *dvs);

#endif /* _NGX_HTTP_PCKG_DATA_H_INCLUDED_ */
