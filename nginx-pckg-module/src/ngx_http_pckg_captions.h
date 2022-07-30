#ifndef _NGX_HTTP_PCKG_CAPTIONS_H_INCLUDED_
#define _NGX_HTTP_PCKG_CAPTIONS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * NGX_BAD_DATA - invalid captions json
 * NGX_ERROR - alloc error
 */
ngx_int_t ngx_http_pckg_captions_init(ngx_http_request_t *r);

#endif /* _NGX_HTTP_PCKG_CAPTIONS_H_INCLUDED_ */
