#ifndef _NGX_HTTP_PCKG_ENC_H_INCLUDED_
#define _NGX_HTTP_PCKG_ENC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_pckg_ksmp.h"


#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE (16)
#endif


enum {
    NGX_HTTP_PCKG_ENC_NONE,
    NGX_HTTP_PCKG_ENC_AES_128,
    NGX_HTTP_PCKG_ENC_CBCS,
    NGX_HTTP_PCKG_ENC_CENC,
};


typedef struct {
    ngx_uint_t                 scheme;
    ngx_uint_t                 scope;
    ngx_flag_t                 serve_key;
    ngx_http_complex_value_t  *key_seed;
    ngx_http_complex_value_t  *iv_seed;
    ngx_http_complex_value_t  *json;
} ngx_http_pckg_enc_loc_conf_t;


size_t ngx_http_pckg_enc_key_uri_get_size(ngx_uint_t scope,
    ngx_pckg_variant_t *variant);

u_char *ngx_http_pckg_enc_key_uri_write(u_char *p, ngx_uint_t scope,
    ngx_pckg_variant_t *variant, uint32_t media_types);


extern ngx_module_t  ngx_http_pckg_enc_module;

#endif /* _NGX_HTTP_PCKG_ENC_H_INCLUDED_ */
