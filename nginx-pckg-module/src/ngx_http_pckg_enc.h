#ifndef _NGX_HTTP_PCKG_ENC_H_INCLUDED_
#define _NGX_HTTP_PCKG_ENC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


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
    ngx_flag_t                 serve_key;
    ngx_http_complex_value_t  *key_seed;
    ngx_http_complex_value_t  *iv_seed;
} ngx_http_pckg_enc_loc_conf_t;


ngx_int_t ngx_http_pckg_enc_get_key(ngx_http_request_t *r, u_char *result);

ngx_int_t ngx_http_pckg_enc_get_iv(ngx_http_request_t *r, u_char *result);


extern ngx_module_t  ngx_http_pckg_enc_module;

extern ngx_str_t  ngx_http_pckg_enc_key_prefix;
extern ngx_str_t  ngx_http_pckg_enc_key_ext;

#endif /* _NGX_HTTP_PCKG_ENC_H_INCLUDED_ */
