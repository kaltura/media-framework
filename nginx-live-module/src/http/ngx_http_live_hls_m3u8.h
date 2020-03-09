#ifndef _NGX_HTTP_LIVE_HLS_M3U8_H_INCLUDED_
#define _NGX_HTTP_LIVE_HLS_M3U8_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_live_core_module.h"
#include "../media/hls/hls_encryption.h"


enum {
    NGX_HTTP_LIVE_HLS_CONTAINER_AUTO,
    NGX_HTTP_LIVE_HLS_CONTAINER_MPEGTS,
    NGX_HTTP_LIVE_HLS_CONTAINER_FMP4,
};


typedef struct {
    ngx_uint_t                 m3u8_version;
    ngx_uint_t                 container_format;

    ngx_http_complex_value_t  *enc_key_uri;
    ngx_str_t                  enc_key_format;
    ngx_str_t                  enc_key_format_versions;
}  ngx_http_live_hls_m3u8_config_t;


ngx_int_t ngx_http_live_hls_m3u8_build_master(ngx_http_request_t *r,
    ngx_http_live_request_objects_t *objects, ngx_str_t *result);

ngx_int_t ngx_http_live_hls_m3u8_build_index(ngx_http_request_t *r,
    ngx_http_live_request_objects_t *objects,
    hls_encryption_params_t *encryption_params, ngx_str_t *result);


extern ngx_str_t  ngx_http_live_hls_prefix_seg;
extern ngx_str_t  ngx_http_live_hls_ext_seg_ts;
extern ngx_str_t  ngx_http_live_hls_ext_seg_m4s;

extern ngx_str_t  ngx_http_live_hls_prefix_master;
extern ngx_str_t  ngx_http_live_hls_prefix_index;
extern ngx_str_t  ngx_http_live_hls_ext_m3u8;

extern ngx_str_t  ngx_http_live_hls_prefix_enc_key;
extern ngx_str_t  ngx_http_live_hls_ext_enc_key;

extern ngx_str_t  ngx_http_live_hls_prefix_init_seg;
extern ngx_str_t  ngx_http_live_hls_ext_init_seg;

#endif /* _NGX_HTTP_LIVE_HLS_M3U8_H_INCLUDED_ */
