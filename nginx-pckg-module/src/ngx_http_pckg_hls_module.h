#ifndef _NGX_HTTP_PCKG_HLS_MODULE_H_INCLUDED_
#define _NGX_HTTP_PCKG_HLS_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_hls_m3u8.h"
#include "media/hls/hls_muxer.h"


typedef struct {
    ngx_uint_t                       encryption_method;
    ngx_http_pckg_hls_m3u8_config_t  m3u8_config;
    hls_mpegts_muxer_conf_t          mpegts_muxer;
} ngx_http_pckg_hls_loc_conf_t;


extern ngx_module_t  ngx_http_pckg_hls_module;

#endif /* _NGX_HTTP_PCKG_HLS_MODULE_H_INCLUDED_ */
