#ifndef _NGX_TS_HEVC_H_INCLUDED_
#define _NGX_TS_HEVC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_TS_HEVC_NAL_IDR_W_RADL  19
#define NGX_TS_HEVC_NAL_IDR_N_LP    20
#define NGX_TS_HEVC_NAL_VPS         32
#define NGX_TS_HEVC_NAL_SPS         33
#define NGX_TS_HEVC_NAL_PPS         34
#define NGX_TS_HEVC_NAL_AUD         35
#define NGX_TS_HEVC_NAL_SEI_PREFIX  39
#define NGX_TS_HEVC_NAL_SEI_SUFFIX  40


typedef struct {
    ngx_buf_t   *elts;
    ngx_uint_t   nelts;
} ngx_ts_hevc_nalu_array_t;


typedef struct {
    ngx_uint_t   width;
    ngx_uint_t   height;
} ngx_ts_hevc_params_t;


ngx_int_t ngx_ts_hevc_get_ps_id(ngx_buf_t *b, ngx_log_t *log, uint32_t *idp);


size_t ngx_ts_hevc_hvcc_get_size(ngx_ts_hevc_nalu_array_t *nalus);

u_char *ngx_ts_hevc_hvcc_write(u_char *p, ngx_log_t *log,
    ngx_ts_hevc_nalu_array_t *nalus, ngx_ts_hevc_params_t *params);

#endif /* _NGX_TS_HEVC_H_INCLUDED_ */
