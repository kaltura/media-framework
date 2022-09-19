#ifndef _NGX_KMP_CC_H_INCLUDED_
#define _NGX_KMP_CC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_json_parser.h>
#include <ngx_kmp_in.h>
#include <ngx_kmp_out_track.h>


typedef struct ngx_kmp_cc_ctx_s  ngx_kmp_cc_ctx_t;


typedef struct {
    ngx_uint_t      max_pending_packets;
    ngx_str_t       dump_folder;
} ngx_kmp_cc_conf_t;


typedef struct {
    ngx_json_str_t  channel_id;
    ngx_json_str_t  track_id;
} ngx_kmp_cc_input_t;


/*
 * NGX_ABORT - fatal error (e.g. memory)
 * NGX_ERROR - parse error
 */
ngx_int_t ngx_kmp_cc_create(ngx_pool_t *pool, ngx_pool_t *temp_pool,
    ngx_kmp_cc_conf_t *conf, ngx_kmp_cc_input_t *input, ngx_json_value_t *json,
    ngx_kmp_out_track_conf_t *oconf, ngx_kmp_cc_ctx_t **pctx);

void ngx_kmp_cc_close(ngx_kmp_cc_ctx_t *ctx, char *reason);


ngx_int_t ngx_kmp_cc_add_media_info(ngx_kmp_cc_ctx_t *ctx,
    ngx_kmp_in_evt_media_info_t *evt);

ngx_int_t ngx_kmp_cc_add_frame(ngx_kmp_cc_ctx_t *ctx,
    ngx_kmp_in_evt_frame_t *evt);

void ngx_kmp_cc_end_stream(ngx_kmp_cc_ctx_t *ctx);

u_char *ngx_kmp_cc_get_min_used(ngx_kmp_cc_ctx_t *ctx);


size_t ngx_kmp_cc_json_get_size(ngx_kmp_cc_ctx_t *ctx);

u_char *ngx_kmp_cc_json_write(u_char *p, ngx_kmp_cc_ctx_t *ctx);

#endif /* _NGX_KMP_CC_H_INCLUDED_ */
