#ifndef _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_
#define _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_pckg_ksmp.h"


#define NGX_HTTP_GONE                      410

#define NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX           (0x1)
#define NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT  (0x2)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS       (0x4)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE     (0x8)


#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)


#define ngx_http_pckg_match_file_name(start_pos, end_pos, prefix, postfix)  \
    ((end_pos) - (start_pos) >= (int) ((prefix).len + (postfix).len)        \
    && ngx_memcmp((end_pos) - (postfix).len, (postfix).data,                \
        (postfix).len) == 0                                                 \
    && ngx_memcmp((start_pos), (prefix).data, (prefix).len) == 0)


typedef struct ngx_http_pckg_request_handler_s
    ngx_http_pckg_request_handler_t;

typedef vod_status_t (*ngx_http_pckg_frame_processor_pt)(void *context);


enum {
    NGX_HTTP_PCKG_EXPIRES_STATIC,
    NGX_HTTP_PCKG_EXPIRES_INDEX,
    NGX_HTTP_PCKG_EXPIRES_INDEX_GONE,
    NGX_HTTP_PCKG_EXPIRES_MASTER,

    NGX_HTTP_PCKG_EXPIRES_COUNT
};


typedef struct {
    ngx_http_complex_value_t         *uri;
    size_t                            max_uncomp_size;
    ngx_http_complex_value_t         *channel_id;
    ngx_http_complex_value_t         *timeline_id;

    time_t                            expires[NGX_HTTP_PCKG_EXPIRES_COUNT];
    time_t                            last_modified_static;

    ngx_http_complex_value_t         *encryption_key_seed;
    ngx_http_complex_value_t         *encryption_iv_seed;

    buffer_pool_t                    *output_buffer_pool;

    ngx_http_complex_value_t         *segment_metadata;

    ngx_flag_t                        empty_segments;
} ngx_http_pckg_core_loc_conf_t;


typedef struct {
    ngx_http_request_t               *r;
    ngx_chain_t                       out;
    ngx_chain_t                      *last;
    size_t                            total_size;
} ngx_http_pckg_writer_ctx_t;


typedef struct {
    ngx_pckg_ksmp_req_t               params;
    ngx_http_pckg_request_handler_t  *handler;

    ngx_pckg_channel_t               *channel;

    request_context_t                 request_context;
    size_t                            content_length;
    size_t                            size_limit;

    segment_writer_t                  segment_writer;
    ngx_http_pckg_writer_ctx_t        segment_writer_ctx;
} ngx_http_pckg_core_ctx_t;


typedef struct {

    ngx_int_t (*parse_uri_file_name)(ngx_http_request_t *r, u_char *start_pos,
        u_char *end_pos, ngx_pckg_ksmp_req_t *result,
        ngx_http_pckg_request_handler_t **handler);

} ngx_http_pckg_submodule_t;


struct ngx_http_pckg_request_handler_s {

    ngx_int_t (*handler)(ngx_http_request_t *r);

    ngx_int_t (*init_frame_processor)(ngx_http_request_t *r,
        media_segment_t *segment, ngx_http_pckg_frame_processor_pt *processor,
        void **processor_ctx, ngx_str_t *output_buffer, size_t *response_size,
        ngx_str_t *content_type);

};


ngx_int_t ngx_http_pckg_status_to_ngx_error(ngx_http_request_t *r,
    vod_status_t rc);

ngx_int_t ngx_http_pckg_send_header(ngx_http_request_t *r,
    off_t content_length_n, ngx_str_t *content_type,
    time_t last_modified_time, ngx_uint_t expires_type);

ngx_int_t ngx_http_pckg_gone(ngx_http_request_t *r);

ngx_int_t ngx_http_pckg_send_response(ngx_http_request_t *r,
    ngx_str_t *response);

size_t ngx_http_pckg_selector_get_size(ngx_pckg_variant_t *variant);

u_char *ngx_http_pckg_selector_write(u_char *p, ngx_pckg_channel_t *channel,
    ngx_pckg_variant_t *variant);

ngx_int_t ngx_http_pckg_generate_key(ngx_http_request_t *r, ngx_flag_t iv,
    ngx_str_t *salt, u_char *result);


ngx_int_t ngx_http_pckg_core_parse_uri_file_name(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, uint32_t flags,
    ngx_pckg_ksmp_req_t *result);

ngx_int_t ngx_http_pckg_core_handler(ngx_http_request_t *r,
    ngx_http_pckg_submodule_t *module);

ngx_int_t ngx_http_pckg_core_write_segment(ngx_http_request_t *r);

ngx_int_t ngx_http_pckg_media_init_segment(ngx_http_request_t *r,
    media_init_segment_t *result);


extern ngx_module_t  ngx_http_pckg_core_module;

extern u_char  ngx_http_pckg_media_type_code[KMP_MEDIA_COUNT];

#endif /* _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_ */
