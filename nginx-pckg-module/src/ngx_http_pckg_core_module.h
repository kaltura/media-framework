#ifndef _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_
#define _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_pckg_ksmp.h"


#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)


#define ngx_http_pckg_match_prefix(start_pos, end_pos, prefix)              \
    ((end_pos) - (start_pos) >= (int) (prefix).len                          \
     && ngx_memcmp((start_pos), (prefix).data, (prefix).len) == 0)


enum {
    NGX_HTTP_PCKG_EXPIRES_STATIC,
    NGX_HTTP_PCKG_EXPIRES_INDEX,
    NGX_HTTP_PCKG_EXPIRES_INDEX_GONE,
    NGX_HTTP_PCKG_EXPIRES_MASTER,

    NGX_HTTP_PCKG_EXPIRES_COUNT
};


typedef vod_status_t (*ngx_http_pckg_frame_processor_pt)(void *context);


typedef struct {

    ngx_str_t    *init_file_ext;
    ngx_str_t    *seg_file_ext;

    void        (*get_bitrate_estimator)(ngx_http_request_t *r,
        media_info_t **media_infos, uint32_t count,
        media_bitrate_estimator_t *result);

    void        (*get_content_type)(media_info_t *media_info,
        ngx_str_t *content_type);

} ngx_http_pckg_container_t;


typedef struct {
    ngx_http_pckg_frame_processor_pt   process;
    void                              *ctx;
    ngx_str_t                          output;
    size_t                             response_size;
    ngx_str_t                          content_type;
} ngx_http_pckg_frame_processor_t;


typedef struct {

    ngx_int_t   (*handler)(ngx_http_request_t *r);

    ngx_int_t   (*init_frame_processor)(ngx_http_request_t *r,
        media_segment_t *segment, ngx_http_pckg_frame_processor_t *processor);

} ngx_http_pckg_request_handler_t;


typedef struct {
    ngx_http_complex_value_t         *uri;
    ngx_uint_t                        format;

    ngx_http_complex_value_t         *channel_id;
    ngx_http_complex_value_t         *timeline_id;
    size_t                            max_uncomp_size;

    time_t                            expires[NGX_HTTP_PCKG_EXPIRES_COUNT];
    time_t                            last_modified_static;

    ngx_uint_t                        active_policy;
    ngx_uint_t                        media_type_selector;

    ngx_flag_t                        empty_segments;
    buffer_pool_t                    *output_buffer_pool;
    ngx_http_complex_value_t         *segment_metadata;
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


typedef ngx_int_t (*ngx_http_pckg_parse_uri_pt)(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler);

ngx_int_t ngx_http_pckg_core_add_handler(ngx_conf_t *cf, ngx_str_t *ext,
    ngx_http_pckg_parse_uri_pt parse);


ngx_int_t ngx_http_pckg_core_write_segment(ngx_http_request_t *r);

ngx_int_t ngx_http_pckg_media_init_segment(ngx_http_request_t *r,
    media_init_segment_t *result);


extern ngx_module_t  ngx_http_pckg_core_module;

extern ngx_str_t  ngx_http_pckg_prefix_manifest;
extern ngx_str_t  ngx_http_pckg_prefix_master;
extern ngx_str_t  ngx_http_pckg_prefix_index;
extern ngx_str_t  ngx_http_pckg_prefix_init_seg;
extern ngx_str_t  ngx_http_pckg_prefix_seg;
extern ngx_str_t  ngx_http_pckg_prefix_frame;

#endif /* _NGX_HTTP_PCKG_CORE_MODULE_H_INCLUDED_ */
