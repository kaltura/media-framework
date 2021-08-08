#ifndef _NGX_HTTP_PCKG_UTILS_H_INCLUDED_
#define _NGX_HTTP_PCKG_UTILS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_pckg_ksmp.h"
#include "ngx_http_pckg_core_module.h"


#define NGX_HTTP_GONE                      410

#define NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX           (0x1)
#define NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT  (0x2)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS       (0x4)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE     (0x8)


u_char *ngx_http_pckg_parse_uint32(u_char *start_pos, u_char *end_pos,
    uint32_t *result);

u_char *ngx_http_pckg_extract_string(u_char *start_pos, u_char *end_pos,
    ngx_str_t *result);

ngx_int_t ngx_http_pckg_parse_uri_file_name(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, uint32_t flags,
    ngx_pckg_ksmp_req_t *result);

ngx_int_t ngx_http_pckg_range_parse(ngx_str_t *range, off_t content_length,
    off_t *out_start, off_t *out_end);


ngx_int_t ngx_http_pckg_send_header(ngx_http_request_t *r,
    off_t content_length_n, ngx_str_t *content_type,
    time_t last_modified_time, ngx_uint_t expires_type);

ngx_int_t ngx_http_pckg_gone(ngx_http_request_t *r);

ngx_int_t ngx_http_pckg_send_response(ngx_http_request_t *r,
    ngx_str_t *response);


size_t ngx_http_pckg_selector_get_size(ngx_pckg_variant_t *variant);

u_char *ngx_http_pckg_selector_write(u_char *p, ngx_pckg_variant_t *variant,
    uint32_t media_type_mask);


ngx_int_t ngx_http_pckg_status_to_ngx_error(ngx_http_request_t *r,
    vod_status_t rc);


void ngx_http_pckg_get_bitrate_estimator(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, media_bitrate_estimator_t *result);

uint32_t ngx_http_pckg_estimate_bitrate(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, uint32_t segment_duration);


extern u_char  ngx_http_pckg_media_type_code[KMP_MEDIA_COUNT];

#endif /*_NGX_HTTP_PCKG_UTILS_H_INCLUDED_ */
