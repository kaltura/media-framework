#ifndef _NGX_HTTP_PCKG_UTILS_H_INCLUDED_
#define _NGX_HTTP_PCKG_UTILS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_json_parser.h>
#include "ngx_pckg_ksmp.h"
#include "ngx_http_pckg_core_module.h"


#define NGX_HTTP_GONE                      410

#define NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX            (0x01)
#define NGX_HTTP_PCKG_PARSE_REQUIRE_PART_INDEX       (0x02)
#define NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT   (0x04)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_SINGLE_VARIANT  (0x08)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS        (0x10)
#define NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE      (0x20)

#define NGX_HTTP_PCKG_GUID_SIZE  (16)


#define ngx_http_pckg_estimate_max_bitrate(r, c, mis, cnt, sd)               \
    ngx_http_pckg_estimate_bitrate(r, c, mis, cnt, sd,                       \
    offsetof(media_info_t, bitrate))

#define ngx_http_pckg_estimate_avg_bitrate(r, c, mis, cnt, sd)               \
    ngx_http_pckg_estimate_bitrate(r, c, mis, cnt, sd,                       \
    offsetof(media_info_t, avg_bitrate))


#define ngx_conf_init_complex_int_value(conf, default)                       \
    if (conf == NULL) {                                                      \
        conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));      \
        if (conf == NULL) {                                                  \
            return NGX_CONF_ERROR;                                           \
        }                                                                    \
                                                                             \
        conf->u.size = default;                                              \
    }


#if nginx_version < 1021000
char *ngx_http_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif

ngx_flag_t ngx_http_complex_value_flag(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_flag_t default_value);

char *ngx_http_set_complex_value_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_uint_t ngx_http_complex_value_percent(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_uint_t default_value);

char *ngx_http_set_complex_value_percent_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


u_char *ngx_http_pckg_parse_uint32(u_char *start_pos, u_char *end_pos,
    uint32_t *result);

u_char *ngx_http_pckg_extract_string(u_char *start_pos, u_char *end_pos,
    ngx_str_t *result);

ngx_int_t ngx_http_pckg_parse_uri_file_name(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, uint32_t flags,
    ngx_pckg_ksmp_req_t *result);


ngx_int_t ngx_http_pckg_complex_value_json(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_json_value_t *json);

ngx_int_t ngx_http_pckg_parse_base64_fixed(ngx_str_t *str, u_char *dst,
    size_t size);

ngx_int_t ngx_http_pckg_parse_base64(ngx_pool_t *pool, ngx_str_t *str,
    ngx_str_t *dst);

ngx_int_t ngx_http_pckg_parse_guid(ngx_str_t *str, u_char *dst);


ngx_int_t ngx_http_pckg_range_parse(ngx_str_t *range, off_t content_length,
    off_t *out_start, off_t *out_end);


ngx_int_t ngx_http_pckg_send_header(ngx_http_request_t *r,
    off_t content_length_n, ngx_str_t *content_type,
    time_t last_modified_time, ngx_uint_t expires_type);

ngx_int_t ngx_http_pckg_gone(ngx_http_request_t *r);

ngx_int_t ngx_http_pckg_send_response(ngx_http_request_t *r,
    ngx_str_t *response);


u_char *ngx_http_pckg_write_media_type_mask(u_char *p,
    uint32_t media_type_mask);

size_t ngx_http_pckg_selector_get_size(ngx_str_t *variant_id);

u_char *ngx_http_pckg_selector_write(u_char *p, ngx_str_t *variant_id,
    uint32_t media_type_mask);


ngx_int_t ngx_http_pckg_status_to_ngx_error(ngx_http_request_t *r,
    vod_status_t rc);


void ngx_http_pckg_get_bitrate_estimator(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, media_bitrate_estimator_t *result);

uint32_t ngx_http_pckg_estimate_bitrate(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, uint32_t segment_duration, ngx_uint_t offset);


extern u_char  ngx_http_pckg_media_type_code[KMP_MEDIA_COUNT];

#endif /*_NGX_HTTP_PCKG_UTILS_H_INCLUDED_ */
