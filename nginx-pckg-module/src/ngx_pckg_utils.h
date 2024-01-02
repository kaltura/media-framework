#ifndef _NGX_PCKG_UTILS_H_INCLUDED_
#define _NGX_PCKG_UTILS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"


#define NGX_PCKG_GUID_SIZE  (16)


ngx_int_t ngx_pckg_parse_base64_fixed(ngx_str_t *str, u_char *dst,
    size_t size);

ngx_int_t ngx_pckg_parse_base64(ngx_pool_t *pool, ngx_str_t *str,
    ngx_str_t *dst);

ngx_int_t ngx_pckg_parse_guid(ngx_str_t *str, u_char *dst);


u_char *ngx_pckg_write_media_type_mask(u_char *p, uint32_t media_type_mask);

size_t ngx_pckg_selector_get_size(ngx_str_t *variant_id);

u_char *ngx_pckg_selector_write(u_char *p, ngx_str_t *variant_id,
    uint32_t media_type_mask);

size_t ngx_pckg_sep_selector_get_size(ngx_str_t *variant_id);

u_char *ngx_pckg_sep_selector_write(u_char *p, ngx_str_t *variant_id,
    uint32_t media_type_mask);


#endif /*_NGX_PCKG_UTILS_H_INCLUDED_ */
