#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_utils.h"


static u_char  ngx_pckg_media_type_code[KMP_MEDIA_COUNT] = {
    'v',    /* video */
    'a',    /* audio */
    't',    /* subtitle (text) */
};


static ngx_int_t
ngx_pckg_base64_decoded_length(ngx_str_t *base64, size_t *decoded_len)
{
    u_char  *p, *end;
    size_t   padding;

    if ((base64->len & 3) != 0) {
        return NGX_BAD_DATA;
    }

    end = base64->data + base64->len;
    for (p = end; p > base64->data && p[-1] == '='; p--);
    padding = end - p;

    if (padding > 2) {
        return NGX_BAD_DATA;
    }

    *decoded_len = (base64->len >> 2) * 3 - padding;
    return NGX_OK;
}


ngx_int_t
ngx_pckg_parse_base64_fixed(ngx_str_t *str, u_char *dst, size_t size)
{
    size_t     decoded_len;
    ngx_str_t  dst_str;

    if (ngx_pckg_base64_decoded_length(str, &decoded_len) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    if (decoded_len != size) {
        return NGX_BAD_DATA;
    }

    dst_str.data = dst;
    if (ngx_decode_base64(&dst_str, str) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    if (dst_str.len != size) {
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


ngx_int_t
ngx_pckg_parse_base64(ngx_pool_t *pool, ngx_str_t *str, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(pool, ngx_base64_decoded_length(str->len));
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(dst, str) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static ngx_inline int
ngx_pckg_parse_hex_char(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return (ch - '0');
    }

    ch = (ch | 0x20);        /* lower case */

    if (ch >= 'a' && ch <= 'f') {
        return (ch - 'a' + 10);
    }

    return -1;
}


ngx_int_t
ngx_pckg_parse_guid(ngx_str_t *str, u_char *dst)
{
    int      c1, c2;
    u_char  *p, *end, *dst_end;

    dst_end = dst + NGX_PCKG_GUID_SIZE;

    p = str->data;
    end = p + str->len;
    while (p + 1 < end) {
        if (*p == '-') {
            p++;
            continue;
        }

        if (dst >= dst_end) {
            return NGX_BAD_DATA;
        }

        c1 = ngx_pckg_parse_hex_char(p[0]);
        c2 = ngx_pckg_parse_hex_char(p[1]);
        if (c1 < 0 || c2 < 0) {
            return NGX_BAD_DATA;
        }

        *dst++ = ((c1 << 4) | c2);
        p += 2;
    }

    if (dst < dst_end) {
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


u_char *
ngx_pckg_write_media_type_mask(u_char *p, uint32_t media_type_mask)
{
    uint32_t  i;

    if (media_type_mask == KMP_MEDIA_TYPE_MASK) {
        return p;
    }

    *p++ = '-';
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        if (media_type_mask & (1 << i)) {
            *p++ = ngx_pckg_media_type_code[i];
        }
    }

    return p;
}


size_t
ngx_pckg_selector_get_size(ngx_str_t *variant_id)
{
    return sizeof("s") - 1 + variant_id->len
        + 2 * ngx_escape_uri(NULL, variant_id->data, variant_id->len,
            NGX_ESCAPE_URI_COMPONENT)
        + sizeof("-") - 1 + KMP_MEDIA_COUNT;
}


u_char *
ngx_pckg_selector_write(u_char *p, ngx_str_t *variant_id,
    uint32_t media_type_mask)
{
    *p++ = 's';
    p = (u_char *) ngx_escape_uri(p, variant_id->data, variant_id->len,
        NGX_ESCAPE_URI_COMPONENT);

    p = ngx_pckg_write_media_type_mask(p, media_type_mask);

    return p;
}


size_t
ngx_pckg_sep_selector_get_size(ngx_str_t *variant_id)
{
    return sizeof("-") - 1 + ngx_pckg_selector_get_size(variant_id);
}


u_char *
ngx_pckg_sep_selector_write(u_char *p, ngx_str_t *variant_id,
    uint32_t media_type_mask)
{
    *p++ = '-';
    return ngx_pckg_selector_write(p, variant_id, media_type_mask);
}
