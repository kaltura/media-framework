#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_live_kmp.h>

#include "ngx_kmp_rtmp_amf.h"


#define NGX_RTMP_AMF_NUMBER             0x00
#define NGX_RTMP_AMF_BOOLEAN            0x01
#define NGX_RTMP_AMF_STRING             0x02
#define NGX_RTMP_AMF_OBJECT             0x03
#define NGX_RTMP_AMF_NULL               0x05
#define NGX_RTMP_AMF_MIXED_ARRAY        0x08
#define NGX_RTMP_AMF_END                0x09

#define NGX_RTMP_AMF_SIZE_TYPE          1
#define NGX_RTMP_AMF_SIZE_BOOL          1
#define NGX_RTMP_AMF_SIZE_NUMBER        sizeof(double)
#define NGX_RTMP_AMF_SIZE_STRLEN        sizeof(uint16_t)


static ngx_inline u_char *
ngx_kmp_rtmp_amf_write_key(u_char *p, ngx_str_t *key)
{
    ngx_kmp_rtmp_amf_write_be16(p, key->len);
    return ngx_copy(p, key->data, key->len);
}


static ngx_inline uintptr_t
ngx_kmp_rtmp_amf_write_bool(u_char *p, ngx_flag_t val)
{
    *p++ = NGX_RTMP_AMF_BOOLEAN;
    *p++ = val ? 1 : 0;

    return (uintptr_t) p;
}


static ngx_inline uintptr_t
ngx_kmp_rtmp_amf_write_number(u_char *p, double val)
{
    u_char  *v;

    v = (u_char *) &val + sizeof(val) - 1;

    *p++ = NGX_RTMP_AMF_NUMBER;
    *p++ = *v--;  *p++ = *v--;  *p++ = *v--;  *p++ = *v--;
    *p++ = *v--;  *p++ = *v--;  *p++ = *v--;  *p++ = *v--;

    return (uintptr_t) p;
}


static ngx_inline uintptr_t
ngx_kmp_rtmp_amf_write_string(u_char *p, ngx_str_t *val)
{
    *p++ = NGX_RTMP_AMF_STRING;
    ngx_kmp_rtmp_amf_write_be16(p, val->len);
    p = ngx_copy(p, val->data, val->len);

    return (uintptr_t) p;
}


uintptr_t
ngx_kmp_rtmp_amf_null(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE;
    }

    *p++ = NGX_RTMP_AMF_NULL;

    return (uintptr_t) p;
}


uintptr_t
ngx_kmp_rtmp_amf_stereo(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    uint16_t  *val;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_BOOL;
    }

    val = (uint16_t *) ((u_char *) data + field->offset);

    return ngx_kmp_rtmp_amf_write_bool(p, *val >= 2);
}


uintptr_t
ngx_kmp_rtmp_amf_uint16(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    uint16_t  *val;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_NUMBER;
    }

    val = (uint16_t *) ((u_char *) data + field->offset);

    return ngx_kmp_rtmp_amf_write_number(p, *val);
}


uintptr_t
ngx_kmp_rtmp_amf_uint32(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    uint32_t  *val;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_NUMBER;
    }

    val = (uint32_t *) ((u_char *) data + field->offset);

    return ngx_kmp_rtmp_amf_write_number(p, *val - (intptr_t) field->data);
}


uintptr_t
ngx_kmp_rtmp_amf_rational(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    kmp_rational_t  *val;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_NUMBER;
    }

    val = (kmp_rational_t *) ((u_char *) data + field->offset);

    return ngx_kmp_rtmp_amf_write_number(p, (double) val->num / val->denom);
}


uintptr_t
ngx_kmp_rtmp_amf_bitrate(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    uint32_t  *val;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_NUMBER;
    }

    val = (uint32_t *) ((u_char *) data + field->offset);

    return ngx_kmp_rtmp_amf_write_number(p, *val / 1000.0);
}


uintptr_t
ngx_kmp_rtmp_amf_string(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    ngx_str_t  *val;

    val = (ngx_str_t *) ((u_char *) data + field->offset);

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_STRLEN + val->len;
    }

    return ngx_kmp_rtmp_amf_write_string(p, val);
}


uintptr_t
ngx_kmp_rtmp_amf_fixed_string(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    ngx_str_t  *val;

    val = (ngx_str_t *) field->offset;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + NGX_RTMP_AMF_SIZE_STRLEN + val->len;
    }

    return ngx_kmp_rtmp_amf_write_string(p, val);
}


static ngx_inline size_t
ngx_kmp_rtmp_amf_fields_get_size(ngx_kmp_rtmp_amf_field_t *fields,
    ngx_uint_t type, void *data)
{
    size_t                     size;
    ngx_kmp_rtmp_amf_field_t  *cur;

    size = 0;
    for (cur = fields; cur->handler; cur++) {
        if (!(cur->type & type)) {
            continue;
        }

        size += NGX_RTMP_AMF_SIZE_STRLEN + cur->key.len;
        size += cur->handler(cur, NULL, type, data);
    }

    return size;
}


static ngx_inline u_char *
ngx_kmp_rtmp_amf_fields_write(ngx_kmp_rtmp_amf_field_t *fields, u_char *p,
    ngx_uint_t type, void *data, uint32_t *len)
{
    ngx_kmp_rtmp_amf_field_t  *cur;

    *len = 0;

    for (cur = fields; cur->handler; cur++) {
        if (!(cur->type & type)) {
            continue;
        }

        p = ngx_kmp_rtmp_amf_write_key(p, &cur->key);
        p = (u_char *) cur->handler(cur, p, type, data);

        (*len)++;
    }

    return p;
}


uintptr_t
ngx_kmp_rtmp_amf_object(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    uint32_t                   ignore;
    ngx_kmp_rtmp_amf_field_t  *fields = field->data;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE
            + ngx_kmp_rtmp_amf_fields_get_size(fields, type, data)
            + NGX_RTMP_AMF_SIZE_STRLEN + NGX_RTMP_AMF_SIZE_TYPE;
    }

    *p++ = NGX_RTMP_AMF_OBJECT;

    p = ngx_kmp_rtmp_amf_fields_write(fields, p, type, data, &ignore);

    ngx_kmp_rtmp_amf_write_be16(p, 0);
    *p++ = NGX_RTMP_AMF_END;

    return (uintptr_t) p;
}


uintptr_t
ngx_kmp_rtmp_amf_mixed_array(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data)
{
    u_char                    *plen;
    uint32_t                   len;
    ngx_kmp_rtmp_amf_field_t  *fields = field->data;

    if (p == NULL) {
        return NGX_RTMP_AMF_SIZE_TYPE + sizeof(len)
            + ngx_kmp_rtmp_amf_fields_get_size(fields, type, data)
            + NGX_RTMP_AMF_SIZE_STRLEN + NGX_RTMP_AMF_SIZE_TYPE;
    }

    *p++ = NGX_RTMP_AMF_MIXED_ARRAY;

    plen = p;
    p += sizeof(len);

    p = ngx_kmp_rtmp_amf_fields_write(fields, p, type, data, &len);

    ngx_kmp_rtmp_amf_write_be32(plen, len);

    ngx_kmp_rtmp_amf_write_be16(p, 0);
    *p++ = NGX_RTMP_AMF_END;

    return (uintptr_t) p;
}


uintptr_t
ngx_kmp_rtmp_amf(ngx_kmp_rtmp_amf_field_t *fields, u_char *p, ngx_uint_t type,
    void *data)
{
    size_t                     size;
    ngx_kmp_rtmp_amf_field_t  *cur;

    if (p == NULL) {
        size = 0;
        for (cur = fields; cur->handler; cur++) {
            if (!(cur->type & type)) {
                continue;
            }

            size += cur->handler(cur, NULL, type, data);
        }

        return size;
    }

    for (cur = fields; cur->handler; cur++) {
        if (!(cur->type & type)) {
            continue;
        }

        p = (u_char *) cur->handler(cur, p, type, data);
    }

    return (uintptr_t) p;
}
