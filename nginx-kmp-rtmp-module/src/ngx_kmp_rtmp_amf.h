#ifndef _NGX_KMP_RTMP_AMF_H_INCLUDED_
#define _NGX_KMP_RTMP_AMF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_KMP_RTMP_AMF_DEFAULT  0xffffffff
#define NGX_KMP_RTMP_AMF_VIDEO    0x01
#define NGX_KMP_RTMP_AMF_AUDIO    0x02

#define ngx_kmp_rtmp_amf_null_field  { NULL, ngx_null_string, 0, 0, NULL }


#define ngx_kmp_rtmp_amf_write_be16(p, w) {                                  \
        *(p)++ = ((w) >> 8) & 0xff;                                          \
        *(p)++ =  (w) & 0xff;                                                \
    }

#define ngx_kmp_rtmp_amf_write_be24(p, dw) {                                 \
        *(p)++ = ((dw) >> 16) & 0xff;                                        \
        *(p)++ = ((dw) >> 8) & 0xff;                                         \
        *(p)++ =  (dw) & 0xff;                                               \
    }

#define ngx_kmp_rtmp_amf_write_be32(p, dw) {                                 \
        *(p)++ = ((dw) >> 24) & 0xff;                                        \
        *(p)++ = ((dw) >> 16) & 0xff;                                        \
        *(p)++ = ((dw) >> 8) & 0xff;                                         \
        *(p)++ =  (dw) & 0xff;                                               \
    }


typedef struct ngx_kmp_rtmp_amf_field_s  ngx_kmp_rtmp_amf_field_t;

typedef uintptr_t (*ngx_kmp_rtmp_amf_handler_pt)(
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, ngx_uint_t type, void *data);


struct ngx_kmp_rtmp_amf_field_s {
    ngx_kmp_rtmp_amf_handler_pt   handler;
    ngx_str_t                     key;
    ngx_uint_t                    type;
    ngx_uint_t                    offset;
    void                         *data;
};


uintptr_t ngx_kmp_rtmp_amf_null(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_stereo(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_uint16(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_uint32(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_rational(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_bitrate(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_string(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_fixed_string(ngx_kmp_rtmp_amf_field_t *field,
    u_char *p, ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_object(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    ngx_uint_t type, void *data);
uintptr_t ngx_kmp_rtmp_amf_mixed_array(ngx_kmp_rtmp_amf_field_t *field,
    u_char *p, ngx_uint_t type, void *data);

uintptr_t ngx_kmp_rtmp_amf(ngx_kmp_rtmp_amf_field_t *fields, u_char *p,
    ngx_uint_t type, void *data);

#endif /* _NGX_KMP_RTMP_AMF_H_INCLUDED_ */
