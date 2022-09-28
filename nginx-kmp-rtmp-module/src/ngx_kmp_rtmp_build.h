#ifndef _NGX_KMP_RTMP_BUILD_H_INCLUDED_
#define _NGX_KMP_RTMP_BUILD_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_stream_kmp_rtmp_module.h"

#define NGX_RTMP_AMF_NUMBER             0x00
#define NGX_RTMP_AMF_BOOLEAN            0x01
#define NGX_RTMP_AMF_STRING             0x02
#define NGX_RTMP_AMF_OBJECT             0x03
#define NGX_RTMP_AMF_NULL               0x05
#define NGX_RTMP_AMF_MIXED_ARRAY        0x08
#define NGX_RTMP_AMF_END                0x09

#define NGX_RTMP_PACKET_AUDIO           0x08
#define NGX_RTMP_PACKET_VIDEO           0x09


#define write_be16(p, w)                                                      \
    {                                                                         \
    *(p)++ = ((w) >> 8) & 0xFF;                                               \
    *(p)++ = (w)& 0xFF;                                                       \
    }

#define write_be24(p, dw)                                                     \
    {                                                                         \
    *(p)++ = ((dw) >> 16) & 0xFF;                                             \
    *(p)++ = ((dw) >> 8) & 0xFF;                                              \
    *(p)++ = (dw)& 0xFF;                                                      \
    }

#define write_be32(p, dw) {                                                   \
        *(p)++ = ((dw) >> 24) & 0xff;                                         \
        *(p)++ = ((dw) >> 16) & 0xff;                                         \
        *(p)++ = ((dw) >> 8) & 0xff;                                          \
        *(p)++ = (dw) & 0xff;                                                 \
    }

#define ngx_kmp_rtmp_amf_write_string(p, str)                                 \
    {                                                                         \
    *p++ = NGX_RTMP_AMF_STRING;                                               \
    write_be16(p, sizeof(str) - 1) ;                                          \
    p = ngx_copy(p, str, sizeof(str) - 1);                                    \
    }

#define ngx_kmp_rtmp_rescale_time(time, cur_scale, new_scale)                 \
    ((((uint64_t) (time)) * (new_scale) + (cur_scale) / 2) / (cur_scale))


ngx_chain_t *ngx_kmp_rtmp_build_get_chain(
    ngx_stream_kmp_rtmp_upstream_t *upstream, ngx_pool_t *pool,
    void *pos, void *last);

size_t ngx_kmp_rtmp_handshake_init_get_size(ngx_str_t *app, ngx_str_t *tc_url,
    ngx_str_t *flash_ver);

void ngx_kmp_rtmp_build_handshake_init(ngx_buf_t *b, ngx_str_t *host,
    ngx_str_t *app, ngx_str_t *tc_url, ngx_str_t *flash_ver,
    ngx_uint_t chunk_size);

size_t ngx_kmp_rtmp_stream_init_get_size(ngx_str_t *stream_name);

void ngx_kmp_rtmp_build_stream_init(ngx_buf_t *b, ngx_str_t *stream_name);

size_t ngx_kmp_rtmp_meta_data_get_size(ngx_stream_kmp_rtmp_track_t *video_ctx,
    ngx_stream_kmp_rtmp_track_t *audio_ctx);

void ngx_kmp_rtmp_build_meta_data(ngx_buf_t *b,
    ngx_stream_kmp_rtmp_track_t *ctx1, ngx_stream_kmp_rtmp_track_t *ctx2);

ngx_int_t ngx_kmp_rtmp_build_rtmp (
    ngx_stream_kmp_rtmp_upstream_t *connection,
    ngx_stream_kmp_rtmp_track_t *ctx, ngx_rtmp_kmp_frame_t *frame,
    ngx_uint_t chunk_size, uint32_t timescale);


#endif /* _NGX_KMP_RTMP_BUILD_H_INCLUDED_ */