#ifndef _NGX_KMP_RTMP_ENCODER_H_INCLUDED_
#define _NGX_KMP_RTMP_ENCODER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>


#define NGX_KMP_RTMP_MEDIA_COUNT  (2)
#define NGX_KMP_RTMP_MEDIA_MASK   ((1 << NGX_KMP_RTMP_MEDIA_COUNT) - 1)

#define NGX_KMP_RTMP_TIMESCALE    (1000)


typedef ngx_int_t (*ngx_kmp_rtmp_write_pt)(void *data, void *buf, size_t size);


typedef struct {
    uint32_t                  tx_id;
} ngx_kmp_rtmp_cmd_base_t;


typedef struct {
    ngx_kmp_rtmp_cmd_base_t   base;
    ngx_str_t                 app;
    ngx_str_t                 flash_ver;
    ngx_str_t                 swf_url;
    ngx_str_t                 tc_url;
    ngx_str_t                 page_url;
} ngx_kmp_rtmp_connect_t;


typedef struct {
    kmp_media_info_t          mi[NGX_KMP_RTMP_MEDIA_COUNT];
} ngx_kmp_rtmp_metadata_t;


typedef struct {
    ngx_str_t                 date;
    ngx_str_t                 time;
} ngx_kmp_rtmp_onfi_t;


typedef struct {
    ngx_log_t                *log;
    uint32_t                  chunk_size;
    uint32_t                  msid;
    u_char                    csid;
    uint32_t                  last_timestamp;
    u_char                    sound_info;
    unsigned                  wrote_frame:1;
} ngx_kmp_rtmp_stream_ctx_t;


typedef struct {
    ngx_msec_t                added;
    int64_t                   created;
    int64_t                   dts;
    int32_t                   pts_delay;
    uint32_t                  flags;
    uint32_t                  size;
    ngx_buf_chain_t          *data;
} ngx_kmp_rtmp_frame_t;


size_t ngx_kmp_rtmp_encoder_connect_get_size(ngx_kmp_rtmp_connect_t *connect);
u_char *ngx_kmp_rtmp_encoder_connect_write(u_char *p,
    ngx_kmp_rtmp_connect_t *connect, uint32_t chunk_size);


size_t ngx_kmp_rtmp_encoder_stream_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name);
u_char *ngx_kmp_rtmp_encoder_stream_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *name, uint32_t *tx_id);

size_t ngx_kmp_rtmp_encoder_unstream_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name);
u_char *ngx_kmp_rtmp_encoder_unstream_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *name, uint32_t *tx_id);


size_t ngx_kmp_rtmp_encoder_metadata_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_metadata_t *meta);
u_char *ngx_kmp_rtmp_encoder_metadata_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_kmp_rtmp_metadata_t *meta);

void ngx_kmp_rtmp_encoder_update_media_info(ngx_kmp_rtmp_stream_ctx_t *sc,
    kmp_media_info_t *media_info);

size_t ngx_kmp_rtmp_encoder_avc_sequence_get_size(
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data);
u_char *ngx_kmp_rtmp_encoder_avc_sequence_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data);

size_t ngx_kmp_rtmp_encoder_aac_sequence_get_size(
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data);
u_char *ngx_kmp_rtmp_encoder_aac_sequence_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data);


size_t ngx_kmp_rtmp_encoder_onfi_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_onfi_t *onfi);
u_char *ngx_kmp_rtmp_encoder_onfi_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_kmp_rtmp_onfi_t *onfi);

ngx_int_t ngx_kmp_rtmp_encoder_frame_write(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_frame_t *frame, uint32_t codec_id,
    ngx_kmp_rtmp_write_pt write, void *data);

#endif /* _NGX_KMP_RTMP_ENCODER_H_INCLUDED_ */
