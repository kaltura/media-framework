#ifndef _NGX_RTMP_KMP_TRACK_H_INCLUDED_
#define _NGX_RTMP_KMP_TRACK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_kmp_push_track.h"


#define NGX_RTMP_TIMESCALE   (1000)


// Note: an ngx_str_t version of ngx_rtmp_publish_t
typedef struct {
    ngx_str_t                name;
    ngx_str_t                args;
    ngx_str_t                type;
} ngx_rtmp_kmp_publish_t;

typedef struct {
    ngx_rtmp_session_t      *s;
    ngx_rtmp_codec_ctx_t    *codec_ctx;
    ngx_rtmp_kmp_publish_t  *publish;
    ngx_uint_t               media_type;
} ngx_rtmp_kmp_track_create_ctx_t;


ngx_kmp_push_track_t *ngx_rtmp_kmp_track_create(
    ngx_kmp_push_track_conf_t *conf, ngx_rtmp_kmp_track_create_ctx_t *ctx);

ngx_int_t ngx_rtmp_kmp_track_av(ngx_kmp_push_track_t *track,
    ngx_rtmp_header_t *h, ngx_chain_t *in);

/* json */
size_t ngx_rtmp_kmp_api_video_codec_info_json_get_size(
    ngx_rtmp_codec_ctx_t *obj);

u_char* ngx_rtmp_kmp_api_video_codec_info_json_write(u_char *p,
    ngx_rtmp_codec_ctx_t *obj);

size_t ngx_rtmp_kmp_api_audio_codec_info_json_get_size(
    ngx_rtmp_codec_ctx_t *obj);

u_char* ngx_rtmp_kmp_api_audio_codec_info_json_write(u_char *p,
    ngx_rtmp_codec_ctx_t *obj);

#endif /* _NGX_RTMP_KMP_TRACK_H_INCLUDED_ */
