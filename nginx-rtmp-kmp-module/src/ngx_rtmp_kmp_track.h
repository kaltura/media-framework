#ifndef _NGX_RTMP_KMP_TRACK_H_INCLUDED_
#define _NGX_RTMP_KMP_TRACK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_kmp_push_track.h"


#define NGX_RTMP_TIMESCALE   (1000)


/* Note: an ngx_str_t version of ngx_rtmp_publish_t */
typedef struct {
    ngx_str_t                name;
    ngx_str_t                args;
    ngx_str_t                type;
} ngx_rtmp_kmp_publish_t;


ngx_kmp_push_track_t *ngx_rtmp_kmp_track_create(
    ngx_kmp_push_track_conf_t *conf, ngx_rtmp_session_t *s,
    ngx_rtmp_kmp_publish_t  *publish, ngx_rtmp_header_t *h, ngx_chain_t *in);

ngx_int_t ngx_rtmp_kmp_track_av(ngx_kmp_push_track_t *track,
    ngx_rtmp_header_t *h, ngx_chain_t *in, ngx_flag_t first_time);

#endif /* _NGX_RTMP_KMP_TRACK_H_INCLUDED_ */
