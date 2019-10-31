#ifndef _NGX_RTMP_KMP_MODULE_H_INCLUDED_
#define _NGX_RTMP_KMP_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_live_kmp.h>
#include "ngx_rtmp_kmp_track.h"


typedef struct {
    ngx_url_t                  *ctrl_connect_url;
    ngx_kmp_push_track_conf_t   t;
    ngx_queue_t                 sessions;
} ngx_rtmp_kmp_app_conf_t;


typedef struct {
    ngx_rtmp_publish_t          publish_buf;
    ngx_rtmp_kmp_publish_t      publish;
    ngx_kmp_push_track_t       *tracks[KMP_MEDIA_COUNT];
} ngx_rtmp_kmp_stream_ctx_t;


typedef struct {
    ngx_queue_t                 queue;
    ngx_rtmp_session_t         *s;
    ngx_str_t                   remote_addr;
    u_char                      remote_addr_buf[NGX_SOCKADDR_STRLEN];
} ngx_rtmp_kmp_ctx_t;


extern ngx_module_t  ngx_rtmp_kmp_module;

#endif /* _NGX_RTMP_KMP_MODULE_H_INCLUDED_ */
