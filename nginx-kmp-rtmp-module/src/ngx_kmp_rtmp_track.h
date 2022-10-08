#ifndef _NGX_KMP_RTMP_TRACK_H_INCLUDED_
#define _NGX_KMP_RTMP_TRACK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_json_parser.h>
#include <ngx_buf_queue.h>
#include <ngx_kmp_in.h>

#include "ngx_kmp_rtmp.h"


typedef struct {
    ngx_pool_t                    *temp_pool;
    ngx_kmp_rtmp_upstream_conf_t  *conf;
    ngx_kmp_in_ctx_t              *input;
    ngx_buf_queue_t               *buf_queue;
    ngx_json_value_t              *value;
    ngx_kmp_in_evt_media_info_t   *media_info;
    ngx_kmp_rtmp_track_t          *track;
} ngx_kmp_rtmp_track_connect_t;


/*
 * NGX_ABORT - fatal error (e.g. memory)
 * NGX_ERROR - parse error
 */
ngx_int_t ngx_kmp_rtmp_track_connect(ngx_kmp_rtmp_track_connect_t *connect);

void ngx_kmp_rtmp_track_free(ngx_kmp_rtmp_track_t *track);

ngx_int_t ngx_kmp_rtmp_track_disconnect_by_num(ngx_kmp_rtmp_upstream_t *u,
    ngx_uint_t connection);


void ngx_kmp_rtmp_track_stream_ready(ngx_kmp_rtmp_track_t *track);

void ngx_kmp_rtmp_track_get_media_info(ngx_kmp_rtmp_track_t *track,
    kmp_media_info_t *mi, ngx_str_t *extra_data);

ngx_int_t ngx_kmp_rtmp_track_process_frame(ngx_rbtree_node_t *node,
    ngx_msec_t *timer);

ngx_int_t ngx_kmp_rtmp_track_process_expired(ngx_rbtree_node_t *node);


size_t ngx_kmp_rtmp_track_json_get_size(ngx_kmp_rtmp_track_t *track);

u_char *ngx_kmp_rtmp_track_json_write(u_char *p, ngx_kmp_rtmp_track_t *track);

#endif /* _NGX_KMP_RTMP_TRACK_H_INCLUDED_ */
