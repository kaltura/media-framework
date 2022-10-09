#ifndef _NGX_TS_KMP_MODULE_H_INCLUDED_
#define _NGX_TS_KMP_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_ts_stream.h>
#include <ngx_live_kmp.h>
#include <ngx_json_str.h>

#include "ngx_kmp_out_track.h"


typedef struct {
    ngx_url_t                  *ctrl_connect_url;
    ngx_kmp_out_track_conf_t    t;
    ngx_queue_t                 sessions;
} ngx_ts_kmp_conf_t;


typedef struct {
    ngx_queue_t                 queue;
    ngx_connection_t           *connection;
    ngx_ts_kmp_conf_t          *conf;
    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 tracks;
    uint32_t                    track_index[KMP_MEDIA_COUNT];
    ngx_msec_t                  start_msec;
    ngx_json_str_t              header;
    ngx_json_str_t              remote_addr;
    u_char                      remote_addr_buf[NGX_SOCKADDR_STRLEN];
    unsigned                    error:1;
} ngx_ts_kmp_ctx_t;


ngx_int_t ngx_ts_kmp_init_handler(ngx_ts_stream_t *ts, void *data);

#endif /* _NGX_TS_KMP_MODULE_H_INCLUDED_ */
