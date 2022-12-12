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

    void                      (*finalize)(ngx_connection_t *c);
} ngx_ts_kmp_conf_t;


typedef enum {
    ngx_ts_kmp_state_initial,
    ngx_ts_kmp_state_connect_done,
    ngx_ts_kmp_state_error,
} ngx_ts_kmp_state_e;


typedef struct {
    ngx_queue_t                 queue;
    ngx_connection_t           *connection;
    ngx_ts_kmp_conf_t          *conf;
    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 tracks;     /* ngx_ts_kmp_track_t */
    uint32_t                    track_index[KMP_MEDIA_COUNT];
    ngx_msec_t                  start_msec;
    ngx_json_str_t              stream_id;

    ngx_json_str_t              remote_addr;
    u_char                      remote_addr_buf[NGX_SOCKADDR_STRLEN];

    ngx_json_str_t              local_addr;
    u_char                      local_addr_buf[NGX_SOCKADDR_STRLEN];

    ngx_ts_kmp_state_e          state;
} ngx_ts_kmp_ctx_t;


ngx_int_t ngx_ts_kmp_init_handler(ngx_ts_stream_t *ts, void *data);

ngx_int_t ngx_ts_kmp_finalize_session(ngx_uint_t connection, ngx_log_t *log);

size_t ngx_ts_kmp_sessions_json_get_size(void *obj);
u_char *ngx_ts_kmp_sessions_json_write(u_char *p, void *obj);

#endif /* _NGX_TS_KMP_MODULE_H_INCLUDED_ */
