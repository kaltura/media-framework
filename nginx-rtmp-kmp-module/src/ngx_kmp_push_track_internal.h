#ifndef _NGX_KMP_PUSH_TRACK_INTERNAL_H_INCLUDED_
#define _NGX_KMP_PUSH_TRACK_INTERNAL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_http_call.h>
#include <ngx_buf_queue.h>
#include "ngx_kmp_push_track.h"


typedef enum {
    NGX_KMP_TRACK_INITIAL,
    NGX_KMP_TRACK_INACTIVE,
    NGX_KMP_TRACK_WAIT_PUBLISH_RESPONSE,
    NGX_KMP_TRACK_ACTIVE,
} ngx_kmp_push_track_state_e;

typedef void(*ngx_kmp_push_track_handler_pt)(void *ctx);

struct ngx_kmp_push_track_s {
    ngx_pool_t                    *pool;
    ngx_log_t                      log;

    ngx_kmp_push_track_conf_t     *conf;
    ngx_str_t                      input_id;
    ngx_uint_t                     media_type;

    ngx_kmp_push_track_state_e     state;
    ngx_queue_t                    upstreams;
    size_t                         memory_limit;
    ngx_http_call_ctx_t           *publish_call;
    ngx_uint_t                     timescale;

    kmp_connect_packet_t           connect;
    ngx_str_t                      channel_id;
    ngx_str_t                      track_id;

    ngx_buf_queue_t                buf_queue;
    ngx_buf_t                      active_buf;

    void                          *ctx;
    ngx_kmp_push_track_handler_pt  handler;

    unsigned                       detached:1;
};


int64_t ngx_kmp_push_track_get_time(ngx_kmp_push_track_t *track);

ngx_http_call_ctx_t *ngx_kmp_push_track_http_call_create(
    ngx_kmp_push_track_t *track, ngx_http_call_init_t *ci);

ngx_int_t ngx_kmp_push_track_write_chain(ngx_kmp_push_track_t *track,
    ngx_chain_t *in, u_char *p);

ngx_int_t ngx_kmp_push_track_write(ngx_kmp_push_track_t *track, u_char *data,
    size_t size);

#endif /* _NGX_KMP_PUSH_TRACK_INTERNAL_H_INCLUDED_ */
