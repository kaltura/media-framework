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
    ngx_str_t                      json_info;

    ngx_kmp_push_track_state_e     state;
    ngx_queue_t                    upstreams;
    size_t                         mem_left;
    size_t                         mem_limit;
    size_t                         mem_high_watermark;
    size_t                         mem_low_watermark;
    ngx_http_call_ctx_t           *publish_call;

    kmp_connect_packet_t           connect;
    ngx_str_t                      channel_id;
    ngx_str_t                      track_id;

    ngx_buf_queue_t                buf_queue;
    ngx_buf_t                      active_buf;
    ngx_event_t                    flush;

    kmp_media_info_t               media_info;
    ngx_str_t                      extra_data;
    size_t                         extra_data_size;
    int64_t                        last_timestamp;
    int64_t                        last_created;
    ngx_uint_t                     sent_frames;
    ngx_uint_t                     sent_key_frames;
    size_t                         written;

    void                          *ctx;
    ngx_kmp_push_track_handler_pt  handler;

    ngx_str_t                      unpublish_reason;

    unsigned                       detached:1;
    unsigned                       write_error:1;
};


int64_t ngx_kmp_push_track_get_time(ngx_kmp_push_track_t *track);

void ngx_kmp_push_track_set_error_reason(ngx_kmp_push_track_t *track,
    char *code);

ngx_http_call_ctx_t *ngx_kmp_push_track_http_call_create(
    ngx_kmp_push_track_t *track, ngx_http_call_init_t *ci);

ngx_int_t ngx_kmp_push_track_write_media_info(ngx_kmp_push_track_t *track);

ngx_int_t ngx_kmp_push_track_write_frame(ngx_kmp_push_track_t *track,
    kmp_frame_packet_t *frame, ngx_chain_t *in, u_char *p);


size_t ngx_kmp_push_track_media_info_json_get_size(ngx_kmp_push_track_t *track);

u_char *ngx_kmp_push_track_media_info_json_write(u_char *p,
    ngx_kmp_push_track_t *track);

#endif /* _NGX_KMP_PUSH_TRACK_INTERNAL_H_INCLUDED_ */
