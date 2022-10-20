#ifndef _NGX_KMP_OUT_TRACK_INTERNAL_H_INCLUDED_
#define _NGX_KMP_OUT_TRACK_INTERNAL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_md5.h>

#include <ngx_live_kmp.h>
#include <ngx_http_call.h>
#include <ngx_buf_queue.h>
#include <ngx_buf_queue_stream.h>
#include <ngx_json_str.h>

#include "ngx_kmp_out_track.h"


#define ngx_kmp_out_track_marker_get_size(track, marker)                     \
    ((track)->stats.written - (marker)->written)


typedef enum {
    NGX_KMP_TRACK_INITIAL,
    NGX_KMP_TRACK_INACTIVE,
    NGX_KMP_TRACK_WAIT_PUBLISH_RESPONSE,
    NGX_KMP_TRACK_ACTIVE,
} ngx_kmp_out_track_state_e;


typedef void (*ngx_kmp_out_track_handler_pt)(void *ctx);


typedef struct {
    size_t                         written;
    ngx_buf_queue_stream_t         reader;
} ngx_kmp_out_track_marker_t;


typedef struct {
    size_t                         written;
    int64_t                        last_timestamp;
    int64_t                        last_created;
    ngx_uint_t                     sent_frames;
    ngx_uint_t                     sent_key_frames;

    time_t                         period_end;
    size_t                         initial_written;
    ngx_uint_t                     initial_sent_frames;

    ngx_uint_t                     frame_rate;     /* frames / 100 sec */
    ngx_uint_t                     bitrate;
} ngx_kmp_out_track_stats_t;


struct ngx_kmp_out_track_s {
    ngx_str_node_t                 sn;
    ngx_queue_t                    queue;
    u_char                         id_buf[NGX_INT_T_LEN];
    uintptr_t                      id_escape;

    ngx_pool_t                    *pool;
    ngx_log_t                      log;

    ngx_kmp_out_track_conf_t      *conf;
    ngx_json_str_t                 input_id;
    ngx_str_t                      json_info;

    ngx_kmp_out_track_state_e      state;
    ngx_queue_t                    upstreams;
    size_t                         mem_left;
    size_t                         mem_limit;
    size_t                         mem_high_watermark;
    size_t                         mem_low_watermark;
    ngx_http_call_ctx_t           *publish_call;

    kmp_connect_packet_t           connect;
    ngx_json_str_t                 channel_id;
    ngx_json_str_t                 track_id;

    ngx_buf_queue_t                buf_queue;
    ngx_buf_t                      active_buf;
    ngx_event_t                    flush;
    ngx_event_t                    keepalive;

    kmp_media_info_t               media_info;
    ngx_str_t                      extra_data;
    size_t                         extra_data_size;

    ngx_kmp_out_track_stats_t      stats;
    ngx_kmp_out_track_marker_t     cur_frame;
    ngx_uint_t                     send_blocked;

    void                          *ctx;
    ngx_kmp_out_track_handler_pt   handler;

    ngx_json_str_t                 unpublish_reason;

    unsigned                       detached:1;
    unsigned                       write_error:1;
};


ngx_int_t ngx_kmp_out_track_init_process(ngx_cycle_t *cycle);


int64_t ngx_kmp_out_track_get_time(ngx_kmp_out_track_t *track);

void ngx_kmp_out_track_set_error_reason(ngx_kmp_out_track_t *track,
    char *code);

ngx_http_call_ctx_t *ngx_kmp_out_track_http_call_create(
    ngx_kmp_out_track_t *track, ngx_http_call_init_t *ci);

ngx_int_t ngx_kmp_out_track_alloc_extra_data(ngx_kmp_out_track_t *track,
    size_t size);


void ngx_kmp_out_track_write_marker_start(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker);

ngx_int_t ngx_kmp_out_track_write_marker_end(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker, void *data, size_t size);


ngx_int_t ngx_kmp_out_track_write_media_info(ngx_kmp_out_track_t *track);

ngx_int_t ngx_kmp_out_track_write_frame(ngx_kmp_out_track_t *track,
    kmp_frame_packet_t *frame, ngx_chain_t *in, u_char *p);

ngx_int_t ngx_kmp_out_track_write_frame_start(ngx_kmp_out_track_t *track);

ngx_int_t ngx_kmp_out_track_write_frame_data(ngx_kmp_out_track_t *track,
    u_char *data, size_t size);

ngx_int_t ngx_kmp_out_track_write_frame_end(ngx_kmp_out_track_t *track,
    kmp_frame_packet_t *frame);


size_t ngx_kmp_out_track_media_info_json_get_size(
    ngx_kmp_out_track_t *track);

u_char *ngx_kmp_out_track_media_info_json_write(u_char *p,
    ngx_kmp_out_track_t *track);

#endif /* _NGX_KMP_OUT_TRACK_INTERNAL_H_INCLUDED_ */
