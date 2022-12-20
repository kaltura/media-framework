#ifndef _NGX_KMP_OUT_UPSTREAM_H_INCLUDED_
#define _NGX_KMP_OUT_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_buf_queue_stream.h>
#include <ngx_json_parser.h>
#include <ngx_http_call.h>


typedef enum {
    ngx_kmp_out_resume_from_last_acked,
    ngx_kmp_out_resume_from_last_sent,
    ngx_kmp_out_resume_from_last_written
} ngx_kmp_out_resume_from_e;


typedef struct {
    ngx_peer_connection_t        peer;
    u_char                       sockaddr_buf[NGX_SOCKADDRLEN];

    u_char                       remote_addr_buf[NGX_SOCKADDR_STRLEN];
    ngx_json_str_t               remote_addr;

    u_char                       local_addr_buf[NGX_SOCKADDR_STRLEN];
    ngx_json_str_t               local_addr;

    ngx_json_str_t               id;
    ngx_queue_t                  queue;
    ngx_kmp_out_track_t         *track;

    ngx_log_t                    log;
    ngx_pool_t                  *pool;
    ngx_msec_t                   timeout;

    ngx_http_call_ctx_t         *republish_call;
    ngx_event_t                  republish;
    ngx_msec_t                   republish_time;
    ngx_uint_t                   republishes;

    ngx_chain_t                **last;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    kmp_connect_packet_t         connect;
    ngx_buf_t                    connect_data;

    kmp_ack_frames_packet_t      ack_frames;
    u_char                      *recv_pos;

    ngx_buf_queue_stream_t       acked_reader;
    uint64_t                     acked_frame_id;
    uint64_t                     acked_upstream_frame_id;
    uint32_t                     acked_offset;
    ngx_buf_t                    acked_media_info;
    off_t                        acked_bytes;
    off_t                        sent_base;
    ngx_uint_t                   auto_acked_frames;
    ngx_kmp_out_resume_from_e    resume_from;

    unsigned                     sent_end:1;
    unsigned                     no_republish:1;
} ngx_kmp_out_upstream_t;


/*
 * NGX_ERROR - bad json
 * NGX_ABORT - memory error
 */
ngx_int_t ngx_kmp_out_upstream_from_json(ngx_pool_t *temp_pool,
    ngx_kmp_out_track_t *track, ngx_kmp_out_upstream_t *src,
    ngx_json_object_t *obj);

ngx_int_t ngx_kmp_out_upstream_send(ngx_kmp_out_upstream_t *u);

ngx_int_t ngx_kmp_out_upstream_append_buffer(ngx_kmp_out_upstream_t *u,
    ngx_buf_t *buffer);

ngx_int_t ngx_kmp_out_upstream_auto_ack(ngx_kmp_out_upstream_t *u,
    size_t left, ngx_flag_t force);

void ngx_kmp_out_upstream_free(ngx_kmp_out_upstream_t *u);


size_t ngx_kmp_out_upstream_json_get_size(ngx_kmp_out_upstream_t *obj);

u_char *ngx_kmp_out_upstream_json_write(u_char *p,
    ngx_kmp_out_upstream_t *obj);

#endif /* _NGX_KMP_OUT_UPSTREAM_H_INCLUDED_ */
