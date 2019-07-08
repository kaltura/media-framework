#ifndef _NGX_KMP_PUSH_UPSTREAM_H_INCLUDED_
#define _NGX_KMP_PUSH_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>
#include <ngx_buf_queue_reader.h>
#include <ngx_json_parser.h>


typedef struct {
    ngx_peer_connection_t      peer;
    u_char                     sockaddr_buf[NGX_SOCKADDRLEN];
    u_char                     addr_text_buf[NGX_SOCKADDR_STRLEN];
    ngx_str_t                  addr_text;

    ngx_str_t                  id;
    ngx_queue_t                queue;
    ngx_kmp_push_track_t      *track;

    ngx_log_t                  log;
    ngx_pool_t                *pool;
    ngx_msec_t                 timeout;

    ngx_chain_t              **last;
    ngx_chain_t               *free;
    ngx_chain_t               *busy;

    kmp_connect_packet_t       connect;

    kmp_ack_frames_packet_t    ack_frames;
    u_char                    *recv_pos;

    ngx_buf_queue_reader_t     acked_reader;
    uint64_t                   acked_frame_id;
    uint32_t                   acked_offset;
    ngx_buf_t                  acked_media_info;
    off_t                      acked_bytes;
    off_t                      sent_base;

    unsigned                   sent_buffered:1;
    unsigned                   sent_end:1;
    unsigned                   auto_ack:1;
    unsigned                   no_republish:1;
} ngx_kmp_push_upstream_t;


ngx_int_t ngx_kmp_push_upstream_from_json(ngx_pool_t *temp_pool,
    ngx_kmp_push_track_t *track, ngx_json_object_t *json);

ngx_int_t ngx_kmp_push_upstream_send(ngx_kmp_push_upstream_t *u);

ngx_int_t ngx_kmp_push_upstream_append_buffer(ngx_kmp_push_upstream_t *u,
    ngx_buf_t *buffer);

void ngx_kmp_push_upstream_free(ngx_kmp_push_upstream_t *u);

#endif /* _NGX_KMP_PUSH_UPSTREAM_H_INCLUDED_ */
