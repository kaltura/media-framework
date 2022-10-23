#ifndef _NGX_KMP_RTMP_UPSTREAM_H_INCLUDED_
#define _NGX_KMP_RTMP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>

#include <ngx_buf_queue.h>
#include <ngx_json_parser.h>
#include <ngx_json_str.h>

#include "ngx_kmp_rtmp.h"
#include "ngx_kmp_rtmp_handshake.h"


typedef struct {
    ngx_rbtree_t                    rbtree;
    ngx_rbtree_node_t               sentinel;
    ngx_queue_t                     queue;
} ngx_kmp_rtmp_streams_t;


typedef struct {
    ngx_rbtree_t                    dts_rbtree;
    ngx_rbtree_node_t               dts_sentinel;

    ngx_rbtree_t                    added_rbtree;
    ngx_rbtree_node_t               added_sentinel;
} ngx_kmp_rtmp_tracks_t;


struct ngx_kmp_rtmp_upstream_s {
    ngx_str_node_t                  sn;        /* must be first */
    uintptr_t                       id_escape;
    ngx_queue_t                     queue;

    ngx_log_t                       log;
    ngx_pool_t                     *pool;
    size_t                          mem_left;
    size_t                          mem_limit;

    ngx_kmp_rtmp_upstream_conf_t    conf;
    ngx_json_str_t                  url;
    ngx_json_str_t                  header;
    ngx_str_t                       opaque;

    ngx_resolver_ctx_t             *resolve_ctx;
    in_port_t                       port;

    ngx_peer_connection_t           peer;
    u_char                          sockaddr_buf[NGX_SOCKADDRLEN];

    u_char                          remote_addr_buf[NGX_SOCKADDR_STRLEN];
    ngx_json_str_t                  remote_addr;

    u_char                          local_addr_buf[NGX_SOCKADDR_STRLEN];
    ngx_json_str_t                  local_addr;

    ngx_kmp_rtmp_handshake_t       *hs;

    ngx_buf_queue_t                 buf_queue;
    ngx_buf_t                       active_buf;
    ngx_event_t                     flush;

    ngx_chain_t                    *free;
    ngx_chain_t                   **last;
    ngx_chain_t                    *busy;

    ngx_buf_chain_t                *free_chains;

    ngx_kmp_rtmp_streams_t          streams;
    uint32_t                        tx_id;
    uint32_t                        last_msid;

    ngx_kmp_rtmp_tracks_t           tracks;
    ngx_event_t                     process;

    u_char                          recv_buf[128];

    size_t                          written_bytes;
    size_t                          received_bytes;

    ngx_event_t                     close;

    ngx_fd_t                        dump_fd;

    unsigned                        write_error:1;
    unsigned                        freed:1;
};


ngx_int_t ngx_kmp_rtmp_upstream_get_or_create(ngx_pool_t *temp_pool,
    ngx_kmp_rtmp_upstream_conf_t *conf, ngx_json_value_t *value,
    ngx_kmp_rtmp_upstream_t **upstream, ngx_str_t *stream_name);

void ngx_kmp_rtmp_upstream_finalize(ngx_kmp_rtmp_upstream_t *u);

ngx_buf_chain_t *ngx_kmp_rtmp_upstream_alloc_chain(ngx_kmp_rtmp_upstream_t *u);
void ngx_kmp_rtmp_upstream_free_chain_list(ngx_kmp_rtmp_upstream_t *u,
    ngx_buf_chain_t *head, ngx_buf_chain_t *tail);

ngx_int_t ngx_kmp_rtmp_upstream_write(void *data, void *buf, size_t size);
u_char *ngx_kmp_rtmp_upstream_get_buf(ngx_kmp_rtmp_upstream_t *u, size_t size);

void ngx_kmp_rtmp_upstream_stream_removed(ngx_kmp_rtmp_upstream_t *u);

#endif /* _NGX_KMP_RTMP_UPSTREAM_H_INCLUDED_ */
