#ifndef _NGX_KMP_IN_H_INCLUDED_
#define _NGX_KMP_IN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>
#include <ngx_json_parser.h>
#include <ngx_json_str.h>


typedef struct ngx_kmp_in_ctx_s  ngx_kmp_in_ctx_t;


typedef struct {
    ngx_msec_t             read_timeout;
    ngx_msec_t             send_timeout;
    ngx_str_t              dump_folder;
    ngx_uint_t             log_frames;
} ngx_kmp_in_conf_t;


typedef struct {
    ngx_uint_t             duplicate;
    ngx_uint_t             empty;
    ngx_uint_t             empty_duration;
    ngx_uint_t             no_media_info;
    ngx_uint_t             no_key;
} ngx_kmp_in_stats_skip_t;


typedef struct {
    uint64_t               min;
    uint64_t               max;
    uint64_t               sum;
    ngx_uint_t             count;
} ngx_kmp_in_stats_latency_t;


typedef struct {
    kmp_connect_packet_t  *header;

    uint64_t               skip_count;
    unsigned               skip_wait_key:1;
} ngx_kmp_in_evt_connected_t;


typedef struct {
    kmp_connect_packet_t  *header;
    ngx_buf_chain_t       *data;
} ngx_kmp_in_evt_connect_data_t;


typedef struct {
    kmp_media_info_t       media_info;
    ngx_buf_chain_t       *extra_data;
    uint32_t               extra_data_size;
} ngx_kmp_in_evt_media_info_t;


typedef struct {
    uint64_t               frame_id;
    kmp_frame_t            frame;

    ngx_buf_chain_t       *data_head;
    ngx_buf_chain_t       *data_tail;
    size_t                 size;
} ngx_kmp_in_evt_frame_t;


typedef ngx_int_t (*ngx_kmp_in_connected_pt)(ngx_kmp_in_ctx_t *ctx,
    ngx_kmp_in_evt_connected_t *evt);
typedef void (*ngx_kmp_in_disconnected_pt)(ngx_kmp_in_ctx_t *ctx);
typedef void (*ngx_kmp_in_disconnect_pt)(ngx_kmp_in_ctx_t *ctx, ngx_uint_t rc);

/*
 * NGX_ABORT - fatal error (e.g. memory)
 * NGX_ERROR - other error
 */
typedef ngx_int_t (*ngx_kmp_in_connect_data_pt)(ngx_kmp_in_ctx_t *ctx,
    ngx_kmp_in_evt_connect_data_t *evt);

/*
 * NGX_OK - handled successfully, the handler takes ownership of
 *      the ngx_buf_chain_t's of the extra data / frame data
 * NGX_DONE - the ngx_buf_chain_t's of the extra data / frame data should be
 *      freed by nginx-kmp-in-module.
 * NGX_ABORT - fatal error (e.g. memory)
 * NGX_ERROR - other error
 */
typedef ngx_int_t  (*ngx_kmp_in_media_info_pt)(void *data,
    ngx_kmp_in_evt_media_info_t *evt);

typedef ngx_int_t  (*ngx_kmp_in_frame_pt)(void *data,
    ngx_kmp_in_evt_frame_t *evt);

typedef void (*ngx_kmp_in_end_stream_pt)(void *data);


typedef ngx_buf_chain_t *(*ngx_kmp_in_alloc_chain_pt)(void *data);
typedef void (*ngx_kmp_in_free_chain_list_pt)(void *data,
    ngx_buf_chain_t *head, ngx_buf_chain_t *tail);
typedef ngx_int_t (*ngx_kmp_in_get_input_buf_pt)(void *data, ngx_buf_t *b);


struct ngx_kmp_in_ctx_s {
    ngx_kmp_in_conf_t               conf;
    ngx_connection_t               *connection;
    ngx_log_t                      *log;
    time_t                          start_sec;

    ngx_json_str_t                  remote_addr;
    u_char                          remote_addr_buf[NGX_SOCKADDR_STRLEN];

    ngx_fd_t                        dump_fd;

    ngx_json_str_t                  channel_id;
    ngx_json_str_t                  track_id;
    void                           *data;

    /* operations */
    ngx_kmp_in_disconnect_pt        disconnect;

    /* events */
    ngx_kmp_in_connected_pt         connected;
    ngx_kmp_in_connect_data_pt      connect_data;
    ngx_kmp_in_disconnected_pt      disconnected;

    ngx_kmp_in_media_info_pt        media_info;
    ngx_kmp_in_frame_pt             frame;
    ngx_kmp_in_end_stream_pt        end_stream;

    /* callbacks */
    ngx_kmp_in_alloc_chain_pt       alloc_chain;
    ngx_kmp_in_free_chain_list_pt   free_chain_list;
    ngx_kmp_in_get_input_buf_pt     get_input_buf;

    /* stats */
    size_t                          received_bytes;
    size_t                          received_data_bytes;
    ngx_uint_t                      received_frames;
    ngx_uint_t                      received_key_frames;
    int64_t                         last_created;
    ngx_kmp_in_stats_skip_t         skipped;
    ngx_kmp_in_stats_latency_t      latency;

    ngx_uint_t                      timescale;
    ngx_uint_t                      media_type;

    /* parser */
    ngx_buf_t                       active_buf;
    kmp_packet_header_t             packet_header;
    u_char                         *packet_header_pos;
    uint32_t                        packet_left;
    ngx_buf_chain_t                *packet_data_first;
    ngx_buf_chain_t                *packet_data_last;

    /* acks */
    kmp_ack_frames_packet_t         ack_packet;
    u_char                         *ack_packet_pos;
    uint64_t                        cur_frame_id;
    uint64_t                        acked_frame_id;
    uint64_t                        skip_left;

    unsigned                        header_read:1;
    unsigned                        wait_key:1;
    unsigned                        skip_wait_key:1;
    unsigned                        writing:1;
};


ngx_kmp_in_ctx_t *ngx_kmp_in_create(ngx_connection_t *c,
    ngx_kmp_in_conf_t *conf);
void ngx_kmp_in_ack_frames(ngx_kmp_in_ctx_t *ctx, uint64_t next_frame_id);

ngx_int_t ngx_kmp_in_write_handler(ngx_kmp_in_ctx_t *ctx);
ngx_int_t ngx_kmp_in_read_handler(ngx_kmp_in_ctx_t *ctx);

void ngx_kmp_in_update_latency_stats(ngx_uint_t timescale,
    ngx_kmp_in_stats_latency_t *stats, int64_t from);

/*
 * NGX_ABORT - fatal error (e.g. memory)
 * NGX_ERROR - parse error
 */
ngx_int_t ngx_kmp_in_parse_json_chain(ngx_pool_t *pool, ngx_buf_chain_t *chain,
    size_t size, ngx_json_value_t *json);

size_t ngx_kmp_in_json_get_size(ngx_kmp_in_ctx_t *ctx);
u_char *ngx_kmp_in_json_write(u_char *p, ngx_kmp_in_ctx_t *ctx);

size_t ngx_kmp_in_stats_latency_json_get_size(
    ngx_kmp_in_stats_latency_t *latency);
u_char *ngx_kmp_in_stats_latency_json_write(u_char *p,
    ngx_kmp_in_stats_latency_t *latency);

void ngx_kmp_in_init_conf(ngx_kmp_in_conf_t *conf);
void ngx_kmp_in_merge_conf(ngx_kmp_in_conf_t *prev, ngx_kmp_in_conf_t *conf);


extern ngx_conf_enum_t  ngx_kmp_in_log_frames[];

#endif /* _NGX_KMP_IN_H_INCLUDED_ */
