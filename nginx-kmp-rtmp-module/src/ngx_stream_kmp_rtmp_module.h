#ifndef _NGX_STREAM_KMP_RTMP_MODULE_H_INCLUDED_
#define _NGX_STREAM_KMP_RTMP_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_live_kmp.h>
#include <ngx_lba.h>
#include <ngx_buf_queue.h>
#include <ngx_buf_queue_stream.h>

#include "ngx_buf_chain.h"

typedef struct ngx_stream_kmp_rtmp_upstream_s ngx_stream_kmp_rtmp_upstream_t;
typedef struct ngx_stream_kmp_rtmp_track_s ngx_stream_kmp_rtmp_track_t;
typedef struct ngx_stream_kmp_rtmp_stream_s ngx_stream_kmp_rtmp_stream_t;

#define NGX_RTMP_KMP_FRAME_PART_COUNT    (10)

typedef struct {
    int64_t                            created;
    ngx_msec_t                         added;
    uint64_t                           id;
    int64_t                            pts;
    int64_t                            dts;
    uint32_t                           flags;
    uint32_t                           size;
    ngx_buf_chain_t                   *data;
} ngx_rtmp_kmp_frame_t;

typedef struct ngx_rtmp_kmp_frame_part_s  ngx_rtmp_kmp_frame_part_t;

struct ngx_rtmp_kmp_frame_part_s {
    ngx_rtmp_kmp_frame_part_t         *next;
    ngx_uint_t                         nelts;
    ngx_rtmp_kmp_frame_t               elts[NGX_RTMP_KMP_FRAME_PART_COUNT];
};


typedef struct {
    ngx_pool_t                        *pool;
    ngx_rtmp_kmp_frame_part_t         *part;
    ngx_rtmp_kmp_frame_part_t         *last;
    ngx_buf_chain_t                   *last_data_part;
    ngx_uint_t                         offset;
    ngx_uint_t                         count;
} ngx_rtmp_kmp_frame_list_t;


typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_queue_t                      queue;
} ngx_stream_kmp_rtmp_streams_t;

typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
} ngx_stream_kmp_rtmp_tracks_t;

struct ngx_stream_kmp_rtmp_upstream_s {
    ngx_str_node_t                   sn;        /* must be first */
    ngx_stream_kmp_rtmp_streams_t    streams;
    ngx_stream_kmp_rtmp_tracks_t     tracks;
    ngx_connection_t                *connection;
    ngx_log_t                       *log;
    ngx_chain_t                     *busy;
    ngx_chain_t                     *free;
    ngx_chain_t                    **last;
    ngx_event_t                      process;
    ngx_buf_queue_t                  buf_queue;
    size_t                           mem_left;
    ngx_msec_t                       wait_frame_timeout;
    ngx_uint_t                       chunk_size;
    ngx_buf_t                        active_buf;
};

struct ngx_stream_kmp_rtmp_track_s {
    ngx_rbtree_node_t                in;        /* must be first */
    ngx_stream_session_t            *s;
    ngx_log_t                       *log;
    ngx_pool_cleanup_t               cln;
    ngx_buf_queue_t                  buf_queue;
    uint64_t                         last_timestamp;
    uint32_t                         media_type;
    uint8_t                          init;
    kmp_media_info_t                 media_info;
    ngx_str_t                        media_info_data;
    ngx_stream_kmp_rtmp_stream_t    *stream;
    ngx_stream_kmp_rtmp_upstream_t  *upstream;
    unsigned                         no_msid:1;
    size_t                           mem_left;
    ngx_pool_t                      *pool;
    ngx_rtmp_kmp_frame_list_t        frames;
    ngx_buf_chain_t                 *free;
    uint32_t                         timescale;
};

struct ngx_stream_kmp_rtmp_stream_s {
    ngx_str_node_t                   sn;        /* must be first */
    ngx_queue_t                      queue;
    ngx_stream_kmp_rtmp_track_t     *tracks_list[2];
    ngx_uint_t                       track_count;
    time_t                           created;
    unsigned                         media_info_sent:1;
};


ngx_int_t ngx_stream_kmp_rtmp_send_chain(
    ngx_stream_kmp_rtmp_upstream_t *upstream);

#endif /* _NGX_STREAM_KMP_RTMP_MODULE_H_INCLUDED_ */