#ifndef _NGX_TS_KMP_TRACK_H_INCLUDED_
#define _NGX_TS_KMP_TRACK_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_ts_aac.h>
#include <ngx_ts_stream.h>
#include <ngx_kmp_push_track.h>


typedef struct  {
    ngx_rbtree_node_t        in;
    ngx_queue_t              queue;
    ngx_kmp_push_track_t    *track;
    ngx_buf_t                sps;
    ngx_buf_t                pps;
    ngx_ts_aac_params_t      last_aac_params;
    uint32_t                 extra_data_alloc;
    uint32_t                 caption_tries;
    int64_t                  timestamp;
    int64_t                  last_timestamp;
    unsigned                 timestamps_synced:1;
    unsigned                 media_info_sent:1;
    unsigned                 published:1;
} ngx_ts_kmp_track_t;

ngx_ts_kmp_track_t *ngx_ts_kmp_track_get(ngx_ts_kmp_ctx_t *ctx, uint16_t pid);

ngx_int_t ngx_ts_kmp_track_create(ngx_ts_handler_data_t *hd);

ngx_int_t ngx_ts_kmp_track_pes_handler(ngx_ts_kmp_track_t *ts_track,
    ngx_ts_handler_data_t *hd);

#endif /* _NGX_TS_KMP_TRACK_H_INCLUDED_ */
