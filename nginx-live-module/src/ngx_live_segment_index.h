#ifndef _NGX_LIVE_SEGMENT_INDEX_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_INDEX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_input_bufs.h"


typedef struct ngx_live_segment_index_s  ngx_live_segment_index_t;

struct ngx_live_segment_cleanup_s {
    ngx_queue_t                    queue;
    ngx_live_segment_cleanup_pt    handler;
    void                          *data;
    ngx_live_input_bufs_lock_t   **locks;
    ngx_live_input_bufs_lock_t   **locks_end;
};


ngx_int_t ngx_live_segment_index_create(ngx_live_channel_t *channel,
    ngx_flag_t exists);

void ngx_live_segment_index_persisted(ngx_live_channel_t *channel,
    uint32_t min_segment_index, uint32_t max_segment_index, ngx_int_t rc);

ngx_live_segment_index_t *ngx_live_segment_index_get(
    ngx_live_channel_t *channel, uint32_t segment_index);

ngx_live_segment_cleanup_t *ngx_live_segment_index_cleanup_add(
    ngx_pool_t *pool, ngx_live_segment_index_t *index, uint32_t max_locks);

ngx_int_t ngx_live_segment_index_lock(ngx_live_segment_cleanup_t *cln,
    ngx_live_segment_t *segment);

#endif /* _NGX_LIVE_SEGMENT_INDEX_H_INCLUDED_ */
