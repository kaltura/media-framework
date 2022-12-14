#ifndef _NGX_LIVE_INPUT_BUFS_H_INCLUDED_
#define _NGX_LIVE_INPUT_BUFS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef struct ngx_live_input_bufs_lock_s  ngx_live_input_bufs_lock_t;


ngx_int_t ngx_live_input_bufs_get(ngx_live_track_t *track, ngx_buf_t *b);

ngx_buf_chain_t *ngx_live_input_bufs_read_chain(ngx_live_track_t *track,
    ngx_str_t *src, ngx_buf_chain_t **tail);

void ngx_live_input_bufs_set_min_used(ngx_live_track_t *track,
    uint32_t segment_index, u_char *ptr);

void ngx_live_input_bufs_link(ngx_live_track_t *dst, ngx_live_track_t *src);


ngx_live_input_bufs_lock_t *ngx_live_input_bufs_lock(ngx_live_track_t *track,
    uint32_t segment_index, u_char *ptr);

void ngx_live_input_bufs_unlock(ngx_live_input_bufs_lock_t *lock);

ngx_int_t ngx_live_input_bufs_lock_cleanup(ngx_pool_t *pool,
    ngx_live_track_t *track, uint32_t segment_index, u_char *ptr);

#endif /* _NGX_LIVE_INPUT_BUFS_H_INCLUDED_ */
