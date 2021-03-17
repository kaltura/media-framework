#ifndef _NGX_LIVE_MEDIA_INFO_H_INCLUDED_
#define _NGX_LIVE_MEDIA_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>
#include "media/media_format.h"


typedef struct ngx_live_media_info_node_s  ngx_live_media_info_node_t;

typedef struct {
    ngx_live_media_info_node_t  *cur;
    ngx_queue_t                 *sentinel;
} ngx_live_media_info_iter_t;


typedef struct {
    uint32_t                     track_id;
    uint32_t                     start_segment_index;
} ngx_live_media_info_persist_t;


media_info_t *ngx_live_media_info_clone(ngx_pool_t *pool, media_info_t *src);


/* pending */
ngx_int_t ngx_live_media_info_pending_add(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, uint32_t frame_index);

void ngx_live_media_info_pending_create_segment(ngx_live_track_t *track,
    uint32_t segment_index, ngx_flag_t *changed);

void ngx_live_media_info_pending_remove_frames(ngx_live_track_t *track,
    ngx_uint_t frame_count);

void ngx_live_media_info_pending_free_all(ngx_live_track_t *track);


/* active */
media_info_t *ngx_live_media_info_queue_get(ngx_live_track_t *track,
    uint32_t segment_index, uint32_t *track_id);

media_info_t *ngx_live_media_info_queue_get_last(ngx_live_track_t *track,
    kmp_media_info_t **kmp_media_info);

ngx_int_t ngx_live_media_info_queue_copy_last(ngx_live_track_t *dst,
    ngx_live_track_t *src, uint32_t segment_index);

ngx_int_t ngx_live_media_info_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_media_info_persist_t *mp, kmp_media_info_t *kmp_media_info,
    ngx_str_t *extra_data);


/* gap filling */
ngx_int_t ngx_live_media_info_queue_fill_gaps(ngx_live_channel_t *channel,
    uint32_t media_types_mask);


/* iterator */
ngx_flag_t ngx_live_media_info_iter_init(ngx_live_media_info_iter_t *iter,
    ngx_live_track_t *track, uint32_t segment_index);

uint32_t ngx_live_media_info_iter_next(ngx_live_media_info_iter_t *iter,
    uint32_t segment_index, media_info_t **media_info);

#endif /* _NGX_LIVE_MEDIA_INFO_H_INCLUDED_ */
