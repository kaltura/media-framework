#ifndef _NGX_LIVE_MEDIA_INFO_H_INCLUDED_
#define _NGX_LIVE_MEDIA_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>


typedef ngx_ksmp_media_info_header_t  ngx_live_media_info_persist_t;

struct ngx_live_media_info_s {
    kmp_media_info_t  info;
    ngx_str_t         extra;
};


/* pending */
ngx_int_t ngx_live_media_info_pending_add(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, uint32_t frame_index);

ngx_int_t ngx_live_media_info_pending_create_segment(ngx_live_track_t *track,
    uint32_t segment_index);

void ngx_live_media_info_pending_remove_frames(ngx_live_track_t *track,
    ngx_uint_t frame_count);

void ngx_live_media_info_pending_free_all(ngx_live_track_t *track);


/* active */
void ngx_live_media_info_update_stats(ngx_live_segment_t *segment,
    uint32_t bitrate);

ngx_live_media_info_node_t *ngx_live_media_info_queue_get_node(
    ngx_live_track_t *track, uint32_t segment_index, uint32_t *track_id);

ngx_live_media_info_t *ngx_live_media_info_queue_get_last(
    ngx_live_track_t *track);

ngx_int_t ngx_live_media_info_queue_copy_last(ngx_live_track_t *dst,
    ngx_live_track_t *src, uint32_t segment_index);

ngx_int_t ngx_live_media_info_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_media_info_persist_t *mp, ngx_live_media_info_t *media_info);

ngx_flag_t ngx_live_media_info_track_exists(ngx_live_timeline_t *timeline,
    ngx_live_track_t *track);


/* gap filling */
ngx_int_t ngx_live_media_info_queue_fill_gaps(ngx_live_channel_t *channel,
    uint32_t media_types_mask);

#endif /* _NGX_LIVE_MEDIA_INFO_H_INCLUDED_ */
