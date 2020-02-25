#ifndef _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef struct ngx_live_segment_info_elt_s   ngx_live_segment_info_elt_t;
typedef struct ngx_live_segment_info_node_s  ngx_live_segment_info_node_t;

typedef struct {
    ngx_queue_t                   *sentinel;
    ngx_live_segment_info_node_t  *node;
    ngx_live_segment_info_elt_t   *cur;
    ngx_live_segment_info_elt_t   *last;
    uint32_t                       bitrate;
} ngx_live_segment_info_iter_t;


/* iterator */
void ngx_live_segment_info_iter_init(ngx_live_segment_info_iter_t *iter,
    ngx_live_track_t *track, uint32_t segment_index);

uint32_t ngx_live_segment_info_iter_next(
    ngx_live_segment_info_iter_t *iter, uint32_t segment_index);


void ngx_live_segment_info_count(ngx_live_track_t *track, uint32_t first_index,
    uint32_t last_index, uint32_t *bitrate_count, uint32_t *gap_count);

#endif /* _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_ */
