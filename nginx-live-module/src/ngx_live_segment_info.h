#ifndef _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_
#define _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef ngx_ksmp_segment_info_elt_t  ngx_live_segment_info_elt_t;

typedef struct ngx_live_segment_info_node_s  ngx_live_segment_info_node_t;


ngx_flag_t ngx_live_segment_info_segment_exists(ngx_live_track_t *track,
    uint32_t start, uint32_t end);

ngx_flag_t ngx_live_segment_info_timeline_exists(ngx_live_track_t *track,
    ngx_live_timeline_t *timeline);

#endif /* _NGX_LIVE_SEGMENT_INFO_H_INCLUDED_ */
