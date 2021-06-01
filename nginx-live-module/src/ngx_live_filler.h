#ifndef _NGX_LIVE_FILLER_H_INCLUDED_
#define _NGX_LIVE_FILLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


ngx_int_t ngx_live_filler_fill(ngx_live_channel_t *channel,
    uint32_t media_type_mask, int64_t start_pts,
    uint32_t min_duration, uint32_t max_duration, uint32_t *fill_duration);

ngx_int_t ngx_live_filler_serve_segments(ngx_pool_t *pool,
    ngx_array_t *track_refs, uint32_t segment_index,
    ngx_chain_t ***last, size_t *size);

#endif /* _NGX_LIVE_FILLER_H_INCLUDED_ */
