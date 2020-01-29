#ifndef _NGX_LIVE_FILLER_H_INCLUDED_
#define _NGX_LIVE_FILLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


ngx_int_t ngx_live_filler_fill(ngx_live_channel_t *channel,
    uint32_t media_type_mask, int64_t start_pts, ngx_flag_t force_new_period,
    uint32_t min_duration, uint32_t max_duration, uint32_t *fill_duration);

#endif /* _NGX_LIVE_FILLER_H_INCLUDED_ */
