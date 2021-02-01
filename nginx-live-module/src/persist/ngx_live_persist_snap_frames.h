#ifndef _NGX_LIVE_PERSIST_SNAP_FRAMES_H_INCLUDED_
#define _NGX_LIVE_PERSIST_SNAP_FRAMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


ngx_live_persist_snap_t *ngx_live_persist_snap_frames_create(
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_SNAP_FRAMES_H_INCLUDED_ */
