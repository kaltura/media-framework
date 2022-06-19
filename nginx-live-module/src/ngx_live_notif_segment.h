#ifndef _NGX_LIVE_NOTIF_SEGMENT_H_INCLUDED_
#define _NGX_LIVE_NOTIF_SEGMENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_notif.h"


typedef struct {
    ngx_rbtree_node_t           node;       /* must be first */
    //ngx_rbtree_t               *rbtree;
    ngx_live_track_t           *track;
    ngx_queue_t                 queue;

    uint32_t                    part_index;
    uint32_t                    timeline_int_id;
    ngx_pool_cleanup_t         *cln;
    ngx_live_notif_handler_pt   handler;
    void                       *data;
} ngx_live_notif_segment_sub_t;


ngx_live_notif_segment_sub_t *ngx_live_notif_segment_subscribe(
    ngx_pool_t *pool, ngx_live_track_t *track, ngx_live_timeline_t *timeline,
    uint32_t segment_index, uint32_t part_index);

void ngx_live_notif_segment_publish(ngx_live_track_t *track,
    uint32_t segment_index, uint32_t part_index, ngx_int_t rc);

void ngx_live_notif_segment_publish_timeline(ngx_live_timeline_t *timeline,
    ngx_int_t rc);

#endif /* _NGX_LIVE_NOTIF_SEGMENT_H_INCLUDED_ */
