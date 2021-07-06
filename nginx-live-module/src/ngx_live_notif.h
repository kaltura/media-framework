#ifndef _NGX_LIVE_NOTIF_H_INCLUDED_
#define _NGX_LIVE_NOTIF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef void (*ngx_live_notif_handler_pt)(void *arg, ngx_int_t rc);


enum {
    NGX_LIVE_NOTIF_CHANNEL_READY,

    NGX_LIVE_NOTIF_COUNT
};


typedef struct {
    ngx_queue_t                 queue;
    ngx_pool_cleanup_t         *cln;
    ngx_live_notif_handler_pt   handler;
    void                       *data;
} ngx_live_notif_sub_t;


void ngx_live_notif_publish(ngx_live_channel_t *pub, ngx_uint_t event,
    ngx_int_t rc);

ngx_live_notif_sub_t *ngx_live_notif_subscribe(ngx_live_channel_t *pub,
    ngx_uint_t event, ngx_live_channel_t *sub, ngx_pool_cleanup_t *cln);

#endif /* _NGX_LIVE_NOTIF_H_INCLUDED_ */
