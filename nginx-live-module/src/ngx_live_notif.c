#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_notif.h"


typedef struct {
    ngx_queue_t           queue[NGX_LIVE_NOTIF_COUNT];
} ngx_live_notif_pub_t;


typedef struct {
    ngx_live_notif_sub_t  sub;
    ngx_live_notif_pub_t  pub;
} ngx_live_notif_channel_ctx_t;


static ngx_int_t ngx_live_notif_postconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_notif_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_live_notif_postconfiguration,       /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create preset configuration */
    NULL,                                   /* merge preset configuration */
};

ngx_module_t  ngx_live_notif_module = {
    NGX_MODULE_V1,
    &ngx_live_notif_module_ctx,             /* module context */
    NULL,                                   /* module directives */
    NGX_LIVE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_live_notif_detach(void *data)
{
    ngx_live_notif_sub_t  *sub = data;

    /* silently remove the notification */
    sub->cln = NULL;
    ngx_queue_remove(&sub->queue);
}


ngx_live_notif_sub_t *
ngx_live_notif_subscribe(ngx_live_channel_t *pub, ngx_uint_t event,
    ngx_live_channel_t *sub, ngx_pool_cleanup_t *cln)
{
    ngx_live_notif_channel_ctx_t  *sub_cctx;
    ngx_live_notif_channel_ctx_t  *pub_cctx;

    ngx_log_error(NGX_LOG_INFO, &sub->log, 0,
        "ngx_live_notif_subscribe: called, pub: %V, event: %ui",
        &pub->sn.str, event);

    sub_cctx = ngx_live_get_module_ctx(sub, ngx_live_notif_module);
    pub_cctx = ngx_live_get_module_ctx(pub, ngx_live_notif_module);

    cln->handler = ngx_live_notif_detach;
    cln->data = &sub_cctx->sub;

    ngx_queue_insert_tail(&pub_cctx->pub.queue[event], &sub_cctx->sub.queue);
    sub_cctx->sub.cln = cln;

    return &sub_cctx->sub;
}


void
ngx_live_notif_publish(ngx_live_channel_t *pub, ngx_uint_t event, ngx_int_t rc)
{
    ngx_queue_t                   *q;
    ngx_live_notif_sub_t          *notif;
    ngx_live_notif_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(pub, ngx_live_notif_module);

    for (q = ngx_queue_head(&cctx->pub.queue[event]);
        q != ngx_queue_sentinel(&cctx->pub.queue[event]); )
    {
        notif = ngx_queue_data(q, ngx_live_notif_sub_t, queue);
        q = ngx_queue_next(q);      /* notification may be freed */

        notif->cln->handler = NULL;
        notif->cln = NULL;

        ngx_log_error(NGX_LOG_INFO, &pub->log, 0,
            "ngx_live_notif_publish: calling handler %i, event: %ui",
            rc, event);

        notif->handler(notif->data, rc);
    }

    ngx_queue_init(&cctx->pub.queue[event]);
}


static ngx_int_t
ngx_live_notif_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_uint_t                     i;
    ngx_live_notif_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_notif_channel_init: alloc failed");
        return NGX_ERROR;
    }

    for (i = 0; i < NGX_LIVE_NOTIF_COUNT; i++) {
        ngx_queue_init(&cctx->pub.queue[i]);
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_notif_module);

    return NGX_OK;
}


static ngx_int_t
ngx_live_notif_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_uint_t                     i;
    ngx_live_notif_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_notif_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    for (i = 0; i < NGX_LIVE_NOTIF_COUNT; i++) {
        ngx_live_notif_publish(channel, i, NGX_ABORT);
    }

    if (cctx->sub.cln != NULL) {
        cctx->sub.cln->handler = NULL;

        ngx_queue_remove(&cctx->sub.queue);

        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_notif_channel_free: calling handler");

        cctx->sub.handler(cctx->sub.data, NGX_ABORT);
    }

    return NGX_OK;
}


static ngx_live_channel_event_t  ngx_live_notif_channel_events[] = {
    { ngx_live_notif_channel_init,     NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_notif_channel_free,     NGX_LIVE_EVENT_CHANNEL_FREE },

      ngx_live_null_event
};


static ngx_int_t
ngx_live_notif_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf, ngx_live_notif_channel_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
