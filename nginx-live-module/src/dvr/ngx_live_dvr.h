#ifndef _NGX_LIVE_DVR_H_INCLUDED_
#define _NGX_LIVE_DVR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


#ifndef NGX_HTTP_NOT_FOUND
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#endif


/* read */

typedef void (*ngx_live_dvr_read_handler_pt)(void *data, ngx_int_t rc,
    ngx_buf_t *response);

typedef struct {
    ngx_pool_t                     *pool;
    ngx_live_channel_t             *channel;
    ngx_str_t                       path;

    ngx_live_dvr_read_handler_pt    handler;
    void                           *data;
} ngx_live_dvr_read_request_t;


typedef void (*ngx_live_dvr_get_info_pt)(ngx_live_channel_t *channel,
    ngx_str_t *name);

typedef void *(*ngx_live_dvr_read_init_pt)(
    ngx_live_dvr_read_request_t *request);

typedef ngx_int_t (*ngx_live_dvr_read_pt)(void *data, off_t offset,
    size_t size);


/* write */

typedef void (*ngx_live_dvr_save_handler_pt)(void *data, ngx_int_t rc);

typedef struct {
    ngx_pool_t                    *pool;
    ngx_live_channel_t            *channel;
    ngx_str_t                      path;
    ngx_chain_t                   *cl;
    size_t                         size;

    ngx_live_dvr_save_handler_pt   handler;
    void                          *data;
} ngx_live_dvr_save_request_t;


typedef void *(*ngx_live_dvr_save_pt)(ngx_live_dvr_save_request_t *request);

typedef void (*ngx_live_dvr_cancel_save_pt)(void *data);

/* read + write */

typedef struct {
    ngx_live_dvr_get_info_pt     get_info;
    ngx_live_dvr_read_init_pt    read_init;
    ngx_live_dvr_read_pt         read;
    ngx_live_dvr_save_pt         save;
    ngx_live_dvr_cancel_save_pt  cancel_save;
} ngx_live_dvr_store_t;


char *ngx_live_dvr_set_store(ngx_conf_t *cf, ngx_live_dvr_store_t *store);

#endif /* _NGX_LIVE_DVR_H_INCLUDED_ */
