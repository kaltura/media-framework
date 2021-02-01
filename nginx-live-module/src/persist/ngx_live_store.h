#ifndef _NGX_LIVE_STORE_H_INCLUDED_
#define _NGX_LIVE_STORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_HTTP_NOT_FOUND
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#endif


/* read */

typedef void (*ngx_live_store_read_handler_pt)(void *data, ngx_int_t rc,
    ngx_buf_t *response);

typedef struct {
    ngx_pool_t                       *pool;
    ngx_live_channel_t               *channel;
    ngx_str_t                         path;
    size_t                            max_size;

    ngx_live_store_read_handler_pt    handler;
    void                             *data;
} ngx_live_store_read_request_t;


typedef void (*ngx_live_store_get_info_pt)(ngx_live_channel_t *channel,
    ngx_str_t *name);

typedef void *(*ngx_live_store_read_init_pt)(
    ngx_live_store_read_request_t *request);

typedef ngx_int_t (*ngx_live_store_read_pt)(void *data, off_t offset,
    size_t size);


/* write */

/* Note: the write pool must be freed when the channel is freed, this will
    cancel the write and prevent the handler from being called */

typedef void (*ngx_live_store_write_handler_pt)(void *data, ngx_int_t rc);

typedef struct {
    ngx_pool_t                       *pool;
    ngx_live_channel_t               *channel;
    ngx_str_t                         path;
    ngx_chain_t                      *cl;
    size_t                            size;

    ngx_live_store_write_handler_pt   handler;
    void                             *data;
} ngx_live_store_write_request_t;


typedef ngx_int_t (*ngx_live_store_write_pt)(
    ngx_live_store_write_request_t *request);

/* read + write */

typedef struct {
    ngx_live_store_get_info_pt        get_info;
    ngx_live_store_read_init_pt       read_init;
    ngx_live_store_read_pt            read;
    ngx_live_store_write_pt           write;
} ngx_live_store_t;

#endif /* _NGX_LIVE_STORE_H_INCLUDED_ */
