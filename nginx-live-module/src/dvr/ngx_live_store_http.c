#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http_call.h>
#include "../ngx_live_segment_cache.h"
#include "ngx_live_store_http.h"


#define NGX_HTTP_OK                        200
#define NGX_HTTP_PARTIAL_CONTENT           206
#define NGX_HTTP_SPECIAL_RESPONSE          300


static void *ngx_live_store_http_create_preset_conf(ngx_conf_t *cf);

static char *ngx_live_store_http_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


typedef struct {
    size_t      read_buffer_size;
    ngx_msec_t  read_req_timeout;
    ngx_msec_t  read_resp_timeout;
    ngx_uint_t  read_retries;
    ngx_msec_t  read_retry_interval;

    size_t      write_buffer_size;
    ngx_msec_t  write_req_timeout;
    ngx_msec_t  write_resp_timeout;
    ngx_uint_t  write_retries;
    ngx_msec_t  write_retry_interval;
} ngx_live_store_http_preset_conf_t;


static ngx_command_t  ngx_live_store_http_commands[] = {

    { ngx_string("store_http_read_req_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, read_req_timeout),
      NULL },

    { ngx_string("store_http_read_resp_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, read_resp_timeout),
      NULL },

    { ngx_string("store_http_read_buffer_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, read_buffer_size),
      NULL },

    { ngx_string("store_http_read_retries"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, read_retries),
      NULL },

    { ngx_string("store_http_read_retry_interval"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, read_retry_interval),
      NULL },


    { ngx_string("store_http_write_req_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, write_req_timeout),
      NULL },

    { ngx_string("store_http_write_resp_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, write_resp_timeout),
      NULL },

    { ngx_string("store_http_write_buffer_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, write_buffer_size),
      NULL },

    { ngx_string("store_http_write_retries"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, write_retries),
      NULL },

    { ngx_string("store_http_write_retry_interval"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_http_preset_conf_t, write_retry_interval),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_store_http_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_store_http_create_preset_conf,   /* create preset configuration */
    ngx_live_store_http_merge_preset_conf     /* merge preset configuration */
};

ngx_module_t  ngx_live_store_http_module = {
    NGX_MODULE_V1,
    &ngx_live_store_http_module_ctx,          /* module context */
    ngx_live_store_http_commands,             /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


/* read */

typedef struct {
    ngx_pool_t                          *pool;
    ngx_live_store_http_preset_conf_t   *conf;
    ngx_url_t                           *url;
    ngx_str_t                            uri;
    size_t                               max_size;

    ngx_live_store_http_create_read_pt   create;
    void                                *create_data;

    ngx_live_store_read_handler_pt       handler;
    void                                *data;

    ngx_uint_t                           retries_left;
    off_t                                offset;
    size_t                               size;
} ngx_live_store_http_read_ctx_t;

void *
ngx_live_store_http_read_init(ngx_live_store_read_request_t *request,
    ngx_url_t *url, ngx_live_store_http_create_read_pt create,
    void *create_data)
{
    ngx_pool_t                      *pool;
    ngx_live_store_http_read_ctx_t  *ctx;

    pool = request->pool;

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_http_read_init: alloc failed");
        return NULL;
    }

    ctx->pool = pool;
    ctx->conf = ngx_live_get_module_preset_conf(request->channel,
        ngx_live_store_http_module);
    ctx->url = url;
    ctx->uri = request->path;
    ctx->max_size = request->max_size;

    ctx->create = create;
    ctx->create_data = create_data;

    ctx->handler = request->handler;
    ctx->data = request->data;

    return ctx;
}

static ngx_chain_t *
ngx_live_store_http_read_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    ngx_buf_t                       *b;
    ngx_chain_t                     *cl;
    ngx_live_store_http_read_ctx_t  *ctx = arg;

    if (ctx->create(pool, ctx->create_data, &ctx->url->host, &ctx->uri,
        ctx->offset, ctx->offset + ctx->size - 1, &b) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_http_read_create: create failed");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_http_read_create: alloc chain failed");
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

static ngx_int_t
ngx_live_store_http_read_finished(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *response)
{
    ngx_int_t                        rc;
    ngx_uint_t                       level;
    ngx_uint_t                       success_code;
    ngx_live_store_http_read_ctx_t  *ctx = arg;

    success_code = ctx->size == 0 ? NGX_HTTP_OK : NGX_HTTP_PARTIAL_CONTENT;

    if (code != success_code) {

        level = (code >= NGX_HTTP_CALL_ERROR_COUNT) ? NGX_LOG_ERR :
            NGX_LOG_NOTICE;

        ngx_log_error(level, temp_pool->log, 0,
            "ngx_live_store_http_read_finished: request failed %ui", code);

        if (ctx->retries_left > 0) {
            ctx->retries_left--;
            return NGX_AGAIN;
        }

        switch (code) {

        case NGX_HTTP_CALL_ERROR_INTERNAL:
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_CALL_ERROR_TIME_OUT:
            rc = NGX_HTTP_GATEWAY_TIME_OUT;
            break;

        case NGX_HTTP_NOT_FOUND:
            rc = code;
            break;

        default:
            rc = NGX_HTTP_BAD_GATEWAY;
            break;
        }

    } else {
        rc = NGX_OK;
    }

    ctx->handler(ctx->data, rc, response);
    return rc;
}

ngx_int_t
ngx_live_store_http_read(void *arg, off_t offset, size_t size)
{
    ngx_http_call_init_t                ci;
    ngx_live_store_http_read_ctx_t     *ctx = arg;
    ngx_live_store_http_preset_conf_t  *conf = ctx->conf;

    ngx_memzero(&ci, sizeof(ci));

    /* Note: allocating the response buffers on r->pool, in case of multiple
        reads, they will be freed only when the request completes */

    ci.response = ngx_create_temp_buf(ctx->pool,
        conf->read_buffer_size + size);
    if (ci.response == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_store_http_read: alloc failed");
        return NGX_ERROR;
    }

    ci.url = ctx->url;
    ci.create = ngx_live_store_http_read_create;
    ci.handle = ngx_live_store_http_read_finished;
    ci.handler_pool = ctx->pool;
    ci.max_response_size = ctx->max_size;

    ci.arg = ctx;

    ci.timeout = conf->read_req_timeout;
    ci.read_timeout = conf->read_resp_timeout;
    ci.retry_interval = conf->read_retry_interval;

    ctx->retries_left = conf->read_retries;
    ctx->offset = offset;
    ctx->size = size;

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_store_http_read: create http call failed");
        return NGX_ERROR;
    }

    return NGX_DONE;
}


/* write */

typedef struct {
    ngx_http_call_ctx_t              *call;
    ngx_live_channel_t               *channel;
    ngx_chain_t                      *headers;
    ngx_chain_t                      *body;
    ngx_str_t                         path;

    ngx_live_store_write_handler_pt   handler;
    void                             *data;

    ngx_uint_t                        retries_left;
} ngx_live_store_http_write_ctx_t;

static void
ngx_live_store_http_write_free(ngx_live_store_http_write_ctx_t *ctx,
    ngx_int_t rc)
{
    if (ctx->call != NULL) {
        ngx_http_call_cancel(ctx->call);
    }

    /* Note: the channel may be deleted after the request is issued,
        however, in this case, the channel pool will be destroyed,
        and the request will be cancelled = this handler won't be called */

    ctx->handler(ctx->data, rc);
}

void
ngx_live_store_http_cancel_write(void *data)
{
    ngx_live_store_http_write_ctx_t  *ctx = data;

    ngx_log_error(NGX_LOG_ERR, &ctx->channel->log, 0,
        "ngx_live_store_http_cancel_write: "
        "cancelling write request, path: %V",
        &ctx->path);

    ngx_live_store_http_write_free(ctx, NGX_ERROR);
}

static ngx_chain_t *
ngx_live_store_http_write_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    ngx_live_store_http_write_ctx_t  *ctx = arg;

    *body = ctx->body;

    return ctx->headers;
}

static ngx_int_t
ngx_live_store_http_write_complete(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *response)
{
    ngx_int_t                         rc;
    ngx_uint_t                        level;
    ngx_live_store_http_write_ctx_t  *ctx = arg;

    if (code < NGX_HTTP_OK || code >= NGX_HTTP_SPECIAL_RESPONSE) {

        level = (code >= NGX_HTTP_CALL_ERROR_COUNT) ? NGX_LOG_ERR :
            NGX_LOG_NOTICE;

        ngx_log_error(level, &ctx->channel->log, 0,
            "ngx_live_store_http_write_complete: "
            "request failed, code: %ui, path: %V", code, &ctx->path);

        if (ctx->retries_left > 0) {
            ctx->retries_left--;
            return NGX_AGAIN;
        }

        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    ctx->call = NULL;

    ngx_live_store_http_write_free(ctx, rc);

    return NGX_OK;
}

void *
ngx_live_store_http_write(ngx_live_store_write_request_t *request,
    ngx_url_t *url, ngx_chain_t *headers, ngx_chain_t *body)
{
    ngx_live_channel_t                 *channel;
    ngx_http_call_init_t                ci;
    ngx_live_store_http_write_ctx_t    *ctx;
    ngx_live_store_http_preset_conf_t  *conf;

    channel = request->channel;
    conf = ngx_live_get_module_preset_conf(channel,
        ngx_live_store_http_module);

    ctx = ngx_palloc(request->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_store_http_write: alloc failed");
        return NULL;
    }

    ctx->channel = channel;
    ctx->headers = headers;
    ctx->body = body;
    ctx->path = request->path;
    ctx->retries_left = conf->write_retries;

    ctx->handler = request->handler;
    ctx->data = request->data;

    ngx_memzero(&ci, sizeof(ci));

    ci.pool = request->pool;
    ci.url = url;
    ci.create = ngx_live_store_http_write_create;
    ci.handle = ngx_live_store_http_write_complete;
    ci.handler_pool = channel->pool;
    ci.arg = ctx;

    ci.buffer_size = conf->write_buffer_size;
    ci.timeout = conf->write_req_timeout;
    ci.read_timeout = conf->write_resp_timeout;
    ci.retry_interval = conf->write_retry_interval;

    ctx->call = ngx_http_call_create(&ci);
    if (ctx->call == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_store_http_write: create http call failed");
        return NULL;
    }

    return ctx;
}


/* read + write */

static void *
ngx_live_store_http_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_store_http_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_store_http_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->read_req_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_resp_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->read_retries = NGX_CONF_UNSET_UINT;
    conf->read_retry_interval = NGX_CONF_UNSET_MSEC;

    conf->write_req_timeout = NGX_CONF_UNSET_MSEC;
    conf->write_resp_timeout = NGX_CONF_UNSET_MSEC;
    conf->write_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->write_retries = NGX_CONF_UNSET_UINT;
    conf->write_retry_interval = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_live_store_http_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_store_http_preset_conf_t  *prev = parent;
    ngx_live_store_http_preset_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->read_req_timeout,
                              prev->read_req_timeout, 2000);

    ngx_conf_merge_msec_value(conf->read_resp_timeout,
                              prev->read_resp_timeout, 10000);

    ngx_conf_merge_size_value(conf->read_buffer_size,
                              prev->read_buffer_size, 4 * 1024);

    ngx_conf_merge_uint_value(conf->read_retries,
                              prev->read_retries, 0);

    ngx_conf_merge_msec_value(conf->read_retry_interval,
                              prev->read_retry_interval, 1000);

    ngx_conf_merge_msec_value(conf->write_req_timeout,
                              prev->write_req_timeout, 10000);

    ngx_conf_merge_msec_value(conf->write_resp_timeout,
                              prev->write_resp_timeout, 10000);

    ngx_conf_merge_size_value(conf->write_buffer_size,
                              prev->write_buffer_size, 4 * 1024);

    ngx_conf_merge_uint_value(conf->write_retries,
                              prev->write_retries, 5);

    ngx_conf_merge_msec_value(conf->write_retry_interval,
                              prev->write_retry_interval, 2000);

    return NGX_CONF_OK;
}
