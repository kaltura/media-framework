#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http_call.h>
#include "ngx_live_dvr_http.h"


#define NGX_HTTP_OK                        200
#define NGX_HTTP_PARTIAL_CONTENT           206


enum {
    NGX_LIVE_BP_SAVE_CTX,

    NGX_LIVE_BP_COUNT
};


static ngx_int_t ngx_live_dvr_http_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_dvr_http_create_preset_conf(ngx_conf_t *cf);

static char *ngx_live_dvr_http_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    size_t      read_buffer_size;
    ngx_msec_t  read_req_timeout;
    ngx_msec_t  read_resp_timeout;
    ngx_uint_t  read_retries;
    ngx_msec_t  read_retry_interval;

    size_t      save_buffer_size;
    ngx_msec_t  save_req_timeout;
    ngx_msec_t  save_resp_timeout;
    ngx_uint_t  save_retries;
    ngx_msec_t  save_retry_interval;
} ngx_live_dvr_http_preset_conf_t;


typedef struct {
    ngx_block_pool_t                  *block_pool;
    ngx_queue_t                        active;
} ngx_live_dvr_http_channel_ctx_t;


static ngx_command_t  ngx_live_dvr_http_commands[] = {

    { ngx_string("dvr_http_read_req_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, read_req_timeout),
      NULL },

    { ngx_string("dvr_http_read_resp_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, read_resp_timeout),
      NULL },

    { ngx_string("dvr_http_read_buffer_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, read_buffer_size),
      NULL },

    { ngx_string("dvr_http_read_retries"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, read_retries),
      NULL },

    { ngx_string("dvr_http_read_retry_interval"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, read_retry_interval),
      NULL },


    { ngx_string("dvr_http_save_req_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, save_req_timeout),
      NULL },

    { ngx_string("dvr_http_save_resp_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, save_resp_timeout),
      NULL },

    { ngx_string("dvr_http_save_buffer_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, save_buffer_size),
      NULL },

    { ngx_string("dvr_http_save_retries"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, save_retries),
      NULL },

    { ngx_string("dvr_http_save_retry_interval"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_http_preset_conf_t, save_retry_interval),
      NULL },


      ngx_null_command
};

static ngx_live_module_t  ngx_live_dvr_http_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_live_dvr_http_postconfiguration,    /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_live_dvr_http_create_preset_conf,   /* create preset configuration */
    ngx_live_dvr_http_merge_preset_conf     /* merge preset configuration */
};

ngx_module_t  ngx_live_dvr_http_module = {
    NGX_MODULE_V1,
    &ngx_live_dvr_http_module_ctx,          /* module context */
    ngx_live_dvr_http_commands,             /* module directives */
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


/* read */

typedef struct {
    ngx_pool_t                        *pool;
    ngx_live_dvr_http_preset_conf_t   *conf;
    ngx_url_t                         *url;
    ngx_str_t                          uri;
    ngx_live_dvr_http_create_read_pt   create;
    void                              *create_ctx;
    void                              *complete_ctx;

    ngx_uint_t                         retries_left;
    off_t                              offset;
    size_t                             size;
} ngx_live_dvr_http_read_ctx_t;

ngx_int_t
ngx_live_dvr_http_read_init(ngx_pool_t *pool, ngx_live_channel_t *channel,
    ngx_str_t *path, ngx_url_t *url, ngx_live_dvr_http_create_read_pt create,
    void *create_ctx, void *complete_ctx, void **result)
{
    ngx_live_dvr_http_read_ctx_t  *ctx;

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_read_init: alloc failed");
        return NGX_ERROR;
    }

    ctx->pool = pool;
    ctx->conf = ngx_live_get_module_preset_conf(channel,
        ngx_live_dvr_http_module);
    ctx->url = url;
    ctx->uri = *path;
    ctx->create = create;
    ctx->create_ctx = create_ctx;
    ctx->complete_ctx = complete_ctx;

    *result = ctx;

    return NGX_OK;
}

static ngx_chain_t *
ngx_live_dvr_http_read_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    ngx_buf_t                     *b;
    ngx_chain_t                   *cl;
    ngx_live_dvr_http_read_ctx_t  *ctx = arg;

    if (ctx->create(pool, ctx->create_ctx, &ctx->url->host, &ctx->uri,
        ctx->offset, ctx->offset + ctx->size - 1, &b) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_read_create: create failed");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_read_create: alloc chain failed");
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

static ngx_int_t
ngx_live_dvr_http_read_finished(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *response)
{
    ngx_int_t                      rc;
    ngx_uint_t                     level;
    ngx_live_dvr_http_read_ctx_t  *ctx = arg;

    if (code != NGX_HTTP_PARTIAL_CONTENT) {

        level = (code >= NGX_HTTP_CALL_ERROR_COUNT) ? NGX_LOG_ERR :
            NGX_LOG_NOTICE;

        ngx_log_error(level, temp_pool->log, 0,
            "ngx_live_dvr_http_read_finished: request failed %ui", code);

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

        default:
            rc = NGX_HTTP_BAD_GATEWAY;
            break;
        }

    } else {
        rc = NGX_OK;
    }

    ngx_live_dvr_read_complete(ctx->complete_ctx, rc, response);
    return rc;
}

ngx_int_t
ngx_live_dvr_http_read(void *arg, off_t offset, size_t size)
{
    ngx_http_call_init_t              ci;
    ngx_live_dvr_http_read_ctx_t     *ctx = arg;
    ngx_live_dvr_http_preset_conf_t  *conf = ctx->conf;

    ngx_memzero(&ci, sizeof(ci));

    /* Note: allocating the response buffers on r->pool, in case of multiple
        reads, they will be freed only when the request completes */

    ci.buffer_size = conf->read_buffer_size + size;
    ci.response = ngx_create_temp_buf(ctx->pool, ci.buffer_size);
    if (ci.response == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_dvr_http_read: alloc failed");
        return NGX_ERROR;
    }

    ci.url = ctx->url;
    ci.create = ngx_live_dvr_http_read_create;
    ci.handle = ngx_live_dvr_http_read_finished;
    ci.handler_pool = ctx->pool;

    ci.arg = ctx;

    ci.timeout = conf->read_req_timeout;
    ci.read_timeout = conf->read_resp_timeout;
    ci.retry_interval = conf->read_retry_interval;

    ctx->retries_left = conf->read_retries;
    ctx->offset = offset;
    ctx->size = size;

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_dvr_http_read: create http call failed");
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}


/* write */

typedef struct {
    ngx_queue_t                        queue;
    ngx_http_call_ctx_t               *call;
    ngx_live_dvr_http_create_save_pt   create;
    void                              *create_ctx;
    ngx_url_t                         *url;
    ngx_live_channel_t                *channel;
    uint32_t                           bucket_id;
    ngx_uint_t                         retries_left;
} ngx_live_dvr_http_save_ctx_t;

ngx_chain_t *
ngx_live_dvr_http_save_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    size_t                         size;
    ngx_buf_t                     *b;
    ngx_str_t                      uri;
    ngx_chain_t                   *cl;
    ngx_live_dvr_http_save_ctx_t  *ctx = *(void **) arg;

    cl = ngx_live_dvr_save_create_file(ctx->channel, pool, ctx->bucket_id, &size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_save_create: create file failed");
        return NULL;
    }

    *body = cl;

    if (ngx_live_dvr_get_path(ctx->channel, pool, ctx->bucket_id, &uri)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_save_create: get path failed");
        return NULL;
    }

    if (ctx->create(pool, ctx->create_ctx, &ctx->url->host, &uri, cl,
        size, &b) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_save_create: create request failed");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_http_save_create: alloc chain failed");
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

static void
ngx_live_dvr_http_save_free(ngx_live_dvr_http_save_ctx_t *ctx, ngx_int_t rc)
{
    ngx_live_dvr_http_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(ctx->channel, ngx_live_dvr_http_module);

    if (ctx->call != NULL) {
        ngx_http_call_cancel(ctx->call);
    }

    ngx_live_dvr_save_complete(ctx->channel, ctx->bucket_id, rc);

    ngx_queue_remove(&ctx->queue);

    ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_SAVE_CTX, ctx);
}

static ngx_int_t
ngx_live_dvr_http_save_complete(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *response)
{
    ngx_int_t                         rc;
    ngx_uint_t                        level;
    ngx_live_dvr_http_save_ctx_t     *ctx = *(void **) arg;

    if (code != NGX_HTTP_OK) {

        level = (code >= NGX_HTTP_CALL_ERROR_COUNT) ? NGX_LOG_ERR :
            NGX_LOG_NOTICE;

        ngx_log_error(level, &ctx->channel->log, 0,
            "ngx_live_dvr_http_save_complete: "
            "request failed %ui, bucket_id: %uD", code, ctx->bucket_id);

        if (ctx->retries_left > 0) {
            ctx->retries_left--;
            return NGX_AGAIN;
        }

        rc = NGX_ERROR;

    } else {
        rc = NGX_OK;
    }

    ctx->call = NULL;

    /* Note: the channel may be deleted after the request is issued,
            however, in this case, the channel pool will be destroyed,
            and the request will be cancelled = this handler won't be called */

    ngx_live_dvr_http_save_free(ctx, rc);

    return NGX_OK;
}

ngx_int_t
ngx_live_dvr_http_save(ngx_live_channel_t *channel, uint32_t bucket_id,
    ngx_url_t *url, ngx_live_dvr_http_create_save_pt create, void *create_ctx)
{
    ngx_http_call_init_t              ci;
    ngx_live_dvr_http_save_ctx_t     *ctx;
    ngx_live_dvr_http_preset_conf_t  *conf;
    ngx_live_dvr_http_channel_ctx_t  *cctx;

    if (channel->mem_left < channel->mem_high_watermark) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_dvr_http_save: memory too low, aborting save");
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_http_module);

    ctx = ngx_block_pool_alloc(cctx->block_pool, NGX_LIVE_BP_SAVE_CTX);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_http_save: alloc failed");
        return NGX_ERROR;
    }

    conf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_http_module);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_live_dvr_http_save_create;
    ci.handle = ngx_live_dvr_http_save_complete;
    ci.handler_pool = channel->pool;

    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ci.buffer_size = conf->save_buffer_size;
    ci.timeout = conf->save_req_timeout;
    ci.read_timeout = conf->save_resp_timeout;
    ci.retry_interval = conf->save_retry_interval;

    ctx->url = url;
    ctx->channel = channel;
    ctx->bucket_id = bucket_id;
    ctx->create = create;
    ctx->create_ctx = create_ctx;
    ctx->retries_left = conf->save_retries;

    ctx->call = ngx_http_call_create(&ci);
    if (ctx->call == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_http_save: create http call failed");
        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_SAVE_CTX, ctx);
        return NGX_ERROR;
    }

    ngx_queue_insert_tail(&cctx->active, &ctx->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_live_dvr_http_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size)
{
    size_t                            block_sizes[NGX_LIVE_BP_COUNT];
    ngx_live_dvr_http_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_http_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_dvr_http_module);

    block_sizes[NGX_LIVE_BP_SAVE_CTX] =
        sizeof(ngx_live_dvr_http_save_ctx_t);

    cctx->block_pool = ngx_live_channel_create_block_pool(channel, block_sizes,
        NGX_LIVE_BP_COUNT);
    if (cctx->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_http_channel_init: create block pool failed");
        return NGX_ERROR;
    }

    ngx_queue_init(&cctx->active);

    return NGX_OK;
}

static ngx_int_t
ngx_live_dvr_http_channel_watermark(ngx_live_channel_t *channel)
{
    uint32_t                          count = 0;
    uint32_t                          min_bucket_id;
    uint32_t                          max_bucket_id;
    ngx_queue_t                      *q;
    ngx_live_dvr_http_save_ctx_t     *ctx;
    ngx_live_dvr_http_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_http_module);

    count = 0;
    min_bucket_id = NGX_MAX_UINT32_VALUE;
    max_bucket_id = 0;

    while (channel->mem_left < channel->mem_low_watermark &&
        !ngx_queue_empty(&cctx->active))
    {
        q = ngx_queue_head(&cctx->active);
        ctx = ngx_queue_data(q, ngx_live_dvr_http_save_ctx_t, queue);

        if (ctx->bucket_id < min_bucket_id) {
            min_bucket_id = ctx->bucket_id;
        }

        if (ctx->bucket_id > max_bucket_id) {
            max_bucket_id = ctx->bucket_id;
        }

        count++;

        ngx_live_dvr_http_save_free(ctx, NGX_ERROR);
    }

    if (count > 0) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_dvr_http_channel_watermark: "
            "cancelled %uD save requests, "
            "min_bucket_id: %uD, max_bucket_id: %uD",
            count, min_bucket_id, max_bucket_id);
    }

    return NGX_OK;
}


/* read + write */

static ngx_int_t
ngx_live_dvr_http_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_channel_handler_pt       *ch;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_dvr_http_channel_init;

    ch = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_WATERMARK]);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    *ch = ngx_live_dvr_http_channel_watermark;

    return NGX_OK;
}

static void *
ngx_live_dvr_http_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_dvr_http_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_dvr_http_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->read_req_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_resp_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->read_retries = NGX_CONF_UNSET_UINT;
    conf->read_retry_interval = NGX_CONF_UNSET_MSEC;

    conf->save_req_timeout = NGX_CONF_UNSET_MSEC;
    conf->save_resp_timeout = NGX_CONF_UNSET_MSEC;
    conf->save_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->save_retries = NGX_CONF_UNSET_UINT;
    conf->save_retry_interval = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_live_dvr_http_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_dvr_http_preset_conf_t  *prev = parent;
    ngx_live_dvr_http_preset_conf_t  *conf = child;

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

    ngx_conf_merge_msec_value(conf->save_req_timeout,
                              prev->save_req_timeout, 10000);

    ngx_conf_merge_msec_value(conf->save_resp_timeout,
                              prev->save_resp_timeout, 10000);

    ngx_conf_merge_size_value(conf->save_buffer_size,
                              prev->save_buffer_size, 4 * 1024);

    ngx_conf_merge_uint_value(conf->save_retries,
                              prev->save_retries, 5);

    ngx_conf_merge_msec_value(conf->save_retry_interval,
                              prev->save_retry_interval, 2000);

    return NGX_CONF_OK;
}
