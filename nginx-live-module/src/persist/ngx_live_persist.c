#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_persist_internal.h"


static ngx_int_t ngx_live_persist_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_create_main_conf(ngx_conf_t *cf);

static void *ngx_live_persist_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);


struct ngx_live_persist_main_conf_s {
    ngx_persist_conf_t                *conf;
};


static ngx_conf_num_bounds_t  ngx_live_persist_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};


static ngx_command_t  ngx_live_persist_commands[] = {

    { ngx_string("persist_write"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, write),
      NULL },

    { ngx_string("persist_comp_level"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, comp_level),
      &ngx_live_persist_comp_level_bounds },

    { ngx_string("persist_opaque"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, opaque),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_persist_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_persist_postconfiguration,       /* postconfiguration */

    ngx_live_persist_create_main_conf,        /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_persist_create_preset_conf,      /* create preset configuration */
    ngx_live_persist_merge_preset_conf        /* merge preset configuration */
};


ngx_module_t  ngx_live_persist_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_module_ctx,             /* module context */
    ngx_live_persist_commands,                /* module directives */
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


ngx_int_t
ngx_live_persist_write_blocks_internal(ngx_live_persist_main_conf_t *pmcf,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj)
{
    return ngx_persist_conf_write_blocks(pmcf->conf, write_ctx, block_ctx,
        obj);
}


ngx_int_t
ngx_live_persist_write_blocks(ngx_live_channel_t *channel,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    return ngx_live_persist_write_blocks_internal(pmcf, write_ctx, block_ctx,
        obj);
}


ngx_int_t
ngx_live_persist_read_blocks_internal(ngx_live_persist_main_conf_t *pmcf,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj)
{
    return ngx_persist_conf_read_blocks(pmcf->conf, ctx, rs, obj);
}


ngx_int_t
ngx_live_persist_read_blocks(ngx_live_channel_t *channel, ngx_uint_t ctx,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    return ngx_live_persist_read_blocks_internal(pmcf, ctx, rs, obj);
}


ngx_int_t
ngx_live_persist_write_channel_header(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_channel_t *channel)
{
    ngx_int_t                        rc;
    ngx_str_t                        opaque;
    ngx_wstream_t                   *ws;
    ngx_live_variables_ctx_t        *vctx;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->opaque != NULL) {
        vctx = ngx_persist_write_vctx(write_ctx);

        rc = ngx_live_complex_value(vctx, ppcf->opaque, &opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_write_channel_header: "
                "complex value failed");
            return NGX_ERROR;
        }

    } else {
        opaque.len = 0;
    }

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_wstream_str(ws, &opaque) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_channel_header: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_persist_read_channel_header(ngx_live_channel_t *channel,
    ngx_mem_rstream_t *rs)
{
    ngx_str_t  id;
    ngx_str_t  opaque;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_channel_header: read id failed");
        return NGX_BAD_DATA;
    }

    if (id.len != channel->sn.str.len ||
        ngx_memcmp(id.data, channel->sn.str.data, id.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_channel_header: "
            "channel id \"%V\" mismatch", &id);
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &opaque) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_channel_header: read opaque failed");
        return NGX_BAD_DATA;
    }

    ngx_log_error(NGX_LOG_INFO, rs->log, 0,
        "ngx_live_persist_read_channel_header: opaque \"%V\"", &opaque);

    return NGX_OK;
}


void
ngx_live_persist_write_file_destroy(ngx_live_persist_write_file_ctx_t *ctx)
{
    ngx_destroy_pool(ctx->pool);
}


ngx_live_persist_write_file_ctx_t *
ngx_live_persist_write_file(ngx_live_channel_t *channel,
    ngx_live_persist_file_conf_t *conf, ngx_live_persist_file_type_t *type,
    ngx_live_store_write_handler_pt handler, void *data,
    void *scope, size_t scope_size)
{
    size_t                              size;
    ngx_int_t                           rc;
    ngx_pool_t                         *pool;
    ngx_persist_write_ctx_t            *write_ctx;
    ngx_live_variables_ctx_t           *vctx;
    ngx_live_store_write_request_t      request;
    ngx_live_persist_preset_conf_t     *ppcf;
    ngx_live_persist_write_file_ctx_t  *ctx;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: create pool failed");
        goto failed;
    }

    ctx = ngx_pcalloc(pool, sizeof(*ctx) - sizeof(ctx->scope) + scope_size);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: alloc failed (1)");
        goto failed;
    }

    vctx = ngx_palloc(pool, sizeof(*vctx));
    if (vctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: alloc failed (2)");
        goto failed;
    }

    rc = ngx_live_variables_init_ctx(channel, pool, vctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: failed to init var ctx");
        goto failed;
    }

    rc = ngx_live_complex_value(vctx, conf->path, &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: complex value failed");
        goto failed;
    }

    if (conf->tag_value != NULL) {
        rc = ngx_live_complex_value(vctx, conf->tag_value, &request.tag_value);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_write_file: tag complex value failed");
            goto failed;
        }

    } else {
        ngx_str_set(&request.tag_value, "");
    }

    write_ctx = ngx_persist_write_init(pool, type->type,
        type->compress ? ppcf->comp_level : 0);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write init failed");
        goto failed;
    }

    ngx_persist_write_ctx(write_ctx) = data;
    ngx_persist_write_vctx(write_ctx) = vctx;

    if (ngx_live_persist_write_blocks(channel, write_ctx, type->ctx,
        channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write blocks failed");
        goto failed;
    }

    size = ngx_persist_write_get_size(write_ctx);
    if (conf->max_size && size > conf->max_size) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_write_file: size %uz exceeds limit %uz",
            size, conf->max_size);
        goto failed;
    }

    request.cl = ngx_persist_write_close(write_ctx, &size, NULL);
    if (request.cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: close failed");
        goto failed;
    }

    request.pool = pool;
    request.channel = channel;
    request.size = size;
    request.handler = handler;
    request.data = ctx;

    ctx->pool = pool;
    ctx->channel = channel;
    ctx->start = ngx_current_msec;
    ctx->size = size;
    ngx_memcpy(ctx->scope, scope, scope_size);

    rc = ppcf->store->write(&request);
    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write failed %i", rc);
        goto failed;
    }

    return ctx;

failed:

    if (pool) {
        ngx_destroy_pool(pool);
    }

    return NULL;
}


ngx_int_t
ngx_live_persist_read_parse(ngx_live_channel_t *channel, ngx_str_t *buf,
    ngx_live_persist_file_type_t *type, size_t max_size, void *scope)
{
    void               *ptr;
    ngx_int_t           rc;
    ngx_mem_rstream_t   rs;

    rc = ngx_persist_read_file_header(buf, type->type, &channel->log,
        scope, &rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read header failed, type: %*s",
            (size_t) sizeof(type->type), &type->type);
        return rc;
    }

    rc = ngx_persist_read_inflate(buf, max_size, &rs, NULL, &ptr);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: inflate failed, type: %*s",
            (size_t) sizeof(type->type), &type->type);
        return rc;
    }

    rc = ngx_live_persist_read_blocks(channel, type->ctx, &rs, channel);

    ngx_free(ptr);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read blocks failed, type: %*s",
            (size_t) sizeof(type->type), &type->type);
        return rc;
    }

    return NGX_OK;
}


static void
ngx_live_persist_read_detach(void *data)
{
    ngx_live_persist_read_file_ctx_t  *ctx = data;

    /* handler pool destroyed, must not call the handler */
    ctx->cln = NULL;
}


ngx_live_persist_read_file_ctx_t *
ngx_live_persist_read_file(ngx_live_channel_t *channel,
    ngx_pool_cleanup_t *cln, ngx_live_persist_file_conf_t *file,
    ngx_live_store_read_handler_pt handler, void *data, size_t data_size)
{
    void                              *read_ctx;
    ngx_int_t                          rc;
    ngx_pool_t                        *pool;
    ngx_live_variables_ctx_t           vctx;
    ngx_live_store_read_request_t      request;
    ngx_live_persist_preset_conf_t    *ppcf;
    ngx_live_persist_read_file_ctx_t  *ctx;

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: create pool failed");
        return NULL;
    }

    rc = ngx_live_variables_init_ctx(channel, pool, &vctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: failed to init var ctx");
        goto failed;
    }

    rc = ngx_live_complex_value(&vctx, file->path, &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: complex value failed");
        goto failed;
    }

    ctx = ngx_palloc(pool, sizeof(*ctx) + data_size);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: alloc failed");
        goto failed;
    }

    ctx->channel = channel;
    ctx->pool = pool;
    ctx->path = request.path;
    ctx->cln = cln;

    if (data_size > 0) {
        ctx->data = ctx + 1;
        ngx_memcpy(ctx->data, data, data_size);

    } else {
        ctx->data = NULL;
    }

    request.pool = pool;
    request.channel = channel;
    request.max_size = file->max_size;

    request.handler = handler;
    request.data = ctx;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    read_ctx = ppcf->store->read_init(&request);
    if (read_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: read init failed");
        goto failed;
    }

    rc = ppcf->store->read(read_ctx, 0, 0);
    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: read failed");
        goto failed;
    }

    if (cln) {
        cln->handler = ngx_live_persist_read_detach;
        cln->data = ctx;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_read_file: "
        "read started, path: %V", &request.path);

    return ctx;

failed:

    ngx_destroy_pool(pool);

    return NULL;
}


char *
ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store)
{
    ngx_live_conf_ctx_t             *live_ctx;
    ngx_live_persist_preset_conf_t  *ppcf;

    live_ctx = cf->ctx;

    ppcf = ngx_live_get_module_preset_conf(live_ctx, ngx_live_persist_module);

    if (ppcf->store != NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "persist store already set");
        return NGX_CONF_ERROR;
    }

    ppcf->store = store;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_live_persist_add_blocks(ngx_conf_t *cf, ngx_persist_block_t *blocks)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    return ngx_persist_conf_add_blocks(cf, pmcf->conf, blocks);
}


static void *
ngx_live_persist_create_main_conf(ngx_conf_t *cf)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->conf = ngx_persist_conf_create(cf, NGX_LIVE_PERSIST_CTX_COUNT);
    if (pmcf->conf == NULL) {
        return NULL;
    }

    return pmcf;
}


static void *
ngx_live_persist_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_persist_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->store = NGX_CONF_UNSET_PTR;
    conf->write = NGX_CONF_UNSET;
    conf->comp_level = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_persist_preset_conf_t  *prev = parent;
    ngx_live_persist_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    ngx_conf_merge_value(conf->write, prev->write, 1);

    ngx_conf_merge_value(conf->comp_level, prev->comp_level, 6);

    if (conf->opaque == NULL) {
        conf->opaque = prev->opaque;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_live_persist_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    if (ngx_persist_conf_init(cf, pmcf->conf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
