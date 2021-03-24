#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "../ngx_live_timeline.h"
#include "ngx_live_persist_internal.h"
#include "ngx_live_persist_index.h"
#include "ngx_live_persist_media.h"
#include "ngx_live_persist_setup.h"
#include "ngx_live_persist_snap_frames.h"


#define NGX_HTTP_CONFLICT                  409


static ngx_int_t ngx_live_persist_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_create_main_conf(ngx_conf_t *cf);

static void *ngx_live_persist_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static void ngx_live_persist_read_handler(void *data, ngx_int_t rc,
    ngx_buf_t *response);


/* files */

typedef struct {
    uint32_t                           type;
    uint32_t                           ctx;
    ngx_flag_t                         compress;

    void                             (*write_handler)(
        ngx_live_persist_write_file_ctx_t *ctx, ngx_int_t rc);

    ngx_int_t                        (*read_handler)(
        ngx_live_channel_t *channel, ngx_uint_t file, ngx_str_t *buf,
        uint32_t *min_index);
} ngx_live_persist_file_t;

typedef struct {
    ngx_live_channel_t                *channel;
    ngx_pool_t                        *pool;
    ngx_uint_t                         file;
    uint32_t                           min_index;
    ngx_live_persist_read_handler_pt   handler;
    void                              *data;
    ngx_pool_cleanup_t                *cln;
} ngx_live_persist_file_read_ctx_t;


/* conf */

struct ngx_live_persist_main_conf_s {
    ngx_persist_conf_t                *conf;
};


/* channel ctx */

typedef struct {
    ngx_live_persist_file_stats_t      stats[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_live_persist_file_read_ctx_t  *read_ctx;
} ngx_live_persist_channel_ctx_t;


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

    { ngx_string("persist_cancel_read_if_empty"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, cancel_read_if_empty),
      NULL },

    { ngx_string("persist_setup_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_SETUP].path),
      NULL },

    { ngx_string("persist_setup_max_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_SETUP].max_size),
      NULL },

    { ngx_string("persist_index_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_INDEX].path),
      NULL },

    { ngx_string("persist_delta_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_DELTA].path),
      NULL },

    { ngx_string("persist_media_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_MEDIA].path),
      NULL },

    { ngx_string("persist_comp_level"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, comp_level),
      &ngx_live_persist_comp_level_bounds },

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


static ngx_live_persist_file_t  ngx_live_persist_files[] = {
    { NGX_LIVE_PERSIST_TYPE_SETUP, NGX_LIVE_PERSIST_CTX_SETUP_MAIN, 0,
        ngx_live_persist_setup_write_complete,
        ngx_live_persist_setup_read_handler },

    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN, 1,
        ngx_live_persist_index_write_complete,
        ngx_live_persist_index_read_handler },

    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN, 1,
        ngx_live_persist_index_write_complete,
        ngx_live_persist_index_read_handler },

    { NGX_LIVE_PERSIST_TYPE_MEDIA, NGX_LIVE_PERSIST_CTX_MEDIA_MAIN, 0,
        ngx_live_persist_media_write_complete,
        NULL },
};


#include "ngx_live_persist_json.h"


ngx_int_t
ngx_live_persist_write_blocks(ngx_live_channel_t *channel,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    return ngx_persist_conf_write_blocks(pmcf->conf, &channel->log,
        write_ctx, block_ctx, obj);
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
ngx_live_persist_read_channel_id(ngx_live_channel_t *channel,
    ngx_mem_rstream_t *rs)
{
    ngx_str_t  id;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_channel_id: read id failed");
        return NGX_BAD_DATA;
    }

    if (id.len != channel->sn.str.len ||
        ngx_memcmp(id.data, channel->sn.str.data, id.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_channel_id: "
            "channel id \"%V\" mismatch", &id);
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


void
ngx_live_persist_write_file_destroy(ngx_live_persist_write_file_ctx_t *ctx)
{
    ngx_destroy_pool(ctx->pool);
}

static void
ngx_live_persist_write_file_complete(void *arg, ngx_int_t rc)
{
    ngx_live_channel_t                 *channel;
    ngx_live_persist_file_stats_t      *stats;
    ngx_live_persist_channel_ctx_t     *cctx;
    ngx_live_persist_write_file_ctx_t  *ctx = arg;

    channel = ctx->channel;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);
    stats = &cctx->stats[ctx->file];

    if (rc != NGX_OK) {
        stats->error++;

    } else {
        stats->success++;
        stats->success_msec += ngx_current_msec - ctx->start;
        stats->success_size += ctx->size;
    }

    ngx_live_persist_files[ctx->file].write_handler(ctx, rc);
}

ngx_live_persist_write_file_ctx_t *
ngx_live_persist_write_file(ngx_live_channel_t *channel, ngx_uint_t file,
    void *data, void *scope, size_t scope_size)
{
    size_t                              size;
    ngx_int_t                           rc;
    ngx_pool_t                         *pool;
    ngx_persist_write_ctx_t            *write_ctx;
    ngx_live_persist_file_t            *file_spec;
    ngx_live_variables_ctx_t            vctx;
    ngx_live_store_write_request_t      request;
    ngx_live_persist_preset_conf_t     *ppcf;
    ngx_live_persist_channel_ctx_t     *cctx;
    ngx_live_persist_write_file_ctx_t  *ctx;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->stats[file].started++;

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: create pool failed");
        goto failed;
    }

    ctx = ngx_pcalloc(pool, sizeof(*ctx) + scope_size);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: alloc failed");
        goto failed;
    }

    rc = ngx_live_variables_init_ctx(channel, pool, &vctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: failed to init var ctx");
        goto failed;
    }

    rc = ngx_live_complex_value(&vctx, ppcf->files[file].path, &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: complex value failed");
        goto failed;
    }

    file_spec = &ngx_live_persist_files[file];
    write_ctx = ngx_persist_write_init(pool, file_spec->type,
        file_spec->compress ? ppcf->comp_level : 0);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write init failed");
        goto failed;
    }

    ngx_persist_write_ctx(write_ctx) = data;

    if (ngx_live_persist_write_blocks(channel, write_ctx, file_spec->ctx,
        channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write blocks failed");
        goto failed;
    }

    size = ngx_persist_write_get_size(write_ctx);
    if (ppcf->files[file].max_size && size > ppcf->files[file].max_size) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_write_file: size %uz exceeds limit %uz",
            size, ppcf->files[file].max_size);
        goto failed;
    }

    request.cl = ngx_persist_write_close(write_ctx, &size);
    if (request.cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: close failed");
        goto failed;
    }

    request.pool = pool;
    request.channel = channel;
    request.size = size;
    request.handler = ngx_live_persist_write_file_complete;
    request.data = ctx;

    ctx->pool = pool;
    ctx->channel = channel;
    ctx->start = ngx_current_msec;
    ctx->file = file;
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

    cctx->stats[file].error++;

    if (pool) {
        ngx_destroy_pool(pool);
    }

    return NULL;
}

void
ngx_live_persist_write_error(ngx_live_channel_t *channel, ngx_uint_t file)
{
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->stats[file].started++;
    cctx->stats[file].error++;
}


ngx_int_t
ngx_live_persist_read_parse(ngx_live_channel_t *channel, ngx_str_t *buf,
    ngx_uint_t file, ngx_live_persist_index_scope_t *scope)
{
    void                            *ptr;
    ngx_int_t                        rc;
    ngx_mem_rstream_t                rs;
    ngx_live_persist_file_t         *file_spec;
    ngx_persist_file_header_t       *header;
    ngx_live_persist_preset_conf_t  *ppcf;

    file_spec = &ngx_live_persist_files[file];

    header = ngx_persist_read_file_header(buf, file_spec->type,
        &channel->log, scope, &rs);
    if (header == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read header failed, file: %ui",
            file);
        return NGX_BAD_DATA;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    rc = ngx_persist_read_inflate(header, ppcf->files[file].max_size, &rs,
        &ptr);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: inflate failed, file: %ui", file);
        return rc;
    }

    rc = ngx_live_persist_read_blocks(channel, file_spec->ctx, &rs, channel);

    ngx_free(ptr);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read blocks failed, file: %ui",
            file);
        return rc;
    }

    return NGX_OK;
}

static void
ngx_live_persist_read_detach(void *data)
{
    ngx_live_persist_file_read_ctx_t  *ctx = data;

    /* handler pool destroyed, must not call the handler */
    ctx->cln = NULL;
}

static ngx_int_t
ngx_live_persist_read_file(ngx_live_channel_t *channel,
    ngx_pool_cleanup_t *cln, ngx_uint_t file, uint32_t min_index,
    ngx_live_persist_read_handler_pt handler, void *data)
{
    void                              *read_ctx;
    ngx_int_t                          rc;
    ngx_pool_t                        *pool;
    ngx_live_variables_ctx_t           vctx;
    ngx_live_store_read_request_t      request;
    ngx_live_persist_channel_ctx_t    *cctx;
    ngx_live_persist_preset_conf_t    *ppcf;
    ngx_live_persist_file_read_ctx_t  *ctx;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->files[file].path == NULL) {
        return NGX_OK;
    }

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: create pool failed");
        return NGX_ERROR;
    }

    rc = ngx_live_variables_init_ctx(channel, pool, &vctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: failed to init var ctx");
        goto failed;
    }

    rc = ngx_live_complex_value(&vctx, ppcf->files[file].path, &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: complex value failed");
        goto failed;
    }

    ctx = ngx_palloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_file: alloc failed");
        goto failed;
    }

    ctx->channel = channel;
    ctx->pool = pool;
    ctx->file = file;
    ctx->min_index = min_index;
    ctx->handler = handler;
    ctx->data = data;
    ctx->cln = cln;

    request.pool = pool;
    request.channel = channel;
    request.max_size = ppcf->files[file].max_size;

    request.handler = ngx_live_persist_read_handler;
    request.data = ctx;

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

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->read_ctx = ctx;

    channel->blocked++;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_read_file: "
        "read started, path: %V, file: %ui, min_index: %uD",
        &request.path, file, min_index);

    return NGX_DONE;

failed:

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}

static void
ngx_live_persist_read_handler(void *data, ngx_int_t rc, ngx_buf_t *response)
{
    uint32_t                           min_index;
    ngx_str_t                          buf;
    ngx_uint_t                         file;
    ngx_pool_t                        *pool;
    ngx_pool_cleanup_t                *cln;
    ngx_live_channel_t                *channel;
    ngx_live_persist_preset_conf_t    *ppcf;
    ngx_live_persist_channel_ctx_t    *cctx;
    ngx_live_persist_read_handler_pt   handler;
    ngx_live_persist_file_read_ctx_t  *ctx = data;

    channel = ctx->channel;
    pool = ctx->pool;
    file = ctx->file;
    min_index = ctx->min_index;
    handler = ctx->handler;
    data = ctx->data;
    cln = ctx->cln;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->read_ctx = NULL;

    channel->blocked--;

    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_NOT_FOUND) {
            ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
                "ngx_live_persist_read_handler: "
                "read file not found, file: %ui", file);
            rc = NGX_OK;

        } else {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_read_handler: "
                "read failed %i, file: %ui", rc, file);
        }
        goto done;
    }

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    rc = ngx_live_persist_files[file].read_handler(channel, file, &buf,
        &min_index);
    if (rc != NGX_OK) {
        goto done;
    }

    ngx_destroy_pool(pool);
    pool = NULL;

    file++;
    if (file >= NGX_LIVE_PERSIST_FILE_MEDIA) {
        goto done;
    }

    rc = ngx_live_persist_read_file(channel, cln, file, min_index,
        handler, data);
    if (rc == NGX_DONE) {
        return;
    }

done:

    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }

    if (rc == NGX_OK && file > 0) {
        ppcf = ngx_live_get_module_preset_conf(channel,
            ngx_live_persist_module);

        if (!ngx_live_timelines_cleanup(channel) &&
            ppcf->cancel_read_if_empty)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_read_handler: "
                "no segments, cancelling read");
            rc = NGX_DECLINED;

        } else {
            rc = ngx_live_core_channel_event(channel,
                NGX_LIVE_EVENT_CHANNEL_READ, NULL);
        }
    }

    if (cln) {
        /* ctx was freed, must disable the cleanup handler */
        cln->handler = NULL;

        handler(data, rc);
    }
}

ngx_int_t
ngx_live_persist_read(ngx_live_channel_t *channel, ngx_pool_t *handler_pool,
    ngx_live_persist_read_handler_pt handler, void *data)
{
    ngx_pool_cleanup_t              *cln;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->files[NGX_LIVE_PERSIST_FILE_SETUP].path == NULL) {
        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(handler_pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: cleanup add failed");
        return NGX_ERROR;
    }

    return ngx_live_persist_read_file(channel, cln,
        NGX_LIVE_PERSIST_FILE_SETUP, 0, handler, data);
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


ngx_live_persist_snap_t *
ngx_live_persist_snap_create(ngx_live_channel_t *channel)
{
    ngx_live_persist_snap_t         *snap;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (!ppcf->write) {
        snap = NULL;

    } else if (ppcf->files[NGX_LIVE_PERSIST_FILE_INDEX].path != NULL) {
        snap = ngx_live_persist_index_snap_create(channel);

    } else if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path != NULL) {
        snap = ngx_live_persist_snap_frames_create(channel);

    } else {
        snap = NULL;
    }

    return snap;
}


ngx_int_t
ngx_live_persist_add_blocks(ngx_conf_t *cf, ngx_persist_block_t *blocks)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    return ngx_persist_conf_add_blocks(cf, pmcf->conf, blocks);
}


static ngx_int_t
ngx_live_persist_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_channel_ctx_t     *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (cctx->read_ctx != NULL) {
        ngx_live_persist_read_handler(cctx->read_ctx, NGX_HTTP_CONFLICT, NULL);
    }

    return NGX_OK;
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
    ngx_uint_t                       i;
    ngx_live_persist_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->store = NGX_CONF_UNSET_PTR;
    conf->write = NGX_CONF_UNSET;
    conf->cancel_read_if_empty = NGX_CONF_UNSET;
    conf->comp_level = NGX_CONF_UNSET;
    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        conf->files[i].max_size = NGX_CONF_UNSET_SIZE;
    }

    return conf;
}

static char *
ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    size_t                           max_size;
    ngx_uint_t                       i;
    ngx_live_persist_preset_conf_t  *prev = parent;
    ngx_live_persist_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    ngx_conf_merge_value(conf->write, prev->write, 1);

    ngx_conf_merge_value(conf->cancel_read_if_empty,
                         prev->cancel_read_if_empty, 1);

    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        if (conf->store == NULL) {
            conf->files[i].path = NULL;

        } else if (conf->files[i].path == NULL) {
            conf->files[i].path = prev->files[i].path;
        }

        max_size = i == NGX_LIVE_PERSIST_FILE_MEDIA ? 0 : 5 * 1024 * 1024;

        ngx_conf_merge_size_value(conf->files[i].max_size,
                                  prev->files[i].max_size, max_size);
    }

    if (conf->files[NGX_LIVE_PERSIST_FILE_INDEX].path != NULL &&
        conf->files[NGX_LIVE_PERSIST_FILE_SETUP].path == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"persist_index_path\" requires \"persist_setup_path\"");
        return NGX_CONF_ERROR;
    }

    if (conf->files[NGX_LIVE_PERSIST_FILE_INDEX].path != NULL &&
        conf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"persist_index_path\" requires \"persist_media_path\"");
        return NGX_CONF_ERROR;
    }

    if (conf->files[NGX_LIVE_PERSIST_FILE_DELTA].path != NULL &&
        conf->files[NGX_LIVE_PERSIST_FILE_INDEX].path == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"persist_delta_path\" requires \"persist_index_path\"");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->comp_level, prev->comp_level, 6);

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_channel_events[] = {
    { ngx_live_persist_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_persist_json_writers[] = {
    { { ngx_live_persist_channel_json_get_size,
        ngx_live_persist_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_persist_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_persist_main_conf_t  *pmcf;

    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_persist_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    if (ngx_persist_conf_init(cf, pmcf->conf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}