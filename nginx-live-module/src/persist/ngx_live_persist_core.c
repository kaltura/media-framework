#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "../ngx_live_notif.h"
#include "../ngx_live_timeline.h"
#include "ngx_live_persist_core.h"
#include "ngx_live_persist_index.h"
#include "ngx_live_persist_media.h"
#include "ngx_live_persist_setup.h"
#include "ngx_live_persist_snap_frames.h"


static ngx_int_t ngx_live_persist_core_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_core_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_core_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);

static void ngx_live_persist_core_read_handler(void *data, ngx_int_t rc,
    ngx_buf_t *response);


typedef struct {
    void                             (*write_handler)(
        ngx_live_persist_write_file_ctx_t *ctx, ngx_int_t rc);

    /*
     * NGX_BAD_DATA - file is corrupt
     * NGX_DECLINED - old version/uid mismatch, consider the file 'not found'
     */
    ngx_int_t                        (*read_handler)(
        ngx_live_channel_t *channel, ngx_uint_t file, ngx_str_t *buf);
} ngx_live_persist_core_file_t;


typedef struct {
    ngx_live_persist_file_stats_t      stats[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_live_persist_read_file_ctx_t  *read_ctx;
} ngx_live_persist_core_channel_ctx_t;


typedef struct {
    ngx_uint_t                         file;
    ngx_live_persist_read_handler_pt   handler;
    void                              *data;
} ngx_live_persist_core_read_ctx_t;


static ngx_command_t  ngx_live_persist_core_commands[] = {

    { ngx_string("persist_setup_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_SETUP].path),
      NULL },

    { ngx_string("persist_setup_max_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_SETUP].max_size),
      NULL },

    { ngx_string("persist_index_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_INDEX].path),
      NULL },

    { ngx_string("persist_delta_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_DELTA].path),
      NULL },

    { ngx_string("persist_media_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_MEDIA].path),
      NULL },

    { ngx_string("persist_cancel_read_if_empty"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_core_preset_conf_t, cancel_read_if_empty),
      NULL },

    { ngx_string("persist_media_tag_value"),
          NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
          ngx_live_set_complex_value_slot,
          NGX_LIVE_PRESET_CONF_OFFSET,
          offsetof(ngx_live_persist_core_preset_conf_t, files[NGX_LIVE_PERSIST_FILE_MEDIA].tag_value),
          NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_persist_core_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_persist_core_postconfiguration,  /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_persist_core_create_preset_conf, /* create preset configuration */
    ngx_live_persist_core_merge_preset_conf   /* merge preset configuration */
};


ngx_module_t  ngx_live_persist_core_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_core_module_ctx,        /* module context */
    ngx_live_persist_core_commands,           /* module directives */
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


#include "ngx_live_persist_json.h"


static ngx_live_persist_file_type_t  ngx_live_persist_core_file_types[] = {
    { NGX_LIVE_PERSIST_TYPE_SETUP, NGX_LIVE_PERSIST_CTX_SETUP_MAIN, 0 },
    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN, 1 },
    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN, 1 },
    { NGX_LIVE_PERSIST_TYPE_MEDIA, NGX_LIVE_PERSIST_CTX_MEDIA_MAIN, 0 },
};


static ngx_live_persist_core_file_t  ngx_live_persist_files[] = {
    { ngx_live_persist_setup_write_complete,
      ngx_live_persist_setup_read_handler },

    { ngx_live_persist_index_write_complete,
      ngx_live_persist_index_read_handler },

    { ngx_live_persist_index_write_complete,
      ngx_live_persist_index_read_handler },

    { ngx_live_persist_media_write_complete,
      NULL },
};


static void
ngx_live_persist_core_write_file_complete(void *arg, ngx_int_t rc)
{
    ngx_live_channel_t                   *channel;
    ngx_live_persist_scope_t             *scope;
    ngx_live_persist_file_stats_t        *stats;
    ngx_live_persist_write_file_ctx_t    *ctx = arg;
    ngx_live_persist_core_channel_ctx_t  *cctx;

    channel = ctx->channel;

    scope = (void *) ctx->scope;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);
    stats = &cctx->stats[scope->file];

    if (rc != NGX_OK) {
        stats->error++;

    } else {
        stats->success++;
        stats->success_msec += ngx_current_msec - ctx->start;
        stats->success_size += ctx->size;
    }

    ngx_live_persist_files[scope->file].write_handler(ctx, rc);
}


ngx_live_persist_write_file_ctx_t *
ngx_live_persist_core_write_file(ngx_live_channel_t *channel,
    void *data, ngx_live_persist_scope_t *scope, size_t scope_size)
{
    ngx_uint_t                            file;
    ngx_live_persist_write_file_ctx_t    *ctx;
    ngx_live_persist_core_channel_ctx_t  *cctx;
    ngx_live_persist_core_preset_conf_t  *pcpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);
    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);

    file = scope->file;
    cctx->stats[file].started++;

    ctx = ngx_live_persist_write_file(channel, &pcpcf->files[file],
        &ngx_live_persist_core_file_types[file],
        ngx_live_persist_core_write_file_complete,
        data, scope, scope_size);
    if (ctx == NULL) {
        cctx->stats[file].error++;
    }

    return ctx;
}


void
ngx_live_persist_core_write_error(ngx_live_channel_t *channel, ngx_uint_t file)
{
    ngx_live_persist_core_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);

    cctx->stats[file].started++;
    cctx->stats[file].error++;
}


ngx_int_t
ngx_live_persist_core_read_parse(ngx_live_channel_t *channel, ngx_str_t *buf,
    ngx_uint_t file, ngx_live_persist_index_scope_t *scope)
{
    ngx_live_persist_core_preset_conf_t  *pcpcf;

    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);

    return ngx_live_persist_read_parse(channel, buf,
        &ngx_live_persist_core_file_types[file], pcpcf->files[file].max_size,
        scope);
}


static ngx_int_t
ngx_live_persist_core_read_file(ngx_live_channel_t *channel,
    ngx_pool_cleanup_t *cln, ngx_live_persist_file_conf_t *file,
    ngx_live_persist_core_read_ctx_t *ctx)
{
    ngx_live_persist_read_file_ctx_t     *read_ctx;
    ngx_live_persist_core_channel_ctx_t  *cctx;

    read_ctx = ngx_live_persist_read_file(channel, cln, file,
        ngx_live_persist_core_read_handler, ctx, sizeof(*ctx));
    if (read_ctx == NULL) {
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);

    cctx->read_ctx = read_ctx;

    return NGX_DONE;
}


static void
ngx_live_persist_core_read_handler(void *data, ngx_int_t rc,
    ngx_buf_t *response)
{
    ngx_str_t                             buf;
    ngx_pool_t                           *pool;
    ngx_pool_cleanup_t                   *cln;
    ngx_live_channel_t                   *channel;
    ngx_live_persist_read_file_ctx_t     *read_ctx = data;
    ngx_live_persist_core_read_ctx_t      ctx;
    ngx_live_persist_core_preset_conf_t  *pcpcf;
    ngx_live_persist_core_channel_ctx_t  *cctx;

    channel = read_ctx->channel;
    pool = read_ctx->pool;
    cln = read_ctx->cln;
    ngx_memcpy(&ctx, read_ctx->data, sizeof(ctx));

    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);

    cctx->read_ctx = NULL;

    switch (rc) {

    case NGX_OK:
        break;

    case NGX_HTTP_NOT_FOUND:
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_core_read_handler: "
            "read file not found, path: %V", &read_ctx->path);
        goto done;

    default:
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_core_read_handler: "
            "read failed %i, path: %V", rc, &read_ctx->path);
        goto failed;
    }

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    rc = ngx_live_persist_files[ctx.file].read_handler(channel, ctx.file,
        &buf);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DECLINED:
        /* ignore files with old version/uid mismatch */
        goto done;

    default:
        goto failed;
    }

    ctx.file++;
    if (ctx.file >= NGX_LIVE_PERSIST_FILE_MEDIA ||
        pcpcf->files[ctx.file].path == NULL)
    {
        goto done;
    }

    ngx_destroy_pool(pool);
    pool = NULL;

    rc = ngx_live_persist_core_read_file(channel, cln, &pcpcf->files[ctx.file],
        &ctx);
    if (rc != NGX_DONE) {
        goto failed;
    }

    return;

done:

    if (ctx.file > NGX_LIVE_PERSIST_FILE_SETUP) {
        if (!ngx_live_timelines_cleanup(channel) &&
            pcpcf->cancel_read_if_empty)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_core_read_handler: "
                "no segments, cancelling read");
            rc = NGX_DECLINED;

        } else {
            channel->read_time = ngx_time();

            rc = ngx_live_core_channel_event(channel,
                NGX_LIVE_EVENT_CHANNEL_READ, NULL);
        }

    } else {
        rc = NGX_DONE;
    }

    channel->blocked--;

    if (channel->blocked <= 0) {
        ngx_live_notif_publish(channel, NGX_LIVE_NOTIF_CHANNEL_READY, NGX_OK);
    }

failed:

    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }

    if (cln) {
        /* ctx was freed, must disable the cleanup handler */
        cln->handler = NULL;

        ctx.handler(ctx.data, rc);
    }
}


ngx_int_t
ngx_live_persist_core_read(ngx_live_channel_t *channel,
    ngx_pool_t *handler_pool, ngx_live_persist_read_handler_pt handler,
    void *data)
{
    ngx_int_t                             rc;
    ngx_pool_cleanup_t                   *cln;
    ngx_live_persist_core_read_ctx_t      ctx;
    ngx_live_persist_core_preset_conf_t  *pcpcf;

    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);
    if (pcpcf->files[NGX_LIVE_PERSIST_FILE_SETUP].path == NULL) {
        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(handler_pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_core_read: cleanup add failed");
        return NGX_ERROR;
    }

    ctx.file = NGX_LIVE_PERSIST_FILE_SETUP;
    ctx.handler = handler;
    ctx.data = data;

    rc = ngx_live_persist_core_read_file(channel, cln,
        &pcpcf->files[ctx.file], &ctx);
    if (rc != NGX_DONE) {
        return rc;
    }

    channel->blocked++;

    return NGX_DONE;
}


ngx_live_persist_snap_t *
ngx_live_persist_snap_create(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_live_persist_snap_t              *snap;
    ngx_live_persist_preset_conf_t       *ppcf;
    ngx_live_persist_core_preset_conf_t  *pcpcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (!ppcf->write) {
        return NULL;
    }

    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);
    if (pcpcf->files[NGX_LIVE_PERSIST_FILE_INDEX].path != NULL) {
        snap = ngx_live_persist_index_snap_create(channel, segment_index);

    } else if (pcpcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path != NULL) {
        snap = ngx_live_persist_snap_frames_create(channel, segment_index);

    } else {
        snap = NULL;
    }

    return snap;
}


static ngx_int_t
ngx_live_persist_core_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_core_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_core_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_core_module);

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_core_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_core_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_core_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    if (cctx->read_ctx != NULL) {
        ngx_live_persist_core_read_handler(cctx->read_ctx, NGX_HTTP_CONFLICT,
            NULL);
    }

    return NGX_OK;
}


static void *
ngx_live_persist_core_create_preset_conf(ngx_conf_t *cf)
{
    ngx_uint_t                            i;
    ngx_live_persist_core_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_core_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        conf->files[i].max_size = NGX_CONF_UNSET_SIZE;
    }

    conf->cancel_read_if_empty = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_live_persist_core_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    size_t                                max_size;
    ngx_uint_t                            i;
    ngx_live_persist_preset_conf_t       *ppcf;
    ngx_live_persist_core_preset_conf_t  *prev = parent;
    ngx_live_persist_core_preset_conf_t  *conf = child;

    ppcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_persist_module);

    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        if (ppcf->store == NULL) {
            conf->files[i].path = NULL;

        } else if (conf->files[i].path == NULL) {
            conf->files[i].path = prev->files[i].path;
        }
        if (ppcf->store == NULL) {
            conf->files[i].tag_value = NULL;

        } else if (conf->files[i].tag_value == NULL) {
            conf->files[i].tag_value = prev->files[i].tag_value;
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

    ngx_conf_merge_value(conf->cancel_read_if_empty,
                         prev->cancel_read_if_empty, 1);

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_core_channel_events[] = {
    { ngx_live_persist_core_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_core_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },

      ngx_live_null_event
};


static ngx_live_json_writer_def_t  ngx_live_persist_core_json_writers[] = {
    { { ngx_live_persist_channel_json_get_size,
        ngx_live_persist_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};


static ngx_int_t
ngx_live_persist_core_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_core_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_persist_core_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
