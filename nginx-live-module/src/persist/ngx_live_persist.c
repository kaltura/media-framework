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


#define ngx_live_persist_block_id_key(id)                                   \
    ngx_hash(ngx_hash(ngx_hash(                                             \
        ( (id)        & 0xff) ,                                             \
        (((id) >> 8)  & 0xff)),                                             \
        (((id) >> 16) & 0xff)),                                             \
        (((id) >> 24) & 0xff))


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
    uint32_t                           started;
    uint32_t                           error;
    uint32_t                           success;
    uint64_t                           success_msec;
    uint64_t                           success_size;
} ngx_live_persist_file_stats_t;

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

typedef struct {
    ngx_hash_t                         hash;
    ngx_array_t                        arr;
    ngx_hash_keys_arrays_t            *keys;
} ngx_live_persist_block_ctx_t;

struct ngx_live_persist_main_conf_s {
    ngx_live_persist_block_ctx_t       blocks[NGX_LIVE_PERSIST_CTX_COUNT];
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
    ngx_live_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj)
{
    ngx_array_t                   *arr;
    ngx_live_persist_block_t      *cur;
    ngx_live_persist_block_t      *last;
    ngx_live_persist_main_conf_t  *pmcf;

    /* set the header size explicitly in case there are no child blocks */
    ngx_live_persist_write_block_set_header(write_ctx,
        NGX_LIVE_PERSIST_HEADER_FLAG_CONTAINER);

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    arr = &pmcf->blocks[block_ctx].arr;
    cur = arr->elts;
    last = cur + arr->nelts;

    for (; cur < last; cur++) {

        if (!(cur->flags & NGX_LIVE_PERSIST_FLAG_SINGLE)) {
            if (cur->write(write_ctx, obj) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                    "ngx_live_persist_write_blocks: write failed, id: %*s",
                    (size_t) sizeof(cur->id), &cur->id);
                return NGX_ERROR;
            }
            continue;
        }

        if (ngx_live_persist_write_block_open(write_ctx, cur->id) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_write_blocks: open failed, id: %*s",
                (size_t) sizeof(cur->id), &cur->id);
            return NGX_ERROR;
        }

        if (cur->write(write_ctx, obj) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_write_blocks: write failed, id: %*s",
                (size_t) sizeof(cur->id), &cur->id);
            return NGX_ERROR;
        }

        ngx_live_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_persist_read_blocks(ngx_live_persist_main_conf_t *pmcf,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj)
{
    ngx_hash_t                       *hash;
    ngx_int_t                         rc;
    ngx_uint_t                        key;
    ngx_mem_rstream_t                 block_rs;
    ngx_live_persist_block_t         *block;
    ngx_live_persist_block_header_t  *header;

    hash = &pmcf->blocks[ctx].hash;

    while (!ngx_mem_rstream_eof(rs)) {

        header = ngx_live_persist_read_block(rs, &block_rs);
        if (header == NULL) {
            return NGX_BAD_DATA;
        }

        key = ngx_live_persist_block_id_key(header->id);
        block = ngx_hash_find(hash, key, (u_char *) &header->id,
            sizeof(header->id));
        if (block == NULL) {
            continue;
        }

        rc = block->read(header, &block_rs, obj);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_persist_read_blocks: read failed, id: %*s",
                (size_t) sizeof(header->id), &header->id);
            return rc;
        }
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
    ngx_live_persist_file_t            *file_spec;
    ngx_live_variables_ctx_t            vctx;
    ngx_live_persist_write_ctx_t       *write_ctx;
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
    write_ctx = ngx_live_persist_write_init(pool, file_spec->type,
        file_spec->compress ? ppcf->comp_level : 0);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write init failed");
        goto failed;
    }

    ngx_live_persist_write_ctx(write_ctx) = data;

    if (ngx_live_persist_write_blocks(channel, write_ctx, file_spec->ctx,
        channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write blocks failed");
        goto failed;
    }

    size = ngx_live_persist_write_get_size(write_ctx);
    if (ppcf->files[file].max_size && size > ppcf->files[file].max_size) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_write_file: size %uz exceeds limit %uz",
            size, ppcf->files[file].max_size);
        goto failed;
    }

    request.cl = ngx_live_persist_write_close(write_ctx, &size);
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
    ngx_live_persist_main_conf_t    *pmcf;
    ngx_live_persist_preset_conf_t  *ppcf;
    ngx_live_persist_file_header_t  *header;

    file_spec = &ngx_live_persist_files[file];

    header = ngx_live_persist_read_file_header(buf, file_spec->type,
        &channel->log, scope, &rs);
    if (header == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read header failed, file: %ui",
            file);
        return NGX_BAD_DATA;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    rc = ngx_live_persist_read_inflate(header, ppcf->files[file].max_size, &rs,
        &ptr);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: inflate failed, file: %ui", file);
        return rc;
    }

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    rc = ngx_live_persist_read_blocks(pmcf, file_spec->ctx, &rs, channel);

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
    ngx_uint_t                         level;
    ngx_pool_t                        *pool;
    ngx_pool_cleanup_t                *cln;
    ngx_live_channel_t                *channel;
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
        level = rc == NGX_HTTP_NOT_FOUND ? NGX_LOG_INFO : NGX_LOG_NOTICE;
        ngx_log_error(level, &channel->log, 0,
            "ngx_live_persist_read_handler: "
            "read failed %i, file: %ui", rc, file);
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

    if (rc == NGX_OK || rc == NGX_HTTP_NOT_FOUND) {
        ngx_live_timelines_cleanup(channel);

        rc = ngx_live_core_channel_event(channel, NGX_LIVE_EVENT_CHANNEL_READ,
            NULL);
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

    if (channel->snapshots <= 0) {
        ngx_live_channel_ack_frames(channel);
    }

    return snap;
}


static ngx_int_t
ngx_live_persist_init_block_hash_keys(ngx_conf_t *cf,
    ngx_live_persist_main_conf_t *pmcf)
{
    ngx_uint_t               i;
    ngx_hash_keys_arrays_t  *keys;

    for (i = 0; i < NGX_LIVE_PERSIST_CTX_COUNT; i++) {
        if (ngx_array_init(&pmcf->blocks[i].arr, cf->pool, 5,
            sizeof(ngx_live_persist_block_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }

        keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (keys == NULL) {
            return NGX_ERROR;
        }

        keys->pool = cf->pool;
        keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(keys, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_ERROR;
        }

        pmcf->blocks[i].keys = keys;
    }

    return NGX_OK;
}

ngx_int_t
ngx_ngx_live_persist_add_block(ngx_conf_t *cf, ngx_live_persist_block_t *block)
{
    ngx_int_t                      rc;
    ngx_str_t                      id;
    ngx_live_persist_block_t      *blk;
    ngx_live_persist_main_conf_t  *pmcf;

    if (block->ctx >= NGX_LIVE_PERSIST_CTX_COUNT) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
            "invalid block ctx %uD", block->ctx);
        return NGX_ERROR;
    }

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    blk = ngx_array_push(&pmcf->blocks[block->ctx].arr);
    if (blk == NULL) {
        return NGX_ERROR;
    }

    *blk = *block;

    if (block->read == NULL) {
        return NGX_OK;
    }

    id.data = (u_char *) &blk->id;
    id.len = sizeof(blk->id);

    rc = ngx_hash_add_key(pmcf->blocks[block->ctx].keys, &id, blk,
        NGX_HASH_READONLY_KEY);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "conflicting block name \"%V\"", &id);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_ngx_live_persist_add_blocks(ngx_conf_t *cf,
    ngx_live_persist_block_t *blocks)
{
    ngx_live_persist_block_t  *block;

    for (block = blocks; block->id; block++) {
        if (ngx_ngx_live_persist_add_block(cf, block) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_init_block_hash(ngx_conf_t *cf)
{
    ngx_uint_t                     i;
    ngx_hash_init_t                hash;
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    hash.key = ngx_hash_key;
    hash.max_size = 1024;
    hash.bucket_size = 64;
    hash.name = "blocks_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    for (i = 0; i < NGX_LIVE_PERSIST_CTX_COUNT; i++) {
        hash.hash = &pmcf->blocks[i].hash;

        if (ngx_hash_init(&hash, pmcf->blocks[i].keys->keys.elts,
            pmcf->blocks[i].keys->keys.nelts) != NGX_OK)
        {
            return NGX_ERROR;
        }

        pmcf->blocks[i].keys = NULL;
    }

    return NGX_OK;
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

    if (ngx_live_persist_init_block_hash_keys(cf, pmcf) != NGX_OK) {
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

    if (ngx_live_persist_init_block_hash(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
