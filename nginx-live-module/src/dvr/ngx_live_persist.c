#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "../ngx_live_timeline.h"


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

static void ngx_live_persist_setup_write_complete(
    ngx_live_channel_t *channel, ngx_uint_t file, void *data, ngx_int_t rc);
static ngx_int_t ngx_live_persist_setup_read_handler(
    ngx_live_channel_t *channel, ngx_uint_t file, ngx_str_t *buf,
    uint32_t *min_index);

static void ngx_live_persist_index_write_complete(
    ngx_live_channel_t *channel, ngx_uint_t file, void *data, ngx_int_t rc);
static ngx_int_t ngx_live_persist_index_read_handler(
    ngx_live_channel_t *channel, ngx_uint_t file, ngx_str_t *buf,
    uint32_t *min_index);


typedef struct {
    ngx_hash_t                         hash;
    ngx_array_t                        arr;
    ngx_hash_keys_arrays_t            *keys;
} ngx_live_persist_block_ctx_t;


/* format */

typedef struct {
    uint32_t                           version;
    uint32_t                           initial_segment_index;
    uint64_t                           start_sec;
} ngx_live_persist_setup_channel_t;

typedef struct {
    uint32_t                           track_id;
    uint32_t                           media_type;
    uint32_t                           type;
    uint32_t                           reserved;
    uint64_t                           start_sec;
} ngx_live_persist_setup_track_t;

typedef struct {
    uint32_t                           role;
    uint32_t                           is_default;
    uint32_t                           track_count;
} ngx_live_persist_setup_variant_t;

typedef struct {
    uint32_t                           reserved;
    uint32_t                           last_segment_media_types;
    int64_t                            last_segment_created;
    int64_t                            last_modified;
} ngx_live_persist_index_channel_t;

typedef struct {
    uint32_t                           track_id;
    uint32_t                           has_last_segment;
    uint32_t                           last_segment_bitrate;
} ngx_live_persist_index_track_t;


/* files */

enum {
    NGX_LIVE_PERSIST_FILE_SETUP,
    NGX_LIVE_PERSIST_FILE_INDEX,
    NGX_LIVE_PERSIST_FILE_DELTA,

    NGX_LIVE_PERSIST_FILE_COUNT
};

typedef struct {
    uint32_t                           type;
    uint32_t                           ctx;
    void                             (*write_handler)(
        ngx_live_channel_t *channel, ngx_uint_t file, void *scope, ngx_int_t rc);
    ngx_int_t                        (*read_handler)(
        ngx_live_channel_t *channel, ngx_uint_t file, ngx_str_t *buf,
        uint32_t *min_index);
} ngx_live_persist_file_t;

typedef struct {
    ngx_live_complex_value_t          *path;
    size_t                             max_size;
} ngx_live_persist_file_conf_t;

typedef struct {
    uint32_t                           started;
    uint32_t                           error;
    uint32_t                           success;
    uint64_t                           success_msec;
    uint64_t                           success_size;
} ngx_live_persist_file_stats_t;

typedef struct {
    ngx_pool_t                        *pool;
    ngx_live_channel_t                *channel;

    ngx_uint_t                         file;
    size_t                             size;
    ngx_msec_t                         start;
    u_char                             scope[1];    /* must be last */
} ngx_live_persist_file_write_ctx_t;

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
    ngx_live_persist_block_ctx_t       blocks[NGX_LIVE_PERSIST_CTX_COUNT];
} ngx_live_persist_main_conf_t;

typedef struct {
    ngx_live_store_t                  *store;

    ngx_live_persist_file_conf_t       files[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_msec_t                         setup_timeout;
    ngx_uint_t                         max_delta_segments;
} ngx_live_persist_preset_conf_t;


/* channel ctx */

typedef struct {
    ngx_event_t                            timer;
    uint32_t                               version;
    uint32_t                               success_version;
    ngx_live_persist_file_write_ctx_t     *write_ctx;
    unsigned                               enabled:1;
} ngx_live_persist_setup_channel_ctx_t;

typedef struct {
    uint32_t                               success_index;
    uint32_t                               success_delta;
    ngx_live_persist_file_write_ctx_t     *write_ctx;
    ngx_live_persist_index_snap_t         *pending;
} ngx_live_persist_index_channel_ctx_t;

typedef struct {
    ngx_live_persist_file_stats_t          stats[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_live_persist_file_read_ctx_t      *read_ctx;
    ngx_live_persist_setup_channel_ctx_t   setup;
    ngx_live_persist_index_channel_ctx_t   index;
} ngx_live_persist_channel_ctx_t;


static ngx_command_t  ngx_live_persist_commands[] = {
    { ngx_string("persist_setup_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t,
        files[NGX_LIVE_PERSIST_FILE_SETUP].path),
      NULL },

    { ngx_string("persist_setup_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, setup_timeout),
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

    { ngx_string("persist_max_delta_segments"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, max_delta_segments),
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


static ngx_live_persist_file_t  ngx_live_persist_files[] = {
    { NGX_LIVE_PERSIST_TYPE_SETUP, NGX_LIVE_PERSIST_CTX_SETUP_MAIN,
        ngx_live_persist_setup_write_complete,
        ngx_live_persist_setup_read_handler },

    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
        ngx_live_persist_index_write_complete,
        ngx_live_persist_index_read_handler },

    { NGX_LIVE_PERSIST_TYPE_INDEX, NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
        ngx_live_persist_index_write_complete,
        ngx_live_persist_index_read_handler },
};


/* shared */

#include "ngx_live_persist_json.h"

static ngx_int_t
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

static ngx_int_t
ngx_live_persist_read_blocks(ngx_mem_rstream_t *rs, ngx_hash_t *hash,
    void *obj)
{
    ngx_int_t                         rc;
    ngx_uint_t                        key;
    ngx_mem_rstream_t                 block_rs;
    ngx_live_persist_block_t         *block;
    ngx_live_persist_block_header_t  *header;

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

static void
ngx_live_persist_write_complete(void *arg, ngx_int_t rc)
{
    ngx_live_channel_t                 *channel;
    ngx_live_persist_file_stats_t      *stats;
    ngx_live_persist_channel_ctx_t     *cctx;
    ngx_live_persist_file_write_ctx_t  *ctx = arg;

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

    ngx_live_persist_files[ctx->file].write_handler(channel, ctx->file,
        ctx->scope, rc);

    ngx_destroy_pool(ctx->pool);
}

static ngx_live_persist_file_write_ctx_t *
ngx_live_persist_write_file(ngx_live_channel_t *channel, ngx_uint_t file,
    void *data, void *scope, size_t scope_size)
{
    ngx_int_t                           rc;
    ngx_pool_t                         *pool;
    ngx_live_persist_write_ctx_t       *write_ctx;
    ngx_live_store_write_request_t      request;
    ngx_live_persist_preset_conf_t     *ppcf;
    ngx_live_persist_channel_ctx_t     *cctx;
    ngx_live_persist_file_write_ctx_t  *ctx;

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

    rc = ngx_live_complex_value(channel, pool, ppcf->files[file].path,
        &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: complex value failed");
        goto failed;
    }

    write_ctx = ngx_live_persist_write_init(pool,
        ngx_live_persist_files[file].type);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write init failed");
        goto failed;
    }

    ngx_live_persist_write_ctx(write_ctx) = data;

    if (ngx_live_persist_write_blocks(channel, write_ctx,
        ngx_live_persist_files[file].ctx, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: write blocks failed");
        goto failed;
    }

    request.cl = ngx_live_persist_write_close(write_ctx, &ctx->size);

    if (ctx->size > ppcf->files[file].max_size) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_write_file: size %uz exceeds limit %uz",
            ctx->size, ppcf->files[file].max_size);
        goto failed;
    }

    request.pool = pool;
    request.channel = channel;
    request.size = ctx->size;
    request.handler = ngx_live_persist_write_complete;
    request.data = ctx;

    ctx->pool = pool;
    ctx->channel = channel;
    ctx->start = ngx_current_msec;
    ctx->file = file;
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

static ngx_int_t
ngx_live_persist_read_parse(ngx_live_channel_t *channel, ngx_str_t *buf,
    uint32_t type, uint32_t ctx, ngx_live_persist_index_scope_t *scope)
{
    ngx_int_t                      rc;
    ngx_hash_t                    *hash;
    ngx_mem_rstream_t              rs;
    ngx_live_persist_main_conf_t  *pmcf;

    if (ngx_live_persist_read_file_header(buf, type, &channel->log, scope, &rs)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read header failed");
        return NGX_BAD_DATA;
    }

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[ctx].hash;
    rc = ngx_live_persist_read_blocks(&rs, hash, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read_parse: read blocks failed");
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

    rc = ngx_live_complex_value(channel, pool, ppcf->files[file].path,
        &request.path);
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
    if (file >= NGX_LIVE_PERSIST_FILE_COUNT) {
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


/* setup */

static ngx_int_t
ngx_live_persist_read_channel_id(ngx_live_channel_t *channel,
    ngx_mem_rstream_t *rs)
{
    ngx_str_t  id;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read id failed");
        return NGX_BAD_DATA;
    }

    if (id.len != channel->sn.str.len ||
        ngx_memcmp(id.data, channel->sn.str.data, id.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: "
            "channel id \"%V\" mismatch", &id);
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_write_channel(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                          *version;
    ngx_wstream_t                     *ws;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_setup_channel_t   cp;

    ws = ngx_live_persist_write_stream(write_ctx);
    version = ngx_live_persist_write_ctx(write_ctx);

    cp.version = *version;
    cp.initial_segment_index = channel->initial_segment_index;
    cp.start_sec = channel->start_sec;

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_live_persist_write(write_ctx, &cp, sizeof(cp)) != NGX_OK ||
        ngx_block_str_write(ws, &channel->opaque) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_channel: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_channel(ngx_live_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                          rc;
    ngx_hash_t                        *hash;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_main_conf_t      *pmcf;
    ngx_live_persist_channel_ctx_t    *cctx;
    ngx_live_persist_setup_channel_t  *cp;

    rc = ngx_live_persist_read_channel_id(channel, rs);
    if (rc != NGX_OK) {
        return rc;
    }

    cp = ngx_mem_rstream_get_ptr(rs, sizeof(*cp));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read failed");
        return NGX_BAD_DATA;
    }

    if (cp->initial_segment_index >= NGX_LIVE_INVALID_SEGMENT_INDEX) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: invalid segment index");
        return NGX_BAD_DATA;
    }

    channel->start_sec = cp->start_sec;
    channel->initial_segment_index = cp->initial_segment_index;
    channel->next_segment_index = cp->initial_segment_index;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->setup.version = cctx->setup.success_version = cp->version;

    rc = ngx_live_channel_block_str_read(channel, &channel->opaque, rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read opaque failed");
        return rc;
    }

    if (ngx_live_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL].hash;
    rc = ngx_live_persist_read_blocks(rs, hash, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read blocks failed");
        return rc;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_write_track(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                     *q;
    ngx_wstream_t                   *ws;
    ngx_live_track_t                *cur_track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_setup_track_t   tp;

    ws = ngx_live_persist_write_stream(write_ctx);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->type == ngx_live_track_type_filler) {
            /* will be created by the filler module */
            continue;
        }

        tp.track_id = cur_track->in.key;
        tp.media_type = cur_track->media_type;
        tp.type = cur_track->type;
        tp.reserved = 0;
        tp.start_sec = cur_track->start_sec;

        if (ngx_live_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_wstream_str(ws, &cur_track->sn.str) != NGX_OK ||
            ngx_live_persist_write(write_ctx, &tp, sizeof(tp)) != NGX_OK ||
            ngx_block_str_write(ws, &cur_track->opaque) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_SETUP_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_persist_setup_write_track: write failed");
            return NGX_ERROR;
        }

        ngx_live_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_track(ngx_live_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                        rc;
    ngx_str_t                        id;
    ngx_hash_t                      *hash;
    ngx_live_track_t                *track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_main_conf_t    *pmcf;
    ngx_live_persist_setup_track_t  *tp;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: read id failed");
        return NGX_BAD_DATA;
    }

    tp = ngx_mem_rstream_get_ptr(rs, sizeof(*tp));
    if (tp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: "
            "read data failed, track: %V", &id);
        return NGX_BAD_DATA;
    }

    rc = ngx_live_track_create(channel, &id, tp->track_id, tp->media_type,
        rs->log, &track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_track: "
            "create failed, track: %V", &id);

        if (rc == NGX_EXISTS || rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    track->start_sec = tp->start_sec;

    rc = ngx_live_channel_block_str_read(channel, &track->opaque, rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: read opaque failed");
        return rc;
    }

    if (ngx_live_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_SETUP_TRACK].hash;
    rc = ngx_live_persist_read_blocks(rs, hash, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_track: read blocks failed");
        return rc;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_write_variant(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                           i;
    uint32_t                          *cur_id;
    uint32_t                           track_ids[KMP_MEDIA_COUNT];
    ngx_queue_t                       *q;
    ngx_wstream_t                     *ws;
    ngx_live_track_t                  *cur_track;
    ngx_live_channel_t                *channel = obj;
    ngx_live_variant_t                *cur_variant;
    ngx_live_persist_setup_variant_t   v;

    ws = ngx_live_persist_write_stream(write_ctx);

    for (q = ngx_queue_head(&channel->variants.queue);
        q != ngx_queue_sentinel(&channel->variants.queue);
        q = ngx_queue_next(q))
    {
        cur_variant = ngx_queue_data(q, ngx_live_variant_t, queue);

        cur_id = track_ids;
        for (i = 0; i < KMP_MEDIA_COUNT; i++) {
            cur_track = cur_variant->tracks[i];
            if (cur_track != NULL) {
                *cur_id++ = cur_track->in.key;
            }
        }

        v.role = cur_variant->conf.role;
        v.is_default = cur_variant->conf.is_default;
        v.track_count = cur_id - track_ids;

        if (ngx_live_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_VARIANT) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->sn.str) != NGX_OK ||
            ngx_live_persist_write(write_ctx, &v, sizeof(v)) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.label) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.lang) != NGX_OK ||
            ngx_live_persist_write(write_ctx, track_ids,
                (u_char *) cur_id - (u_char *) track_ids) != NGX_OK ||
            ngx_block_str_write(ws, &cur_variant->opaque) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_setup_write_variant: "
                "write failed, variant: %V", &cur_variant->sn.str);
            return NGX_ERROR;
        }

        ngx_live_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_variant(ngx_live_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                           i;
    uint32_t                           track_id;
    ngx_int_t                          rc;
    ngx_str_t                          id;
    ngx_live_track_t                  *cur_track;
    ngx_live_variant_t                *variant;
    ngx_live_channel_t                *channel = obj;
    ngx_live_variant_conf_t            conf;
    ngx_live_persist_setup_variant_t  *v;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_variant: read id failed");
        return NGX_BAD_DATA;
    }

    v = ngx_mem_rstream_get_ptr(rs, sizeof(*v));
    if (v == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_variant: "
            "read data failed (1), variant: %V", &id);
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &conf.label) != NGX_OK ||
        ngx_mem_rstream_str_get(rs, &conf.lang) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_variant: "
            "read data failed (2), variant: %V", &id);
        return NGX_BAD_DATA;
    }

    conf.role = v->role;
    conf.is_default = v->is_default;

    rc = ngx_live_variant_create(channel, &id, &conf, rs->log, &variant);
    if (rc != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_variant: "
            "create failed, variant: %V", &id);

        if (rc == NGX_EXISTS || rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    for (i = 0; i < v->track_count; i++) {

        if (ngx_mem_rstream_read(rs, &track_id, sizeof(track_id)) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_setup_read_variant: "
                "read track id failed, variant: %V", &id);
            return NGX_BAD_DATA;
        }

        cur_track = ngx_live_track_get_by_int(channel, track_id);
        if (cur_track == NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_setup_read_variant: "
                "failed to get track %uD, variant: %V", track_id, &id);
            return NGX_BAD_DATA;
        }

        if (variant->tracks[cur_track->media_type] != NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_setup_read_variant: "
                "media type %uD already assigned, variant: %V",
                cur_track->media_type, &id);
            return NGX_BAD_DATA;
        }

        if (ngx_live_variant_set_track(variant, cur_track, rs->log)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_live_persist_setup_read_variant: "
                "set track failed, variant: %V", &id);
            return NGX_BAD_DATA;
        }
    }

    rc = ngx_live_channel_block_str_read(channel, &variant->opaque, rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_variant: read opaque failed");
        return rc;
    }

    return NGX_OK;
}

static void
ngx_live_persist_setup_write_complete(ngx_live_channel_t *channel,
    ngx_uint_t file, void *data, ngx_int_t rc)
{
    uint32_t                         version;
    ngx_live_persist_channel_ctx_t  *cctx;

    version = *(uint32_t *) data;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->setup.write_ctx = NULL;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_complete: "
            "write failed %i, version: %uD", rc, version);

    } else {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_setup_write_complete: "
            "write success, version: %uD", version);

        cctx->setup.success_version = version;
    }

    if (version != cctx->setup.version) {
        ngx_add_timer(&cctx->setup.timer, 1);
    }
}

static void
ngx_live_persist_setup_write_handler(ngx_event_t *ev)
{
    uint32_t                         version;
    ngx_live_channel_t              *channel = ev->data;
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    version = cctx->setup.version;

    cctx->setup.write_ctx = ngx_live_persist_write_file(channel,
        NGX_LIVE_PERSIST_FILE_SETUP, &version, &version, sizeof(version));
    if (cctx->setup.write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: "
            "write failed, version: %uD", version);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_setup_write_handler: "
        "write started, version: %uD", version);
}

static ngx_int_t
ngx_live_persist_channel_setup_changed(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_preset_conf_t  *ppcf;
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (!cctx->setup.enabled) {
        return NGX_OK;
    }

    cctx->setup.version++;

    if (cctx->setup.write_ctx != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
            "ngx_live_persist_channel_setup_changed: write already active");
        return NGX_OK;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    ngx_add_timer(&cctx->setup.timer, ppcf->setup_timeout);

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf, uint32_t *min_index)
{
    ngx_int_t                        rc;
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    /* avoid triggering setup write due to changes made while reading */
    cctx->setup.enabled = 0;

    rc = ngx_live_persist_read_parse(channel, buf, NGX_LIVE_PERSIST_TYPE_SETUP,
        NGX_LIVE_PERSIST_CTX_SETUP_MAIN, NULL);

    cctx->setup.enabled = 1;

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_setup_read_handler: read success");

    *min_index = 0;
    return NGX_OK;
}


/* index snapshot */

static ngx_int_t
ngx_live_persist_channel_index_snap(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_persist_index_snap_t     *snap = ectx;
    ngx_live_persist_index_track_t    *tp;
    ngx_live_persist_index_channel_t  *cp;

    cp = ngx_palloc(snap->pool, sizeof(*cp) +
        sizeof(*tp) * (channel->tracks.count + 1));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_channel_index_snap: alloc failed");
        return NGX_ERROR;
    }

    tp = (void *) (cp + 1);

    ngx_live_set_ctx(snap, cp, ngx_live_persist_module);

    cp->reserved = 0;
    cp->last_modified = channel->last_modified;
    cp->last_segment_media_types = channel->last_segment_media_types;

    /* when called from segment_created, this field wasn't updated yet */
    cp->last_segment_created = ngx_time();

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        tp->track_id = cur_track->in.key;
        tp->has_last_segment = cur_track->has_last_segment;
        tp->last_segment_bitrate = cur_track->last_segment_bitrate;
        tp++;
    }

    tp->track_id = NGX_LIVE_INVALID_TRACK_ID;

    return NGX_OK;
}

ngx_live_persist_index_snap_t *
ngx_live_persist_index_snap_create(ngx_live_channel_t *channel)
{
    ngx_pool_t                      *pool;
    ngx_live_persist_index_snap_t   *snap;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->files[NGX_LIVE_PERSIST_FILE_INDEX].path == NULL) {
        return NULL;
    }

    pool = ngx_create_pool(1024, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: create pool failed");
        return NULL;
    }

    snap = ngx_palloc(pool, sizeof(*snap));
    if (snap == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: alloc snap failed");
        goto failed;
    }

    snap->ctx = ngx_pcalloc(pool, sizeof(void *) * ngx_live_max_module);
    if (snap->ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: alloc ctx failed");
        goto failed;
    }

    snap->channel = channel;
    snap->pool = pool;

    snap->max_track_id = channel->tracks.last_id;
    snap->scope.max_index = channel->next_segment_index;

    if (ngx_live_core_channel_event(channel, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP,
        snap) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: event failed");
        goto failed;
    }

    return snap;

failed:

    ngx_destroy_pool(pool);

    return NULL;
}

void
ngx_live_persist_index_snap_free(ngx_live_persist_index_snap_t *snap)
{
    ngx_destroy_pool(snap->pool);
}

ngx_int_t
ngx_live_persist_index_snap_write(ngx_live_persist_index_snap_t *snap)
{
    ngx_int_t                        rc;
    ngx_uint_t                       file;
    ngx_live_channel_t              *channel = snap->channel;
    ngx_live_persist_preset_conf_t  *ppcf;
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (cctx->index.write_ctx != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
            "ngx_live_persist_index_snap_write: write already active");

        if (cctx->index.pending != NULL) {
            ngx_live_persist_index_snap_free(cctx->index.pending);
        }
        cctx->index.pending = snap;
        return NGX_OK;
    }

    if (snap->scope.max_index < channel->min_segment_index) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_index_snap_write: no segments");
        rc = NGX_OK;
        goto done;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_DELTA].path != NULL &&
        snap->scope.max_index - channel->min_segment_index + 1 >
            ppcf->max_delta_segments &&
        snap->scope.max_index - cctx->index.success_index <=
            ppcf->max_delta_segments)
    {
        file = NGX_LIVE_PERSIST_FILE_DELTA;
        snap->scope.min_index = cctx->index.success_index + 1;

    } else {
        file = NGX_LIVE_PERSIST_FILE_INDEX;
        snap->scope.min_index = channel->min_segment_index;
    }

    cctx->index.write_ctx = ngx_live_persist_write_file(channel, file,
        snap, &snap->scope, sizeof(snap->scope));
    if (cctx->index.write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_write: "
            "write failed, file: %ui, scope: %uD..%uD",
            file, snap->scope.min_index, snap->scope.max_index);
        rc = NGX_ERROR;
        goto done;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_snap_write: "
        "write started, file: %ui, scope: %uD..%uD",
        file, snap->scope.min_index, snap->scope.max_index);
    rc = NGX_OK;

done:

    ngx_live_persist_index_snap_free(snap);

    return rc;
}


/* index */

static ngx_int_t
ngx_live_persist_index_write_channel(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t                     *ws;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_index_snap_t     *snap;
    ngx_live_persist_index_channel_t  *cp;

    ws = ngx_live_persist_write_stream(write_ctx);
    snap = ngx_live_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_module);

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_live_persist_write(write_ctx, &snap->scope,
            sizeof(snap->scope)) != NGX_OK ||
        ngx_live_persist_write(write_ctx, cp, sizeof(*cp)) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_write_channel: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_index_read_channel(ngx_live_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                          rc;
    ngx_hash_t                        *hash;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_main_conf_t      *pmcf;
    ngx_live_persist_index_scope_t    *fs;
    ngx_live_persist_index_scope_t    *scope;
    ngx_live_persist_index_channel_t  *cp;

    rc = ngx_live_persist_read_channel_id(channel, rs);
    if (rc != NGX_OK) {
        return rc;
    }

    fs = ngx_mem_rstream_get_ptr(rs, sizeof(*fs) + sizeof(*cp));
    if (fs == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "read data failed");
        return NGX_BAD_DATA;
    }

    if (fs->min_index > fs->max_index ||
        fs->max_index >= NGX_LIVE_INVALID_SEGMENT_INDEX)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "invalid scope, min: %uD, max: %uD", fs->min_index, fs->max_index);
        return NGX_BAD_DATA;
    }

    scope = ngx_mem_rstream_scope(rs);

    if (scope->min_index != 0 && fs->min_index != scope->min_index) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "file delta index %uD doesn't match expected %uD",
            fs->min_index, scope->min_index);
        return NGX_OK;
    }

    *scope = *fs;

    cp = (void *) (fs + 1);

    channel->last_modified = cp->last_modified;
    channel->last_segment_media_types = cp->last_segment_media_types;
    channel->last_segment_created = cp->last_segment_created;

    channel->next_segment_index = fs->max_index + 1;

    if (ngx_live_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL].hash;
    rc = ngx_live_persist_read_blocks(rs, hash, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_index_read_channel: read blocks failed");
        return rc;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_index_write_track(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_index_snap_t     *snap;
    ngx_live_persist_index_track_t    *tp;
    ngx_live_persist_index_channel_t  *cp;

    snap = ngx_live_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_module);
    tp = (void *) (cp + 1);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->type == ngx_live_track_type_filler) {
            /* will be created by the filler module */
            continue;
        }

        if (cur_track->in.key > snap->max_track_id) {
            continue;
        }

        for (; tp->track_id != cur_track->in.key; tp++) {
            if (tp->track_id == NGX_LIVE_INVALID_TRACK_ID) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_persist_index_write_track: "
                    "track %ui not found in snapshot", cur_track->in.key);
                return NGX_OK;
            }
        }

        if (ngx_live_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_live_persist_write(write_ctx, tp, sizeof(*tp)) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_INDEX_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_persist_index_write_track: write failed");
            return NGX_ERROR;
        }

        ngx_live_persist_write_block_close(write_ctx);

        tp++;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_index_read_track(ngx_live_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                        rc;
    ngx_hash_t                      *hash;
    ngx_live_track_t                *track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_main_conf_t    *pmcf;
    ngx_live_persist_index_track_t  *tp;

    tp = ngx_mem_rstream_get_ptr(rs, sizeof(*tp));
    if (tp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_track: read failed");
        return NGX_BAD_DATA;
    }

    track = ngx_live_track_get_by_int(channel, tp->track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_track: "
            "track index %uD not found", tp->track_id);
        return NGX_OK;
    }

    track->has_last_segment = tp->has_last_segment;
    track->last_segment_bitrate = tp->last_segment_bitrate;

    if (ngx_live_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_INDEX_TRACK].hash;
    rc = ngx_live_persist_read_blocks(rs, hash, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_index_read_track: read blocks failed");
        return rc;
    }

    return NGX_OK;
}

static void
ngx_live_persist_index_write_complete(ngx_live_channel_t *channel,
    ngx_uint_t file, void *data, ngx_int_t rc)
{
    ngx_live_persist_index_snap_t   *snap;
    ngx_live_persist_channel_ctx_t  *cctx;
    ngx_live_persist_index_scope_t  *scope = data;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->index.write_ctx = NULL;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_write_complete: "
            "write failed %i, file: %ui, scope: %uD..%uD",
            rc, file, scope->min_index, scope->max_index);

    } else {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_index_write_complete: "
            "write success, file: %ui, scope: %uD..%uD",
            file, scope->min_index, scope->max_index);

        if (file == NGX_LIVE_PERSIST_FILE_INDEX) {
            cctx->index.success_index = scope->max_index;

        } else {
            cctx->index.success_delta = scope->max_index;
        }
    }

    if (cctx->index.pending != NULL) {
        snap = cctx->index.pending;
        cctx->index.pending = NULL;

        (void) ngx_live_persist_index_snap_write(snap);
    }
}

static ngx_int_t
ngx_live_persist_index_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf, uint32_t *min_index)
{
    ngx_int_t                        rc;
    ngx_live_persist_index_scope_t   scope;
    ngx_live_persist_channel_ctx_t  *cctx;

    scope.min_index = *min_index;
    scope.max_index = 0;

    rc = ngx_live_persist_read_parse(channel, buf, NGX_LIVE_PERSIST_TYPE_INDEX,
        NGX_LIVE_PERSIST_CTX_INDEX_MAIN, &scope);
    if (rc != NGX_OK) {
        return rc;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (file == NGX_LIVE_PERSIST_FILE_INDEX) {
        cctx->index.success_index = scope.max_index;

    } else {
        cctx->index.success_delta = scope.max_index;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_read_handler: "
        "read success, scope: %uD..%uD",
        scope.min_index, scope.max_index);

    *min_index = scope.max_index + 1;
    return NGX_OK;
}


/* shared */

ngx_live_store_t *
ngx_live_persist_get_store(ngx_live_channel_t *channel)
{
    ngx_live_persist_preset_conf_t  *dpcf;

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    return dpcf->store;
}

char *
ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store)
{
    ngx_live_conf_ctx_t             *live_ctx;
    ngx_live_persist_preset_conf_t  *dmcf;

    live_ctx = cf->ctx;

    dmcf = ngx_live_get_module_preset_conf(live_ctx, ngx_live_persist_module);

    if (dmcf->store != NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "persist store already set");
        return NGX_CONF_ERROR;
    }

    dmcf->store = store;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_live_persist_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_channel_ctx_t  *cctx;
    ngx_live_persist_preset_conf_t  *ppcf;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_module);

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_SETUP].path != NULL &&
        ppcf->store != NULL)
    {
        cctx->setup.enabled = 1;

        cctx->setup.timer.handler = ngx_live_persist_setup_write_handler;
        cctx->setup.timer.data = channel;
        cctx->setup.timer.log = &channel->log;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_channel_ctx_t     *cctx;
    ngx_live_persist_index_scope_t     *scope;
    ngx_live_persist_file_write_ctx_t  *ctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

#if 0       // TODO: remove if unneeded
    if (cctx->setup.timer.data == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }
#endif

    if (cctx->read_ctx != NULL) {
        ngx_live_persist_read_handler(cctx->read_ctx, NGX_HTTP_CONFLICT, NULL);
    }

    ctx = cctx->setup.write_ctx;
    if (ctx != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_channel_free: "
            "cancelling setup write, version: %uD", *(uint32_t *) ctx->scope);

        ngx_destroy_pool(ctx->pool);
    }

    ctx = cctx->index.write_ctx;
    if (ctx != NULL) {
        scope = (void *) ctx->scope;
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_channel_free: "
            "cancelling index write, file: %ui, scope: %uD..%uD",
            ctx->file, scope->min_index, scope->max_index);

        ngx_destroy_pool(ctx->pool);
    }

    if (cctx->index.pending != NULL) {
        ngx_live_persist_index_snap_free(cctx->index.pending);
    }

    if (cctx->setup.timer.timer_set) {
        ngx_del_timer(&cctx->setup.timer);
    }

    return NGX_OK;
}




static ngx_int_t
ngx_ngx_live_persist_add_block_internal(ngx_conf_t *cf,
    ngx_live_persist_main_conf_t *pmcf, ngx_live_persist_block_t *block)
{
    ngx_int_t                  rc;
    ngx_str_t                  id;
    ngx_live_persist_block_t  *blk;

    if (block->ctx >= NGX_LIVE_PERSIST_CTX_COUNT) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
            "invalid block ctx %uD", block->ctx);
        return NGX_ERROR;
    }

    blk = ngx_array_push(&pmcf->blocks[block->ctx].arr);
    if (blk == NULL) {
        return NGX_ERROR;
    }

    *blk = *block;

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
ngx_ngx_live_persist_add_block(ngx_conf_t *cf, ngx_live_persist_block_t *block)
{
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_persist_module);

    return ngx_ngx_live_persist_add_block_internal(cf, pmcf, block);
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


static ngx_live_persist_block_t  ngx_live_persist_blocks[] = {

    /* setup */

    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_SETUP_MAIN,
      NGX_LIVE_PERSIST_FLAG_SINGLE,
      ngx_live_persist_setup_write_channel,
      ngx_live_persist_setup_read_channel },

    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_persist_setup_write_track,
      ngx_live_persist_setup_read_track },

    { NGX_LIVE_PERSIST_BLOCK_VARIANT, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_persist_setup_write_variant,
      ngx_live_persist_setup_read_variant },

    /* index */

    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
      NGX_LIVE_PERSIST_FLAG_SINGLE,
      ngx_live_persist_index_write_channel,
      ngx_live_persist_index_read_channel },

    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, 0,
      ngx_live_persist_index_write_track,
      ngx_live_persist_index_read_track },

    ngx_live_null_persist_block
};

static void *
ngx_live_persist_create_main_conf(ngx_conf_t *cf)
{
    ngx_uint_t                     i;
    ngx_hash_keys_arrays_t        *keys;
    ngx_live_persist_block_t      *block;
    ngx_live_persist_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    for (i = 0; i < NGX_LIVE_PERSIST_CTX_COUNT; i++) {
        if (ngx_array_init(&pmcf->blocks[i].arr, cf->pool, 5,
            sizeof(ngx_live_persist_block_t)) != NGX_OK)
        {
            return NULL;
        }

        keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (keys == NULL) {
            return NULL;
        }

        keys->pool = cf->pool;
        keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(keys, NGX_HASH_SMALL)
            != NGX_OK)
        {
            return NULL;
        }

        pmcf->blocks[i].keys = keys;
    }

    for (block = ngx_live_persist_blocks; block->id; block++) {
        if (ngx_ngx_live_persist_add_block_internal(cf, pmcf, block)
            != NGX_OK)
        {
            return NULL;
        }
    }

    return pmcf;
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
    conf->setup_timeout = NGX_CONF_UNSET_MSEC;
    conf->max_delta_segments = NGX_CONF_UNSET_UINT;
    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        conf->files[i].max_size = NGX_CONF_UNSET_SIZE;
    }

    return conf;
}

static char *
ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t                       i;
    ngx_live_persist_preset_conf_t  *prev = parent;
    ngx_live_persist_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    for (i = 0; i < NGX_LIVE_PERSIST_FILE_COUNT; i++) {
        if (conf->files[i].path == NULL) {
            conf->files[i].path = prev->files[i].path;
        }

        if (conf->files[i].path != NULL && conf->store == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "persist_xxx_path was used but no store was set");
            return NGX_CONF_ERROR;
        }

        ngx_conf_merge_size_value(conf->files[i].max_size,
                                  prev->files[i].max_size, 5 * 1024 * 1024);
    }

    if (conf->files[NGX_LIVE_PERSIST_FILE_INDEX].path != NULL &&
        conf->files[NGX_LIVE_PERSIST_FILE_SETUP].path == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"persist_index_path\" requires \"persist_setup_path\"");
        return NGX_CONF_ERROR;
    }

    if (conf->files[NGX_LIVE_PERSIST_FILE_DELTA].path != NULL &&
        conf->files[NGX_LIVE_PERSIST_FILE_INDEX].path == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"persist_delta_path\" requires \"persist_index_path\"");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_msec_value(conf->setup_timeout,
                              prev->setup_timeout, 10000);

    ngx_conf_merge_uint_value(conf->max_delta_segments,
                              prev->max_delta_segments, 100);

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_channel_events[] = {
    { ngx_live_persist_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_persist_channel_setup_changed,
        NGX_LIVE_EVENT_CHANNEL_SETUP_CHANGED },
    { ngx_live_persist_channel_index_snap, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP },

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
