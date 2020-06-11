#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


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


enum {
    NGX_LIVE_PERSIST_DISABLED,
    NGX_LIVE_PERSIST_ENABLED,
    NGX_LIVE_PERSIST_ACTIVE,
};


typedef struct {
    ngx_hash_t                         hash;
    ngx_array_t                        arr;
    ngx_hash_keys_arrays_t            *keys;
} ngx_live_persist_block_ctx_t;


typedef struct {
    ngx_live_persist_block_ctx_t       blocks[NGX_LIVE_PERSIST_CTX_COUNT];
} ngx_live_persist_main_conf_t;


typedef struct {
    ngx_live_store_t                  *store;
    ngx_live_complex_value_t          *setup_path;
    ngx_msec_t                         setup_timeout;
    size_t                             setup_max_size;
} ngx_live_persist_preset_conf_t;


typedef struct {
    ngx_pool_t                        *pool;
    ngx_live_channel_t                *channel;
    size_t                             size;
    ngx_msec_t                         start;
    uint32_t                           version;
} ngx_live_persist_setup_write_ctx_t;


typedef struct {
    ngx_event_t                        timer;
    uint32_t                           version;

    uint32_t                           started;
    uint32_t                           error;
    uint32_t                           success;
    uint64_t                           success_msec;
    uint64_t                           success_size;
    uint32_t                           success_version;

    uint32_t                           state;
} ngx_live_persist_setup_channel_ctx_t;


typedef struct {
    ngx_live_persist_setup_channel_ctx_t  setup;
} ngx_live_persist_channel_ctx_t;


typedef struct {
    uint32_t                           track_id;
    uint32_t                           media_type;
    uint32_t                           type;
} ngx_live_persist_track_t;


typedef struct {
    uint32_t                           role;
    uint32_t                           is_default;
    uint32_t                           track_count;
} ngx_live_persist_variant_t;


typedef struct {
    ngx_live_channel_t                *channel;
    ngx_pool_t                        *pool;
    ngx_live_persist_read_handler_pt   handler;
    void                              *data;
    ngx_pool_cleanup_t                *cln;
} ngx_live_persist_read_ctx_t;


static ngx_command_t  ngx_live_persist_commands[] = {
    { ngx_string("persist_setup_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_preset_conf_t, setup_path),
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
      offsetof(ngx_live_persist_preset_conf_t, setup_max_size),
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

static ngx_int_t
ngx_live_persist_setup_write_channel(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t       *ws;
    ngx_live_channel_t  *channel = obj;

    ws = ngx_live_persist_write_stream(write_ctx);

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_block_str_write(ws, &channel->opaque) != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_CHANNEL, channel) != NGX_OK)
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
    ngx_int_t                      rc;
    ngx_str_t                      id;
    ngx_hash_t                    *hash;
    ngx_live_channel_t            *channel = obj;
    ngx_live_persist_main_conf_t  *pmcf;

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

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_CHANNEL].hash;
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
    ngx_queue_t               *q;
    ngx_wstream_t             *ws;
    ngx_live_track_t          *cur_track;
    ngx_live_channel_t        *channel = obj;
    ngx_live_persist_track_t   t;

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

        t.track_id = cur_track->in.key;
        t.media_type = cur_track->media_type;
        t.type = cur_track->type;

        if (ngx_live_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_wstream_str(ws, &cur_track->sn.str) != NGX_OK ||
            ngx_live_persist_write(write_ctx, &t, sizeof(t)) != NGX_OK ||
            ngx_block_str_write(ws, &cur_track->opaque) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_TRACK, cur_track) != NGX_OK)
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
    ngx_int_t                      rc;
    ngx_str_t                      id;
    ngx_hash_t                    *hash;
    ngx_live_track_t              *track;
    ngx_live_channel_t            *channel = obj;
    ngx_live_persist_track_t      *t;
    ngx_live_persist_main_conf_t  *pmcf;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: read id failed");
        return NGX_BAD_DATA;
    }

    t = ngx_mem_rstream_get_ptr(rs, sizeof(*t));
    if (t == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: "
            "read data failed, track: %V", &id);
        return NGX_BAD_DATA;
    }

    rc = ngx_live_track_create(channel, &id, t->track_id, t->media_type,
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

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_TRACK].hash;
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
    uint32_t                     i;
    uint32_t                    *cur_id;
    uint32_t                     track_ids[KMP_MEDIA_COUNT];
    ngx_queue_t                 *q;
    ngx_wstream_t               *ws;
    ngx_live_track_t            *cur_track;
    ngx_live_channel_t          *channel = obj;
    ngx_live_variant_t          *cur_variant;
    ngx_live_persist_variant_t   v;

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
    uint32_t                     i;
    uint32_t                     track_id;
    ngx_int_t                    rc;
    ngx_str_t                    id;
    ngx_live_track_t            *cur_track;
    ngx_live_variant_t          *variant;
    ngx_live_channel_t          *channel = obj;
    ngx_live_variant_conf_t      conf;
    ngx_live_persist_variant_t  *v;

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

static ngx_chain_t *
ngx_live_persist_setup_write_create(ngx_live_persist_setup_write_ctx_t *ctx)
{
    ngx_live_channel_t            *channel;
    ngx_live_persist_write_ctx_t  *write_ctx;

    channel = ctx->channel;

    write_ctx = ngx_live_persist_write_init(ctx->pool,
        NGX_LIVE_PERSIST_TYPE_SETUP);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_create: write init failed");
        return NULL;
    }

    if (ngx_live_persist_write_blocks(channel, write_ctx,
        NGX_LIVE_PERSIST_CTX_MAIN, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_create: write blocks failed");
        return NULL;
    }

    return ngx_live_persist_write_close(write_ctx, &ctx->size);
}

static ngx_int_t
ngx_live_persist_setup_read_parse(ngx_live_channel_t *channel, ngx_str_t *buf)
{
    ngx_int_t                      rc;
    ngx_hash_t                    *hash;
    ngx_mem_rstream_t              rs;
    ngx_live_persist_main_conf_t  *pmcf;

    if (ngx_live_persist_read_file_header(buf, NGX_LIVE_PERSIST_TYPE_SETUP,
        &channel->log, &rs) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_read_parse: read header failed");
        return NGX_BAD_DATA;
    }

    pmcf = ngx_live_get_module_main_conf(channel, ngx_live_persist_module);

    hash = &pmcf->blocks[NGX_LIVE_PERSIST_CTX_MAIN].hash;
    rc = ngx_live_persist_read_blocks(&rs, hash, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_read_parse: read blocks failed");
        return rc;
    }

    return NGX_OK;
}


static void
ngx_live_persist_setup_write_complete(void *arg, ngx_int_t rc)
{
    ngx_live_channel_t                  *channel;
    ngx_live_persist_channel_ctx_t      *cctx;
    ngx_live_persist_setup_write_ctx_t  *ctx = arg;

    channel = ctx->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_complete: "
            "write failed %i, version: %uD", rc, ctx->version);
        cctx->setup.error++;

    } else {
        cctx->setup.success++;
        cctx->setup.success_msec += ngx_current_msec - ctx->start;
        cctx->setup.success_size += ctx->size;
        cctx->setup.success_version = ctx->version;
    }

    cctx->setup.state = NGX_LIVE_PERSIST_ENABLED;

    if (ctx->version != cctx->setup.version) {
        ngx_add_timer(&cctx->setup.timer, 1);
    }

    ngx_destroy_pool(ctx->pool);
}

static void
ngx_live_persist_setup_write_handler(ngx_event_t *ev)
{
    ngx_int_t                            rc;
    ngx_pool_t                          *pool;
    ngx_live_channel_t                  *channel = ev->data;
    ngx_live_store_write_request_t       request;
    ngx_live_persist_preset_conf_t      *ppcf;
    ngx_live_persist_channel_ctx_t      *cctx;
    ngx_live_persist_setup_write_ctx_t  *ctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    cctx->setup.started++;

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: create pool failed");
        goto failed;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    rc = ngx_live_complex_value(channel, pool, ppcf->setup_path,
        &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: complex value failed");
        goto failed;
    }

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: alloc failed");
        goto failed;
    }

    ctx->pool = pool;
    ctx->channel = channel;
    ctx->start = ngx_current_msec;
    ctx->version = cctx->setup.version;

    request.cl = ngx_live_persist_setup_write_create(ctx);
    if (request.cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: create file failed");
        goto failed;
    }

    if (ctx->size > ppcf->setup_max_size) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: "
            "size %uz exceeds limit %uz", ctx->size, ppcf->setup_max_size);
        goto failed;
    }

    request.pool = pool;
    request.channel = channel;
    request.size = ctx->size;
    request.handler = ngx_live_persist_setup_write_complete;
    request.data = ctx;

    if (ppcf->store->write(&request) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_handler: write failed");
        goto failed;
    }

    cctx->setup.state = NGX_LIVE_PERSIST_ACTIVE;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_setup_write_handler: "
        "write started, version: %uD", ctx->version);

    return;

failed:

    cctx->setup.error++;

    if (pool) {
        ngx_destroy_pool(pool);
    }
}

static void
ngx_live_persist_setup_read_handler(void *data, ngx_int_t rc,
    ngx_buf_t *response)
{
    uint32_t                           saved;
    ngx_str_t                          buf;
    ngx_pool_cleanup_t                *cln;
    ngx_live_channel_t                *channel;
    ngx_live_persist_read_ctx_t       *ctx = data;
    ngx_live_persist_channel_ctx_t    *cctx;
    ngx_live_persist_read_handler_pt   handler;

    channel = ctx->channel;

    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_NOT_FOUND) {
            rc = NGX_OK;

        } else {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_setup_read_handler: read failed %i", rc);
        }

        goto done;
    }

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    /* avoid triggering setup write due to changes made while reading */
    saved = cctx->setup.state;
    cctx->setup.state = NGX_LIVE_PERSIST_DISABLED;

    rc = ngx_live_persist_setup_read_parse(channel, &buf);

    cctx->setup.state = saved;

    if (rc != NGX_OK) {
        goto done;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_setup_read_handler: read success");

done:

    handler = ctx->handler;
    data = ctx->data;
    cln = ctx->cln;

    ngx_destroy_pool(ctx->pool);

    if (handler) {
        /* ctx was freed, must disable the cleanup handler */
        cln->handler = NULL;

        handler(data, rc);
    }
}

static void
ngx_live_persist_read_detach(void *data)
{
    ngx_live_persist_read_ctx_t  *ctx = data;

    /* handler pool destroyed, must not call the handler */
    ctx->handler = NULL;
}

ngx_int_t
ngx_live_persist_read(ngx_live_channel_t *channel, ngx_pool_t *handler_pool,
    ngx_live_persist_read_handler_pt handler, void *data)
{
    void                            *read_ctx;
    ngx_int_t                        rc;
    ngx_pool_t                      *pool;
    ngx_pool_cleanup_t              *cln;
    ngx_live_persist_read_ctx_t     *ctx;
    ngx_live_store_read_request_t    request;
    ngx_live_persist_preset_conf_t  *ppcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->setup_path == NULL || ppcf->store == NULL) {
        return NGX_OK;
    }

    pool = ngx_create_pool(2048, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: create pool failed");
        return NGX_ERROR;
    }

    rc = ngx_live_complex_value(channel, pool, ppcf->setup_path,
        &request.path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: complex value failed");
        goto failed;
    }

    ctx = ngx_palloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: alloc failed");
        goto failed;
    }

    cln = ngx_pool_cleanup_add(handler_pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: cleanup add failed");
        goto failed;
    }

    ctx->channel = channel;
    ctx->pool = pool;
    ctx->handler = handler;
    ctx->data = data;
    ctx->cln = cln;

    request.pool = pool;
    request.channel = channel;
    request.max_size = ppcf->setup_max_size;

    request.handler = ngx_live_persist_setup_read_handler;
    request.data = ctx;

    read_ctx = ppcf->store->read_init(&request);
    if (read_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: read init failed");
        goto failed;
    }

    rc = ppcf->store->read(read_ctx, 0, 0);
    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_read: read failed");
        goto failed;
    }

    cln->handler = ngx_live_persist_read_detach;
    cln->data = ctx;

    return NGX_DONE;

failed:

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


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

    if (ppcf->setup_path != NULL && ppcf->store != NULL) {

        cctx->setup.state = NGX_LIVE_PERSIST_ENABLED;

        cctx->setup.timer.handler = ngx_live_persist_setup_write_handler;
        cctx->setup.timer.data = channel;
        cctx->setup.timer.log = &channel->log;

    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

#if 0       // TODO: remove if unneeded
    if (cctx->setup.timer.data == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }
#endif

    if (cctx->setup.timer.timer_set) {
        ngx_del_timer(&cctx->setup.timer);
    }

    /* Note: if there's a pending write request, it will be closed by
        the channel pool cleanup */

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_channel_setup_changed(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_preset_conf_t  *ppcf;
    ngx_live_persist_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_module);

    if (cctx->setup.state == NGX_LIVE_PERSIST_DISABLED) {
        return NGX_OK;
    }

    cctx->setup.version++;

    if (cctx->setup.state == NGX_LIVE_PERSIST_ACTIVE) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_channel_setup_changed: write already active");
        return NGX_OK;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    ngx_add_timer(&cctx->setup.timer, ppcf->setup_timeout);

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

#if 0       // TODO: remove if unneeded
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
#endif

static ngx_live_persist_block_t  ngx_live_persist_blocks[] = {
    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_MAIN,
      NGX_LIVE_PERSIST_FLAG_SINGLE,
      ngx_live_persist_setup_write_channel,
      ngx_live_persist_setup_read_channel },

    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_CHANNEL, 0,
      ngx_live_persist_setup_write_track,
      ngx_live_persist_setup_read_track },

    { NGX_LIVE_PERSIST_BLOCK_VARIANT, NGX_LIVE_PERSIST_CTX_CHANNEL, 0,
      ngx_live_persist_setup_write_variant,
      ngx_live_persist_setup_read_variant },

    { 0, 0, 0, NULL, NULL}
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
    ngx_live_persist_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->store = NGX_CONF_UNSET_PTR;
    conf->setup_timeout = NGX_CONF_UNSET_MSEC;
    conf->setup_max_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_live_persist_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_persist_preset_conf_t  *prev = parent;
    ngx_live_persist_preset_conf_t  *conf = child;

    if (conf->setup_path == NULL) {
        conf->setup_path = prev->setup_path;
    }

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    ngx_conf_merge_msec_value(conf->setup_timeout,
                              prev->setup_timeout, 10000);

    ngx_conf_merge_size_value(conf->setup_max_size,
                              prev->setup_max_size, 5 * 1024 * 1024);

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_channel_events[] = {
    { ngx_live_persist_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_persist_channel_setup_changed,
        NGX_LIVE_EVENT_CHANNEL_SETUP_CHANGED },
      ngx_live_null_event
};

static ngx_int_t
ngx_live_persist_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_persist_init_block_hash(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
