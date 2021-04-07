#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_persist_internal.h"


static ngx_int_t ngx_live_persist_setup_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_persist_setup_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_setup_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_setup_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


typedef struct {
    ngx_event_t                         timer;
    uint32_t                            version;
    uint32_t                            success_version;
    ngx_live_persist_write_file_ctx_t  *write_ctx;
    unsigned                            enabled:1;
} ngx_live_persist_setup_channel_ctx_t;


typedef struct {
    ngx_msec_t                          setup_timeout;
} ngx_live_persist_setup_preset_conf_t;


/* format */

typedef struct {
    uint32_t                            version;
    uint32_t                            initial_segment_index;
    uint64_t                            start_sec;
} ngx_live_persist_setup_channel_t;

typedef struct {
    uint32_t                            track_id;
    uint32_t                            media_type;
    uint32_t                            type;
    uint32_t                            reserved;
    uint64_t                            start_sec;
} ngx_live_persist_setup_track_t;

typedef struct {
    uint32_t                            role;
    uint32_t                            is_default;
    uint32_t                            track_count;
} ngx_live_persist_setup_variant_t;


static ngx_command_t  ngx_live_persist_setup_commands[] = {
    { ngx_string("persist_setup_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_setup_preset_conf_t, setup_timeout),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_persist_setup_module_ctx = {
    ngx_live_persist_setup_preconfiguration,  /* preconfiguration */
    ngx_live_persist_setup_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_persist_setup_create_preset_conf,/* create preset configuration */
    ngx_live_persist_setup_merge_preset_conf  /* merge preset configuration */
};


ngx_module_t  ngx_live_persist_setup_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_setup_module_ctx,       /* module context */
    ngx_live_persist_setup_commands,          /* module directives */
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
ngx_live_persist_setup_write_channel(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                          *version;
    ngx_wstream_t                     *ws;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_setup_channel_t   cp;

    ws = ngx_persist_write_stream(write_ctx);
    version = ngx_persist_write_ctx(write_ctx);

    cp.version = *version;
    cp.initial_segment_index = channel->initial_segment_index;
    cp.start_sec = channel->start_sec;

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_persist_write(write_ctx, &cp, sizeof(cp)) != NGX_OK ||
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
ngx_live_persist_setup_read_channel(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                              rc;
    ngx_live_channel_t                    *channel = obj;
    ngx_live_persist_setup_channel_t      *cp;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

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

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    cctx->version = cctx->success_version = cp->version;

    rc = ngx_live_channel_block_str_read(channel, &channel->opaque, rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read opaque failed");
        return rc;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, rs, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_channel: read blocks failed");
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_setup_write_track(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                     *q;
    ngx_wstream_t                   *ws;
    ngx_live_track_t                *cur_track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_setup_track_t   tp;

    ws = ngx_persist_write_stream(write_ctx);

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

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_wstream_str(ws, &cur_track->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &tp, sizeof(tp)) != NGX_OK ||
            ngx_block_str_write(ws, &cur_track->opaque) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_SETUP_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_persist_setup_write_track: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_track(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                        rc;
    ngx_str_t                        id;
    ngx_log_t                       *orig_log;
    ngx_live_track_t                *track;
    ngx_live_channel_t              *channel = obj;
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
            "create failed %i, track: %V", rc, &id);

        if (rc == NGX_EXISTS || rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    orig_log = rs->log;
    rs->log = &track->log;

    track->start_sec = tp->start_sec;

    rc = ngx_live_channel_block_str_read(channel, &track->opaque, rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_setup_read_track: read opaque failed");
        return rc;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_SETUP_TRACK, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_setup_read_track: read blocks failed");
        return rc;
    }

    rs->log = orig_log;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_setup_write_variant(ngx_persist_write_ctx_t *write_ctx,
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

    ws = ngx_persist_write_stream(write_ctx);

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

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_VARIANT) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &v, sizeof(v)) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.label) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.lang) != NGX_OK ||
            ngx_persist_write(write_ctx, track_ids,
                (u_char *) cur_id - (u_char *) track_ids) != NGX_OK ||
            ngx_block_str_write(ws, &cur_variant->opaque) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_setup_write_variant: "
                "write failed, variant: %V", &cur_variant->sn.str);
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_read_variant(ngx_persist_block_header_t *header,
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
            "create failed %i, variant: %V", rc, &id);

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


void
ngx_live_persist_setup_write_complete(ngx_live_persist_write_file_ctx_t *ctx,
    ngx_int_t rc)
{
    uint32_t                               version;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    channel = ctx->channel;
    version = *(uint32_t *) ctx->scope;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    cctx->write_ctx = NULL;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_write_complete: "
            "write failed %i, version: %uD", rc, version);

    } else {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_setup_write_complete: "
            "write success, version: %uD", version);

        cctx->success_version = version;
    }

    if (version != cctx->version) {
        ngx_add_timer(&cctx->timer, 1);
    }

    ngx_live_persist_write_file_destroy(ctx);
}

static void
ngx_live_persist_setup_write_handler(ngx_event_t *ev)
{
    uint32_t                               version;
    ngx_live_channel_t                    *channel = ev->data;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    version = cctx->version;

    cctx->write_ctx = ngx_live_persist_write_file(channel,
        NGX_LIVE_PERSIST_FILE_SETUP, &version, &version, sizeof(version));
    if (cctx->write_ctx == NULL) {
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
ngx_live_persist_setup_channel_changed(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_setup_preset_conf_t  *pspcf;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    if (!cctx->enabled) {
        return NGX_OK;
    }

    cctx->version++;

    if (cctx->write_ctx != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
            "ngx_live_persist_setup_channel_changed: write already active");
        return NGX_OK;
    }

    pspcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_setup_module);

    ngx_add_timer(&cctx->timer, pspcf->setup_timeout);

    return NGX_OK;
}


ngx_int_t
ngx_live_persist_setup_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf, uint32_t *min_index)
{
    ngx_int_t                              rc;
    ngx_flag_t                             enabled;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    /* avoid triggering setup write due to changes made while reading */
    enabled = cctx->enabled;
    cctx->enabled = 0;

    rc = ngx_live_persist_read_parse(channel, buf, file, NULL);

    cctx->enabled = enabled;

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_setup_read_handler: read success");

    *min_index = 0;
    return NGX_OK;
}


size_t
ngx_live_persist_setup_json_get_size(ngx_live_channel_t *channel)
{
    size_t  result =
        sizeof("\"version\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"success_version\":") - 1 + NGX_INT32_LEN;

    return result;
}

u_char *
ngx_live_persist_setup_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    p = ngx_copy_fix(p, "\"version\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) cctx->version);
    p = ngx_copy_fix(p, ",\"success_version\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) cctx->success_version);

    return p;
}


static ngx_int_t
ngx_live_persist_setup_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_setup_module);

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_SETUP].path != NULL && ppcf->write) {
        cctx->enabled = 1;

        cctx->timer.handler = ngx_live_persist_setup_write_handler;
        cctx->timer.data = channel;
        cctx->timer.log = &channel->log;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_setup_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    uint32_t                              *version;
    ngx_live_persist_write_file_ctx_t     *ctx;
    ngx_live_persist_setup_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_setup_module);

    ctx = cctx->write_ctx;
    if (ctx != NULL) {
        version = (void *) ctx->scope;
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_setup_channel_free: "
            "cancelling write, version: %uD", *version);

        ngx_live_persist_write_file_destroy(ctx);
    }

    if (cctx->timer.timer_set) {
        ngx_del_timer(&cctx->timer);
    }

    return NGX_OK;
}


static void *
ngx_live_persist_setup_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_persist_setup_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_setup_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->setup_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_live_persist_setup_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_persist_setup_preset_conf_t  *prev = parent;
    ngx_live_persist_setup_preset_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->setup_timeout,
                              prev->setup_timeout, 10000);

    return NGX_CONF_OK;
}


static ngx_persist_block_t  ngx_live_persist_setup_blocks[] = {
    /*
     * persist header:
     *   ngx_str_t                         id;
     *   ngx_live_persist_setup_channel_t  p;
     *   ngx_str_t                         opaque;
     */
    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_SETUP_MAIN,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_persist_setup_write_channel,
      ngx_live_persist_setup_read_channel },

    /*
     * persist header:
     *   ngx_str_t                       id;
     *   ngx_live_persist_setup_track_t  p;
     *   ngx_str_t                       opaque;
     */
    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_persist_setup_write_track,
      ngx_live_persist_setup_read_track },

    /*
     * persist data:
     *   ngx_str_t                         id;
     *   ngx_live_persist_setup_variant_t  p;
     *   ngx_str_t                         label;
     *   ngx_str_t                         lang;
     *   uint32_t                          track_id[p.track_count];
     *   ngx_str_t                         opaque;
     */
    { NGX_LIVE_PERSIST_BLOCK_VARIANT, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_persist_setup_write_variant,
      ngx_live_persist_setup_read_variant },

      ngx_null_persist_block
};

static ngx_int_t
ngx_live_persist_setup_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_persist_setup_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_setup_channel_events[] = {
    { ngx_live_persist_setup_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_setup_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_persist_setup_channel_changed,
        NGX_LIVE_EVENT_CHANNEL_SETUP_CHANGED },

      ngx_live_null_event
};

static ngx_int_t
ngx_live_persist_setup_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_setup_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
