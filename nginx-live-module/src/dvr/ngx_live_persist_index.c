#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_persist_internal.h"
#include "ngx_live_persist_snap_frames.h"


static ngx_int_t ngx_live_persist_index_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_persist_index_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_index_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_index_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


typedef struct {
    uint32_t                            success_index;
    uint32_t                            success_delta;
    ngx_live_persist_write_file_ctx_t  *write_ctx;
    ngx_live_persist_snap_t            *frames_snap;
    ngx_live_persist_snap_index_t      *pending;
} ngx_live_persist_index_channel_ctx_t;

typedef struct {
    ngx_uint_t                          max_delta_segments;
} ngx_live_persist_index_preset_conf_t;


/* format */

typedef struct {
    uint32_t                            reserved;
    uint32_t                            last_segment_media_types;
    int64_t                             last_segment_created;
    int64_t                             last_modified;
} ngx_live_persist_index_channel_t;

typedef struct {
    uint32_t                            track_id;
    uint32_t                            has_last_segment;
    uint32_t                            last_segment_bitrate;
    uint32_t                            reserved;
    int64_t                             last_frame_pts;
    uint64_t                            next_frame_id;
} ngx_live_persist_index_track_t;


static ngx_command_t  ngx_live_persist_index_commands[] = {
    { ngx_string("persist_max_delta_segments"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_index_preset_conf_t, max_delta_segments),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_persist_index_module_ctx = {
    ngx_live_persist_index_preconfiguration,  /* preconfiguration */
    ngx_live_persist_index_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_persist_index_create_preset_conf,/* create preset configuration */
    ngx_live_persist_index_merge_preset_conf  /* merge preset configuration */
};


ngx_module_t  ngx_live_persist_index_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_index_module_ctx,       /* module context */
    ngx_live_persist_index_commands,          /* module directives */
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


/* index snapshot */

static ngx_int_t
ngx_live_persist_index_channel_snap(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_persist_snap_index_t     *snap = ectx;
    ngx_live_persist_index_track_t    *tp;
    ngx_live_persist_index_channel_t  *cp;

    cp = ngx_palloc(snap->pool, sizeof(*cp) +
        sizeof(*tp) * (channel->tracks.count + 1));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_channel_snap: alloc failed");
        return NGX_ERROR;
    }

    tp = (void *) (cp + 1);

    ngx_live_set_ctx(snap, cp, ngx_live_persist_index_module);

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
        tp->last_frame_pts = cur_track->last_frame_pts;
        tp->next_frame_id = cur_track->next_frame_id;
        tp->reserved = 0;
        tp++;
    }

    tp->track_id = NGX_LIVE_INVALID_TRACK_ID;

    return NGX_OK;
}

static void
ngx_live_persist_index_snap_free(ngx_live_persist_snap_index_t *snap)
{
    snap->frames_snap->close(snap->frames_snap,
        ngx_live_persist_snap_close_free);
    ngx_destroy_pool(snap->pool);
}

static void
ngx_live_persist_index_snap_close(void *data,
    ngx_live_persist_snap_close_action_e action)
{
    ngx_uint_t                             file;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_index_t         *snap = data;
    ngx_live_persist_index_scope_t        *scope;
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_index_preset_conf_t  *pipcf;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    channel = snap->base.channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
        "ngx_live_persist_index_snap_close: index: %uD, action: %d",
        snap->base.scope.max_index, action);

    switch (action) {

    case ngx_live_persist_snap_close_free:
        ngx_live_persist_index_snap_free(snap);
        return;

    case ngx_live_persist_snap_close_ack:

        if (cctx->pending != NULL) {
            cctx->pending->frames_snap->close(cctx->pending->frames_snap,
                ngx_live_persist_snap_close_free);
            cctx->pending->frames_snap = snap->frames_snap;

        } else if (cctx->write_ctx != NULL) {
            cctx->frames_snap->close(cctx->frames_snap,
                ngx_live_persist_snap_close_free);
            cctx->frames_snap = snap->frames_snap;

        } else {
            snap->frames_snap->close(snap->frames_snap, action);
        }

        ngx_destroy_pool(snap->pool);
        return;

    case ngx_live_persist_snap_close_write:
        break;      /* handled outside the switch */
    }

    if (cctx->write_ctx != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
            "ngx_live_persist_index_snap_close: write already active");

        if (cctx->pending != NULL) {
            ngx_live_persist_index_snap_free(cctx->pending);
        }
        cctx->pending = snap;
        return;
    }

    scope = &snap->base.scope;
    if (scope->max_index < channel->min_segment_index) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_index_snap_close: no segments");
        goto close;
    }

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    pipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_index_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_DELTA].path != NULL &&
        scope->max_index - channel->min_segment_index + 1 >
            pipcf->max_delta_segments &&
        scope->max_index - cctx->success_index <=
            pipcf->max_delta_segments)
    {
        file = NGX_LIVE_PERSIST_FILE_DELTA;
        scope->min_index = cctx->success_index + 1;

    } else {
        file = NGX_LIVE_PERSIST_FILE_INDEX;
        scope->min_index = channel->min_segment_index;
    }

    cctx->write_ctx = ngx_live_persist_write_file(channel, file,
        snap, scope, sizeof(*scope));
    if (cctx->write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_close: "
            "write failed, file: %ui, scope: %uD..%uD",
            file, scope->min_index, scope->max_index);
        goto close;
    }

    cctx->frames_snap = snap->frames_snap;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_snap_close: "
        "write started, file: %ui, scope: %uD..%uD",
        file, scope->min_index, scope->max_index);

    ngx_destroy_pool(snap->pool);
    return;

close:

    snap->frames_snap->close(snap->frames_snap, action);
    ngx_destroy_pool(snap->pool);
}

ngx_live_persist_snap_t *
ngx_live_persist_index_snap_create(ngx_live_channel_t *channel)
{
    ngx_pool_t                     *pool;
    ngx_live_persist_snap_index_t  *snap;

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

    snap->frames_snap = ngx_live_persist_snap_frames_create(channel);
    if (snap->frames_snap == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: create frames snap failed");
        goto failed;
    }

    snap->base.channel = channel;
    snap->base.max_track_id = channel->tracks.last_id;
    snap->base.scope.max_index = channel->next_segment_index;
    snap->base.close = ngx_live_persist_index_snap_close;

    snap->pool = pool;

    if (ngx_live_core_channel_event(channel, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP,
        snap) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: event failed");
        snap->frames_snap->close(snap->frames_snap,
            ngx_live_persist_snap_close_free);
        goto failed;
    }

    return &snap->base;

failed:

    ngx_destroy_pool(pool);

    return NULL;
}


/* index */

static ngx_int_t
ngx_live_persist_index_write_channel(ngx_live_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t                     *ws;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_snap_index_t     *snap;
    ngx_live_persist_index_channel_t  *cp;

    ws = ngx_live_persist_write_stream(write_ctx);
    snap = ngx_live_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_index_module);

    if (ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_live_persist_write(write_ctx, &snap->base.scope,
            sizeof(snap->base.scope)) != NGX_OK ||
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
    ngx_live_channel_t                *channel = obj;
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

    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, rs, channel);
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
    ngx_live_persist_snap_index_t     *snap;
    ngx_live_persist_index_track_t    *tp;
    ngx_live_persist_index_channel_t  *cp;

    snap = ngx_live_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_index_module);
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

        if (cur_track->in.key > snap->base.max_track_id) {
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
    ngx_live_track_t                *track;
    ngx_live_channel_t              *channel = obj;
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
    track->last_frame_pts = tp->last_frame_pts;
    track->next_frame_id = tp->next_frame_id;

    if (ngx_live_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_INDEX_TRACK, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_index_read_track: read blocks failed");
        return rc;
    }

    return NGX_OK;
}


void
ngx_live_persist_index_write_complete(ngx_live_channel_t *channel,
    ngx_uint_t file, void *data, ngx_int_t rc)
{
    ngx_live_persist_snap_index_t         *snap;
    ngx_live_persist_index_scope_t        *scope = data;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    cctx->frames_snap->close(cctx->frames_snap,
        ngx_live_persist_snap_close_ack);

    cctx->write_ctx = NULL;
    cctx->frames_snap = NULL;

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
            cctx->success_index = scope->max_index;

        } else {
            cctx->success_delta = scope->max_index;
        }
    }

    if (cctx->pending != NULL) {
        snap = cctx->pending;
        cctx->pending = NULL;

        ngx_live_persist_index_snap_close(snap,
            ngx_live_persist_snap_close_write);
    }
}

ngx_int_t
ngx_live_persist_index_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf, uint32_t *min_index)
{
    ngx_int_t                              rc;
    ngx_live_persist_index_scope_t         scope;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    scope.min_index = *min_index;
    scope.max_index = 0;

    rc = ngx_live_persist_read_parse(channel, buf, file, &scope);
    if (rc != NGX_OK) {
        return rc;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    if (file == NGX_LIVE_PERSIST_FILE_INDEX) {
        cctx->success_index = scope.max_index;

    } else {
        cctx->success_delta = scope.max_index;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_read_handler: "
        "read success, scope: %uD..%uD",
        scope.min_index, scope.max_index);

    *min_index = scope.max_index + 1;
    return NGX_OK;
}


size_t
ngx_live_persist_index_json_get_size(ngx_live_channel_t *channel)
{
    size_t  result =
        sizeof("\"success_index\":") - 1 + NGX_INT32_LEN;

    return result;
}

u_char *
ngx_live_persist_index_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_persist_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    p = ngx_copy_fix(p, "\"success_index\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) cctx->success_index);

    return p;
}


size_t
ngx_live_persist_delta_json_get_size(ngx_live_channel_t *channel)
{
    size_t  result =
        sizeof("\"success_index\":") - 1 + NGX_INT32_LEN;

    return result;
}

u_char *
ngx_live_persist_delta_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_persist_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    p = ngx_copy_fix(p, "\"success_index\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) cctx->success_delta);

    return p;
}


static ngx_int_t
ngx_live_persist_index_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_index_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_index_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_index_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_index_scope_t        *scope;
    ngx_live_persist_write_file_ctx_t     *ctx;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    ctx = cctx->write_ctx;
    if (ctx != NULL) {
        scope = ngx_live_persist_write_file_scope(ctx);
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_channel_free: "
            "cancelling write, scope: %uD..%uD",
            scope->min_index, scope->max_index);

        ngx_live_persist_write_file_destroy(ctx);
    }

    if (cctx->frames_snap != NULL) {
        cctx->frames_snap->close(cctx->frames_snap,
            ngx_live_persist_snap_close_free);
    }

    if (cctx->pending != NULL) {
        ngx_live_persist_index_snap_free(cctx->pending);
    }

    return NGX_OK;
}


static void *
ngx_live_persist_index_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_persist_index_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_index_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_delta_segments = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_persist_index_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_persist_index_preset_conf_t  *prev = parent;
    ngx_live_persist_index_preset_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->max_delta_segments,
                              prev->max_delta_segments, 100);

    return NGX_CONF_OK;
}


static ngx_live_persist_block_t  ngx_live_persist_index_blocks[] = {

    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
      NGX_LIVE_PERSIST_FLAG_SINGLE,
      ngx_live_persist_index_write_channel,
      ngx_live_persist_index_read_channel },

    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, 0,
      ngx_live_persist_index_write_track,
      ngx_live_persist_index_read_track },

    ngx_live_null_persist_block
};

static ngx_int_t
ngx_live_persist_index_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_ngx_live_persist_add_blocks(cf, ngx_live_persist_index_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t  ngx_live_persist_index_channel_events[] = {
    { ngx_live_persist_index_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_index_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_persist_index_channel_snap, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP },

      ngx_live_null_event
};

static ngx_int_t
ngx_live_persist_index_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_index_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
