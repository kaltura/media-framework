#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_persist_core.h"
#include "ngx_live_persist_snap_frames.h"


static ngx_int_t ngx_live_persist_index_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_persist_index_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_index_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_index_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


typedef struct {
    uint32_t                            success_index;
    uint32_t                            success_delta;
    uint32_t                            history_changed;
    ngx_live_persist_write_file_ctx_t  *write_ctx;
    ngx_live_persist_snap_t            *frames_snap;
    ngx_live_persist_snap_index_t      *pending;
} ngx_live_persist_index_channel_ctx_t;


typedef struct {
    ngx_uint_t                          max_delta_segments;
} ngx_live_persist_index_preset_conf_t;


/* format */

typedef struct {
    uint64_t                            uid;
    uint32_t                            min_index;
    uint32_t                            max_index;
    uint32_t                            next_part_sequence;
    uint32_t                            last_segment_media_types;
    int64_t                             last_segment_created;
    int64_t                             last_modified;
} ngx_live_persist_index_channel_t;


typedef struct {
    uint32_t                            initial_segment_index;
} ngx_live_persist_index_variant_t;


typedef struct {
    uint32_t                            track_id;
    uint32_t                            has_last_segment;
    uint32_t                            last_segment_bitrate;
    uint32_t                            initial_segment_index;
    int64_t                             last_frame_pts;
    uint64_t                            next_frame_id;
} ngx_live_persist_index_track_v1_t;


typedef struct {
    uint32_t                            track_id;
    uint32_t                            has_last_segment;
    uint32_t                            last_segment_bitrate;
    uint32_t                            initial_segment_index;
    int64_t                             last_frame_pts;
    int64_t                             last_frame_dts;
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

    cp = ngx_palloc(snap->base.pool, sizeof(*cp) +
        sizeof(*tp) * (channel->tracks.count + 1));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_channel_snap: alloc failed");
        return NGX_ERROR;
    }

    tp = (void *) (cp + 1);

    ngx_live_set_ctx(snap, cp, ngx_live_persist_index_module);

    cp->last_modified = channel->last_modified;
    cp->next_part_sequence = channel->next_part_sequence;
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
        tp->initial_segment_index = cur_track->initial_segment_index;
        tp->last_frame_pts = cur_track->last_frame_pts;
        tp->last_frame_dts = cur_track->last_frame_dts;
        tp->next_frame_id = cur_track->next_frame_id;
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
    ngx_destroy_pool(snap->base.pool);
}


static void
ngx_live_persist_index_snap_close(void *data,
    ngx_live_persist_snap_close_action_e action)
{
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_index_t         *snap = data;
    ngx_live_persist_index_scope_t        *scope;
    ngx_live_persist_core_preset_conf_t   *pcpcf;
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

        ngx_destroy_pool(snap->base.pool);
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

    pcpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_core_module);
    pipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_index_module);

    if (pcpcf->files[NGX_LIVE_PERSIST_FILE_DELTA].path != NULL &&
        scope->max_index - channel->min_segment_index + 1 >
            pipcf->max_delta_segments &&
        scope->max_index - cctx->success_index <=
            pipcf->max_delta_segments &&
        !cctx->history_changed)
    {
        scope->base.file = NGX_LIVE_PERSIST_FILE_DELTA;
        scope->min_index = cctx->success_index + 1;

    } else {
        scope->base.file = NGX_LIVE_PERSIST_FILE_INDEX;
        scope->min_index = channel->min_segment_index;
        if (scope->max_index >= cctx->history_changed) {
            cctx->history_changed = 0;
        }
    }

    cctx->write_ctx = ngx_live_persist_core_write_file(channel,
        snap, &scope->base, sizeof(*scope));
    if (cctx->write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_close: "
            "write failed, file: %ui, scope: %uD..%uD",
            scope->base.file, scope->min_index, scope->max_index);
        goto close;
    }

    cctx->frames_snap = snap->frames_snap;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_snap_close: "
        "write started, file: %ui, scope: %uD..%uD",
        scope->base.file, scope->min_index, scope->max_index);

    ngx_destroy_pool(snap->base.pool);
    return;

close:

    snap->frames_snap->close(snap->frames_snap, action);
    ngx_destroy_pool(snap->base.pool);
}


static ngx_int_t
ngx_live_persist_index_snap_update(void *data)
{
    ngx_live_channel_t             *channel;
    ngx_live_persist_snap_index_t  *snap = data;

    channel = snap->base.channel;

    if (snap->frames_snap->update(snap->frames_snap) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_update: update failed");
        return NGX_ERROR;
    }

    snap->base.max_track_id = channel->tracks.last_id;

    if (ngx_live_core_channel_event(channel, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP,
        snap) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_update: event failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_live_persist_snap_t *
ngx_live_persist_index_snap_create(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_pool_t                     *pool;
    ngx_live_persist_snap_index_t  *snap;

    pool = ngx_create_pool(1024, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: create pool failed");
        return NGX_LIVE_PERSIST_INVALID_SNAP;
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

    snap->frames_snap = ngx_live_persist_snap_frames_create(channel,
        segment_index);
    if (snap->frames_snap == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_index_snap_create: create frames snap failed");
        goto failed;
    }

    snap->base.channel = channel;
    snap->base.pool = pool;
    snap->base.scope.max_index = segment_index;

    snap->base.update = ngx_live_persist_index_snap_update;
    snap->base.close = ngx_live_persist_index_snap_close;

    if (ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_INDEX_PRE_SNAP, snap) != NGX_OK)
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

    return NGX_LIVE_PERSIST_INVALID_SNAP;
}


/* index */

static ngx_int_t
ngx_live_persist_index_write_channel(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_snap_index_t     *snap;
    ngx_live_persist_index_channel_t  *cp;

    snap = ngx_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_index_module);

    cp->uid = channel->uid;
    cp->min_index = snap->base.scope.min_index;
    cp->max_index = snap->base.scope.max_index;

    if (ngx_live_persist_write_channel_header(write_ctx, channel) != NGX_OK ||
        ngx_persist_write(write_ctx, cp, sizeof(*cp)) != NGX_OK ||
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
ngx_live_persist_index_read_channel(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                          rc;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_index_scope_t    *scope;
    ngx_live_persist_index_channel_t  *cp;

    rc = ngx_live_persist_read_channel_header(channel, rs);
    if (rc != NGX_OK) {
        return rc;
    }

    cp = ngx_mem_rstream_get_ptr(rs, sizeof(*cp));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "read data failed");
        return NGX_BAD_DATA;
    }

    if (cp->uid != channel->uid) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "uid mismatch, actual: %016uxL, expected: %016uxL",
            cp->uid, channel->uid);
        return NGX_DECLINED;
    }

    if (cp->min_index > cp->max_index ||
        cp->max_index >= NGX_LIVE_INVALID_SEGMENT_INDEX)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "invalid scope, min: %uD, max: %uD",
            cp->min_index, cp->max_index);
        return NGX_BAD_DATA;
    }

    if (channel->next_segment_index != channel->conf.initial_segment_index &&
        cp->min_index != channel->next_segment_index)
    {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_channel: "
            "delta scope %uD..%uD doesn't match next_segment_index",
            cp->min_index, cp->max_index);
        return NGX_OK;
    }

    scope = ngx_mem_rstream_scope(rs);
    scope->min_index = cp->min_index;
    scope->max_index = cp->max_index;

    channel->last_modified = cp->last_modified;
    channel->next_part_sequence = cp->next_part_sequence;
    channel->last_segment_media_types = cp->last_segment_media_types;
    channel->last_segment_created = cp->last_segment_created;

    channel->next_segment_index = cp->max_index + 1;

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
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
ngx_live_persist_index_write_variant(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                       *q;
    ngx_wstream_t                     *ws;
    ngx_live_variant_t                *cur_variant;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_snap_t           *snap;
    ngx_live_persist_index_variant_t   vp;

    ws = ngx_persist_write_stream(write_ctx);
    snap = ngx_persist_write_ctx(write_ctx);

    for (q = ngx_queue_head(&channel->variants.queue);
        q != ngx_queue_sentinel(&channel->variants.queue);
        q = ngx_queue_next(q))
    {
        cur_variant = ngx_queue_data(q, ngx_live_variant_t, queue);

        vp.initial_segment_index = cur_variant->initial_segment_index;
        if (vp.initial_segment_index > snap->scope.max_index) {
            vp.initial_segment_index = NGX_LIVE_INVALID_SEGMENT_INDEX;
        }

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_VARIANT) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &vp, sizeof(vp)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_index_write_variant: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_index_read_variant(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_str_t                          id;
    ngx_live_variant_t                *variant;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_index_variant_t  *vp;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_variant: read id failed");
        return NGX_BAD_DATA;
    }

    vp = ngx_mem_rstream_get_ptr(rs, sizeof(*vp));
    if (vp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_variant: read failed");
        return NGX_BAD_DATA;
    }

    variant = ngx_live_variant_get(channel, &id);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_variant: "
            "variant \"%V\" not found", &id);
        return NGX_OK;
    }

    variant->initial_segment_index = vp->initial_segment_index;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_index_write_track(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                       *q;
    ngx_wstream_t                     *ws;
    ngx_live_track_t                  *cur_track;
    ngx_live_channel_t                *channel = obj;
    ngx_live_persist_snap_index_t     *snap;
    ngx_live_persist_index_track_t    *tp;
    ngx_live_persist_index_channel_t  *cp;

    snap = ngx_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_persist_index_module);
    tp = (void *) (cp + 1);

    ws = ngx_persist_write_stream(write_ctx);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

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

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_PERSIST_BLOCK_TRACK) != NGX_OK ||
            ngx_wstream_str(ws, &cur_track->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, tp, sizeof(*tp)) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_INDEX_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_persist_index_write_track: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);

        tp++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_index_read_track(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                            track_id;
    ngx_int_t                           rc;
    ngx_str_t                           id;
    ngx_log_t                          *orig_log;
    ngx_live_track_t                   *track;
    ngx_live_channel_t                 *channel = obj;
    ngx_live_persist_index_track_t     *tp;
    ngx_live_persist_index_track_v1_t  *tp1;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_track: read id failed");
        return NGX_BAD_DATA;
    }

    if (rs->version >= 8) {
        tp = ngx_mem_rstream_get_ptr(rs, sizeof(*tp));
        if (tp == NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_index_read_track: read failed");
            return NGX_BAD_DATA;
        }

        track_id = tp->track_id;

        tp1 = NULL;

    } else {
        /* TODO: remove this */
        tp1 = ngx_mem_rstream_get_ptr(rs, sizeof(*tp1));
        if (tp1 == NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_index_read_track: read failed");
            return NGX_BAD_DATA;
        }

        track_id = tp1->track_id;

        tp = NULL;
    }

    track = ngx_live_track_get_by_int(channel, track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_persist_index_read_track: "
            "track index %uD not found", track_id);
        return NGX_OK;
    }

    if (id.len != track->sn.str.len ||
        ngx_memcmp(id.data, track->sn.str.data, id.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_index_read_track: "
            "track id mismatch, stored: %V, actual: %V",
            &id, track->sn.str);
        return NGX_BAD_DATA;
    }


    orig_log = rs->log;
    rs->log = &track->log;

    if (rs->version >= 8) {
        track->has_last_segment = tp->has_last_segment;
        track->last_segment_bitrate = tp->last_segment_bitrate;
        track->initial_segment_index = tp->initial_segment_index;
        track->last_frame_pts = tp->last_frame_pts;
        track->last_frame_dts = tp->last_frame_dts;
        track->next_frame_id = tp->next_frame_id;

    } else {
        /* TODO: remove this */
        track->has_last_segment = tp1->has_last_segment;
        track->last_segment_bitrate = tp1->last_segment_bitrate;
        track->initial_segment_index = tp1->initial_segment_index;
        track->last_frame_pts = tp1->last_frame_pts;
        track->last_frame_dts = NGX_LIVE_INVALID_TIMESTAMP;
        track->next_frame_id = tp1->next_frame_id;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_INDEX_TRACK, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_index_read_track: read blocks failed");
        return rc;
    }

    rs->log = orig_log;

    return NGX_OK;
}


void
ngx_live_persist_index_write_complete(ngx_live_persist_write_file_ctx_t *ctx,
    ngx_int_t rc)
{
    ngx_uint_t                             file;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_index_t         *snap;
    ngx_live_persist_index_scope_t        *scope;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    channel = ctx->channel;
    scope = (void *) ctx->scope;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    cctx->frames_snap->close(cctx->frames_snap,
        ngx_live_persist_snap_close_ack);

    cctx->write_ctx = NULL;
    cctx->frames_snap = NULL;

    file = scope->base.file;

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

    ngx_live_persist_write_file_destroy(ctx);
}


ngx_int_t
ngx_live_persist_index_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf)
{
    ngx_int_t                              rc;
    ngx_live_persist_index_scope_t         scope;
    ngx_live_persist_index_channel_ctx_t  *cctx;

    rc = ngx_live_persist_core_read_parse(channel, buf, file, &scope);
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
    if (cctx == NULL) {
        return NGX_OK;
    }

    ctx = cctx->write_ctx;
    if (ctx != NULL) {
        scope = (void *) ctx->scope;
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


static ngx_int_t
ngx_live_persist_index_channel_history_changed(ngx_live_channel_t *channel,
    void *ectx)
{
    ngx_live_persist_index_channel_ctx_t  *cctx;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_index_channel_history_changed: called");

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_index_module);

    cctx->history_changed = channel->next_segment_index;

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


static ngx_persist_block_t  ngx_live_persist_index_blocks[] = {
    /*
     * persist header:
     *   ngx_str_t                         id;
     *   ngx_str_t                         opaquep;
     *   ngx_live_persist_index_channel_t  p;
     */
    { NGX_LIVE_PERSIST_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_persist_index_write_channel,
      ngx_live_persist_index_read_channel },

    /*
     * persist header:
     *   ngx_str_t                         id;
     *   ngx_live_persist_index_variant_t  p;
     */
    { NGX_LIVE_PERSIST_BLOCK_VARIANT, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, 0,
      ngx_live_persist_index_write_variant,
      ngx_live_persist_index_read_variant },

    /*
     * persist header:
     *   ngx_str_t                       id;
     *   ngx_live_persist_index_track_t  p;
     */
    { NGX_LIVE_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, 0,
      ngx_live_persist_index_write_track,
      ngx_live_persist_index_read_track },

      ngx_null_persist_block
};


static ngx_int_t
ngx_live_persist_index_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_persist_index_blocks)
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
    { ngx_live_persist_index_channel_history_changed,
        NGX_LIVE_EVENT_CHANNEL_HISTORY_CHANGED },

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
