#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segmenter.h"


#define NGX_LIVE_SYNCER_INVALID_TIMESTAMP  LLONG_MAX

#define ngx_live_syncer_wraparound_value(timescale)     \
    (0x100000000L * ((timescale) / 1000))


typedef struct {
    ngx_flag_t  enabled;
    time_t      jump_threshold;
    ngx_uint_t  jump_sync_frames;
    time_t      max_forward_drift;
    time_t      correction_reuse_threshold;

    ngx_uint_t  timescale;
} ngx_live_syncer_preset_conf_t;

typedef struct {
    int64_t     last_pts;
    int64_t     correction;
    uint32_t    force_sync_count;
    uint32_t    count;
} ngx_live_syncer_track_ctx_t;

typedef struct {
    int64_t     correction;
    uint32_t    count;
} ngx_live_syncer_channel_ctx_t;


static void *ngx_live_syncer_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_syncer_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_syncer_postconfiguration(ngx_conf_t *cf);


static ngx_command_t  ngx_live_syncer_commands[] = {

    { ngx_string("syncer"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, enabled),
      NULL },

    { ngx_string("syncer_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, jump_threshold),
      NULL },

    { ngx_string("syncer_jump_sync_frames"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, jump_sync_frames),
      NULL },

    { ngx_string("syncer_max_forward_drift"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, max_forward_drift),
      NULL },

    { ngx_string("syncer_correction_reuse_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, correction_reuse_threshold),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_syncer_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_syncer_postconfiguration,        /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_syncer_create_preset_conf,       /* create preset configuration */
    ngx_live_syncer_merge_preset_conf,        /* merge preset configuration */
};

ngx_module_t  ngx_live_syncer_module = {
    NGX_MODULE_V1,
    &ngx_live_syncer_module_ctx,              /* module context */
    ngx_live_syncer_commands,                 /* module directives */
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


static ngx_live_add_frame_pt  next_add_frame;


static ngx_int_t
ngx_live_syncer_track_reset(ngx_live_track_t *track, void *ectx)
{
    ngx_live_syncer_track_ctx_t  *ctx;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_syncer_track_reset: called");

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    ctx->last_pts = NGX_LIVE_SYNCER_INVALID_TIMESTAMP;
    ctx->force_sync_count = 0;
    return NGX_OK;
}

static void
ngx_live_syncer_sync_track(ngx_live_track_t *track, int64_t pts,
    int64_t created, ngx_flag_t *channel_synched)
{
    int64_t                         track_correction;
    int64_t                         channel_correction;
    ngx_live_channel_t             *channel = track->channel;
    ngx_live_syncer_track_ctx_t    *ctx;
    ngx_live_syncer_preset_conf_t  *spcf;
    ngx_live_syncer_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);
    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_syncer_module);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_syncer_sync_track: performing sync, pts: %L, created: %L",
        pts, created);

    track_correction = created - pts;
    channel_correction = cctx->correction;

    /* Note: since rtmp timestamps can wrap around, it is possible that
        different tracks will have timestamps that are several wrap around
        values apart */

    channel_correction += ngx_round_to_multiple(
        track_correction - channel_correction,
        ngx_live_syncer_wraparound_value(spcf->timescale));

    if ((uint64_t) ngx_abs(channel_correction - track_correction) <
        spcf->correction_reuse_threshold * spcf->timescale)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_sync_track: "
            "using channel, track: %L, channel_wrapped: %L, channel: %L",
            track_correction, channel_correction, cctx->correction);
        ctx->correction = channel_correction;
        ctx->count++;
        *channel_synched = 0;

    } else {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_sync_track: "
            "using track, track: %L, channel_wrapped: %L, channel: %L",
            track_correction, channel_correction, cctx->correction);
        ctx->correction = cctx->correction = track_correction;
        ctx->count++;
        cctx->count++;
        *channel_synched = 1;
    }
}

static void
ngx_live_syncer_enable_sync_flag(ngx_live_channel_t *channel,
    ngx_live_track_t *skip, uint32_t force_sync_count)
{
    ngx_queue_t                  *q;
    ngx_live_track_t             *cur_track;
    ngx_live_syncer_track_ctx_t  *cur_ctx;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track == skip) {
            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_syncer_module);
        cur_ctx->force_sync_count = force_sync_count;
    }
}

static ngx_int_t
ngx_live_syncer_add_frame(ngx_live_track_t *track, kmp_frame_t *frame,
    ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail, size_t size)
{
    int64_t                         pts;
    uint32_t                        sync_frames;
    ngx_flag_t                      channel_synched;
    ngx_live_syncer_track_ctx_t    *ctx;
    ngx_live_syncer_preset_conf_t  *spcf;

    spcf = ngx_live_get_module_preset_conf(track->channel,
        ngx_live_syncer_module);

    if (!spcf->enabled) {
        return next_add_frame(track, frame, data_head, data_tail, size);
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);

    if (ctx->force_sync_count > 1) {
        ctx->force_sync_count--;
    }

    pts = frame->dts + frame->pts_delay;

    if (track->media_type == KMP_MEDIA_VIDEO &&
        (frame->flags & KMP_FRAME_FLAG_KEY) == 0)
    {
        goto done;
    }

    sync_frames = 1;

    if (ctx->force_sync_count == 1) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: applying forced sync");
        goto sync;

    } else if (ctx->last_pts == NGX_LIVE_SYNCER_INVALID_TIMESTAMP) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: first time sync");
        goto sync;

    } else if ((uint64_t) ngx_abs_diff(pts, ctx->last_pts) >
        spcf->jump_threshold * spcf->timescale)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: pts jump, cur: %L, last %L",
            pts, ctx->last_pts);
        sync_frames = spcf->jump_sync_frames;
        goto sync;

    } else if (pts + ctx->correction > frame->created +
        spcf->max_forward_drift * (ngx_int_t) spcf->timescale)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: "
            "forward drift too large, pts: %L, correction: %L",
            pts, ctx->correction);
        goto sync;

    } else {

        goto done;
    }

sync:

    frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

    ngx_live_syncer_sync_track(track, pts, frame->created, &channel_synched);
    if (channel_synched && ctx->force_sync_count == 0) {
        ngx_live_syncer_enable_sync_flag(track->channel, track, sync_frames);

    } else {

        ctx->force_sync_count = 0;
    }

done:

    ctx->last_pts = pts;

    frame->dts = pts + ctx->correction - frame->pts_delay;

    return next_add_frame(track, frame, data_head, data_tail, size);
}

static size_t
ngx_live_syncer_channel_json_get_size(void *obj)
{
    return sizeof("\"syncer\":{\"correction\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"count\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_syncer_channel_json_write(u_char *p, void *obj)
{
    ngx_live_channel_t             *channel = obj;
    ngx_live_syncer_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);

    p = ngx_copy_fix(p, "\"syncer\":{\"correction\":");
    p = ngx_sprintf(p, "%L", cctx->correction);
    p = ngx_copy_fix(p, ",\"count\":");
    p = ngx_sprintf(p, "%uD", cctx->count);
    *p++ = '}';
    return p;
}


static size_t
ngx_live_syncer_track_json_get_size(void *obj)
{
    return sizeof("\"syncer\":{\"correction\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"count\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_syncer_track_json_write(u_char *p, void *obj)
{
    ngx_live_track_t             *track = obj;
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);

    p = ngx_copy_fix(p, "\"syncer\":{\"correction\":");
    p = ngx_sprintf(p, "%L", ctx->correction);
    p = ngx_copy_fix(p, ",\"count\":");
    p = ngx_sprintf(p, "%uD", ctx->count);
    *p++ = '}';
    return p;
}


static ngx_int_t
ngx_live_syncer_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    size_t                         *track_ctx_size = ectx;
    ngx_live_syncer_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_syncer_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_syncer_module);

    ngx_live_reserve_track_ctx_size(channel, ngx_live_syncer_module,
        sizeof(ngx_live_syncer_track_ctx_t), track_ctx_size);

    return NGX_OK;
}

static void *
ngx_live_syncer_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_syncer_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_core_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->jump_threshold = NGX_CONF_UNSET;
    conf->jump_sync_frames = NGX_CONF_UNSET_UINT;
    conf->max_forward_drift = NGX_CONF_UNSET;
    conf->correction_reuse_threshold = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_live_syncer_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_core_preset_conf_t    *cpcf;
    ngx_live_syncer_preset_conf_t  *prev = parent;
    ngx_live_syncer_preset_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 1);

    ngx_conf_merge_sec_value(conf->jump_threshold,
                             prev->jump_threshold, 10);

    ngx_conf_merge_uint_value(conf->jump_sync_frames,
                              prev->jump_sync_frames, 10);

    ngx_conf_merge_sec_value(conf->max_forward_drift,
                             prev->max_forward_drift, 30);

    ngx_conf_merge_sec_value(conf->correction_reuse_threshold,
                             prev->correction_reuse_threshold, 10);

    /* copy the timescale to avoid the need to reference the core conf */
    cpcf = ngx_live_get_module_preset_conf((ngx_live_conf_ctx_t *) cf->ctx,
        ngx_live_core_module);
    conf->timescale = cpcf->timescale;

    return NGX_CONF_OK;
}


static ngx_live_channel_event_t    ngx_live_syncer_channel_events[] = {
    { ngx_live_syncer_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
      ngx_live_null_event
};

static ngx_live_track_event_t      ngx_live_syncer_track_events[] = {
    { ngx_live_syncer_track_reset, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_syncer_track_reset, NGX_LIVE_EVENT_TRACK_INACTIVE },
      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_syncer_json_writers[] = {
    { { ngx_live_syncer_channel_json_get_size,
        ngx_live_syncer_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

    { { ngx_live_syncer_track_json_get_size,
        ngx_live_syncer_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_syncer_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_syncer_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf,
        ngx_live_syncer_track_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_syncer_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    next_add_frame = ngx_live_add_frame;
    ngx_live_add_frame = ngx_live_syncer_add_frame;

    return NGX_OK;
}
