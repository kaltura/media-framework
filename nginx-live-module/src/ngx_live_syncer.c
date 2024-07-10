#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segmenter.h"


#define NGX_LIVE_SYNCER_PERSIST_BLOCK        (0x636e7973)  /* sync */
#define NGX_LIVE_SYNCER_PERSIST_BLOCK_TRACK  (0x746e7973)  /* synt */

#define NGX_LIVE_SYNCER_LOG_COUNT            (3)

#define NGX_LIVE_SYNCER_PTS_JUMP_PERIOD      (5)


#define ngx_live_syncer_wraparound_value(timescale)                          \
    (0x100000000L * ((timescale) / 1000))


typedef struct {
    ngx_flag_t             enabled;
    ngx_kmp_in_frame_pt    next_add_frame;

    time_t                 inter_jump_log_threshold;
    time_t                 inter_jump_threshold;
    ngx_uint_t             jump_sync_frames;
    time_t                 max_backward_drift;
    time_t                 max_forward_drift;
    time_t                 correction_reuse_threshold;
} ngx_live_syncer_preset_conf_t;


typedef struct {
    uint64_t               frame_id;
    int64_t                correction;
    uint32_t               sequence;
} ngx_live_syncer_log_t;


typedef struct {
    int64_t                last_pts;
    int64_t                last_output_dts;
    int64_t                correction;
    time_t                 pts_jump_time;
    uint32_t               force_sync_count;
    uint32_t               count;
    ngx_live_syncer_log_t  log[NGX_LIVE_SYNCER_LOG_COUNT];
    uint32_t               log_index;
} ngx_live_syncer_track_ctx_t;


typedef struct {
    int64_t                correction;
    uint32_t               count;
    uint32_t               sequence;
} ngx_live_syncer_channel_ctx_t;


typedef struct {
    int64_t                correction;
} ngx_live_syncer_persist_track_t;


typedef struct {
    int64_t                correction;
} ngx_live_syncer_persist_channel_t;


typedef struct {
    uint32_t                            track_id;
    ngx_live_syncer_persist_track_t     tp;
    unsigned                            valid:1;
} ngx_live_syncer_snap_track_t;


typedef struct {
    ngx_live_syncer_persist_channel_t   cp;
    ngx_live_syncer_snap_track_t       *cur;
} ngx_live_syncer_snap_channel_t;


static void *ngx_live_syncer_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_syncer_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_syncer_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_syncer_postconfiguration(ngx_conf_t *cf);


static ngx_command_t  ngx_live_syncer_commands[] = {

    { ngx_string("syncer"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, enabled),
      NULL },

    { ngx_string("syncer_inter_jump_log_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, inter_jump_log_threshold),
      NULL },

    { ngx_string("syncer_inter_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, inter_jump_threshold),
      NULL },

    { ngx_string("syncer_jump_sync_frames"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, jump_sync_frames),
      NULL },

    { ngx_string("syncer_max_backward_drift"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_syncer_preset_conf_t, max_backward_drift),
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
    ngx_live_syncer_preconfiguration,         /* preconfiguration */
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


static ngx_int_t
ngx_live_syncer_track_reset(ngx_live_track_t *track, void *ectx)
{
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_syncer_track_reset: called");

    ctx->last_pts = NGX_LIVE_INVALID_TIMESTAMP;
    ctx->last_output_dts = NGX_LIVE_INVALID_TIMESTAMP;
    ctx->force_sync_count = 0;
    return NGX_OK;
}


static void
ngx_live_syncer_log_add(ngx_live_channel_t *channel,
    ngx_live_syncer_track_ctx_t *ctx, uint64_t frame_id)
{
    ngx_live_syncer_log_t          *log;
    ngx_live_syncer_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);

    cctx->sequence++;

    log = &ctx->log[ctx->log_index];
    log->frame_id = frame_id;
    log->correction = ctx->correction;
    log->sequence = cctx->sequence;

    ctx->log_index++;
    if (ctx->log_index >= NGX_LIVE_SYNCER_LOG_COUNT) {
        ctx->log_index = 0;
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


static void
ngx_live_syncer_sync_track(ngx_live_track_t *track, int64_t pts,
    int64_t created, uint64_t frame_id, uint32_t sync_frames,
    int64_t min_correction)
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
    if (track_correction < min_correction) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_sync_track: adjusting track correction to min, "
            "correction: %L, min: %L", track_correction, min_correction);

        track_correction = min_correction;

        /* force resync of other tracks, if track correction will be used */
        ctx->force_sync_count = 0;
    }

    channel_correction = cctx->correction;

    /* Note: since rtmp timestamps can wrap around, it is possible that
        different tracks will have timestamps that are several wrap around
        values apart */

    channel_correction += ngx_round_to_multiple(
        track_correction - channel_correction,
        ngx_live_syncer_wraparound_value(channel->timescale));

    if ((uint64_t) ngx_abs(channel_correction - track_correction) <
        spcf->correction_reuse_threshold * channel->timescale &&
        channel_correction >= min_correction)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_sync_track: "
            "using channel, track: %L, channel_wrapped: %L, channel: %L",
            track_correction, channel_correction, cctx->correction);
        ctx->correction = channel_correction;

    } else {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_sync_track: "
            "using track, track: %L, channel_wrapped: %L, channel: %L",
            track_correction, channel_correction, cctx->correction);
        ctx->correction = cctx->correction = track_correction;
        cctx->count++;

        if (ctx->force_sync_count == 0 && sync_frames > 0) {
            ngx_live_syncer_enable_sync_flag(channel, track, sync_frames);
        }
    }

    ctx->force_sync_count = 0;
    ctx->count++;

    ngx_live_syncer_log_add(channel, ctx, frame_id);
}


static ngx_int_t
ngx_live_syncer_add_frame(void *data, ngx_kmp_in_evt_frame_t *evt)
{
    int64_t                         pts;
    int64_t                         min_correction;
    uint32_t                        sync_frames;
    uint64_t                        pts_diff;
    kmp_frame_t                    *frame;
    ngx_live_track_t               *track;
    ngx_live_channel_t             *channel;
    ngx_live_syncer_track_ctx_t    *ctx;
    ngx_live_syncer_preset_conf_t  *spcf;

    track = data;
    channel = track->channel;
    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_syncer_module);

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);

    if (ctx->force_sync_count > 1) {
        ctx->force_sync_count--;
    }

    frame = &evt->frame;
    pts = frame->dts;

    if (track->media_type == KMP_MEDIA_VIDEO) {
        pts += frame->pts_delay;

        if (!(frame->flags & KMP_FRAME_FLAG_KEY)) {
            pts_diff = ngx_abs_diff(pts, ctx->last_pts);
            if (pts_diff <= spcf->inter_jump_log_threshold * channel->timescale
                || ctx->last_pts == NGX_LIVE_INVALID_TIMESTAMP)
            {
                goto done;
            }

            if (pts_diff <= spcf->inter_jump_threshold * channel->timescale) {

                if (ngx_time() >= ctx->pts_jump_time) {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_live_syncer_add_frame: "
                        "inter-frame pts jump, cur: %L, last %L",
                        pts, ctx->last_pts);

                    /* avoid writing to log too often */
                    ctx->pts_jump_time = ngx_time() +
                        NGX_LIVE_SYNCER_PTS_JUMP_PERIOD;
                }

                goto done;
            }

            if (ctx->last_output_dts != NGX_LIVE_INVALID_TIMESTAMP) {
                /* make sure the frame duration will come out positive */
                min_correction = ctx->last_output_dts + 1 - frame->dts;

            } else {
                min_correction = LLONG_MIN;
            }

            ngx_log_error(NGX_LOG_WARN, &track->log, 0,
                "ngx_live_syncer_add_frame: large inter-frame pts jump, "
                "cur: %L, last: %L, min_correction: %L",
                pts, ctx->last_pts, min_correction);

            ngx_live_syncer_sync_track(track, pts, frame->created,
                evt->frame_id, spcf->jump_sync_frames, min_correction);
            goto done;
        }
    }

    sync_frames = 0;

    if (ctx->force_sync_count == 1) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: applying forced sync");
        goto sync;

    } else if (ctx->last_pts == NGX_LIVE_INVALID_TIMESTAMP) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: first time sync");
        goto sync;

    } else if (pts + ctx->correction < frame->created -
        spcf->max_backward_drift * (ngx_int_t) channel->timescale)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: "
            "backward drift too large, pts: %L, correction: %L, created: %L",
            pts, ctx->correction, frame->created);
        sync_frames = spcf->jump_sync_frames;
        goto sync;

    } else if (pts + ctx->correction > frame->created +
        spcf->max_forward_drift * (ngx_int_t) channel->timescale)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: "
            "forward drift too large, pts: %L, correction: %L, created: %L",
            pts, ctx->correction, frame->created);
        sync_frames = spcf->jump_sync_frames;
        goto sync;

    } else {

        goto done;
    }

sync:

    frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

    ngx_live_syncer_sync_track(track, pts, frame->created, evt->frame_id,
        sync_frames, LLONG_MIN);

done:

    ctx->last_pts = pts;

    frame->dts += ctx->correction;
    ctx->last_output_dts = frame->dts;

#if (NGX_DEBUG)
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_add_frame: "
            " created: %L dts: %L pts_delay %L flags %uL",
            frame->created, frame->dts, frame->pts_delay, frame->flags);
#endif

    return spcf->next_add_frame(track, evt);
}


static size_t
ngx_live_syncer_channel_json_get_size(void *obj)
{
    ngx_live_channel_t             *channel = obj;
    ngx_live_syncer_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);
    if (cctx == NULL) {
        return 0;
    }

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
    if (cctx == NULL) {
        return p;
    }

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
    ngx_live_track_t             *track = obj;
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    if (ctx == NULL) {
        return 0;
    }

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
    if (ctx == NULL) {
        return p;
    }

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
    ngx_live_syncer_channel_ctx_t  *cctx;
    ngx_live_syncer_preset_conf_t  *spcf;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_syncer_module);
    if (!spcf->enabled) {
        return NGX_OK;
    }

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_syncer_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_syncer_module);

    return NGX_OK;
}


static ngx_live_syncer_log_t *
ngx_live_syncer_get_log(ngx_live_track_t *track)
{
    ngx_uint_t                    i;
    ngx_live_syncer_log_t        *cur, *best;
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);

    best = NULL;

    for (i = 0; i < NGX_LIVE_SYNCER_LOG_COUNT; i++) {
        cur = &ctx->log[i];

        if (cur->sequence == 0) {
            continue;
        }

        if (cur->frame_id >= track->next_frame_id) {
            continue;
        }

        if (best == NULL || best->frame_id < cur->frame_id) {
            best = cur;
        }
    }

    return best;
}


static void
ngx_live_syncer_remove_future_logs(ngx_live_track_t *track)
{
    ngx_uint_t                    i;
    ngx_live_syncer_log_t        *cur;
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);

    for (i = 0; i < NGX_LIVE_SYNCER_LOG_COUNT; i++) {
        cur = &ctx->log[i];

        if (cur->frame_id >= track->next_frame_id) {
            cur->sequence = 0;
        }
    }
}


static ngx_int_t
ngx_live_syncer_channel_index_snap(ngx_live_channel_t *channel, void *ectx)
{
    uint32_t                         sequence;
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_syncer_log_t           *log;
    ngx_live_syncer_snap_track_t    *ts;
    ngx_live_persist_snap_index_t   *snap = ectx;
    ngx_live_syncer_channel_ctx_t   *cctx;
    ngx_live_syncer_snap_channel_t  *cs;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    cs = ngx_palloc(snap->base.pool, sizeof(*cs) +
        sizeof(*ts) * (channel->tracks.count + 1));
    if (cs == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_syncer_channel_index_snap: alloc failed");
        return NGX_ERROR;
    }

    ts = (void *) (cs + 1);

    ngx_live_set_ctx(snap, cs, ngx_live_syncer_module);

    cs->cp.correction = 0;
    cs->cur = ts;

    sequence = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        ts->track_id = cur_track->in.key;

        log = ngx_live_syncer_get_log(cur_track);
        if (log == NULL) {
            ts->valid = 0;
            ts++;
            continue;
        }

        ts->valid = 1;
        ts->tp.correction = log->correction;
        ts++;

        if (log->sequence > sequence) {
            cs->cp.correction = log->correction;
            sequence = log->sequence;
        }
    }

    ts->track_id = NGX_LIVE_INVALID_TRACK_ID;

    return NGX_OK;
}


static ngx_int_t
ngx_live_syncer_write_index_track(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_track_t                 *track = obj;
    ngx_live_persist_snap_index_t    *snap;
    ngx_live_syncer_snap_channel_t   *cs;
    ngx_live_syncer_persist_track_t  *tp;

    snap = ngx_persist_write_ctx(write_ctx);

    cs = ngx_live_get_module_ctx(snap, ngx_live_syncer_module);
    if (cs == NULL) {
        return NGX_OK;
    }

    for (; cs->cur->track_id != track->in.key; cs->cur++) {
        if (cs->cur->track_id == NGX_LIVE_INVALID_TRACK_ID) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_syncer_write_index_track: "
                "track %ui not found in snapshot", track->in.key);
            return NGX_OK;
        }
    }

    if (!cs->cur->valid) {
        return NGX_OK;
    }

    tp = &cs->cur->tp;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_SYNCER_PERSIST_BLOCK_TRACK) != NGX_OK ||
        ngx_persist_write(write_ctx, tp, sizeof(*tp)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}


static ngx_int_t
ngx_live_syncer_read_index_track(ngx_persist_block_hdr_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_track_t                 *track = obj;
    ngx_live_syncer_log_t            *log;
    ngx_live_syncer_track_ctx_t      *ctx;
    ngx_live_syncer_channel_ctx_t    *cctx;
    ngx_live_syncer_persist_track_t   tp;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    if (ngx_mem_rstream_read(rs, &tp, sizeof(tp)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_syncer_read_index_track: read failed");
        return NGX_BAD_DATA;
    }

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_syncer_module);

    ctx->correction = tp.correction;
    if (track->last_frame_pts != NGX_LIVE_INVALID_TIMESTAMP) {
        ctx->last_pts = track->last_frame_pts - ctx->correction;

    } else {
        ctx->last_pts = NGX_LIVE_INVALID_TIMESTAMP;
    }

    ctx->last_output_dts = track->last_frame_dts;

    log = &ctx->log[0];
    log->frame_id = 0;
    log->correction = ctx->correction;
    log->sequence = ctx->correction == cctx->correction ? 2 : 1;

    ctx->log_index = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_live_syncer_write_index(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_snap_index_t   *snap;
    ngx_live_syncer_snap_channel_t  *cs;

    snap = ngx_persist_write_ctx(write_ctx);

    cs = ngx_live_get_module_ctx(snap, ngx_live_syncer_module);
    if (cs == NULL) {
        return NGX_OK;
    }

    if (ngx_persist_write(write_ctx, &cs->cp, sizeof(cs->cp)) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_syncer_write_index: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_syncer_read_index(ngx_persist_block_hdr_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_channel_t                 *channel = obj;
    ngx_live_syncer_channel_ctx_t      *cctx;
    ngx_live_syncer_persist_channel_t   cp;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_syncer_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    if (ngx_mem_rstream_read(rs, &cp, sizeof(cp)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_syncer_read_index: read failed");
        return NGX_BAD_DATA;
    }

    cctx->correction = cp.correction;
    cctx->sequence = 2;

    return NGX_OK;
}


static ngx_int_t
ngx_live_syncer_track_reconnect(ngx_live_track_t *track, void *ectx)
{
    ngx_live_syncer_log_t        *log;
    ngx_live_syncer_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_syncer_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    log = ngx_live_syncer_get_log(track);
    if (!log) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_syncer_track_reconnect: log not found, frame_id: %uL",
            track->next_frame_id);
        return ngx_live_syncer_track_reset(track, NULL);
    }

    ctx->correction = log->correction;
    if (track->last_frame_pts != NGX_LIVE_INVALID_TIMESTAMP) {
        ctx->last_pts = track->last_frame_pts - ctx->correction;

    } else {
        ctx->last_pts = NGX_LIVE_INVALID_TIMESTAMP;
    }

    ctx->last_output_dts = track->last_frame_dts;
    ctx->force_sync_count = 0;

    ngx_live_syncer_remove_future_logs(track);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_syncer_track_reconnect: "
        "state was reset, next_frame_id: %uL, correction: %L, "
        "last_pts: %L, last_output_dts: %L",
        track->next_frame_id, ctx->correction,
        ctx->last_pts, ctx->last_output_dts);

    return NGX_OK;
}


static void *
ngx_live_syncer_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_syncer_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_syncer_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->inter_jump_log_threshold = NGX_CONF_UNSET;
    conf->inter_jump_threshold = NGX_CONF_UNSET;
    conf->jump_sync_frames = NGX_CONF_UNSET_UINT;
    conf->max_backward_drift = NGX_CONF_UNSET;
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

    ngx_conf_merge_sec_value(conf->inter_jump_log_threshold,
                             prev->inter_jump_log_threshold, 10);

    ngx_conf_merge_sec_value(conf->inter_jump_threshold,
                             prev->inter_jump_threshold, 100);

    ngx_conf_merge_uint_value(conf->jump_sync_frames,
                              prev->jump_sync_frames, 10);

    ngx_conf_merge_sec_value(conf->max_backward_drift,
                             prev->max_backward_drift, 20);

    ngx_conf_merge_sec_value(conf->max_forward_drift,
                             prev->max_forward_drift, 20);

    ngx_conf_merge_sec_value(conf->correction_reuse_threshold,
                             prev->correction_reuse_threshold, 10);

    if (!conf->enabled) {
        return NGX_CONF_OK;
    }

    cpcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_core_module);

    conf->next_add_frame = cpcf->segmenter.add_frame;
    cpcf->segmenter.add_frame = ngx_live_syncer_add_frame;

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_syncer_module,
        sizeof(ngx_live_syncer_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_persist_block_t  ngx_live_syncer_blocks[] = {
    /*
     * persist data:
     *   ngx_live_syncer_persist_channel_t  p;
     */
    { NGX_LIVE_SYNCER_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_syncer_write_index,
      ngx_live_syncer_read_index },

    /*
     * persist data:
     *   ngx_live_syncer_persist_track_t  p;
     */
    { NGX_LIVE_SYNCER_PERSIST_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_INDEX_TRACK, 0,
      ngx_live_syncer_write_index_track,
      ngx_live_syncer_read_index_track },

      ngx_null_persist_block
};


static ngx_int_t
ngx_live_syncer_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_syncer_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t    ngx_live_syncer_channel_events[] = {
    { ngx_live_syncer_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_syncer_channel_index_snap, NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP },

      ngx_live_null_event
};


static ngx_live_track_event_t      ngx_live_syncer_track_events[] = {
    { ngx_live_syncer_track_reset, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_syncer_track_reset, NGX_LIVE_EVENT_TRACK_INACTIVE },
    { ngx_live_syncer_track_reconnect, NGX_LIVE_EVENT_TRACK_RECONNECT },

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

    return NGX_OK;
}
