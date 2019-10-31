#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_timeline.h"
#include "ngx_live_segmenter.h"
#include "dvr/ngx_live_dvr.h"       // XXXX remove this


#define NGX_LIVE_TEST_KF_COUNT              (4)
#define NGX_LIVE_SEGMENTER_FRAME_PART_COUNT (32)

#define NGX_LIVE_INVALID_FRAME_INDEX        (NGX_MAX_UINT32_VALUE)


#define ngx_live_segmenter_track_is_ready(cctx, ctx)                        \
    ((ctx)->last_key_pts >= (ctx)->start_pts + cctx->cur_ready_duration)


enum {
    NGX_LIVE_BP_PENDING_FRAME_PART,

    NGX_LIVE_BP_COUNT
};

typedef enum {
    ngx_live_track_inactive,
    ngx_live_track_pending,
    ngx_live_track_ready,

    ngx_live_track_state_count
} ngx_live_track_state_e;


typedef struct {
    ngx_msec_t                        segment_duration;
    ngx_msec_t                        min_segment_duration;
    ngx_msec_t                        inactive_timeout;
    ngx_uint_t                        ready_threshold;
    ngx_uint_t                        initial_ready_threshold;
} ngx_live_segmenter_preset_conf_t;

typedef struct {
    ngx_int_t                         segment_duration;
} ngx_live_segmenter_dyn_conf_t;


typedef struct {
    ngx_buf_chain_t                  *data;
    int64_t                           pts;
    int64_t                           dts;
    uint32_t                          flags;
    uint32_t                          size;
} ngx_live_segmenter_frame_t;

typedef struct ngx_live_segmenter_frame_part_s
    ngx_live_segmenter_frame_part_t;

struct ngx_live_segmenter_frame_part_s {
    ngx_live_segmenter_frame_part_t  *next;
    ngx_uint_t                        nelts;

    ngx_live_segmenter_frame_t  elts[NGX_LIVE_SEGMENTER_FRAME_PART_COUNT];
};

typedef struct {
    ngx_live_segmenter_frame_part_t  *last;
    ngx_live_segmenter_frame_part_t   part;
} ngx_live_segmenter_frame_list_t;

typedef struct {
    ngx_int_t                         state;

    ngx_live_segmenter_frame_list_t   frames;
    uint32_t                          frame_count;
    int64_t                           last_created;
    int64_t                           start_pts;
    int64_t                           last_pts;
    int64_t                           last_key_pts;
    ngx_buf_chain_t                  *last_data_part;

    uint32_t                          force_split_index;
    int64_t                           force_split_pts;

    uint32_t                          last_segment_index;

    uint32_t                          last_segment_bitrate;
    ngx_uint_t                        received_frames;
    ngx_uint_t                        received_key_frames;

    ngx_event_t                       inactive;
} ngx_live_segmenter_track_ctx_t;

typedef struct {
    ngx_live_segmenter_dyn_conf_t     conf;
    uint32_t                          segment_duration;
    uint32_t                          min_segment_duration;
    uint32_t                          keyframe_alignment_margin;
    uint32_t                          ready_duration;
    uint32_t                          initial_ready_duration;
    uint32_t                          cur_ready_duration;

    ngx_block_pool_t                 *block_pool;

    int64_t                           last_segment_end_pts;
    uint32_t                          segment_index;
    uint32_t                          count[ngx_live_track_state_count];

    ngx_event_t                       create;

    unsigned                          force_new_period:1;
    unsigned                          has_force_splits:1;
} ngx_live_segmenter_channel_ctx_t;


static ngx_int_t ngx_live_segmenter_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_segmenter_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_segmenter_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_segmenter_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_live_segmenter_commands[] = {
    { ngx_string("segmenter_duration"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, segment_duration),
      NULL },

    { ngx_string("segmenter_min_duration"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, min_segment_duration),
      NULL },

    { ngx_string("segmenter_inactive_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, inactive_timeout),
      NULL },

    { ngx_string("segmenter_ready_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, ready_threshold),
      NULL },

    { ngx_string("segmenter_initial_ready_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, initial_ready_threshold),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_segmenter_module_ctx = {
    ngx_live_segmenter_preconfiguration,      /* preconfiguration */
    ngx_live_segmenter_postconfiguration,     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_segmenter_create_preset_conf,    /* create preset configuration */
    ngx_live_segmenter_merge_preset_conf,     /* merge preset configuration */
};

ngx_module_t  ngx_live_segmenter_module = {
    NGX_MODULE_V1,
    &ngx_live_segmenter_module_ctx,           /* module context */
    ngx_live_segmenter_commands,              /* module directives */
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


static ngx_str_t  ngx_live_segmenter_segment_duration =
    ngx_string("segment_duration");

ngx_live_add_frame_pt  ngx_live_add_frame;

ngx_live_end_of_stream_pt ngx_live_end_of_stream;


static ngx_inline void
ngx_live_segmenter_set_state(ngx_live_track_t *track,
    ngx_live_track_state_e new_state)
{
    ngx_live_track_state_e             old_state;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    old_state = ctx->state;
    if (new_state == old_state) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_segmenter_set_state: %d -> %d", old_state, new_state);

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    cctx->count[old_state]--;
    cctx->count[new_state]++;

    ctx->state = new_state;

    if (new_state == ngx_live_track_inactive) {
        (void) ngx_live_core_track_event(track, NGX_LIVE_EVENT_TRACK_INACTIVE);
    }
}

static void
ngx_live_segmenter_channel_inactive(ngx_live_channel_t *channel)
{
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    cctx->cur_ready_duration = cctx->initial_ready_duration;

    channel->active = 0;

    (void) ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_INACTIVE);
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_segmenter_validate_track_ctx(ngx_live_track_t *track)
{
    int64_t                           last_key_pts;
    uint32_t                          frame_count;
    ngx_uint_t                        i;
    ngx_buf_chain_t                  *buf_chain;
    ngx_live_segmenter_frame_t       *frames;
    ngx_live_segmenter_frame_t       *last_frame;
    ngx_live_segmenter_track_ctx_t   *ctx;
    ngx_live_segmenter_frame_part_t  *part;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->force_split_index != NGX_LIVE_INVALID_FRAME_INDEX) {

        if (ctx->force_split_index == 0 ||
            ctx->force_split_index > ctx->frame_count)
        {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "invalid split index %uD, frame count %uD",
                ctx->force_split_index, ctx->frame_count);
            ngx_debug_point();
        }
    }

    if (ctx->frames.part.nelts == 0) {

        if (ctx->frame_count != 0) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "nonzero frame count %uD with no frames",
                ctx->frame_count);
            ngx_debug_point();
        }

        if (ctx->last_data_part != NULL) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "last data part is null when no frames");
            ngx_debug_point();
        }

        return;
    }

    frame_count = 0;
    last_frame = NULL;
    last_key_pts = 0;

    part = &ctx->frames.part;
    frames = part->elts;

    if (ctx->start_pts != part->elts[0].pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "start pts %L doesn't match first frame pts %L",
            ctx->start_pts, part->elts[0].pts);
        ngx_debug_point();
    }

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            frame_count += part->nelts;

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            frames = part->elts;
            i = 0;
        }

        last_frame = &frames[i];
        if (track->media_type != KMP_MEDIA_VIDEO ||
            (frames[i].flags & KMP_FRAME_FLAG_KEY))
        {
            last_key_pts = last_frame->pts;
        }
    }

    if (ctx->frame_count != frame_count) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "frame count %uD different than actual %uD",
            ctx->frame_count, frame_count);
        ngx_debug_point();
    }

    if (ctx->last_pts != last_frame->pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "last pts %L different than actual %L",
            ctx->last_pts, last_frame->pts);
        ngx_debug_point();
    }

    if (ctx->last_key_pts != last_key_pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "last key pts %L different than actual %L",
            ctx->last_key_pts, last_key_pts);
        ngx_debug_point();
    }

    buf_chain = last_frame->data;
    for ( ;; ) {

        if (buf_chain->next == NULL) {
            break;
        }

        buf_chain = buf_chain->next;
    }

    if (ctx->last_data_part != buf_chain) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: data tail mismatch");
        ngx_debug_point();
    }
}

static void
ngx_live_segmenter_validate_channel_ctx(ngx_live_channel_t *channel)
{
    uint32_t                           count[ngx_live_track_state_count];
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    ngx_memzero(count, sizeof(count));

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        count[cur_ctx->state]++;
    }

    if (ngx_memcmp(count, cctx->count, sizeof(count)) != 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_validate_channel_ctx: count mismatch");
        ngx_debug_point();
    }
}
#else
#define ngx_live_segmenter_validate_track_ctx(track)
#define ngx_live_segmenter_validate_channel_ctx(channel)
#endif

static void
ngx_live_segmenter_remove_frames(ngx_live_track_t *track,
    ngx_uint_t count)
{
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_frame_part_t   *part;
    ngx_live_segmenter_frame_part_t   *next_part;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    ctx->frame_count -= count;

    // XXXXXXX postpone to after saving state + dvr
    if (track->input.ack_frames != NULL && count > 0) {
        track->input.ack_frames(track, count);
    }

    /* update force split index */
    if (ctx->force_split_index != NGX_LIVE_INVALID_FRAME_INDEX) {

        if (ctx->force_split_index <= count) {
            ctx->force_split_index = NGX_LIVE_INVALID_FRAME_INDEX;

        } else {
            ctx->force_split_index -= count;
        }
    }

    /* remove fully unused parts */
    part = &ctx->frames.part;
    while (count >= part->nelts) {

        next_part = part->next;
        if (next_part == NULL) {
            count = part->nelts;
            break;
        }

        count -= part->nelts;

        if (part != &ctx->frames.part) {
            ngx_block_pool_free(cctx->block_pool,
                NGX_LIVE_BP_PENDING_FRAME_PART, part);
        }

        part = next_part;
    }

    /* remove frames from the last part */
    ctx->frames.part.nelts = part->nelts - count;
    ngx_memmove(ctx->frames.part.elts, part->elts + count,
        ctx->frames.part.nelts * sizeof(part->elts[0]));
    ctx->frames.part.next = part->next;

    if (ctx->frames.part.next == NULL) {
        ctx->frames.last = &ctx->frames.part;
    }

    if (part != &ctx->frames.part) {
        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_PENDING_FRAME_PART,
            part);
    }

    /* update start pts / last data part */
    if (ctx->frames.part.nelts > 0) {
        ctx->start_pts = ctx->frames.part.elts[0].pts;

    } else {
        ctx->last_data_part = NULL;
    }

    /* update ready status */
    if (ctx->state == ngx_live_track_ready &&
        !ngx_live_segmenter_track_is_ready(cctx, ctx))
    {
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
    }

    ngx_live_segmenter_validate_track_ctx(track);
}

static void
ngx_live_segmenter_remove_all_frames(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_frame_part_t   *part;
    ngx_live_segmenter_frame_part_t   *next_part;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    for (part = ctx->frames.part.next; part != NULL; part = next_part) {

        next_part = part->next;

        ngx_block_pool_free(cctx->block_pool,
            NGX_LIVE_BP_PENDING_FRAME_PART, part);
    }

    ctx->frames.part.nelts = 0;
    ctx->frames.part.next = NULL;
    ctx->frames.last = &ctx->frames.part;
    ctx->frame_count = 0;
    ctx->force_split_index = NGX_LIVE_INVALID_FRAME_INDEX;
    ctx->last_data_part = NULL;

    /* update ready status */
    if (ctx->state == ngx_live_track_ready) {
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
    }

    ngx_live_segmenter_validate_track_ctx(track);
}

static ngx_uint_t
ngx_live_segmenter_get_frame_index(ngx_live_track_t *track, int64_t target_pts)
{
    int64_t                           pts;
    ngx_uint_t                        base_index, i;
    ngx_uint_t                        index;
    ngx_live_segmenter_frame_t       *data;
    ngx_live_segmenter_track_ctx_t   *ctx;
    ngx_live_segmenter_frame_part_t  *part;

    pts = LLONG_MAX;
    index = 0;
    base_index = 0;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    part = &ctx->frames.part;
    data = part->elts;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;

            base_index += i;
            i = 0;
        }

        if (track->media_type == KMP_MEDIA_VIDEO &&
            (data[i].flags & KMP_FRAME_FLAG_KEY) == 0)
        {
            continue;
        }

        if (pts != LLONG_MAX &&
            ngx_abs(data[i].pts - target_pts) >=
            ngx_abs(pts - target_pts))
        {
            continue;
        }

        pts = data[i].pts;
        index = base_index + i;
    }

    return index;
}

static void
ngx_live_segmenter_prepare_create_segment(ngx_live_channel_t *channel,
    int64_t *min_pts)
{
    ngx_uint_t                         split_index;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    *min_pts = LLONG_MAX;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count == 0) {
            continue;
        }

        if (cur_ctx->last_segment_index != cctx->segment_index - 1 ||
            cctx->force_new_period)
        {
            split_index = ngx_live_segmenter_get_frame_index(cur_track,
                cctx->last_segment_end_pts);

            if (split_index > 0) {
                ngx_live_segmenter_remove_frames(cur_track, split_index);
                if (cur_ctx->frame_count == 0) {
                    continue;
                }
            }
        }

        if (cur_ctx->start_pts < *min_pts) {
            *min_pts = cur_ctx->start_pts;
        }
    }
}

static int64_t
ngx_live_segmenter_get_average_force_split_pts(ngx_live_channel_t *channel)
{
    int64_t                          pts_sum = 0;
    uint32_t                         pts_count = 0;
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_segmenter_track_ctx_t  *cur_ctx;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count == 0) {
            continue;
        }

        if (cur_ctx->force_split_index == NGX_LIVE_INVALID_FRAME_INDEX) {
            continue;
        }

        pts_sum += cur_ctx->force_split_pts;
        pts_count++;
    }

    if (pts_count == 0) {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_segmenter_get_average_force_split_pts: "
            "no tracks found");
        return LLONG_MAX;
    }

    return pts_sum / pts_count;
}

static ngx_live_track_t*
ngx_live_segmenter_get_base_track(ngx_live_channel_t *channel)
{
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_track_t                *base_track;
    ngx_live_segmenter_track_ctx_t  *cur_ctx;
    ngx_live_segmenter_track_ctx_t  *base_ctx;

    base_track = NULL;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count <= 0) {
            continue;
        }

        if (base_track == NULL) {
            base_track = cur_track;
            base_ctx = cur_ctx;
            continue;
        }

        /* prefer ready tracks */
        if (base_ctx->state != cur_ctx->state) {

            if (cur_ctx->state == ngx_live_track_ready) {
                base_track = cur_track;
                base_ctx = cur_ctx;
            }
            continue;
        }

        /* prefer video tracks */
        if (base_track->media_type != cur_track->media_type) {

            if (cur_track->media_type == KMP_MEDIA_VIDEO) {
                base_track = cur_track;
                base_ctx = cur_ctx;
            }
            continue;
        }

        /* prefer longer tracks when all are not ready */
        if (cur_ctx->state != ngx_live_track_ready &&
            cur_ctx->last_pts > base_ctx->last_pts)
        {
            base_track = cur_track;
            base_ctx = cur_ctx;
        }
    }

    return base_track;
}

static ngx_uint_t
ngx_live_segmenter_get_keyframe_pts(ngx_live_segmenter_track_ctx_t *ctx,
    int64_t pts, int64_t *result, uint32_t max_index)
{
    ngx_uint_t                        i;
    ngx_uint_t                        index = 0;
    ngx_live_segmenter_frame_t       *data;
    ngx_live_segmenter_frame_part_t  *part;

    part = &ctx->frames.part;
    data = part->elts;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

        if ((data[i].flags & KMP_FRAME_FLAG_KEY) == 0) {
            continue;
        }

        if (data[i].pts <= ctx->start_pts) {
            continue;
        }

        if (index < max_index) {
            result[index++] = data[i].pts;
            continue;
        }

        if (ngx_abs(data[i].pts - pts) > ngx_abs(result[0] - pts)) {
            return index;
        }

        ngx_memmove(result, result + 1, (max_index - 1) * sizeof(result[0]));
        result[index - 1] = data[i].pts;
    }

    if (ctx->state != ngx_live_track_inactive) {
        return index;
    }

    /* track is inactive, treat the last frame as key frame */
    if (index < max_index) {
        result[index++] = ctx->last_pts;

    } else if (ngx_abs(ctx->last_pts - pts) <= ngx_abs(result[0] - pts)) {
        ngx_memmove(result, result + 1, (max_index - 1) * sizeof(result[0]));
        result[index - 1] = ctx->last_pts;
    }

    return index;
}

static void
ngx_live_segmenter_find_nearest_keyframe_pts(
    ngx_live_segmenter_track_ctx_t *ctx, ngx_uint_t count, int64_t *target,
    int64_t *result)
{
    ngx_uint_t                        i, j;
    ngx_live_segmenter_frame_t       *frame;
    ngx_live_segmenter_frame_t       *frames;
    ngx_live_segmenter_frame_part_t  *part;

    for (j = 0; j < count; j++) {
        result[j] = LLONG_MAX;
    }

    part = &ctx->frames.part;
    frames = part->elts;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            frames = part->elts;
            i = 0;
        }

        frame = &frames[i];
        if ((frame->flags & KMP_FRAME_FLAG_KEY) == 0) {
            continue;
        }

        for (j = 0; j < count; j++) {

            if (result[j] == LLONG_MAX ||
                ngx_abs(frame->pts - target[j]) <
                ngx_abs(result[j] - target[j]))
            {
                result[j] = frame->pts;
            }
        }
    }

    if (ctx->state == ngx_live_track_inactive) {

        /* track is inactive, treat the last frame as key frame */
        for (j = 0; j < count; j++) {

            if (result[j] == LLONG_MAX ||
                ngx_abs(ctx->last_pts - target[j]) <
                ngx_abs(result[j] - target[j]))
            {
                result[j] = ctx->last_pts;
            }
        }
    }
}

static int64_t
ngx_live_segmenter_get_segment_end_pts(ngx_live_track_t *base_track)
{
    int64_t                            boundary;
    int64_t                            cur_diff, min_diff;
    int64_t                            cur_pts, target_pts;
    int64_t                            kf_pts[NGX_LIVE_TEST_KF_COUNT];
    int64_t                            kf_min[NGX_LIVE_TEST_KF_COUNT];
    int64_t                            kf_max[NGX_LIVE_TEST_KF_COUNT];
    int64_t                            kf_nearest[NGX_LIVE_TEST_KF_COUNT];
    ngx_uint_t                         kf_count, j;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_channel_t                *channel = base_track->channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(base_track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    boundary = cctx->last_segment_end_pts + cctx->segment_duration;
    if (base_track->media_type != KMP_MEDIA_VIDEO) {
        return boundary;
    }

    /* find the keyframes of the base track closest to boundary */
    kf_count = ngx_live_segmenter_get_keyframe_pts(ctx, boundary,
        kf_pts, sizeof(kf_pts) / sizeof(kf_pts[0]));
    if (kf_count == 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_get_segment_end_pts: no key frames");
        return LLONG_MAX;
    }

    ngx_memcpy(kf_min, kf_pts, sizeof(kf_min));
    ngx_memcpy(kf_max, kf_pts, sizeof(kf_max));

    for (q = ngx_queue_next(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track == base_track) {
            break;
        }

        if (cur_track->media_type != KMP_MEDIA_VIDEO) {
            break;      /* the tracks are sorted by media type */
        }

        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);
        if (cur_ctx->state != ngx_live_track_ready) {
            continue;
        }

        /* for each base track keyframe, find the pts of the closest keyframe
            in the current track */
        ngx_live_segmenter_find_nearest_keyframe_pts(cur_ctx, kf_count,
            kf_pts, kf_nearest);

        /* update the min / max ptss */
        for (j = 0; j < kf_count; j++)
        {
            if (kf_nearest[j] < kf_min[j]) {
                kf_min[j] = kf_nearest[j];
            }

            if (kf_nearest[j] > kf_max[j]) {
                kf_max[j] = kf_nearest[j];
            }
        }
    }

    /* find smallest pts gap */
    min_diff = LLONG_MAX;
    for (j = 0; j < kf_count; j++) {

        cur_diff = kf_max[j] - kf_min[j];
        if (cur_diff < min_diff) {
            min_diff = cur_diff;
        }
    }

    /* allow some margin around the min diff */
    min_diff *= 2;
    min_diff += cctx->keyframe_alignment_margin;

    /* choose the pts closest to the boundary, with span smaller than min */
    target_pts = LLONG_MAX;
    for (j = 0; j < kf_count; j++) {

        cur_diff = kf_max[j] - kf_min[j];
        if (cur_diff > min_diff) {
            continue;
        }

        cur_pts = (kf_max[j] + kf_min[j]) / 2;
        if (target_pts == LLONG_MAX ||
            ngx_abs(cur_pts - boundary) < ngx_abs(target_pts - boundary))
        {
            target_pts = cur_pts;
        }
    }

    if (target_pts == LLONG_MAX) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_get_segment_end_pts: no target pts");
        return LLONG_MAX;
    }

    return target_pts;
}

static ngx_int_t
ngx_live_segmenter_set_split_indexes(ngx_live_channel_t *channel,
    int64_t target_pts)
{
    ngx_int_t                          rc;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    rc = NGX_OK;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count == 0) {
            continue;
        }

        if (cur_ctx->force_split_index != NGX_LIVE_INVALID_FRAME_INDEX) {
            continue;
        }

        if (cur_ctx->state != ngx_live_track_ready &&
            target_pts >= cur_ctx->last_pts) {
            cur_ctx->force_split_index = cur_ctx->frame_count;
            continue;
        }

        cur_ctx->force_split_index = ngx_live_segmenter_get_frame_index(
            cur_track, target_pts);
        if (cur_ctx->force_split_index == 0) {
            cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
            ngx_log_error(NGX_LOG_ERR, &cur_track->log, 0,
                "ngx_live_segmenter_set_split_indexes: empty segment %uD",
                cctx->segment_index);
            rc = NGX_ERROR;
        }
    }

    return rc;
}

static void
ngx_live_segmenter_dispose_segment(ngx_live_channel_t *channel)
{
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_segmenter_track_ctx_t  *cur_ctx;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count == 0) {
            continue;
        }

        ngx_live_segmenter_remove_frames(cur_track,
            cur_ctx->force_split_index);
    }
}

static ngx_buf_chain_t *
ngx_live_segmenter_terminate_frame_chain(ngx_live_segmenter_frame_t *frame)
{
    uint32_t          size = frame->size;
    ngx_buf_chain_t  *data;

    for (data = frame->data; ; data = data->next) {

        size -= data->size;
        if (size <= 0) {
            break;
        }
    }

    data->next = NULL;
    return data;
}

static ngx_int_t
ngx_live_segmenter_track_create_segment(ngx_live_track_t *track,
    uint32_t segment_index)
{
    size_t                            size;
    ngx_uint_t                        i;
    ngx_uint_t                        frames_left;
    input_frame_t                    *dest, *prev_dest;
    ngx_live_segment_t               *segment;
    ngx_live_segmenter_frame_t       *src, *prev_src;
    ngx_live_segmenter_frame_t       *frames;
    ngx_live_core_preset_conf_t      *cpcf;
    ngx_live_segmenter_track_ctx_t   *ctx;
    ngx_live_segmenter_frame_part_t  *part;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    /* create the segment */
    segment = ngx_live_segment_cache_create(track, segment_index);
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: create segment failed");
        return NGX_ERROR;
    }

    frames_left = ctx->force_split_index;

    /* add the frames */
    part = &ctx->frames.part;
    frames = part->elts;

    segment->frame_count = frames_left;
    segment->start_dts = frames[0].dts;
    segment->data_head = frames[0].data;

    prev_src = NULL;
    prev_dest = NULL;
    size = 0;

    for (i = 0;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            frames = part->elts;
            i = 0;
        }

        src = &frames[i];

        if (prev_dest != NULL) {
            prev_dest->duration = src->dts - prev_src->dts;
        }

        if (frames_left <= 0) {
            break;
        }

        dest = ngx_list_push(&segment->frames);
        if (dest == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segmenter_track_create_segment: push frame failed");
            return NGX_ERROR;
        }

        dest->key_frame = (src->flags & KMP_FRAME_FLAG_KEY) ? 1 : 0;
        dest->pts_delay = src->pts - src->dts;
        dest->size = src->size;
        dest->duration = 0;        /* set when the next frame arrives */
        prev_dest = dest;
        prev_src = src;

        size += src->size;
        frames_left--;
    }

    if (prev_src != NULL) {
        segment->data_tail = ngx_live_segmenter_terminate_frame_chain(
            prev_src);
    }

    segment->data_size = size;

    ngx_live_segment_cache_validate(segment);

    ctx->last_segment_index = segment_index;
    if (src->dts > segment->start_dts) {
        cpcf = ngx_live_get_module_preset_conf(track->channel,
            ngx_live_core_module);

        ctx->last_segment_bitrate = (size * 8 * cpcf->timescale) /
            (src->dts - segment->start_dts);
    }

    ngx_live_segmenter_remove_frames(track, ctx->force_split_index);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_create_segment(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_segmenter_track_ctx_t  *cur_ctx;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count == 0) {
            continue;
        }

        if (ngx_live_segmenter_track_create_segment(cur_track, segment_index)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_segmenter_create_segment: create segment failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static int64_t
ngx_live_segmenter_get_target_pts(ngx_live_channel_t *channel)
{
    int64_t                            target_pts;
    ngx_live_track_t                  *base_track;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    if (cctx->has_force_splits) {

        /* there are force splits, use their average timestamp */
        cctx->has_force_splits = 0;

        target_pts = ngx_live_segmenter_get_average_force_split_pts(
            channel);
        if (target_pts != LLONG_MAX) {
            cctx->force_new_period = 1;
            goto done;
        }

        /* Note: has_force_splits may in some cases be wrongly enabled
            (e.g. after all pending frames got removed)
            if this happens, just fall back to regular flow */
    }

    /* find a timestamp closest to key frame on all tracks */
    base_track = ngx_live_segmenter_get_base_track(channel);
    if (base_track == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_create_segments: no base track");
        return LLONG_MAX;
    }

    target_pts = ngx_live_segmenter_get_segment_end_pts(base_track);
    if (target_pts == LLONG_MAX) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_create_segments: failed to get pts");
        return LLONG_MAX;
    }

done:

    target_pts = ngx_max(target_pts, cctx->last_segment_end_pts +
        cctx->min_segment_duration);

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_create_segments: boundary pts %L", target_pts);

    return target_pts;
}

static ngx_int_t
ngx_live_segmenter_create_segments(ngx_live_channel_t *channel)
{
    int64_t                            min_pts;
    int64_t                            target_pts;
    uint32_t                           duration;
    uint32_t                           segment_index;
    ngx_int_t                          rc;
    ngx_flag_t                         exists;
    ngx_flag_t                         force_new_period;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    while (cctx->count[ngx_live_track_pending] <= 0)
    {
        /* get the min pts of all tracks */
        ngx_live_segmenter_prepare_create_segment(channel, &min_pts);
        if (cctx->count[ngx_live_track_pending] > 0) {
            /* can happen if some frames got stripped */
            break;
        }

        if (min_pts == LLONG_MAX) {
            cctx->force_new_period = 1;
            break;
        }

        force_new_period = cctx->force_new_period;
        cctx->force_new_period = 0;

        if (min_pts > cctx->last_segment_end_pts + cctx->segment_duration)
        {
            cctx->last_segment_end_pts = min_pts;
            force_new_period = 1;
        }

        target_pts = ngx_live_segmenter_get_target_pts(channel);
        if (target_pts == LLONG_MAX) {
            return NGX_ERROR;
        }

        /* calculate the split indexes */
        if (ngx_live_segmenter_set_split_indexes(channel, target_pts)
            != NGX_OK)
        {
            ngx_live_segmenter_dispose_segment(channel);
            cctx->last_segment_end_pts = target_pts;
            continue;
        }

        /* create the segment on all tracks */
        segment_index = cctx->segment_index;

        cctx->cur_ready_duration = cctx->ready_duration;

        if (ngx_live_segmenter_create_segment(channel, segment_index)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: create failed");
            return NGX_ERROR;
        }

        /* add to the timeline */
        duration = target_pts - cctx->last_segment_end_pts;

        rc = ngx_live_timelines_add_segment(channel, segment_index,
            cctx->last_segment_end_pts, duration, force_new_period);
        switch (rc)
        {
        case NGX_DONE:
            exists = 0;
            break;

        case NGX_OK:
            exists = 1;
            break;

        default:
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: add segment failed");
            return NGX_ERROR;
        }

        /* notify the creation */
        ngx_live_dvr_save_segment_created(channel, segment_index, exists);

        cctx->segment_index++;
        cctx->last_segment_end_pts = target_pts;
    }

    if (cctx->count[ngx_live_track_inactive] >= channel->track_count) {
        ngx_live_segmenter_channel_inactive(channel);
    }

    ngx_live_segmenter_validate_channel_ctx(channel);

    return NGX_OK;
}

static ngx_live_segmenter_frame_t *
ngx_live_segmenter_push_frame(ngx_live_segmenter_channel_ctx_t *cctx,
    ngx_live_segmenter_frame_list_t *list)
{
    ngx_live_segmenter_frame_t       *elt;
    ngx_live_segmenter_frame_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_LIVE_SEGMENTER_FRAME_PART_COUNT) {

        last = ngx_block_pool_alloc(cctx->block_pool,
            NGX_LIVE_BP_PENDING_FRAME_PART);
        if (last == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        list->last->next = last;
        list->last = last;
    }

    elt = &last->elts[last->nelts];
    last->nelts++;
    return elt;
}

static ngx_int_t
ngx_live_segmenter_add_frame(ngx_live_track_t *track, kmp_frame_t *frame_info,
    ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail, size_t size)
{
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_frame_t        *frame;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_preset_conf_t  *spcf;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    channel = track->channel;
    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, &track->log, 0,
        "ngx_live_segmenter_add_frame: track: %V, created: %L, size: %uz, "
        "dts: %L, flags: %uD, ptsDelay: %uD",
        &track->sn.str, frame_info->created, size, frame_info->dts,
        frame_info->flags, frame_info->pts_delay);

    ctx->received_frames++;

    if (frame_info->flags & KMP_FRAME_FLAG_KEY) {
        ctx->received_key_frames++;
    }

    if (ctx->frame_count >= NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_add_frame: frame count exceeds limit");
        return NGX_ERROR;
    }

    frame = ngx_live_segmenter_push_frame(cctx, &ctx->frames);
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_add_frame: push frame failed");
        return NGX_ABORT;
    }

    frame->dts = frame_info->dts;
    frame->pts = frame_info->dts + frame_info->pts_delay;
    frame->flags = frame_info->flags;
    frame->size = size;
    frame->data = data_head;

    if (ctx->last_data_part != NULL) {
        ctx->last_data_part->next = data_head;
    }
    ctx->last_data_part = data_tail;

    if (ctx->frame_count <= 0) {
        ctx->start_pts = frame->pts;
    }

    ctx->last_created = frame_info->created;
    ctx->last_pts = frame->pts;
    if (track->media_type != KMP_MEDIA_VIDEO ||
        (frame->flags & KMP_FRAME_FLAG_KEY))
    {
        ctx->last_key_pts = frame->pts;
    }

    ctx->frame_count++;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);

    ngx_add_timer(&ctx->inactive, spcf->inactive_timeout);

    switch (ctx->state) {

    case ngx_live_track_ready:
        break;

    case ngx_live_track_inactive:
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
        channel->active = 1;
        /* fall through */

    default:
        if (ngx_live_segmenter_track_is_ready(cctx, ctx) ||
            ctx->force_split_index != NGX_LIVE_INVALID_FRAME_INDEX)
        {
            ngx_live_segmenter_set_state(track, ngx_live_track_ready);

            if (cctx->count[ngx_live_track_pending] <= 0) {
                ngx_post_event(&cctx->create, &ngx_posted_events);
            }
        }
    }

    return NGX_OK;
}

static void
ngx_live_segmenter_end_of_stream(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    ngx_live_segmenter_set_state(track, ngx_live_track_inactive);

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    if (cctx->count[ngx_live_track_pending] <= 0) {
        ngx_post_event(&cctx->create, &ngx_posted_events);
    }
}

void
ngx_live_segmenter_get_oldest_data_ptr(ngx_live_track_t *track, u_char **ptr)
{
    ngx_live_segmenter_track_ctx_t    *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    if (ctx->frames.part.nelts <= 0) {
        *ptr = NULL;
        return;
    }

    *ptr = ctx->frames.part.elts[0].data->data;
}

ngx_int_t
ngx_live_segmenter_force_split(ngx_live_track_t *track,
    uint32_t *segment_index)
{
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->frame_count <= 0) {

        if (segment_index != NULL) {
            cctx = ngx_live_get_module_ctx(track->channel,
                ngx_live_segmenter_module);

            *segment_index = cctx->segment_index;
        }

        return NGX_OK;
    }

    if (ctx->force_split_index != NGX_LIVE_INVALID_FRAME_INDEX &&
        ctx->force_split_index != ctx->frame_count)
    {
        /* TODO: consider removing the frames added after the first
            forced split */
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_force_split: "
            "called when another split is already set");
        return NGX_ERROR;
    }

    ctx->force_split_index = ctx->frame_count;
    ctx->force_split_pts = ctx->last_pts;

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);
    cctx->has_force_splits = 1;
    if (segment_index != NULL) {
        *segment_index = cctx->segment_index + 1;
    }

    return NGX_OK;
}


static void
ngx_live_segmenter_inactive_handler(ngx_event_t *ev)
{
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_track_t                  *track = ev->data;
    ngx_live_channel_t                *channel = track->channel;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_preset_conf_t  *spcf;

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
        "ngx_live_segmenter_inactive_handler: called");

    ngx_live_segmenter_set_state(track, ngx_live_track_inactive);

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);

    /* expire all tracks nearing their inactivity timer, in order to avoid
        segmentation glitches when video becomes inactive slightly earlier
        than audio */
    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track == track) {
            continue;
        }

        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);
        if (!cur_ctx->inactive.timer_set ||
            ngx_current_msec + spcf->inactive_timeout / 4 <
            cur_ctx->inactive.timer.key) {
            continue;
        }

        ngx_del_timer(&cur_ctx->inactive);
        ngx_live_segmenter_set_state(cur_track, ngx_live_track_inactive);
    }

    if (ngx_live_segmenter_create_segments(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_inactive_handler: create segments failed");
        ngx_live_channel_free(channel);
        return;
    }
}

static void
ngx_live_segmenter_create_handler(ngx_event_t *ev)
{
    ngx_live_channel_t  *channel = ev->data;

    if (ngx_live_segmenter_create_segments(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_create_handler: create segments failed");
        ngx_live_channel_free(channel);
        return;
    }
}

static ngx_int_t
ngx_live_segmenter_track_init(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);
    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    ctx->state = ngx_live_track_inactive;
    ctx->last_segment_index = NGX_LIVE_INVALID_SEGMENT_INDEX;
    ctx->force_split_index = NGX_LIVE_INVALID_FRAME_INDEX;

    ctx->frames.part.nelts = 0;
    ctx->frames.part.next = NULL;
    ctx->frames.last = &ctx->frames.part;

    ctx->inactive.handler = ngx_live_segmenter_inactive_handler;
    ctx->inactive.data = track;
    ctx->inactive.log = &track->log;

    cctx->count[ctx->state]++;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_free(ngx_live_track_t *track)
{
    ngx_live_channel_t                *channel = track->channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_frame_part_t   *part, *next;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    cctx->count[ctx->state]--;

    if (ctx->state != ngx_live_track_inactive &&
        cctx->count[ngx_live_track_inactive] >= track->channel->track_count)
    {
        ngx_live_segmenter_channel_inactive(channel);
    }

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    for (part = ctx->frames.part.next; part != NULL; part = next) {
        next = part->next;

        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_PENDING_FRAME_PART,
            part);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_channel_free(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_connect(ngx_live_track_t *track)
{
    ngx_live_segmenter_remove_all_frames(track);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size)
{
    size_t                             block_sizes[NGX_LIVE_BP_COUNT];
    ngx_live_core_preset_conf_t       *cpcf;
    ngx_live_segmenter_preset_conf_t  *spcf;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_segmenter_module);

    block_sizes[NGX_LIVE_BP_PENDING_FRAME_PART] =
        sizeof(ngx_live_segmenter_frame_part_t);

    cctx->block_pool = ngx_live_channel_create_block_pool(channel, block_sizes,
        NGX_LIVE_BP_COUNT);
    if (cctx->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_channel_init: create block pool failed");
        return NGX_ERROR;
    }

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    cctx->conf.segment_duration = spcf->segment_duration;
    cctx->segment_duration = ngx_live_rescale_time(cctx->conf.segment_duration,
        1000, cpcf->timescale);
    cctx->ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->ready_threshold) / 100;
    cctx->initial_ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->initial_ready_threshold) / 100;
    cctx->cur_ready_duration = cctx->initial_ready_duration;

    cctx->min_segment_duration = ngx_live_rescale_time(
        spcf->min_segment_duration, 1000, cpcf->timescale);
    cctx->keyframe_alignment_margin = cpcf->timescale / 100;    /* 10ms */

    cctx->create.data = channel;
    cctx->create.handler = ngx_live_segmenter_create_handler;
    cctx->create.log = &channel->log;

    ngx_live_reserve_track_ctx_size(channel, ngx_live_segmenter_module,
        sizeof(ngx_live_segmenter_track_ctx_t), track_ctx_size);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_channel_free(ngx_live_channel_t *channel)
{
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    if (cctx != NULL && cctx->create.posted) {
        ngx_delete_posted_event(&cctx->create);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_set_segment_duration(void *ctx,
    ngx_live_json_command_t *cmd, ngx_json_value_t *value)
{
    ngx_flag_t                         initial;
    ngx_live_channel_t                *channel = ctx;
    ngx_live_core_preset_conf_t       *cpcf;
    ngx_live_segmenter_preset_conf_t  *spcf;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);
    if (value->v.num.num < (int64_t) spcf->min_segment_duration) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_segmenter_set_segment_duration: "
            "segment duration %L smaller than configured min %M",
            value->v.num.num, spcf->min_segment_duration);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    cctx->conf.segment_duration = value->v.num.num;
    cctx->segment_duration = ngx_live_rescale_time(cctx->conf.segment_duration,
        1000, cpcf->timescale);

    initial = cctx->cur_ready_duration == cctx->initial_ready_duration;
    cctx->ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->ready_threshold) / 100;
    cctx->initial_ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->initial_ready_threshold) / 100;
    cctx->cur_ready_duration = initial ? cctx->initial_ready_duration :
        cctx->ready_duration;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_set_segment_duration: set to %ui",
        cctx->conf.segment_duration);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_preconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_command_t  *cmd;

    cmd = ngx_live_json_commands_add(cf, &ngx_live_segmenter_segment_duration,
        NGX_LIVE_JSON_CTX_CHANNEL);
    if (cmd == NULL) {
        return NGX_ERROR;
    }

    cmd->set_handler = ngx_live_segmenter_set_segment_duration;
    cmd->type = NGX_JSON_INT;

    return NGX_OK;
}

static size_t
ngx_live_segmenter_channel_json_get_size(void *obj)
{
    return sizeof("\"segment_duration\":") - 1 + NGX_INT_T_LEN;
}

static u_char *
ngx_live_segmenter_channel_json_write(u_char *p, void *obj)
{
    ngx_live_channel_t                *channel = obj;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    p = ngx_copy(p, "\"segment_duration\":",
        sizeof("\"segment_duration\":") - 1);
    p = ngx_sprintf(p, "%i", cctx->conf.segment_duration);
    return p;
}


static size_t
ngx_live_segmenter_json_track_get_size(void *obj)
{
    return sizeof("\"last_created\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"last_segment_bitrate\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"pending_frames\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"received_frames\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"received_key_frames\":") - 1 + NGX_INT_T_LEN;
}

static u_char *
ngx_live_segmenter_json_track_write(u_char *p, void *obj)
{
    ngx_live_track_t                *track = obj;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    p = ngx_copy(p, "\"last_created\":", sizeof("\"last_created\":") - 1);
    p = ngx_sprintf(p, "%L", ctx->last_created);

    p = ngx_copy(p, ",\"last_segment_bitrate\":",
        sizeof(",\"last_segment_bitrate\":") - 1);
    p = ngx_sprintf(p, "%uD", ctx->last_segment_bitrate);

    p = ngx_copy(p, ",\"pending_frames\":",
        sizeof(",\"pending_frames\":") - 1);
    p = ngx_sprintf(p, "%uD", ctx->frame_count);

    p = ngx_copy(p, ",\"received_frames\":",
        sizeof(",\"received_frames\":") - 1);
    p = ngx_sprintf(p, "%ui", ctx->received_frames);

    if (track->media_type == KMP_MEDIA_VIDEO) {
        p = ngx_copy(p, ",\"received_key_frames\":",
            sizeof(",\"received_key_frames\":") - 1);
        p = ngx_sprintf(p, "%ui", ctx->received_key_frames);
    }

    return p;
}


static ngx_int_t
ngx_live_segmenter_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_writer_t            *writer;
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_track_handler_pt         *th;
    ngx_live_channel_handler_pt       *ch;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_segmenter_channel_init;

    ch = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_FREE]);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    *ch = ngx_live_segmenter_channel_free;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_INIT]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segmenter_track_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segmenter_track_free;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_CHANNEL_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segmenter_track_channel_free;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_CONNECT]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_segmenter_track_connect;

    writer = ngx_array_push(&cmcf->json_writers[NGX_LIVE_JSON_CTX_CHANNEL]);
    if (writer == NULL) {
        return NGX_ERROR;
    }
    writer->get_size = ngx_live_segmenter_channel_json_get_size;
    writer->write = ngx_live_segmenter_channel_json_write;

    writer = ngx_array_push(&cmcf->json_writers[NGX_LIVE_JSON_CTX_TRACK]);
    if (writer == NULL) {
        return NGX_ERROR;
    }
    writer->get_size = ngx_live_segmenter_json_track_get_size;
    writer->write = ngx_live_segmenter_json_track_write;

    ngx_live_add_frame = ngx_live_segmenter_add_frame;
    ngx_live_end_of_stream = ngx_live_segmenter_end_of_stream;

    return NGX_OK;
}

static void *
ngx_live_segmenter_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_segmenter_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_segmenter_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->segment_duration = NGX_CONF_UNSET_MSEC;
    conf->min_segment_duration = NGX_CONF_UNSET_MSEC;
    conf->inactive_timeout = NGX_CONF_UNSET_MSEC;
    conf->ready_threshold = NGX_CONF_UNSET_UINT;
    conf->initial_ready_threshold = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_segmenter_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_segmenter_preset_conf_t  *prev = parent;
    ngx_live_segmenter_preset_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->segment_duration,
                              prev->segment_duration, 4000);

    ngx_conf_merge_msec_value(conf->min_segment_duration,
                              prev->min_segment_duration, 20);

    ngx_conf_merge_msec_value(conf->inactive_timeout,
                              prev->inactive_timeout, 10000);

    ngx_conf_merge_uint_value(conf->ready_threshold,
                              prev->ready_threshold, 150);

    ngx_conf_merge_uint_value(conf->initial_ready_threshold,
                              prev->initial_ready_threshold, 200);

    return NGX_CONF_OK;
}
