#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_timeline.h"
#include "ngx_live_segmenter.h"
#include "ngx_live_media_info.h"
#include "ngx_live_notif_segment.h"


/*
 * segment phases:
 *  start = the segment is created and accepting frames
 *  stop = the segment got all its frames, no additional frames will be added
 *  end = the segment duration was decided, the full segment can be published
 *  close = the segment ended across all tracks and can be persisted
 *
 *  flush = stop a segment after inactivity / end of stream
 */


#define NGX_LIVE_LLS_ID                     (0x67736c6c)    /* llsg */

#define NGX_LIVE_LLS_FLAG_FLUSH_PART        (0x01)
#define NGX_LIVE_LLS_FLAG_FLUSH_SEGMENT     (0x02)
#define NGX_LIVE_LLS_FLAG_FLUSH_ANY         (NGX_LIVE_LLS_FLAG_FLUSH_PART   \
                                             | NGX_LIVE_LLS_FLAG_FLUSH_SEGMENT)

#define NGX_LIVE_LLS_FRAME_PART_COUNT       (32)

#define NGX_LIVE_LLS_DISPOSE_ACK_FREQUENCY  (16)


#define ngx_live_lls_pending_next_part_sequence(ch, p)                      \
    ((p)->part_sequence + ngx_ceil_div((p)->end_pts - (p)->start_pts,       \
     (ch)->part_duration))


enum {
    NGX_LIVE_BP_PENDING_FRAME_PART,

    NGX_LIVE_BP_COUNT
};


/* frame states */

enum {
    ngx_live_lls_fs_idle,       /* inactive + no pending frames */
    ngx_live_lls_fs_inactive,   /* timeout passed since last frame
                                        / got eos */
    ngx_live_lls_fs_active,     /* a frame arrived recently */
};


/* segment states */

enum {
    ngx_live_lls_ss_idle,       /* segment == null */
    ngx_live_lls_ss_started,    /* segment != null && !segment->ready */
    ngx_live_lls_ss_stopped,    /* segment != null && segment->ready */
};


typedef struct {
    ngx_uint_t                         max_pending_segments;
    ngx_msec_t                         min_part_duration;

    ngx_msec_t                         inactive_timeout;
    ngx_msec_t                         forward_jump_threshold;
    ngx_msec_t                         backward_jump_threshold;
    ngx_msec_t                         dispose_threshold;
    ngx_msec_t                         start_period_threshold;

    ngx_msec_t                         frame_process_delay;
    ngx_msec_t                         audio_process_delay;
    ngx_msec_t                         wait_video_timeout;
    ngx_msec_t                         close_segment_delay;

    ngx_uint_t                         segment_start_margin;
    ngx_uint_t                         video_end_segment_margin;
    ngx_uint_t                         video_duration_margin;

    ngx_uint_t                         max_skip_frames;

    ngx_uint_t                         bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_lls_preset_conf_t;


/* frame list */

typedef struct {
    int64_t                            created;
    ngx_msec_t                         added;
    uint64_t                           id;
    int64_t                            pts;
    int64_t                            dts;
    uint32_t                           flags;
    uint32_t                           size;
    ngx_buf_chain_t                   *data;
} ngx_live_lls_frame_t;

typedef struct ngx_live_lls_frame_part_s  ngx_live_lls_frame_part_t;

struct ngx_live_lls_frame_part_s {
    ngx_live_lls_frame_part_t         *next;    /* must be first -
                                                    ngx_block_pool_free_list */
    ngx_uint_t                         nelts;

    ngx_live_lls_frame_t               elts[NGX_LIVE_LLS_FRAME_PART_COUNT];
};

typedef struct {
    ngx_live_track_t                  *track;
    ngx_block_pool_t                  *block_pool;
    ngx_uint_t                         bp_idx;

    ngx_live_lls_frame_part_t         *part;
    ngx_live_lls_frame_part_t         *last;
    ngx_buf_chain_t                   *last_data_part;
    ngx_uint_t                         offset;
    ngx_uint_t                         count;
} ngx_live_lls_frame_list_t;


/* track context */

typedef struct {
    int64_t                            last_frame_pts;
    int64_t                            last_frame_dts;
    uint64_t                           next_frame_id;
    uint32_t                           bitrate;
} ngx_live_lls_track_pending_seg_t;

typedef struct {
    ngx_rbtree_node_t                  node;        /* must be first */
    ngx_live_track_t                  *track;

    ngx_int_t                          fstate;
    ngx_live_lls_frame_list_t          frames;
    uint32_t                           next_flags;
    int64_t                            last_added_pts;
    u_char                            *last_data_ptr;
    ngx_event_t                        inactive;

    ngx_int_t                          sstate;
    ngx_live_segment_t                *segment;
    int64_t                            part_start_pts;
    int64_t                            part_end_pts;
    int64_t                            part_frame_created;

    int64_t                            last_frame_pts;
    int64_t                            last_frame_dts;
    uint64_t                           next_frame_id;
    uint32_t                           last_dropped_frames;

    /* stats */
    int64_t                            last_created;
    off_t                              received_bytes;
    ngx_uint_t                         received_frames;
    ngx_uint_t                         received_key_frames;
    ngx_uint_t                         dropped_frames;
    ngx_live_latency_stats_t           latency;

    ngx_live_lls_track_pending_seg_t   pending[1];  /* must be last */
} ngx_live_lls_track_ctx_t;


/* channel context */

typedef struct {
    int64_t                            start_pts;
    int64_t                            end_pts;

    ngx_msec_t                         created;
    uint32_t                           part_sequence;

    uint32_t                           total_started_tracks;
    uint32_t                           started_tracks[KMP_MEDIA_COUNT];

    unsigned                           exists:1;    /* in some timeline */
    unsigned                           index_created:1;
    unsigned                           end_set:1;
} ngx_live_lls_pending_seg_t;

typedef struct {
    uint32_t                           nelts;
    ngx_live_lls_pending_seg_t         elts[1];  /* must be last */
} ngx_live_lls_pending_segs_t;

typedef struct {
    uint32_t                           min_part_duration;
    uint32_t                           forward_jump_threshold;
    uint32_t                           backward_jump_threshold;
    uint32_t                           dispose_threshold;
    uint32_t                           start_period_threshold;
    uint32_t                           audio_process_delay;

    ngx_rbtree_t                       rbtree;
    ngx_rbtree_node_t                  sentinel;
    uint32_t                           pending_frames_tracks[KMP_MEDIA_COUNT];
    uint32_t                           non_idle_tracks;

    int64_t                            last_segment_end_pts;
    int64_t                            min_pending_end_pts;

    ngx_event_t                        process;
    ngx_event_t                        close;

    ngx_live_lls_pending_segs_t        pending;     /* must be last */
} ngx_live_lls_channel_ctx_t;


static char *ngx_live_lls_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_live_lls_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_lls_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_lls_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_lls_set_end_pts(ngx_live_channel_t *channel,
    ngx_log_t *log);

static ngx_int_t ngx_live_lls_track_end_segment(ngx_live_track_t *track);
static ngx_int_t ngx_live_lls_end_segments(ngx_live_channel_t *channel);

static ngx_int_t ngx_live_lls_close_segments(ngx_live_channel_t *channel);
static ngx_int_t ngx_live_lls_force_close_segment(ngx_live_channel_t *channel);


static ngx_conf_num_bounds_t  ngx_live_lls_max_pending_segments_bounds = {
    ngx_conf_check_num_bounds, 1, 128
};

static ngx_conf_num_bounds_t  ngx_live_lls_percent_bounds = {
    ngx_conf_check_num_bounds, 0, 99
};


static ngx_command_t  ngx_live_lls_commands[] = {

    { ngx_string("ll_segmenter"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_NOARGS,
      ngx_live_lls_enable,
      NGX_LIVE_PRESET_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ll_segmenter_max_pending_segments"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, max_pending_segments),
      &ngx_live_lls_max_pending_segments_bounds },

    { ngx_string("ll_segmenter_min_part_duration"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, min_part_duration),
      NULL },

    { ngx_string("ll_segmenter_inactive_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, inactive_timeout),
      NULL },

    { ngx_string("ll_segmenter_forward_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, forward_jump_threshold),
      NULL },

    { ngx_string("ll_segmenter_backward_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, backward_jump_threshold),
      NULL },

    { ngx_string("ll_segmenter_dispose_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, dispose_threshold),
      NULL },

    { ngx_string("ll_segmenter_start_period_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, start_period_threshold),
      NULL },

    { ngx_string("ll_segmenter_frame_process_delay"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, frame_process_delay),
      NULL },

    { ngx_string("ll_segmenter_audio_process_delay"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, audio_process_delay),
      NULL },

    { ngx_string("ll_segmenter_wait_video_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, wait_video_timeout),
      NULL },

    { ngx_string("ll_segmenter_close_segment_delay"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, close_segment_delay),
      NULL },

    { ngx_string("ll_segmenter_segment_start_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, segment_start_margin),
      &ngx_live_lls_percent_bounds },

    { ngx_string("ll_segmenter_video_end_segment_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, video_end_segment_margin),
      &ngx_live_lls_percent_bounds },

    { ngx_string("ll_segmenter_video_duration_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, video_duration_margin),
      &ngx_live_lls_percent_bounds },

    { ngx_string("ll_segmenter_max_skip_frames"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_lls_preset_conf_t, max_skip_frames),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_lls_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_lls_postconfiguration,           /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_lls_create_preset_conf,          /* create preset configuration */
    ngx_live_lls_merge_preset_conf,           /* merge preset configuration */
};

ngx_module_t  ngx_live_lls_module = {
    NGX_MODULE_V1,
    &ngx_live_lls_module_ctx,                 /* module context */
    ngx_live_lls_commands,                    /* module directives */
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


/* frame list */

static ngx_int_t
ngx_live_lls_frame_list_init(ngx_live_lls_frame_list_t *list,
    ngx_live_track_t *track, ngx_block_pool_t *block_pool, ngx_uint_t bp_idx)
{
    ngx_live_lls_frame_part_t  *part;

    list->track = track;
    list->block_pool = block_pool;
    list->bp_idx = bp_idx;

    part = ngx_block_pool_alloc(list->block_pool, list->bp_idx);
    if (part == NULL) {
        return NGX_ERROR;
    }

    part->nelts = 0;
    part->next = NULL;

    list->last = list->part = part;

    return NGX_OK;
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_lls_frame_list_validate(ngx_live_lls_frame_list_t *list)
{
    ngx_uint_t                  count;
    ngx_live_lls_frame_part_t  *part;

    part = list->part;

    if (list->offset > part->nelts) {
        ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
            "ngx_live_lls_frame_list_validate: "
            "invalid offset %ui", list->offset);
        ngx_debug_point();
    }

    count = 0;

    for ( ;; ) {

        if (part->nelts > NGX_LIVE_LLS_FRAME_PART_COUNT) {
            ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
                "ngx_live_lls_frame_list_validate: "
                "invalid part count %ui (1)", part->nelts);
            ngx_debug_point();
        }

        count += part->nelts;

        if (part->next == NULL) {
            break;
        }

        part = part->next;

        if (part->nelts <= 0) {
            ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
                "ngx_live_lls_frame_list_validate: "
                "invalid part count %ui (2)", part->nelts);
            ngx_debug_point();
        }
    }

    if (list->last != part) {
        ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
            "ngx_live_lls_frame_list_validate: invalid last part");
        ngx_debug_point();
    }

    count -= list->offset;
    if (list->count != count) {
        ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
            "ngx_live_lls_frame_list_validate: "
            "invalid count %ui expected %ui", list->count, count);
        ngx_debug_point();
    }
}
#else
#define ngx_live_lls_frame_list_validate(list)
#endif

static ngx_live_lls_frame_t *
ngx_live_lls_frame_list_push(ngx_live_lls_frame_list_t *list,
    ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail)
{
    ngx_live_lls_frame_t       *frame;
    ngx_live_lls_frame_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_LIVE_LLS_FRAME_PART_COUNT) {

        last = ngx_block_pool_alloc(list->block_pool, list->bp_idx);
        if (last == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        list->last->next = last;
        list->last = last;
    }

    frame = &last->elts[last->nelts];
    last->nelts++;

    list->count++;

    frame->data = data_head;

    if (list->last_data_part != NULL) {
        list->last_data_part->next = data_head;
    }
    list->last_data_part = data_tail;

    ngx_live_lls_frame_list_validate(list);

    return frame;
}

static void
ngx_live_lls_frame_list_pop(ngx_live_lls_frame_list_t *list)
{
    ngx_live_lls_frame_part_t  *part;

    list->count--;

    list->offset++;
    if (list->offset < NGX_LIVE_LLS_FRAME_PART_COUNT) {
        goto done;
    }

    list->offset = 0;

    part = list->part;
    if (part->next == NULL) {
        part->nelts = 0;
        goto done;
    }

    list->part = part->next;

    ngx_block_pool_free(list->block_pool, list->bp_idx, part);

done:

    ngx_live_lls_frame_list_validate(list);
}

static ngx_live_lls_frame_t *
ngx_live_lls_frame_list_head(ngx_live_lls_frame_list_t *list)
{
    return list->part->elts + list->offset;
}

static ngx_live_lls_frame_t *
ngx_live_lls_frame_list_last(ngx_live_lls_frame_list_t *list)
{
    ngx_live_lls_frame_part_t  *last;

    last = list->last;

    return &last->elts[last->nelts - 1];
}

static void
ngx_live_lls_frame_list_free(ngx_live_lls_frame_list_t *list)
{
    ngx_live_lls_frame_t  *frame;

    if (list->count > 0) {
        frame = ngx_live_lls_frame_list_head(list);

        ngx_live_channel_buf_chain_free_list(list->track->channel,
            frame->data, list->last_data_part);
    }

    if (list->part != NULL) {
        ngx_block_pool_free_list(list->block_pool, list->bp_idx, list->part,
            list->last);
    }
}

static void
ngx_live_lls_frame_list_reset(ngx_live_lls_frame_list_t *list)
{
    ngx_live_lls_frame_t       *frame;
    ngx_live_lls_frame_part_t  *part;

    if (list->count > 0) {
        frame = ngx_live_lls_frame_list_head(list);

        ngx_live_channel_buf_chain_free_list(list->track->channel,
            frame->data, list->last_data_part);
    }

    part = list->part;

    if (part->next != NULL) {
        ngx_block_pool_free_list(list->block_pool, list->bp_idx, part->next,
            list->last);
    }

    part->nelts = 0;
    part->next = NULL;

    list->last = part;
    list->last_data_part = NULL;
    list->offset = 0;
    list->count = 0;
}


#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_lls_validate_pending(ngx_live_channel_t *channel,
    ngx_uint_t pending_index)
{
    uint32_t                     total_started_tracks;
    uint32_t                     started_tracks[KMP_MEDIA_COUNT];
    ngx_uint_t                   i;
    ngx_queue_t                 *q;
    ngx_live_track_t            *cur_track;
    ngx_live_lls_track_ctx_t    *cur_ctx;
    ngx_live_lls_pending_seg_t  *pending;
    ngx_live_lls_channel_ctx_t  *cctx;

    total_started_tracks = 0;
    ngx_memzero(started_tracks, sizeof(started_tracks));

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_lls_module);

        if (cur_track->pending_index == pending_index
            && cur_ctx->sstate == ngx_live_lls_ss_started)
        {
            total_started_tracks++;
            started_tracks[cur_track->media_type]++;
        }
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    pending = &cctx->pending.elts[pending_index];

    if (pending->total_started_tracks != total_started_tracks) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_lls_validate_pending: "
            "invalid pending tracks count %uD expected %uD",
            pending->total_started_tracks, total_started_tracks);
        ngx_debug_point();
    }

    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        if (pending->started_tracks[i] != started_tracks[i]) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_lls_validate_pending: "
                "invalid pending tracks (%ui) count %uD expected %uD",
                i, pending->started_tracks[i], started_tracks[i]);
            ngx_debug_point();
        }
    }
}

static void
ngx_live_lls_validate(ngx_live_channel_t *channel)
{
    uint32_t                     non_idle_tracks;
    uint32_t                     has_pending_segment;
    uint32_t                     pending_frames_tracks[KMP_MEDIA_COUNT];
    ngx_int_t                    sstate;
    ngx_queue_t                 *q;
    ngx_uint_t                   i;
    ngx_live_track_t            *cur_track;
    ngx_live_lls_track_ctx_t    *cur_ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    for (i = 0; i < cctx->pending.nelts; i++) {
        ngx_live_lls_validate_pending(channel, i);
    }

    non_idle_tracks = 0;
    ngx_memzero(pending_frames_tracks, sizeof(pending_frames_tracks));

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_lls_module);

        has_pending_segment = cur_ctx->segment != NULL;
        if (cur_track->has_pending_segment != has_pending_segment) {
            ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                "ngx_live_lls_validate: "
                "invalid has_pending_segment %uD expected %uD",
                (uint32_t) cur_track->has_pending_segment,
                has_pending_segment);
            ngx_debug_point();
        }

        if (cur_track->pending_index + has_pending_segment
            > cctx->pending.nelts)
        {
            ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                "ngx_live_lls_validate: "
                "invalid pending_index %uD, has_pending: %uD, limit: %uD",
                cur_track->pending_index, has_pending_segment,
                cctx->pending.nelts);
            ngx_debug_point();
        }

        if (cur_ctx->fstate != ngx_live_lls_fs_idle) {
            non_idle_tracks++;
        }

        if (cur_ctx->frames.count > 0) {
            pending_frames_tracks[cur_track->media_type]++;

            if (cur_ctx->fstate == ngx_live_lls_fs_idle) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_lls_validate: idle track with pending frames");
                ngx_debug_point();
            }

        } else {
            if (cur_ctx->fstate == ngx_live_lls_fs_inactive) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_lls_validate: "
                    "inactive track without pending frames");
                ngx_debug_point();
            }
        }

        if (cur_ctx->segment != NULL) {
            if (cur_ctx->segment->ready) {
                sstate = ngx_live_lls_ss_stopped;

            } else {
                sstate = ngx_live_lls_ss_started;
            }

        } else {
            sstate = ngx_live_lls_ss_idle;
        }

        if (cur_ctx->sstate != sstate) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_lls_validate: "
                "invalid segment state %i expected %i",
                cur_ctx->sstate, sstate);
            ngx_debug_point();
        }
    }

    if (cctx->non_idle_tracks != non_idle_tracks) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_lls_validate: "
            "invalid non-idle tracks count %uD expected %uD",
            cctx->non_idle_tracks, non_idle_tracks);
        ngx_debug_point();
    }

    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        if (cctx->pending_frames_tracks[i] != pending_frames_tracks[i]) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_lls_validate: "
                "invalid pending frames tracks (%ui) count %uD expected %uD",
                i, cctx->pending_frames_tracks[i], pending_frames_tracks[i]);
            ngx_debug_point();
        }
    }
}
#else
#define ngx_live_lls_validate(channel)
#endif


static void
ngx_live_lls_free_frame_chains(ngx_live_channel_t *channel,
    ngx_live_lls_frame_t *frame)
{
    ngx_buf_chain_t  *tail;

    tail = ngx_buf_chain_terminate(frame->data, frame->size);

    ngx_live_channel_buf_chain_free_list(channel, frame->data, tail);
}


static ngx_int_t
ngx_live_lls_track_start_part(ngx_live_track_t *track,
    ngx_live_lls_frame_t *frame)
{
    ngx_list_part_t           *last_part;
    ngx_live_frame_t          *frames;
    ngx_live_segment_t        *segment;
    ngx_live_channel_t        *channel;
    ngx_live_segment_part_t   *part;
    ngx_live_lls_track_ctx_t  *ctx;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    segment = ctx->segment;

    /* add gap parts if needed */

    while (frame->pts >= ctx->part_end_pts) {

        part = ngx_live_segment_part_push(segment);
        if (part == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_start_part: push gap failed");
            return NGX_ERROR;
        }

        part->duration = channel->part_duration;

        ctx->part_start_pts = ctx->part_end_pts;
        ctx->part_end_pts += channel->part_duration;

        track->next_part_index = segment->parts.nelts;
    }

    /* add the part */

    part = ngx_live_segment_part_push(segment);
    if (part == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_start_part: push failed");
        return NGX_ERROR;
    }

    last_part = segment->frames.last;
    frames = last_part->elts;

    part->start_dts = frame->dts;

    part->frame = &frames[last_part->nelts - 1];
    part->frame_part = last_part;
    part->frame_count = segment->frame_count;

    part->data_head = frame->data;
    part->data_size = segment->data_size;

    ctx->part_frame_created = frame->created;

    ngx_log_debug4(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_start_part: "
        "index: %ui, part: %ui, pts: %L, track: %V",
        segment->node.key, segment->parts.nelts - 1, ctx->part_start_pts,
        &track->sn.str);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_track_stop_part(ngx_live_track_t *track, ngx_flag_t is_last)
{
    int64_t                      min_end_pts;
    uint32_t                     part_index;
    ngx_live_segment_t          *segment;
    ngx_live_channel_t          *channel;
    ngx_live_segment_part_t     *part, *parts;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_pending_seg_t  *pending;
    ngx_live_lls_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    segment = ctx->segment;

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    pending = &cctx->pending.elts[track->pending_index];

    if (!pending->index_created) {
        if (ngx_live_segment_index_create(channel, segment->node.key)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_stop_part: create index failed");
            return NGX_ERROR;
        }

        pending->index_created = 1;
    }

    parts = segment->parts.elts;
    part_index = segment->parts.nelts - 1;

    part = parts + part_index;

    part->frame_count = segment->frame_count - part->frame_count;
    part->data_size = segment->data_size - part->data_size;

    if (is_last) {
        ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &track->log, 0,
            "ngx_live_lls_track_stop_part: "
            "last part, index: %ui, part: %uD, track: %V",
            segment->node.key, part_index, &track->sn.str);
        return NGX_OK;
    }

    part->duration = channel->part_duration;

    ctx->part_start_pts = ctx->part_end_pts;
    ctx->part_end_pts += channel->part_duration;

    if (!pending->end_set) {
        min_end_pts = ctx->part_start_pts + cctx->min_part_duration;
        if (cctx->min_pending_end_pts < min_end_pts) {
            cctx->min_pending_end_pts = min_end_pts;
        }
    }

    track->next_part_index = segment->parts.nelts;

    ngx_live_channel_update_latency_stats(channel, &ctx->latency,
        ctx->part_frame_created);

    ngx_live_notif_segment_publish(track, segment->node.key, part_index,
        NGX_OK);

    ngx_log_debug6(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_stop_part: index: %ui, part: %uD, pts: %L, "
        "duration: %uD, min_end: %L, track: %V",
        segment->node.key, part_index, ctx->part_start_pts, part->duration,
        cctx->min_pending_end_pts, &track->sn.str);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_pending_segment_push(ngx_live_channel_t *channel,
    ngx_live_lls_frame_t *frame, ngx_flag_t force_new_period, ngx_log_t *log)
{
    int64_t                      last_pts;
    uint32_t                     part_sequence;
    uint32_t                     pending_index;
    uint32_t                     segment_index;
    ngx_int_t                    rc;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *last, *pending;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending_index = cctx->pending.nelts;

    if (pending_index > 0) {
        last = &cctx->pending.elts[pending_index - 1];

        last_pts = last->end_pts;
        part_sequence = ngx_live_lls_pending_next_part_sequence(channel, last);

    } else {
        last_pts = cctx->last_segment_end_pts;
        part_sequence = channel->next_part_sequence;
    }

    pending = &cctx->pending.elts[pending_index];
    ngx_memzero(pending, sizeof(*pending));

    pending->created = ngx_current_msec;
    pending->part_sequence = part_sequence;

    if (frame->pts >= last_pts + cctx->start_period_threshold) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_lls_pending_segment_push: "
            "forcing new period due to pts forward jump, "
            "pts: %L, last_pts: %L", frame->pts, last_pts);

        pending->start_pts = frame->pts;
        force_new_period = 1;

    } else {
        pending->start_pts = last_pts;
    }

    pending->end_pts = pending->start_pts + channel->segment_duration;
    cctx->pending.nelts++;

    cctx->min_pending_end_pts = pending->start_pts;

    segment_index = channel->next_segment_index + pending_index;

    rc = ngx_live_timelines_add_segment(channel, pending->start_pts,
        segment_index, NGX_LIVE_PENDING_SEGMENT_DURATION, force_new_period);
    switch (rc) {

    case NGX_OK:
        pending->exists = 1;
        break;

    case NGX_DONE:
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_lls_pending_segment_push: add segment failed");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_live_lls_pending_segment_push: "
        "index: %uD, pts: %L, new_period: %i",
        segment_index, pending->start_pts, force_new_period);

    return NGX_OK;
}


static void
ngx_live_lls_pending_segment_pop(ngx_live_channel_t *channel)
{
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *pending;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending = cctx->pending.elts;

    cctx->pending.nelts--;
    ngx_memmove(pending, pending + 1,
        sizeof(pending[0]) * cctx->pending.nelts);
}


static ngx_inline ngx_flag_t
ngx_live_lls_should_start_segment(ngx_live_track_t *track,
    ngx_live_lls_frame_t *frame)
{
    int64_t                      min_end_pts;
    ngx_uint_t                   margin_percent;
    ngx_live_channel_t          *channel;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_preset_conf_t  *spcf;
    ngx_live_lls_pending_seg_t  *pending;

    if (track->media_type == KMP_MEDIA_VIDEO
        && !(frame->flags & KMP_FRAME_FLAG_KEY))
    {
        return 0;
    }

    if (frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_lls_should_start_segment: "
            "starting new segment due to split frame, id: %uL, pts: %L",
            frame->id, frame->pts);
        return 1;
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending = &cctx->pending.elts[track->pending_index];

    if (track->media_type != KMP_MEDIA_VIDEO
        && pending->started_tracks[KMP_MEDIA_VIDEO] > 0
        && !pending->end_set)
    {
        return 0;
    }

    min_end_pts = pending->end_pts;
    if (track->media_type == KMP_MEDIA_VIDEO) {
        spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

        margin_percent = pending->end_set
            ? spcf->video_duration_margin
            : spcf->video_end_segment_margin;

        min_end_pts -= (pending->end_pts - pending->start_pts)
            * margin_percent / 100;
    }

    return frame->pts >= min_end_pts;
}


static ngx_flag_t
ngx_live_lls_check_dispose_frame(ngx_live_track_t *track,
    ngx_live_lls_frame_t *frame)
{
    int64_t                      last_track_pts;
    uint32_t                     margin;
    ngx_live_channel_t          *channel;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (track->media_type == KMP_MEDIA_VIDEO
        && !(frame->flags & KMP_FRAME_FLAG_KEY))
    {
        if (!ctx->last_dropped_frames) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_check_dispose_frame: "
                "disposing non-key frame, id: %uL, pts: %L",
                frame->id, frame->pts);

        } else {
            ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &track->log, 0,
                "ngx_live_lls_check_dispose_frame: "
                "disposing non-key frame, id: %uL, pts: %L, track: %V",
                frame->id, frame->pts, &track->sn.str);
        }

        goto dispose;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    if (track->pending_index > 0) {
        last_track_pts = cctx->pending.elts[track->pending_index - 1].end_pts;

    } else {
        last_track_pts = cctx->last_segment_end_pts;
    }

    if (ctx->last_dropped_frames <= 0) {
        if (frame->pts < last_track_pts - cctx->dispose_threshold) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_check_dispose_frame: "
                "disposing frame with old pts, "
                "id: %uL, pts: %L, last_pts: %L",
                frame->id, frame->pts, last_track_pts);
            goto dispose;
        }

        return 0;
    }

    margin = track->media_type == KMP_MEDIA_VIDEO
        ? cctx->dispose_threshold : 0;

    if (frame->pts < last_track_pts - margin) {
        ngx_log_debug4(NGX_LOG_DEBUG_LIVE, &track->log, 0,
            "ngx_live_lls_check_dispose_frame: "
            "disposing frame with old pts, "
            "id: %uL, pts: %L, last_pts: %L, track: %V",
            frame->id, frame->pts, last_track_pts, &track->sn.str);
        goto dispose;
    }

    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
        "ngx_live_lls_check_dispose_frame: "
        "enabling split due to disposed frames, "
        "id: %uL, pts: %L, disposed: %uD",
        frame->id, frame->pts, ctx->last_dropped_frames);

    frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

    ngx_live_media_info_pending_remove_frames(track,
        ctx->last_dropped_frames);

    ctx->last_dropped_frames = 0;

    return 0;

dispose:

    ctx->dropped_frames++;
    ctx->last_dropped_frames++;

    ngx_live_lls_free_frame_chains(channel, frame);

    if (ctx->frames.count <= 1) {
        ctx->frames.last_data_part = NULL;
    }

    if (track->pending_index <= 0) {
        track->last_frame_pts = frame->pts;
        track->last_frame_dts = frame->dts;
        track->next_frame_id = frame->id + 1;

        if (ctx->last_dropped_frames % NGX_LIVE_LLS_DISPOSE_ACK_FREQUENCY == 0
            && channel->snapshots <= 0 && track->input.ack_frames != NULL)
        {
            track->input.ack_frames(track, track->next_frame_id);
        }
    }

    return 1;
}


static ngx_int_t
ngx_live_lls_track_start_segment(ngx_live_track_t *track,
    ngx_live_lls_frame_t *frame)
{
    uint32_t                        margin;
    uint32_t                        duration;
    uint32_t                        pending_index;
    uint32_t                        segment_index;
    ngx_int_t                       rc;
    ngx_flag_t                      track_existed;
    ngx_flag_t                      force_new_period;
    ngx_live_channel_t             *channel;
    ngx_live_segment_t             *segment;
    ngx_live_media_info_t          *media_info;
    ngx_live_lls_track_ctx_t       *ctx;
    ngx_live_lls_channel_ctx_t     *cctx;
    ngx_live_lls_pending_seg_t     *pending;
    ngx_live_lls_preset_conf_t     *spcf;
    ngx_live_track_segment_info_t   info;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    /* choose pending segment */

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    for (pending_index = track->pending_index;
        pending_index < cctx->pending.nelts;
        pending_index++)
    {
        pending = &cctx->pending.elts[pending_index];

        duration = pending->end_pts - pending->start_pts;
        margin = duration * spcf->segment_start_margin / 100;
        if (frame->pts < pending->end_pts - margin) {
            break;
        }
    }

    if (channel->next_segment_index >= NGX_LIVE_INVALID_SEGMENT_INDEX
        - pending_index)
    {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_lls_track_start_segment: "
            "invalid segment index, pending_index: %uD", pending_index);
        return NGX_ERROR;
    }

    /* add media info if needed */

    segment_index = channel->next_segment_index + pending_index;

    rc = ngx_live_media_info_pending_create_segment(track, segment_index);
    switch (rc) {

    case NGX_OK:
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_lls_track_start_segment: "
            "media info changed, forcing new period");

        force_new_period = 1;
        break;

    case NGX_DONE:
        force_new_period = 0;
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_start_segment: "
            "create media info failed");
        return NGX_ERROR;
    }

    if (pending_index >= cctx->pending.nelts) {

        if (pending_index > 0
            && !cctx->pending.elts[pending_index - 1].end_set)
        {
            if (ngx_live_lls_set_end_pts(channel, &track->log) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_lls_track_start_segment: set end pts failed");
                return NGX_ERROR;
            }
        }

        if (pending_index >= spcf->max_pending_segments) {
            if (ngx_live_lls_force_close_segment(channel) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_lls_track_start_segment: force close failed");
                return NGX_ERROR;
            }

            pending_index = cctx->pending.nelts;
        }

        /* create pending segment */

        if (frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            if (track->pending_index > 0) {
                track_existed = ctx->pending[track->pending_index - 1].bitrate;

            } else {
                track_existed = track->has_last_segment;
            }

            if (track_existed) {
                ngx_log_error(NGX_LOG_INFO, &track->log, 0,
                    "ngx_live_lls_track_start_segment: "
                    "forcing new period due to split frame");
                force_new_period = 1;
            }
        }

        if (ngx_live_lls_pending_segment_push(channel, frame,
            force_new_period, &track->log) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_start_segment: "
                "add pending segment failed");
            return NGX_ERROR;
        }
    }

    if (pending_index > track->pending_index) {

        /* add gap segments */

        ngx_memzero(ctx->pending + track->pending_index,
            sizeof(ctx->pending[0]) * (pending_index - track->pending_index));

        info.segment_index = channel->next_segment_index
            + track->pending_index;
        info.bitrate = 0;

        if (ngx_live_core_track_event(track,
            NGX_LIVE_EVENT_TRACK_SEGMENT_CREATED, &info) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_start_segment: event failed");
            return NGX_ERROR;
        }

        track->pending_index = pending_index;

        ngx_live_notif_segment_publish(track, channel->next_segment_index
            + pending_index - 1, NGX_LIVE_INVALID_PART_INDEX, NGX_OK);
    }

    /* create the segment */

    segment = ngx_live_segment_cache_create(track, segment_index);
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_start_segment: create segment failed");
        return NGX_ERROR;
    }

    media_info = ngx_live_media_info_queue_get_last(track);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_lls_track_start_segment: no media info");
        return NGX_ERROR;
    }

    ctx->sstate = ngx_live_lls_ss_started;
    ctx->segment = segment;

    pending = &cctx->pending.elts[pending_index];

    pending->total_started_tracks++;
    pending->started_tracks[track->media_type]++;

    segment->media_info = media_info;
    segment->part_sequence = pending->part_sequence;
    segment->start_dts = frame->dts;
    segment->data_head = frame->data;

    ctx->part_start_pts = pending->start_pts;
    ctx->part_end_pts = ctx->part_start_pts + channel->part_duration;

    track->has_pending_segment = 1;

    if (!track->has_last_segment) {
        ngx_live_variants_update_active(channel);
    }

    ngx_log_debug4(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_start_segment: "
        "index: %ui, pts: %L, frame_pts: %L, track: %V",
        segment->node.key, pending->start_pts, frame->pts, &track->sn.str);

    ngx_live_lls_validate(channel);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_track_stop_segment(ngx_live_track_t *track,
    ngx_live_frame_t *frame)
{
    uint32_t                           bitrate;
    ngx_live_segment_t                *segment;
    ngx_live_channel_t                *channel;
    ngx_live_lls_track_ctx_t          *ctx;
    ngx_live_lls_pending_seg_t        *pending;
    ngx_live_lls_channel_ctx_t        *cctx;
    ngx_live_lls_track_pending_seg_t  *tpending;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (ctx->sstate != ngx_live_lls_ss_started) {
        return NGX_OK;
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    segment = ctx->segment;
    segment->end_dts = ctx->last_frame_dts + frame->duration;
    segment->data_tail = ngx_buf_chain_terminate(segment->data_tail,
        frame->size);

    if (ctx->frames.count <= 0) {
        ctx->frames.last_data_part = NULL;
    }

    ctx->sstate = ngx_live_lls_ss_stopped;
    ngx_live_segment_cache_finalize(segment, &bitrate);

    pending = &cctx->pending.elts[track->pending_index];

    pending->total_started_tracks--;
    pending->started_tracks[track->media_type]--;

    tpending = &ctx->pending[track->pending_index];

    tpending->bitrate = bitrate;
    tpending->last_frame_pts = ctx->last_frame_pts;
    tpending->last_frame_dts = ctx->last_frame_dts;
    tpending->next_frame_id = ctx->next_frame_id;

    ngx_live_media_info_pending_remove_frames(track, segment->frame_count);

    ngx_log_debug6(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_stop_segment: index: %ui, parts: %ui, "
        "pts: %L, duration: %L, bitrate: %uD, track: %V",
        segment->node.key, segment->parts.nelts, pending->start_pts,
        segment->end_dts - segment->start_dts, bitrate, &track->sn.str);

    if (pending->end_set) {
        if (ngx_live_lls_track_end_segment(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_stop_segment: end segment failed");
            return NGX_ERROR;
        }
    }

    if (pending->total_started_tracks <= 0) {
        if (ngx_live_lls_close_segments(channel) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_stop_segment: close segments failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_live_lls_track_dispose_all(ngx_live_track_t *track)
{
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx->frames.count <= 0) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
        "ngx_live_lls_track_dispose_all: "
        "disposing %uD frames, next_frame_id: %uL",
        ctx->frames.count, ctx->next_frame_id);

    ctx->last_dropped_frames = ctx->frames.count;

    track->last_frame_pts = ctx->last_frame_pts;
    track->last_frame_dts = ctx->last_frame_dts;
    track->next_frame_id = ctx->next_frame_id;

    ngx_live_lls_frame_list_reset(&ctx->frames);

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_lls_module);

    ngx_rbtree_delete(&cctx->rbtree, &ctx->node);
    cctx->pending_frames_tracks[track->media_type]--;
}


static void
ngx_live_lls_channel_idle(ngx_live_channel_t *channel)
{
    /* Note: must be called when non_idle_tracks and pending.nelts are zero */

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_lls_channel_idle: called");

    channel->active = 0;

    (void) ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_INACTIVE, NULL);
}


static void
ngx_live_lls_track_idle(ngx_live_track_t *track)
{
    ngx_live_channel_t          *channel;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_idle: track: %V", &track->sn.str);

    ctx->fstate = ngx_live_lls_fs_idle;

    (void) ngx_live_core_track_event(track,
        NGX_LIVE_EVENT_TRACK_INACTIVE, NULL);

    cctx->non_idle_tracks--;
    if (cctx->non_idle_tracks <= 0 && cctx->pending.nelts <= 0) {
        ngx_live_lls_channel_idle(channel);
    }
}


static ngx_int_t
ngx_live_lls_track_flush_segment(ngx_live_track_t *track)
{
    ngx_list_part_t           *last;
    ngx_live_frame_t          *frames, *frame;
    ngx_live_segment_t        *segment;
    ngx_live_lls_track_ctx_t  *ctx;

    /* Note: must be called when fstate = inactive and no pending frames */

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (ctx->frames.count > 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_lls_track_flush_segment: flush when frames are pending");
        return NGX_ERROR;
    }

    if (ctx->sstate != ngx_live_lls_ss_started) {
        goto done;
    }

    segment = ctx->segment;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_lls_track_flush_segment: index: %ui, parts: %ui",
        segment->node.key, segment->parts.nelts);

    /* update last frame duration */

    last = segment->frames.last;
    frames = last->elts;

    frame = &frames[last->nelts - 1];

    if (segment->frame_count > 1
        && ctx->last_frame_dts > segment->start_dts)
    {
        frame->duration = (ctx->last_frame_dts - segment->start_dts)
            / (segment->frame_count - 1);

    } else {
        frame->duration = 1;
    }

    /* stop the part and segment */

    if (ngx_live_lls_track_stop_part(track, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_flush_segment: stop part failed");
        return NGX_ERROR;
    }

    if (ngx_live_lls_track_stop_segment(track, frame) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_flush_segment: stop segment failed");
        return NGX_ERROR;
    }

done:

    if (ctx->fstate == ngx_live_lls_fs_inactive) {
        ngx_live_lls_track_idle(track);
    }

    ngx_live_lls_validate(track->channel);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_set_end_pts(ngx_live_channel_t *channel, ngx_log_t *log)
{
    int64_t                      pts, cur_pts;
    uint32_t                     duration;
    uint32_t                     pending_index;
    uint32_t                     segment_index;
    ngx_queue_t                 *q;
    ngx_list_part_t             *last;
    ngx_live_track_t            *cur_track;
    ngx_live_frame_t            *frames, *seg_frame;
    ngx_live_segment_t          *segment;
    ngx_live_lls_track_ctx_t    *cur_ctx;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *pending;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending_index = cctx->pending.nelts - 1;
    pending = &cctx->pending.elts[pending_index];

    if (pending->end_set) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_lls_set_end_pts: end pts already set");
        return NGX_ERROR;
    }

    pts = cctx->min_pending_end_pts;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track->pending_index != pending_index) {
            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_lls_module);

        switch (cur_ctx->sstate) {

        case ngx_live_lls_ss_started:
            cur_pts = cur_ctx->last_frame_pts;
            break;

        case ngx_live_lls_ss_stopped:
            segment = cur_ctx->segment;
            last = segment->frames.last;

            frames = last->elts;
            seg_frame = &frames[last->nelts - 1];

            cur_pts = cur_ctx->last_frame_pts + seg_frame->duration;
            break;

        default:    /* ngx_live_lls_ss_idle */
            continue;
        }

        if (cur_pts > cur_ctx->part_end_pts) {
            cur_pts = cur_ctx->part_end_pts;
        }

        if (pts < cur_pts) {
            pts = cur_pts;
        }
    }

    pending->end_pts = pts;
    pending->end_set = 1;

    duration = pending->end_pts - pending->start_pts;
    segment_index = channel->next_segment_index + pending_index;

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_live_lls_set_end_pts: index: %uD, pts: %L, duration: %uD",
        segment_index, pending->start_pts, duration);

    if (ngx_live_timelines_update_last_segment(channel, duration) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_lls_set_end_pts: update last segment failed");
        return NGX_ERROR;
    }

    if (ngx_live_segment_index_create_snap(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_lls_set_end_pts: create snap failed");
        return NGX_ERROR;
    }

    if (ngx_live_lls_end_segments(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_lls_set_end_pts: end segments failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_track_end_segment(ngx_live_track_t *track)
{
    ngx_live_channel_t             *channel;
    ngx_live_segment_t             *segment;
    ngx_live_segment_part_t        *parts, *part;
    ngx_live_lls_track_ctx_t       *ctx;
    ngx_live_lls_channel_ctx_t     *cctx;
    ngx_live_lls_pending_seg_t     *pending;
    ngx_live_track_segment_info_t   info;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (ctx->sstate != ngx_live_lls_ss_stopped) {
        return NGX_OK;
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending = &cctx->pending.elts[track->pending_index];

    segment = ctx->segment;
    parts = segment->parts.elts;
    part = &parts[segment->parts.nelts - 1];

    part->duration = pending->end_pts - ctx->part_start_pts;
    if (part->duration > channel->part_duration) {
        part->duration = channel->part_duration;
    }
    ctx->part_start_pts += part->duration;

    ngx_live_channel_update_latency_stats(channel, &ctx->latency,
        ctx->part_frame_created);

    /* add gap parts */

    while (ctx->part_start_pts < pending->end_pts) {

        part = ngx_live_segment_part_push(segment);
        if (part == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_track_end_segment: push part failed");
            return NGX_ERROR;
        }

        part->duration = pending->end_pts - ctx->part_start_pts;
        if (part->duration > channel->part_duration) {
            part->duration = channel->part_duration;
        }

        ctx->part_start_pts += part->duration;
    }

    info.segment_index = segment->node.key;
    info.bitrate = ctx->pending[track->pending_index].bitrate;

    if (ngx_live_core_track_event(track, NGX_LIVE_EVENT_TRACK_SEGMENT_CREATED,
        &info) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_end_segment: segment created event failed");
        return NGX_ERROR;
    }

    ctx->sstate = ngx_live_lls_ss_idle;
    ctx->segment = NULL;

    track->pending_index++;
    track->next_part_index = 0;
    track->has_pending_segment = 0;

    ngx_log_debug5(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_track_end_segment: "
        "index: %ui, parts: %ui, pts: %L, duration: %L, track: %V",
        segment->node.key, segment->parts.nelts, pending->start_pts,
        pending->end_pts - pending->start_pts, &track->sn.str);

    ngx_live_notif_segment_publish(track, segment->node.key,
        NGX_LIVE_INVALID_PART_INDEX, NGX_OK);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_end_segments(ngx_live_channel_t *channel)
{
    ngx_queue_t       *q;
    ngx_live_track_t  *cur_track;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (ngx_live_lls_track_end_segment(cur_track) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_live_lls_track_close_segment(ngx_live_track_t *track)
{
    uint32_t                           bitrate;
    ngx_live_channel_t                *channel;
    ngx_live_lls_track_ctx_t          *ctx;
    ngx_live_lls_track_pending_seg_t  *pending;

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (track->pending_index > 0) {
        pending = &ctx->pending[0];
        bitrate = pending->bitrate;

        track->last_frame_pts = pending->last_frame_pts;
        track->last_frame_dts = pending->last_frame_dts;
        track->next_frame_id = pending->next_frame_id;

        track->pending_index--;
        ngx_memmove(pending, pending + 1, sizeof(pending[0])
            * (track->pending_index + track->has_pending_segment));

    } else {
        bitrate = 0;

        ngx_live_notif_segment_publish(track, channel->next_segment_index,
            NGX_LIVE_INVALID_PART_INDEX, NGX_OK);
    }

    track->last_segment_bitrate = bitrate;

    if (!bitrate) {

        if (!track->has_last_segment) {
            return;
        }

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_lls_track_close_segment: track removed");

        track->has_last_segment = 0;

    } else {

        if (track->has_last_segment) {
            return;
        }

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_lls_track_close_segment: track added");

        track->has_last_segment = 1;
    }

    channel->last_modified = ngx_time();
}


static ngx_int_t
ngx_live_lls_close_segment(ngx_live_channel_t *channel)
{
    uint32_t                     track_count;
    uint32_t                     media_types_mask;
    ngx_int_t                    rc;
    ngx_queue_t                 *q;
    ngx_live_track_t            *cur_track;
    ngx_live_lls_pending_seg_t  *pending;
    ngx_live_lls_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    pending = &cctx->pending.elts[0];

    if (!pending->end_set) {
        if (ngx_live_lls_set_end_pts(channel, &channel->log) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_lls_close_segment: set end pts failed");
            return NGX_ERROR;
        }
    }

    track_count = 0;
    media_types_mask = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->type == ngx_live_track_type_filler) {
            continue;
        }

        ngx_live_lls_track_close_segment(cur_track);

        if (cur_track->has_last_segment) {
            track_count++;
            media_types_mask |= 1 << cur_track->media_type;
        }
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_lls_close_segment: "
        "pts: %L, duration: %L, track_count: %uD, media_types: 0x%uxD",
        pending->start_pts, pending->end_pts - pending->start_pts,
        track_count, media_types_mask);

    channel->last_segment_media_types = media_types_mask;
    channel->next_part_sequence = ngx_live_lls_pending_next_part_sequence(
        channel, pending);

    rc = ngx_live_segment_index_ready(channel, pending->exists);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_lls_close_segment: add segment failed");
        return NGX_ERROR;
    }

    channel->next_segment_index++;
    channel->last_segment_created = ngx_time();

    cctx->last_segment_end_pts = pending->end_pts;

    ngx_live_lls_pending_segment_pop(channel);

    ngx_live_variants_update_active(channel);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_close_segments(ngx_live_channel_t *channel)
{
    ngx_msec_t                   timer;
    ngx_live_lls_pending_seg_t  *pending;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    if (cctx->pending.nelts <= 0) {
        return NGX_OK;
    }

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    for ( ;; ) {

        pending = &cctx->pending.elts[0];
        if (pending->total_started_tracks > 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
                "ngx_live_lls_close_segments: started_tracks: %uD",
                pending->total_started_tracks);
            break;
        }

        if (ngx_current_msec < pending->created + spcf->close_segment_delay) {
            timer = pending->created + spcf->close_segment_delay
                - ngx_current_msec;

            ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
                "ngx_live_lls_close_segments: delaying segment, "
                "msec: %M, current: %M, wait: %M",
                pending->created, ngx_current_msec, timer);

            ngx_add_timer(&cctx->close, timer);
            break;
        }

        if (ngx_live_lls_close_segment(channel) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cctx->pending.nelts > 0) {
            continue;
        }

        if (cctx->non_idle_tracks <= 0) {
            ngx_live_lls_channel_idle(channel);
        }

        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_process_frame(ngx_live_track_t *track,
    ngx_live_lls_frame_t *frame, ngx_uint_t flags)
{
    ngx_flag_t                   start_part;
    ngx_flag_t                   start_segment;
    ngx_list_part_t             *last;
    ngx_live_frame_t            *frames, *seg_frame;
    ngx_live_channel_t          *channel;
    ngx_live_segment_t          *segment;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *pending;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    ngx_log_debug8(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_process_frame: id: %uL, created: %M, size: %uD, "
        "dts: %L, flags: 0x%uxD, ptsDelay: %D, data: %p, track: %V",
        frame->id, frame->created, frame->size, frame->dts, frame->flags,
        (int32_t) (frame->pts - frame->dts), frame->data, &track->sn.str);

    if (ctx->sstate == ngx_live_lls_ss_started) {

        /* update last frame duration */

        segment = ctx->segment;
        last = segment->frames.last;

        frames = last->elts;
        seg_frame = &frames[last->nelts - 1];

        if (!(frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT)) {
            seg_frame->duration = frame->dts - ctx->last_frame_dts;

        } else if (segment->frame_count > 1
            && ctx->last_frame_dts > segment->start_dts)
        {
            seg_frame->duration = (ctx->last_frame_dts - segment->start_dts)
                / (segment->frame_count - 1);

        } else {
            seg_frame->duration = 1;
        }

        /* decide whether to start a new segment / part */

        start_segment = ngx_live_lls_should_start_segment(track, frame);

        if (start_segment) {
            start_part = 1;

        } else if (frame->pts >= ctx->part_end_pts) {
            channel = track->channel;
            cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

            pending = &cctx->pending.elts[track->pending_index];
            if (!pending->end_set || ctx->part_end_pts < pending->end_pts) {
                start_part = 1;

            } else {
                ngx_log_debug4(NGX_LOG_DEBUG_LIVE, &track->log, 0,
                    "ngx_live_lls_process_frame: postponing part start, "
                    "frame_pts: %L, part_end_pts: %L, segment_end_pts: %L, "
                    "track: %V",
                    frame->pts, ctx->part_end_pts, pending->end_pts,
                    &track->sn.str);

                start_part = 0;
            }

        } else {
            start_part = 0;
        }

        /* stop part / segment if needed */

        if (start_part) {
            if (ngx_live_lls_track_stop_part(track, start_segment) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_lls_process_frame: stop part failed");
                return NGX_ERROR;
            }

            if (start_segment || (flags & NGX_LIVE_LLS_FLAG_FLUSH_PART)) {
                if (ngx_live_lls_track_stop_segment(track, seg_frame)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_live_lls_process_frame: stop segment failed");
                    return NGX_ERROR;
                }

                ngx_live_lls_validate(track->channel);

                if (flags & NGX_LIVE_LLS_FLAG_FLUSH_ANY) {
                    return NGX_DONE;
                }
            }
        }

    } else {

        if (flags & NGX_LIVE_LLS_FLAG_FLUSH_ANY) {
            return NGX_DONE;
        }

        start_part = 1;

        segment = NULL;     /* suppress warning */
    }

    switch (ctx->sstate) {

    case ngx_live_lls_ss_stopped:

        /* end the segment */

        channel = track->channel;
        if (ngx_live_lls_set_end_pts(channel, &track->log) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_process_frame: set end pts failed");
            return NGX_ERROR;
        }

        ngx_live_lls_validate(channel);

        if (ctx->sstate != ngx_live_lls_ss_idle) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_lls_process_frame: segment did not end");
            return NGX_ERROR;
        }

        /* fall through */

    case ngx_live_lls_ss_idle:

        /* start segment */

        if (ngx_live_lls_check_dispose_frame(track, frame)) {
            return NGX_OK;
        }

        if (ngx_live_lls_track_start_segment(track, frame) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_process_frame: start segment failed");
            return NGX_ERROR;
        }

        segment = ctx->segment;
    }

    /* push the frame */

    seg_frame = ngx_list_push(&segment->frames);
    if (seg_frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_process_frame: push failed");
        return NGX_ERROR;
    }

    seg_frame->size = frame->size;
    seg_frame->key_frame = (frame->flags & KMP_FRAME_FLAG_KEY) ? 1 : 0;
    seg_frame->pts_delay = frame->pts - frame->dts;

    /* Note: duration is set when the next frame arrives */

    if (start_part) {
        if (ngx_live_lls_track_start_part(track, frame) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_process_frame: start part failed");
            return NGX_ERROR;
        }
    }

    segment->frame_count++;

    segment->data_size += frame->size;
    segment->data_tail = frame->data;

    ctx->last_frame_pts = frame->pts;
    ctx->last_frame_dts = frame->dts;
    ctx->next_frame_id = frame->id + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_process(ngx_live_channel_t *channel)
{
    ngx_msec_t                   timer;
    ngx_live_track_t            *track;
    ngx_rbtree_node_t           *root, *sentinel, *node;
    ngx_live_lls_frame_t        *frame;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_preset_conf_t  *spcf;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    sentinel = &cctx->sentinel;

    for ( ;; ) {

        root = cctx->rbtree.root;
        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);

        ctx = (void *) node;
        track = ctx->track;

        frame = ngx_live_lls_frame_list_head(&ctx->frames);

        if (ngx_current_msec < frame->added + spcf->frame_process_delay) {

            timer = frame->added + spcf->frame_process_delay
                - ngx_current_msec;

            ngx_log_debug5(NGX_LOG_DEBUG_LIVE, &track->log, 0,
                "ngx_live_lls_process: delaying frame, "
                "id: %uL, msec: %M, current: %M, wait: %M, track: %V",
                frame->id, frame->created, ngx_current_msec, timer,
                &track->sn.str);

            ngx_add_timer(&cctx->process, timer);
            break;
        }

        if (track->media_type == KMP_MEDIA_AUDIO
            && cctx->pending_frames_tracks[KMP_MEDIA_VIDEO] <= 0
            && ngx_current_msec < frame->added + spcf->wait_video_timeout)
        {
            timer = frame->added + spcf->wait_video_timeout
                - ngx_current_msec;

            ngx_log_debug5(NGX_LOG_DEBUG_LIVE, &track->log, 0,
                "ngx_live_lls_process: waiting for video, "
                "id: %uL, msec: %M, current: %M, wait: %M, track: %V",
                frame->id, frame->created, ngx_current_msec, timer,
                &track->sn.str);

            ngx_add_timer(&cctx->process, timer);
            break;
        }

        if (ngx_live_lls_process_frame(track, frame, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_rbtree_delete(&cctx->rbtree, node);

        ngx_live_lls_frame_list_pop(&ctx->frames);

        if (ctx->frames.count <= 0) {
            cctx->pending_frames_tracks[track->media_type]--;

            if (ctx->fstate == ngx_live_lls_fs_inactive) {
                if (ngx_live_lls_track_flush_segment(track) != NGX_OK) {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_live_lls_process: flush segment failed");
                    return NGX_ERROR;
                }
            }

            continue;
        }

        frame = ngx_live_lls_frame_list_head(&ctx->frames);

        node->key = frame->pts;
        if (track->media_type == KMP_MEDIA_AUDIO) {
            node->key += cctx->audio_process_delay;
        }

        ngx_rbtree_insert(&cctx->rbtree, node);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_track_flush_frames(ngx_live_track_t *track, ngx_uint_t flags)
{
    ngx_int_t                    rc;
    ngx_live_lls_frame_t        *frame;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx->frames.count <= 0) {
        return NGX_OK;
    }

    do {
        frame = ngx_live_lls_frame_list_head(&ctx->frames);

        rc = ngx_live_lls_process_frame(track, frame, flags);
        if (rc != NGX_OK) {     /* incl NGX_DONE */
            return rc;
        }

        ngx_live_lls_frame_list_pop(&ctx->frames);

    } while (ctx->frames.count > 0);

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_lls_module);

    ngx_rbtree_delete(&cctx->rbtree, &ctx->node);
    cctx->pending_frames_tracks[track->media_type]--;

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_flush_segment(ngx_live_channel_t *channel, uint32_t pending_index)
{
    ngx_int_t          rc;
    ngx_queue_t       *q;
    ngx_live_track_t  *cur_track;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->pending_index != pending_index) {
            continue;
        }

        rc = ngx_live_lls_track_flush_frames(cur_track,
            NGX_LIVE_LLS_FLAG_FLUSH_SEGMENT);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            continue;

        default:
            return rc;
        }

        if (ngx_live_lls_track_flush_segment(cur_track) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_force_close_segment(ngx_live_channel_t *channel)
{
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_lls_force_close_segment: forcing close, started_tracks: %uD",
        cctx->pending.elts[0].total_started_tracks);

    if (cctx->pending.elts[0].total_started_tracks > 0) {
        if (ngx_live_lls_flush_segment(channel, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_lls_force_close_segment: flush segment failed");
            return NGX_ERROR;
        }

        spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

        if (cctx->pending.nelts < spcf->max_pending_segments) {
            return NGX_OK;
        }

        if (cctx->pending.elts[0].total_started_tracks > 0) {
            ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                "ngx_live_lls_force_close_segment: "
                "nonzero started tracks after flush");
            return NGX_ERROR;
        }
    }

    if (ngx_live_lls_close_segment(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_lls_force_close_segment: close failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_add_media_info(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    ngx_int_t                  rc;
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    rc = ngx_live_media_info_pending_add(track, media_info, extra_data,
        extra_data_size, ctx->frames.count);
    switch (rc) {

    case NGX_OK:

        /* force a split on the next frame to arrive */

        ctx->next_flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
        break;

    case NGX_DONE:
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_add_media_info: add failed");
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_add_frame(ngx_live_add_frame_req_t *req)
{
    int64_t                      last_pts;
    ngx_flag_t                   is_first;
    kmp_frame_t                 *kmp_frame;
    ngx_live_track_t            *track;
    ngx_rbtree_node_t           *node;
    ngx_live_channel_t          *channel;
    ngx_live_lls_frame_t        *frame;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_preset_conf_t  *spcf;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *pending;

    track = req->track;
    channel = track->channel;
    kmp_frame = req->frame;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    ngx_log_debug8(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_lls_add_frame: id: %uL, created: %L, size: %uz, "
        "dts: %L, flags: 0x%uxD, head: %p, tail: %p, track: %V",
        req->frame_id, kmp_frame->created, req->size, kmp_frame->dts,
        kmp_frame->flags, req->data_head, req->data_tail, &track->sn.str);

    if (kmp_frame->dts >= LLONG_MAX - kmp_frame->pts_delay
        && kmp_frame->pts_delay >= 0)
    {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_lls_add_frame: invalid dts %L", kmp_frame->dts);
        return NGX_ERROR;
    }

    if (ctx->frames.count >= NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_lls_add_frame: pending frame count exceeds limit");
        return NGX_ERROR;
    }

    if (kmp_frame->flags & KMP_FRAME_FLAG_KEY) {
        ctx->received_key_frames++;
    }

    ctx->received_frames++;
    ctx->received_bytes += req->size;
    ctx->last_created = kmp_frame->created;

    is_first = ctx->frames.count <= 0;

    frame = ngx_live_lls_frame_list_push(&ctx->frames, req->data_head,
        req->data_tail);
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_add_frame: push frame failed");
        return NGX_ABORT;
    }

    frame->created = kmp_frame->created;
    frame->added = ngx_current_msec;
    frame->id = req->frame_id;
    frame->dts = kmp_frame->dts;
    frame->pts = kmp_frame->dts + kmp_frame->pts_delay;
    frame->flags = kmp_frame->flags;
    frame->size = req->size;

    if (track->media_type != KMP_MEDIA_VIDEO
        || (frame->flags & KMP_FRAME_FLAG_KEY))
    {
        if (ctx->next_flags) {
            ngx_log_error(NGX_LOG_INFO, &track->log, 0,
                "ngx_live_lls_add_frame: "
                "enabling split on current frame, id: %uL, pts: %L",
                frame->id, frame->pts);

            frame->flags |= ctx->next_flags;
            ctx->next_flags = 0;
        }

        if (!is_first || ctx->sstate == ngx_live_lls_ss_started) {

            last_pts = ctx->last_added_pts;

            if (frame->pts < last_pts - cctx->backward_jump_threshold) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_lls_add_frame: "
                    "enabling split due to pts backward jump, "
                    "id: %uL, pts: %L, last_pts: %L, delta: %L",
                    frame->id, frame->pts, last_pts, last_pts - frame->pts);

                frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

            } else if (frame->pts > last_pts + cctx->forward_jump_threshold) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_lls_add_frame: "
                    "enabling split due to pts forward jump, "
                    "id: %uL, pts: %L, last_pts: %L, delta: %L",
                    frame->id, frame->pts, last_pts, frame->pts - last_pts);

                frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
            }
        }
    }

    if ((frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT)
        && cctx->pending.nelts > 0)
    {
        pending = &cctx->pending.elts[cctx->pending.nelts - 1];

        if (!pending->end_set
            && ctx->last_added_pts >= cctx->min_pending_end_pts
            && ctx->last_added_pts < pending->end_pts)
        {
            ngx_log_error(NGX_LOG_INFO, &track->log, 0,
                "ngx_live_lls_add_frame: "
                "updating end target from %L to %L due to split",
                pending->end_pts, ctx->last_added_pts);

            pending->end_pts = ctx->last_added_pts;
        }

        /* TODO: save last_added_pts and use it as hint also when it's ahead
            of the currently pending segment */
    }

    ctx->last_added_pts = frame->pts;
    ctx->last_data_ptr = req->data_tail->data;

    if (ctx->fstate == ngx_live_lls_fs_idle) {
        cctx->non_idle_tracks++;
    }
    ctx->fstate = ngx_live_lls_fs_active;

    channel->active = 1;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    ngx_add_timer(&ctx->inactive, spcf->inactive_timeout);

    if (!is_first) {
        return NGX_OK;
    }

    node = &ctx->node;

    node->key = frame->pts;
    if (track->media_type == KMP_MEDIA_AUDIO) {
        node->key += cctx->audio_process_delay;
    }

    ngx_rbtree_insert(&cctx->rbtree, node);
    cctx->pending_frames_tracks[track->media_type]++;

    if (ngx_live_lls_process(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_add_frame: process failed");
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_start_stream(ngx_live_stream_stream_req_t *req)
{
    uint64_t                     next_frame_id;
    uint64_t                     initial_frame_id;
    ngx_int_t                    rc;
    ngx_live_track_t            *track;
    ngx_live_lls_frame_t        *frame;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_preset_conf_t  *spcf;

    track = req->track;
    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_lls_start_stream: flags: 0x%uxD, pending_frames: %ui",
        req->header->flags, ctx->frames.count);

    if (!(req->header->flags & KMP_CONNECT_FLAG_CONSISTENT)) {

        rc = ngx_live_lls_track_flush_frames(track,
            NGX_LIVE_LLS_FLAG_FLUSH_PART);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            ngx_live_lls_track_dispose_all(track);

            (void) ngx_live_core_track_event(track,
                NGX_LIVE_EVENT_TRACK_RECONNECT, NULL);
            break;

        default:
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_start_stream: flush frames failed");
            return rc;
        }

        if (ngx_live_lls_track_flush_segment(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_lls_start_stream: flush segment failed");
            return NGX_ERROR;
        }
    }

    if (ctx->frames.count > 0) {
        frame = ngx_live_lls_frame_list_last(&ctx->frames);

        next_frame_id = frame->id + 1;

    } else {
        next_frame_id = ctx->next_frame_id;
    }

    initial_frame_id = req->header->initial_frame_id;
    if (next_frame_id > initial_frame_id) {
        spcf = ngx_live_get_module_preset_conf(track->channel,
            ngx_live_lls_module);

        req->skip_count = next_frame_id - initial_frame_id;
        if (req->skip_count > spcf->max_skip_frames) {
            ngx_log_error(NGX_LOG_WARN, &track->log, 0,
                "ngx_live_lls_start_stream: "
                "skip count exceeds limit, cur: %uL, next: %uL",
                initial_frame_id, next_frame_id);

            req->skip_count = 0;
        }
    }

    if ((req->header->flags & KMP_CONNECT_FLAG_CONSISTENT)
        && initial_frame_id + req->skip_count == next_frame_id
        && (ctx->frames.count > 0 || ctx->sstate == ngx_live_lls_ss_started))
    {
        req->skip_wait_key = 1;
    }

    return NGX_OK;
}


static void
ngx_live_lls_end_stream(ngx_live_track_t *track)
{
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (ctx->fstate != ngx_live_lls_fs_active) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_lls_end_stream: "
        "end of stream, pending_frames: %ui", ctx->frames.count);

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    ctx->fstate = ngx_live_lls_fs_inactive;

    if (ctx->frames.count > 0) {
        return;
    }

    if (ngx_live_lls_track_flush_segment(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_end_stream: flush segment failed");
        ngx_live_channel_free(track->channel,
            ngx_live_free_flush_segment_failed);
    }
}


static void
ngx_live_lls_inactive_handler(ngx_event_t *ev)
{
    ngx_live_track_t          *track = ev->data;
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    if (ctx->fstate != ngx_live_lls_fs_active) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_lls_inactive_handler: "
        "track inactive, pending_frames: %ui", ctx->frames.count);

    ctx->fstate = ngx_live_lls_fs_inactive;

    if (ctx->frames.count > 0) {
        return;
    }

    if (ngx_live_lls_track_flush_segment(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_inactive_handler: flush segment failed");
        ngx_live_channel_free(track->channel,
            ngx_live_free_flush_segment_failed);
    }
}


static void
ngx_live_lls_get_min_used(ngx_live_track_t *track, uint32_t *segment_index,
    u_char **ptr)
{
    ngx_live_lls_frame_t      *frame;
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);

    /* ctx->segment must be null if this func is called */

    *segment_index = track->channel->next_segment_index + track->pending_index;

    if (ctx->frames.count > 0) {
        frame = ngx_live_lls_frame_list_head(&ctx->frames);
        *ptr = frame->data->data;

    } else {
        *ptr = ctx->last_data_ptr;
    }
}


static void
ngx_live_lls_process_handler(ngx_event_t *ev)
{
    ngx_live_channel_t  *channel = ev->data;

    if (ngx_live_lls_process(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_lls_process_handler: process failed");
        ngx_live_channel_free(channel, ngx_live_free_process_frame_failed);
    }
}


static void
ngx_live_lls_close_handler(ngx_event_t *ev)
{
    ngx_live_channel_t  *channel = ev->data;

    if (ngx_live_lls_close_segments(channel) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_lls_close_handler: close failed");
        ngx_live_channel_free(channel, ngx_live_free_close_segment_failed);
        return;
    }

    ngx_live_lls_validate(channel);
}


static ngx_int_t
ngx_live_lls_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_channel_t          *channel;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_preset_conf_t  *spcf;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    channel = track->channel;
    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    ctx->fstate = ngx_live_lls_fs_idle;
    ctx->track = track;

    if (ngx_live_lls_frame_list_init(&ctx->frames, track,
        channel->block_pool, spcf->bp_idx[NGX_LIVE_BP_PENDING_FRAME_PART])
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_lls_track_init: init frame list failed");
        return NGX_ERROR;
    }

    ctx->inactive.handler = ngx_live_lls_inactive_handler;
    ctx->inactive.data = track;
    ctx->inactive.log = &track->log;

    return NGX_OK;
}

static ngx_int_t
ngx_live_lls_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_channel_t          *channel;
    ngx_live_lls_track_ctx_t    *ctx;
    ngx_live_lls_channel_ctx_t  *cctx;
    ngx_live_lls_pending_seg_t  *pending;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx == NULL || ctx->inactive.data == NULL) {
        /* module not enabled / init wasn't called */
        return NGX_OK;
    }

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);

    if (ctx->frames.count > 0) {
        ngx_rbtree_delete(&cctx->rbtree, &ctx->node);
        cctx->pending_frames_tracks[track->media_type]--;
    }

    if (ctx->sstate == ngx_live_lls_ss_started) {
        pending = &cctx->pending.elts[track->pending_index];

        pending->total_started_tracks--;
        pending->started_tracks[track->media_type]--;

        if (pending->total_started_tracks <= 0) {
            ngx_add_timer(&cctx->close, 1);
        }
    }

    if (ctx->fstate != ngx_live_lls_fs_idle) {
        cctx->non_idle_tracks--;
        if (cctx->non_idle_tracks <= 0 && cctx->pending.nelts <= 0) {
            ngx_live_lls_channel_idle(channel);
        }
    }

    ngx_live_lls_frame_list_free(&ctx->frames);

    return NGX_OK;
}

static ngx_int_t
ngx_live_lls_track_channel_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_channel_duration_changed(ngx_live_channel_t *channel,
    void *ectx)
{
    ngx_live_lls_channel_ctx_t   *cctx;
    ngx_live_core_preset_conf_t  *cpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    if (channel->conf.segment_duration < cpcf->part_duration) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_lls_channel_duration_changed: "
            "segment duration %M smaller than configured part duration %M",
            channel->conf.segment_duration, cpcf->part_duration);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_lls_channel_duration_changed: set to %M",
        channel->conf.segment_duration);

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    size_t                        size;
    ngx_live_lls_preset_conf_t   *spcf;
    ngx_live_lls_channel_ctx_t   *cctx;
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);
    if (cpcf->segmenter.id != NGX_LIVE_LLS_ID) {
        return NGX_OK;
    }

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_lls_module);

    size = sizeof(ngx_live_lls_channel_ctx_t)
        + sizeof(ngx_live_lls_pending_seg_t)
        * (spcf->max_pending_segments - 1);
    cctx = ngx_pcalloc(channel->pool, size);
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_lls_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_lls_module);

    if (ngx_live_lls_channel_duration_changed(channel, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel,
        ngx_rbtree_insert_value);

    cctx->process.data = channel;
    cctx->process.handler = ngx_live_lls_process_handler;
    cctx->process.log = &channel->log;

    cctx->close.data = channel;
    cctx->close.handler = ngx_live_lls_close_handler;
    cctx->close.log = &channel->log;

    cctx->min_part_duration = ngx_live_rescale_time(
        spcf->min_part_duration, 1000, channel->timescale);
    cctx->forward_jump_threshold = ngx_live_rescale_time(
        spcf->forward_jump_threshold, 1000, channel->timescale);
    cctx->backward_jump_threshold = ngx_live_rescale_time(
        spcf->backward_jump_threshold, 1000, channel->timescale);
    cctx->dispose_threshold = ngx_live_rescale_time(
        spcf->dispose_threshold, 1000, channel->timescale);
    cctx->start_period_threshold = ngx_live_rescale_time(
        spcf->start_period_threshold, 1000, channel->timescale);
    cctx->audio_process_delay = ngx_live_rescale_time(
        spcf->audio_process_delay, 1000, channel->timescale);

    return NGX_OK;
}

static ngx_int_t
ngx_live_lls_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_lls_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    if (cctx->process.timer_set) {
        ngx_del_timer(&cctx->process);
    }

    if (cctx->close.timer_set) {
        ngx_del_timer(&cctx->close);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_lls_channel_read(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                 *q;
    ngx_live_track_t            *cur_track;
    ngx_live_lls_track_ctx_t    *cur_ctx;
    ngx_live_lls_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_lls_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    if (ngx_live_lls_channel_duration_changed(channel, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    cctx->last_segment_end_pts = ngx_live_timelines_get_last_time(channel);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track, ngx_live_lls_module);

        cur_ctx->last_frame_pts = cur_track->last_frame_pts;
        cur_ctx->last_frame_dts = cur_track->last_frame_dts;
        cur_ctx->next_frame_id = cur_track->next_frame_id;
    }

    return NGX_OK;
}


static size_t
ngx_live_lls_track_json_get_size(void *obj)
{
    ngx_live_track_t          *track = obj;
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx == NULL) {
        return 0;
    }

    return sizeof("\"pending_segments\":") - 1 + NGX_INT32_LEN
        + sizeof(",\"pending_frames\":") - 1 + NGX_INT32_LEN
        + sizeof(",\"last_created\":") - 1 + NGX_INT64_LEN
        + sizeof(",\"received_bytes\":") - 1 + NGX_OFF_T_LEN
        + sizeof(",\"received_frames\":") - 1 + NGX_INT_T_LEN
        + sizeof(",\"received_key_frames\":") - 1 + NGX_INT_T_LEN
        + sizeof(",\"dropped_frames\":") - 1 + NGX_INT_T_LEN
        + sizeof(",\"latency\":") - 1
        + ngx_live_latency_stats_get_size(&ctx->latency);
}

static u_char *
ngx_live_lls_track_json_write(u_char *p, void *obj)
{
    uint32_t                   pending_segments;
    ngx_live_track_t          *track = obj;
    ngx_live_lls_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_lls_module);
    if (ctx == NULL) {
        return p;
    }

    pending_segments = track->pending_index + track->has_pending_segment;
    p = ngx_copy_fix(p, "\"pending_segments\":");
    p = ngx_sprintf(p, "%uD", pending_segments);

    p = ngx_copy_fix(p, ",\"pending_frames\":");
    p = ngx_sprintf(p, "%uD", ctx->frames.count);

    p = ngx_copy_fix(p, ",\"last_created\":");
    p = ngx_sprintf(p, "%L", ctx->last_created);

    p = ngx_copy_fix(p, ",\"received_bytes\":");
    p = ngx_sprintf(p, "%O", ctx->received_bytes);

    p = ngx_copy_fix(p, ",\"received_frames\":");
    p = ngx_sprintf(p, "%ui", ctx->received_frames);

    if (track->media_type == KMP_MEDIA_VIDEO) {
        p = ngx_copy_fix(p, ",\"received_key_frames\":");
        p = ngx_sprintf(p, "%ui", ctx->received_key_frames);
    }

    p = ngx_copy_fix(p, ",\"dropped_frames\":");
    p = ngx_sprintf(p, "%ui", ctx->dropped_frames);

    p = ngx_copy_fix(p, ",\"latency\":");
    p = ngx_live_latency_stats_write(p, &ctx->latency);

    return p;
}


static ngx_live_channel_event_t    ngx_live_lls_channel_events[] = {
    { ngx_live_lls_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_lls_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_lls_channel_read, NGX_LIVE_EVENT_CHANNEL_READ },
    { ngx_live_lls_channel_duration_changed,
        NGX_LIVE_EVENT_CHANNEL_DURATION_CHANGED },

      ngx_live_null_event
};

static ngx_live_track_event_t      ngx_live_lls_track_events[] = {
    { ngx_live_lls_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_lls_track_free, NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_lls_track_channel_free, NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_lls_json_writers[] = {
    { { ngx_live_lls_track_json_get_size,
        ngx_live_lls_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_live_segmenter_t  ngx_live_lls_ll = {
    NGX_LIVE_LLS_ID,
    NGX_LIVE_SEGMENTER_FLAG_PARTS_CAP,
    ngx_live_lls_start_stream,
    ngx_live_lls_end_stream,
    ngx_live_lls_add_media_info,
    ngx_live_lls_add_frame,
    ngx_live_lls_get_min_used,
};


static char *
ngx_live_lls_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_core_module);

    if (cpcf->segmenter.id) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "segmenter redefined");
    }

    cpcf->segmenter = ngx_live_lls_ll;

    return NGX_OK;
}


static ngx_int_t
ngx_live_lls_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf, ngx_live_lls_channel_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf, ngx_live_lls_track_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf, ngx_live_lls_json_writers)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_live_lls_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_lls_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_lls_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_pending_segments = NGX_CONF_UNSET_UINT;
    conf->min_part_duration = NGX_CONF_UNSET_MSEC;
    conf->inactive_timeout = NGX_CONF_UNSET_MSEC;
    conf->forward_jump_threshold = NGX_CONF_UNSET_MSEC;
    conf->backward_jump_threshold = NGX_CONF_UNSET_MSEC;
    conf->dispose_threshold = NGX_CONF_UNSET_MSEC;
    conf->start_period_threshold = NGX_CONF_UNSET_MSEC;
    conf->frame_process_delay = NGX_CONF_UNSET_MSEC;
    conf->audio_process_delay = NGX_CONF_UNSET_MSEC;
    conf->wait_video_timeout = NGX_CONF_UNSET_MSEC;
    conf->close_segment_delay = NGX_CONF_UNSET_MSEC;
    conf->segment_start_margin = NGX_CONF_UNSET_UINT;
    conf->video_end_segment_margin = NGX_CONF_UNSET_UINT;
    conf->video_duration_margin = NGX_CONF_UNSET_UINT;
    conf->max_skip_frames = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_lls_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    size_t                        size;
    ngx_live_lls_preset_conf_t   *prev = parent;
    ngx_live_lls_preset_conf_t   *conf = child;
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_core_module);
    if (!cpcf->segmenter.id) {
        cpcf->segmenter = ngx_live_lls_ll;
    }

    ngx_conf_merge_msec_value(conf->max_pending_segments,
                              prev->max_pending_segments, 5);

    ngx_conf_merge_msec_value(conf->min_part_duration,
                              prev->min_part_duration, 50);

    ngx_conf_merge_msec_value(conf->inactive_timeout,
                              prev->inactive_timeout, 2000);

    ngx_conf_merge_msec_value(conf->forward_jump_threshold,
                              prev->forward_jump_threshold, 10000);

    ngx_conf_merge_msec_value(conf->backward_jump_threshold,
                              prev->backward_jump_threshold, 0);

    ngx_conf_merge_msec_value(conf->dispose_threshold,
                              prev->dispose_threshold, 250);

    ngx_conf_merge_msec_value(conf->start_period_threshold,
                              prev->start_period_threshold, 500);

    ngx_conf_merge_msec_value(conf->frame_process_delay,
                              prev->frame_process_delay, 100);

    ngx_conf_merge_msec_value(conf->audio_process_delay,
                              prev->audio_process_delay, 100);

    ngx_conf_merge_msec_value(conf->wait_video_timeout,
                              prev->wait_video_timeout, 3000);

    ngx_conf_merge_msec_value(conf->close_segment_delay,
                              prev->close_segment_delay, 5000);

    ngx_conf_merge_uint_value(conf->segment_start_margin,
                              prev->segment_start_margin, 15);

    ngx_conf_merge_uint_value(conf->video_end_segment_margin,
                              prev->video_end_segment_margin, 15);

    ngx_conf_merge_uint_value(conf->video_duration_margin,
                              prev->video_duration_margin, 5);

    ngx_conf_merge_uint_value(conf->max_skip_frames,
                              prev->max_skip_frames, 2000);

    if (cpcf->segmenter.id != NGX_LIVE_LLS_ID) {
        return NGX_CONF_OK;
    }

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_PENDING_FRAME_PART],
        sizeof(ngx_live_lls_frame_part_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    size = sizeof(ngx_live_lls_track_ctx_t)
        + sizeof(ngx_live_lls_track_pending_seg_t)
        * (conf->max_pending_segments - 1);
    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_lls_module, size)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
