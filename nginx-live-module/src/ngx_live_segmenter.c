#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_timeline.h"
#include "ngx_live_segmenter.h"
#include "ngx_live_media_info.h"
#include "ngx_live_filler.h"


#define NGX_LIVE_SEGMENTER_PERSIST_BLOCK        (0x72746773)    /* sgtr */


#define NGX_LIVE_SEGMENTER_FRAME_PART_COUNT  (32)
#define NGX_LIVE_SEGMENTER_KF_PART_COUNT     (10)
#define NGX_LIVE_SEGMENTER_CANDIDATE_COUNT   (10)

#define NGX_LIVE_INVALID_FRAME_INDEX         (NGX_MAX_UINT32_VALUE)

#define NGX_LIVE_INVALID_PTS                 (LLONG_MAX)


#define ngx_live_segmenter_track_is_ready(cctx, ctx)                        \
    ((ctx)->pending_duration >= (cctx)->cur_ready_duration)


enum {
    NGX_LIVE_BP_PENDING_FRAME_PART,
    NGX_LIVE_BP_PENDING_KF_PART,

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
    ngx_msec_t                        forward_skip_threshold;
    ngx_msec_t                        forward_jump_threshold;
    ngx_msec_t                        backward_jump_threshold;
    ngx_msec_t                        inactive_timeout;
    ngx_msec_t                        start_truncate_limit;

    ngx_msec_t                        track_add_snap_range;
    ngx_msec_t                        track_remove_snap_range;
    ngx_msec_t                        split_snap_range;

    ngx_msec_t                        candidate_margin;
    ngx_msec_t                        keyframe_alignment_margin;

    ngx_uint_t                        ready_threshold;
    ngx_uint_t                        initial_ready_threshold;

    ngx_uint_t                        bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_segmenter_preset_conf_t;

typedef struct {
    ngx_msec_t                        segment_duration;
} ngx_live_segmenter_dyn_conf_t;


/* candidate list */
typedef struct {
    int64_t                           pts;
    uint32_t                          count;
} ngx_live_segmenter_candidate_t;

typedef struct {
    ngx_live_channel_t               *channel;
    int64_t                           boundary_pts;
    int64_t                           min_pts;
    uint32_t                          margin;

    ngx_uint_t                        nelts;
    ngx_live_segmenter_candidate_t    elts[NGX_LIVE_SEGMENTER_CANDIDATE_COUNT];
} ngx_live_segmenter_candidate_list_t;


/* frame list */
typedef struct {
    ngx_buf_chain_t                  *data;
    uint64_t                          id;
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
    ngx_live_track_t                 *track;
    ngx_block_pool_t                 *block_pool;
    ngx_uint_t                        bp_idx;

    ngx_live_segmenter_frame_part_t  *last;
    ngx_live_segmenter_frame_part_t   part;
    ngx_buf_chain_t                  *last_data_part;
    uint32_t                          dts_shift;
} ngx_live_segmenter_frame_list_t;

typedef struct {
    int64_t                           split_duration;
    uint64_t                          last_id;
    int64_t                           last_pts;
} ngx_live_segmenter_remove_res_t;


/* key frame list */
typedef struct {
    int64_t                           pts;
    int64_t                           prev_pts;
    uint32_t                          flags;
    uint32_t                          index_delta;
} ngx_live_segmenter_kf_t;

typedef struct ngx_live_segmenter_kf_part_s  ngx_live_segmenter_kf_part_t;

struct ngx_live_segmenter_kf_part_s {
    ngx_live_segmenter_kf_part_t     *next;
    ngx_uint_t                        nelts;

    ngx_live_segmenter_kf_t           elts[NGX_LIVE_SEGMENTER_KF_PART_COUNT];
};

typedef struct {
    ngx_live_track_t                 *track;
    ngx_block_pool_t                 *block_pool;
    ngx_uint_t                        bp_idx;

    ngx_live_segmenter_kf_part_t     *last;
    ngx_live_segmenter_kf_part_t      part;
    uint32_t                          last_key_index;
} ngx_live_segmenter_kf_list_t;


/* main */
typedef struct {
    ngx_int_t                         state;

    ngx_live_segmenter_frame_list_t   frames;
    uint32_t                          frame_count;
    int64_t                           start_pts;
    int64_t                           last_pts;
    int64_t                           last_key_pts;
    int64_t                           pending_duration;
    u_char                           *last_data_ptr;
    uint32_t                          next_flags;

    ngx_live_segmenter_kf_list_t      key_frames;

    uint32_t                          split_index;      /* volatile */

    /* Note: split_count ignores the first pending frame */
    uint32_t                          split_count;

    /* Note: min_split_pts is the pts of the frame before the split */
    int64_t                           min_split_pts;

    /* stats */
    int64_t                           last_created;
    off_t                             received_bytes;
    ngx_uint_t                        received_frames;
    ngx_uint_t                        received_key_frames;
    ngx_uint_t                        dropped_frames;

    ngx_event_t                       inactive;
} ngx_live_segmenter_track_ctx_t;

typedef struct {
    ngx_live_segmenter_dyn_conf_t     conf;
    uint32_t                          segment_duration;
    uint32_t                          min_segment_duration;
    uint32_t                          forward_skip_threshold;
    uint32_t                          forward_jump_threshold;
    uint32_t                          backward_jump_threshold;
    uint32_t                          start_truncate_limit;

    uint32_t                          track_add_snap_range;
    uint32_t                          track_remove_snap_range;
    uint32_t                          split_snap_range;

    uint32_t                          candidate_margin;
    uint32_t                          keyframe_alignment_margin;

    uint32_t                          ready_duration;
    uint32_t                          initial_ready_duration;
    uint32_t                          cur_ready_duration;

    int64_t                           last_segment_end_pts;
    uint32_t                          count[ngx_live_track_state_count];

    ngx_event_t                       create;

    unsigned                          force_new_period:1;
} ngx_live_segmenter_channel_ctx_t;


static ngx_int_t ngx_live_segmenter_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_segmenter_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_segmenter_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_segmenter_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_segmenter_set_segment_duration(void *ctx,
    ngx_live_json_command_t *cmd, ngx_json_value_t *value, ngx_pool_t *pool);


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

    { ngx_string("segmenter_forward_skip_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, forward_skip_threshold),
      NULL },

    { ngx_string("segmenter_forward_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, forward_jump_threshold),
      NULL },

    { ngx_string("segmenter_backward_jump_threshold"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, backward_jump_threshold),
      NULL },

    { ngx_string("segmenter_inactive_timeout"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, inactive_timeout),
      NULL },

    { ngx_string("segmenter_start_truncate_limit"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, start_truncate_limit),
      NULL },

    { ngx_string("segmenter_track_add_snap_range"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, track_add_snap_range),
      NULL },

    { ngx_string("segmenter_track_remove_snap_range"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, track_remove_snap_range),
      NULL },

    { ngx_string("segmenter_split_snap_range"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, split_snap_range),
      NULL },

    { ngx_string("segmenter_candidate_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, candidate_margin),
      NULL },

    { ngx_string("segmenter_keyframe_alignment_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, keyframe_alignment_margin),
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


static ngx_live_json_command_t  ngx_live_segmenter_dyn_cmds[] = {

    { ngx_string("segment_duration"), NGX_JSON_INT,
      ngx_live_segmenter_set_segment_duration },

      ngx_live_null_json_command
};


ngx_live_add_media_info_pt  ngx_live_add_media_info;

ngx_live_add_frame_pt       ngx_live_add_frame;

ngx_live_end_of_stream_pt   ngx_live_end_of_stream;


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


/* candidate list */
static void
ngx_live_segmenter_candidate_list_add(
    ngx_live_segmenter_candidate_list_t *list, int64_t pts)
{
    int64_t                          last_diff;
    int64_t                          first_diff;
    int64_t                          boundary_pts;
    ngx_live_segmenter_candidate_t  *cur, *last;

    cur = list->elts;
    last = cur + list->nelts;
    for (; cur < last; cur++) {
        if (pts < cur->pts - list->margin) {
            break;
        }

        if (pts >= cur->pts + list->margin) {
            continue;
        }

        cur->pts = (cur->pts * cur->count + pts) / (cur->count + 1);
        cur->count++;
        return;
    }

    if (list->nelts < ngx_array_entries(list->elts)) {
        ngx_memmove(cur + 1, cur, (u_char *) last - (u_char *) cur);
        cur->pts = pts;
        cur->count = 1;
        list->nelts++;
        return;
    }

    boundary_pts = list->boundary_pts;
    first_diff = ngx_abs_diff(list->elts[0].pts, boundary_pts);
    last_diff = ngx_abs_diff(last[-1].pts, boundary_pts);

    if (first_diff < last_diff) {

        if (ngx_abs_diff(pts, boundary_pts) > last_diff) {
            return;
        }

        if (cur >= last) {
            ngx_log_error(NGX_LOG_ALERT, &list->channel->log, 0,
                "ngx_live_segmenter_candidate_list_add: "
                "insert pos at list end");
            return;
        }

        ngx_memmove(cur + 1, cur, (u_char *) (last - 1) - (u_char *) cur);

    } else {

        if (ngx_abs_diff(pts, boundary_pts) > first_diff) {
            return;
        }

        if (cur <= list->elts) {
            ngx_log_error(NGX_LOG_ALERT, &list->channel->log, 0,
                "ngx_live_segmenter_candidate_list_add: "
                "insert pos at list start");
            return;
        }

        cur--;
        ngx_memmove(list->elts, list->elts + 1,
            (u_char *) cur - (u_char *) list->elts);
    }

    cur->pts = pts;
    cur->count = 1;
}

static void
ngx_live_segmenter_candidate_list_truncate(
    ngx_live_segmenter_candidate_list_t *list, int64_t pts)
{
    uint32_t  i;

    for (i = list->nelts; i > 0; i--) {
        if (list->elts[i - 1].pts < pts) {
            break;
        }
    }

    list->nelts = i;
}


/* frame list */
static void
ngx_live_segmenter_frame_list_init(ngx_live_segmenter_frame_list_t *list,
    ngx_live_track_t *track, ngx_block_pool_t *block_pool, ngx_uint_t bp_idx)
{
    list->block_pool = block_pool;
    list->bp_idx = bp_idx;
    list->track = track;
    list->last = &list->part;
}

static void
ngx_live_segmenter_frame_list_reset(ngx_live_segmenter_frame_list_t *list)
{
    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;

    list->last_data_part = NULL;
}

static void
ngx_live_segmenter_frame_list_free(ngx_live_segmenter_frame_list_t *list)
{
    ngx_live_segmenter_frame_part_t  *part, *next;

    if (list->part.nelts > 0) {
        ngx_live_channel_buf_chain_free_list(list->track->channel,
            list->part.elts[0].data, list->last_data_part);
    }

    for (part = list->part.next; part != NULL; part = next) {
        next = part->next;

        ngx_block_pool_free(list->block_pool, list->bp_idx, part);
    }
}

static ngx_live_segmenter_frame_t *
ngx_live_segmenter_frame_list_push(ngx_live_segmenter_frame_list_t *list,
    ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail)
{
    ngx_live_segmenter_frame_t       *frame;
    ngx_live_segmenter_frame_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_LIVE_SEGMENTER_FRAME_PART_COUNT) {

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

    frame->data = data_head;

    if (list->last_data_part != NULL) {
        list->last_data_part->next = data_head;
    }
    list->last_data_part = data_tail;

    return frame;
}

static ngx_live_segmenter_frame_t *
ngx_live_segmenter_frame_list_get(ngx_live_segmenter_frame_list_t *list,
    uint32_t index)
{
    ngx_live_segmenter_frame_part_t  *part;

    part = &list->part;

    while (index >= part->nelts) {

        if (part->next == NULL) {
            return NULL;
        }

        index -= part->nelts;
        part = part->next;
    }

    return part->elts + index;
}

static void
ngx_live_segmenter_frame_list_remove(ngx_live_segmenter_frame_list_t *list,
    ngx_uint_t count, ngx_flag_t free_data_chains, uint32_t *split_count,
    ngx_live_segmenter_remove_res_t *res)
{
    int64_t                            prev_pts;
    ngx_uint_t                         left;
    ngx_buf_chain_t                   *data_tail;
    ngx_live_segmenter_frame_t        *cur, *last;
    ngx_live_segmenter_frame_part_t   *part;
    ngx_live_segmenter_frame_part_t   *next_part;

    left = count;
    part = &list->part;
    cur = part->elts;

    if (free_data_chains) {
        last = ngx_live_segmenter_frame_list_get(list, count - 1);
        data_tail = ngx_live_segmenter_terminate_frame_chain(last);

        ngx_live_channel_buf_chain_free_list(list->track->channel,
            cur->data, data_tail);

        if ((cur->flags & NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT) &&
            list->dts_shift > 0)
        {
            ngx_log_error(NGX_LOG_NOTICE, &list->track->log, 0,
                "ngx_live_segmenter_frame_list_remove: "
                "resetting dts shift (1), prev: %uD", list->dts_shift);
            list->dts_shift = 0;
        }
    }

    ngx_memzero(res, sizeof(*res));

    if (*split_count > 0) {

        /* free whole parts and check for splits */
        last = cur + part->nelts;

        for ( ;; ) {

            /* Note: intentionally skipping the first frame */
            prev_pts = cur->pts;
            cur++;
            left--;

            if (cur >= last) {
                next_part = part->next;
                if (next_part == NULL) {
                    if (left) {
                        ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
                            "ngx_live_segmenter_frame_list_remove: "
                            "count too large (1)");
                        ngx_debug_point();
                    }
                    break;
                }

                res->last_id = last[-1].id;
                res->last_pts = last[-1].pts;

                if (part != &list->part) {
                    ngx_block_pool_free(list->block_pool, list->bp_idx, part);
                }

                part = next_part;
                cur = part->elts;
                last = cur + part->nelts;
            }

            if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
                res->split_duration += cur->pts - prev_pts;
                (*split_count)--;

                if ((cur->flags & NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT) &&
                    list->dts_shift > 0)
                {
                    ngx_log_error(NGX_LOG_NOTICE, &list->track->log, 0,
                        "ngx_live_segmenter_frame_list_remove: "
                        "resetting dts shift (2), prev: %uD", list->dts_shift);
                    list->dts_shift = 0;
                }
            }

            if (!left) {
                break;
            }
        }

        list->part.nelts = last - cur;

    } else {

        /* more optimized implementation - free whole parts */
        while (left >= part->nelts) {

            next_part = part->next;
            if (next_part == NULL) {
                if (left != part->nelts) {
                    ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
                        "ngx_live_segmenter_frame_list_remove: "
                        "count too large (2)");
                    ngx_debug_point();
                    left = part->nelts;
                }
                break;
            }

            left -= part->nelts;

            res->last_id = part->elts[part->nelts - 1].id;
            res->last_pts = part->elts[part->nelts - 1].pts;

            if (part != &list->part) {
                ngx_block_pool_free(list->block_pool, list->bp_idx, part);
            }

            part = next_part;
        }

        cur = part->elts + left;
        list->part.nelts = part->nelts - left;
    }

    if (cur > part->elts) {
        res->last_id = cur[-1].id;
        res->last_pts = cur[-1].pts;
    }

    /* remove frames from the last part */
    ngx_memmove(list->part.elts, cur,
        list->part.nelts * sizeof(part->elts[0]));
    list->part.next = part->next;

    if (part != &list->part) {
        ngx_block_pool_free(list->block_pool, list->bp_idx, part);
    }

    if (list->part.next == NULL) {
        list->last = &list->part;

        if (list->part.nelts <= 0) {
            list->last_data_part = NULL;
        }
    }
}

static int64_t
ngx_live_segmenter_frame_list_get_min_split_pts(
    ngx_live_segmenter_frame_list_t *list)
{
    int64_t                           prev_pts;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    /* Note: it is possible to create some data structure more optimized for
        this, but the assumption is that multiple pending splits are rare */

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* ignore the first frame (one must exist) */
    prev_pts = cur->pts;
    cur++;

    for (;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            return prev_pts;
        }

        prev_pts = cur->pts;
    }

    ngx_log_error(NGX_LOG_ALERT, &list->track->log, 0,
        "ngx_live_segmenter_frame_list_get_min_split_pts: split not found");
    ngx_debug_point();
    return NGX_LIVE_INVALID_PTS;
}

static ngx_uint_t
ngx_live_segmenter_frame_list_get_index(ngx_live_segmenter_frame_list_t *list,
    int64_t target_pts)
{
    int64_t                           diff, cur_diff;
    ngx_uint_t                        index;
    ngx_uint_t                        cur_index;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* handle first frame */
    if (cur->pts >= target_pts) {
        return 0;
    }

    cur_index = index = 1;
    diff = ngx_abs_diff(cur->pts, target_pts);
    cur++;

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            break;
        }

        cur_index++;

        cur_diff = ngx_abs_diff(cur->pts, target_pts);
        if (cur_diff <= diff) {
            index = cur_index;
            diff = cur_diff;
        }
    }

    return index;
}

static ngx_uint_t
ngx_live_segmenter_frame_list_get_truncate_index(
    ngx_live_segmenter_frame_list_t *list, int64_t target_pts)
{
    ngx_uint_t                        index;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* handle first frame */
    if (cur->pts >= target_pts) {
        return 0;
    }

    cur++;

    for (index = 1 ;; cur++, index++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->pts >= target_pts) {
            break;
        }
    }

    return index;
}

static ngx_int_t
ngx_live_segmenter_frame_list_copy(ngx_live_segmenter_frame_list_t *list,
    ngx_live_segment_t *segment, uint32_t count)
{
    size_t                            size;
    int32_t                           pts_delay;
    uint32_t                          dts_shift;
    ngx_uint_t                        left;
    ngx_live_frame_t                 *dest, *prev_dest;
    ngx_live_segmenter_frame_t       *last;
    ngx_live_segmenter_frame_t       *src, *prev_src;
    ngx_live_segmenter_frame_part_t  *part;

    prev_src = NULL;
    prev_dest = NULL;
    size = 0;
    dts_shift = 0;

    part = &list->part;
    src = part->elts;
    last = src + part->nelts;

    if ((src[0].flags & NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT) &&
        list->dts_shift > 0)
    {
        ngx_log_error(NGX_LOG_NOTICE, &list->track->log, 0,
            "ngx_live_segmenter_frame_list_copy: "
            "resetting dts shift, prev: %uD", list->dts_shift);
        list->dts_shift = 0;
    }

    segment->frame_count = count;
    segment->start_dts = src[0].dts - list->dts_shift;
    segment->data_head = src[0].data;

    for (left = count ;; left--, src++) {

        if (src >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            src = part->elts;
            last = src + part->nelts;
        }

        if (!left) {
            break;
        }

        if (prev_dest != NULL) {
            prev_dest->duration = src->dts - prev_src->dts;
        }

        dest = ngx_list_push(&segment->frames);
        if (dest == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &list->track->log, 0,
                "ngx_live_segmenter_frame_list_copy: push frame failed");
            return NGX_ERROR;
        }

        pts_delay = src->pts + list->dts_shift - src->dts;
        if (pts_delay < 0) {
            dts_shift = ngx_max(dts_shift, (uint32_t) -pts_delay);
        }

        dest->key_frame = (src->flags & KMP_FRAME_FLAG_KEY) ? 1 : 0;
        dest->pts_delay = pts_delay;
        dest->size = src->size;
        /* duration is set when the next frame arrives */


        size += src->size;

        prev_dest = dest;
        prev_src = src;
    }

    if (src < last && !(src->flags & NGX_LIVE_FRAME_FLAG_SPLIT)) {
        prev_dest->duration = src->dts - prev_src->dts;

    } else if (count > 1) {
        prev_dest->duration = (prev_src->dts - segment->start_dts) /
            (count - 1);

    } else {
        prev_dest->duration = 0;
    }

    segment->end_dts = prev_src->dts + prev_dest->duration - list->dts_shift;

    if (dts_shift > 0) {
        ngx_log_error(NGX_LOG_NOTICE, &list->track->log, 0,
            "ngx_live_segmenter_frame_list_copy: "
            "applying dts shift %uD, prev: %uD", dts_shift, list->dts_shift);

        ngx_live_segment_cache_shift_dts(segment, dts_shift);

        list->dts_shift += dts_shift;
    }

    segment->data_tail = ngx_live_segmenter_terminate_frame_chain(prev_src);
    segment->data_size = size;

    return NGX_OK;
}


/* key frame list */
static void
ngx_live_segmenter_kf_list_init(ngx_live_segmenter_kf_list_t *list,
    ngx_live_track_t *track, ngx_block_pool_t *block_pool, ngx_uint_t bp_idx)
{
    list->block_pool = block_pool;
    list->bp_idx = bp_idx;
    list->track = track;
    list->last = &list->part;
}

static void
ngx_live_segmenter_kf_list_reset(ngx_live_segmenter_kf_list_t *list)
{
    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->last_key_index = 0;
}

static void
ngx_live_segmenter_kf_list_free(ngx_live_segmenter_kf_list_t *list)
{
    ngx_live_segmenter_kf_part_t  *part, *next;

    for (part = list->part.next; part != NULL; part = next) {
        next = part->next;

        ngx_block_pool_free(list->block_pool, list->bp_idx, part);
    }
}

static ngx_live_segmenter_kf_t *
ngx_live_segmenter_kf_list_push(ngx_live_segmenter_kf_list_t *list,
    uint32_t frame_index)
{
    ngx_live_segmenter_kf_t       *elt;
    ngx_live_segmenter_kf_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_LIVE_SEGMENTER_KF_PART_COUNT) {

        last = ngx_block_pool_alloc(list->block_pool, list->bp_idx);
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

    elt->index_delta = frame_index - list->last_key_index;
    list->last_key_index = frame_index;

    return elt;
}

static void
ngx_live_segmenter_kf_list_remove(ngx_live_segmenter_kf_list_t *list,
    ngx_uint_t frame_count)
{
    ngx_uint_t                      left;
    ngx_live_segmenter_kf_t        *cur, *last;
    ngx_live_segmenter_kf_part_t   *part;
    ngx_live_segmenter_kf_part_t   *next_part;

    if (frame_count >= list->last_key_index) {
        list->last_key_index = 0;

    } else {
        list->last_key_index -= frame_count;
    }

    left = frame_count;
    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    for (; ; cur++) {

        if (cur >= last) {
            next_part = part->next;
            if (next_part == NULL) {
                break;
            }

            if (part != &list->part) {
                ngx_block_pool_free(list->block_pool, list->bp_idx, part);
            }

            part = next_part;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->index_delta >= left) {
            cur->index_delta -= left;
            break;
        }

        left -= cur->index_delta;
    }

    list->part.nelts = last - cur;

    /* remove frames from the last part */
    ngx_memmove(list->part.elts, cur,
        list->part.nelts * sizeof(part->elts[0]));
    list->part.next = part->next;

    if (part != &list->part) {
        ngx_block_pool_free(list->block_pool, list->bp_idx, part);
    }

    if (list->part.next == NULL) {
        list->last = &list->part;
    }
}

static void
ngx_live_segmenter_kf_list_add_candidates(ngx_live_segmenter_kf_list_t *list,
    ngx_live_segmenter_candidate_list_t *candidates, int64_t max_pts)
{
    ngx_live_segmenter_kf_t       *cur, *last;
    ngx_live_segmenter_kf_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    if (cur >= last) {
        return;
    }

    cur++;      /* skip the first frame */

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->prev_pts >= candidates->min_pts && cur->prev_pts < max_pts) {
            ngx_live_segmenter_candidate_list_add(candidates, cur->prev_pts);
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            break;
        }
    }
}

static void
ngx_live_segmenter_kf_list_find_nearest_pts(ngx_live_segmenter_kf_list_t *list,
    ngx_live_segmenter_candidate_list_t *candidates, int64_t *result)
{
    int64_t                        target;
    uint32_t                       i;
    ngx_live_segmenter_kf_t       *cur, *last;
    ngx_live_segmenter_kf_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    if (cur >= last) {
        return;
    }

    /* handle first frame */
    for (i = 0; i < candidates->nelts; i++) {

        target = candidates->elts[i].pts;

        if (result[i] == NGX_LIVE_INVALID_PTS ||
            ngx_abs_diff(cur->pts, target) <
            ngx_abs_diff(result[i], target))
        {
            result[i] = cur->pts;
        }
    }

    cur++;

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        for (i = 0; i < candidates->nelts; i++) {

            target = candidates->elts[i].pts;

            if (result[i] == NGX_LIVE_INVALID_PTS ||
                ngx_abs_diff(cur->prev_pts, target) <
                ngx_abs_diff(result[i], target))
            {
                result[i] = cur->prev_pts;
            }
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            break;
        }
    }
}

static ngx_uint_t
ngx_live_segmenter_kf_list_get_index(ngx_live_segmenter_kf_list_t *list,
    int64_t target_pts)
{
    int64_t                        diff, cur_diff;
    ngx_uint_t                     index;
    ngx_uint_t                     cur_index;
    ngx_live_segmenter_kf_t       *cur, *last;
    ngx_live_segmenter_kf_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* handle first frame */
    if (cur >= last || cur->pts >= target_pts) {
        return 0;
    }

    cur_index = index = cur->index_delta;
    diff = ngx_abs_diff(cur->pts, target_pts);
    cur++;

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        cur_index += cur->index_delta;

        cur_diff = ngx_abs_diff(cur->prev_pts, target_pts);
        if (cur_diff <= diff) {
            index = cur_index;
            diff = cur_diff;
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            break;
        }
    }

    return index;
}

static ngx_uint_t
ngx_live_segmenter_kf_list_get_truncate_index(
    ngx_live_segmenter_kf_list_t *list, int64_t target_pts)
{
    ngx_uint_t                     index;
    ngx_live_segmenter_kf_t       *cur, *last;
    ngx_live_segmenter_kf_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* handle first frame */
    if (cur >= last || cur->pts >= target_pts) {
        return 0;
    }

    index = cur->index_delta;
    cur++;

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (cur->prev_pts >= target_pts) {
            break;
        }

        index += cur->index_delta;
    }

    return index;
}

static void
ngx_live_segmenter_kf_list_dump(ngx_live_segmenter_kf_list_t *list,
    int64_t base_pts)
{
    ngx_live_segmenter_kf_t       *cur, *last;
    ngx_live_segmenter_kf_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    for (; ; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        ngx_log_error(NGX_LOG_INFO, &list->track->log, 0,
            "    kf: pts: %L, prev_pts: %L, flags=0x%uxD, delta=%uD",
            cur->pts - base_pts, cur->prev_pts - base_pts,
            cur->flags, cur->index_delta);
    }
}


/* main */
static ngx_inline void
ngx_live_segmenter_set_state(ngx_live_track_t *track,
    ngx_live_track_state_e new_state)
{
    ngx_live_track_state_e             old_state;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    old_state = ctx->state;
    if (new_state == old_state) {
        return;
    }

    if (old_state == ngx_live_track_inactive ||
        new_state == ngx_live_track_inactive)
    {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_set_state: %d -> %d", old_state, new_state);

    } else {
        ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &track->log, 0,
            "ngx_live_segmenter_set_state: %d -> %d, track: %V",
            old_state, new_state, &track->sn.str);
    }

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    cctx->count[old_state]--;
    cctx->count[new_state]++;

    ctx->state = new_state;

    if (new_state == ngx_live_track_inactive) {
        (void) ngx_live_core_track_event(track,
            NGX_LIVE_EVENT_TRACK_INACTIVE, NULL);
    }
}

static void
ngx_live_segmenter_channel_inactive(ngx_live_channel_t *channel)
{
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_channel_inactive: called");

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    cctx->cur_ready_duration = cctx->initial_ready_duration;

    channel->active = 0;

    (void) ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_INACTIVE, NULL);
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_segmenter_validate_empty_track_ctx(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->frame_count != 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "nonzero frame count %uD", ctx->frame_count);
        ngx_debug_point();
    }

    if (ctx->split_count != 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "nonzero split count %uD", ctx->split_count);
        ngx_debug_point();
    }

    if (ctx->min_split_pts != NGX_LIVE_INVALID_PTS) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "nonzero split pts %L", ctx->min_split_pts);
        ngx_debug_point();
    }

    if (ctx->pending_duration != 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "nonzero pending duration %L", ctx->pending_duration);
        ngx_debug_point();
    }

    if (ctx->frames.last_data_part != NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "last data part is not null");
        ngx_debug_point();
    }

    if (ctx->key_frames.part.nelts != 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "key frames list not empty");
        ngx_debug_point();
    }

    if (ctx->key_frames.last_key_index != 0) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_empty_track_ctx: "
            "nonzero last key index %uD", ctx->key_frames.last_key_index);
        ngx_debug_point();
    }
}

static void
ngx_live_segmenter_validate_track_ctx(ngx_live_track_t *track)
{
    int64_t                           prev_pts;
    int64_t                           last_key_pts;
    int64_t                           min_split_pts;
    int64_t                           pending_duration;
    uint32_t                          index;
    uint32_t                          last_key_index;
    uint32_t                          frame_count;
    uint32_t                          split_count;
    ngx_buf_chain_t                  *buf_chain;
    ngx_live_segmenter_kf_t          *kf_cur, *kf_last;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_t       *last_frame;
    ngx_live_segmenter_kf_part_t     *kf_part;
    ngx_live_segmenter_track_ctx_t   *ctx;
    ngx_live_segmenter_frame_part_t  *part;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->frames.part.nelts == 0) {
        ngx_live_segmenter_validate_empty_track_ctx(track);
        return;
    }

    frame_count = 0;
    last_frame = NULL;
    last_key_pts = 0;
    last_key_index = 0;
    pending_duration = 0;
    split_count = 0;
    min_split_pts = NGX_LIVE_INVALID_PTS;
    prev_pts = NGX_LIVE_INVALID_PTS;

    part = &ctx->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    kf_part = &ctx->key_frames.part;
    kf_cur = kf_part->elts;
    kf_last = kf_cur + kf_part->nelts;

    if (ctx->start_pts != part->elts[0].pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid start pts %L expected %L",
            ctx->start_pts, part->elts[0].pts);
        ngx_debug_point();
    }

    for (index = 0;; cur++, index++) {

        if (cur >= last) {
            frame_count += part->nelts;

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (track->media_type != KMP_MEDIA_VIDEO ||
            (cur->flags & KMP_FRAME_FLAG_KEY))
        {
            if (index > 0) {
                if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
                    pending_duration += prev_pts - last_key_pts;

                } else {
                    pending_duration += cur->pts - last_key_pts;
                }
            }

            last_key_pts = cur->pts;

            if (track->media_type == KMP_MEDIA_VIDEO) {

                if (kf_cur >= kf_last) {
                    if (kf_part->next == NULL) {
                        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                            "ngx_live_segmenter_validate_track_ctx: "
                            "key frame list is partial");
                        ngx_debug_point();
                    }

                    kf_part = kf_part->next;
                    kf_cur = kf_part->elts;
                    kf_last = kf_cur + kf_part->nelts;
                }

                if (kf_cur->index_delta != index - last_key_index) {
                    ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                        "ngx_live_segmenter_validate_track_ctx: "
                        "invalid kf index delta %uD expected %uD",
                        kf_cur->index_delta, index - last_key_index);
                    ngx_debug_point();
                }

                if (kf_cur->pts != cur->pts) {
                    ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                        "ngx_live_segmenter_validate_track_ctx: "
                        "invalid kf pts %L expected %L",
                        kf_cur->pts, cur->pts);
                    ngx_debug_point();
                }

                if (kf_cur != ctx->key_frames.part.elts &&
                    kf_cur->prev_pts != prev_pts)
                {
                    ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                        "ngx_live_segmenter_validate_track_ctx: "
                        "invalid kf prev pts %L expected %L",
                        kf_cur->prev_pts, prev_pts);
                    ngx_debug_point();
                }

                if (kf_cur->flags != cur->flags) {
                    ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                        "ngx_live_segmenter_validate_track_ctx: "
                        "invalid kf flags 0x%uxD expected 0x%uxD",
                        kf_cur->flags, cur->flags);
                    ngx_debug_point();
                }

                kf_cur++;
                last_key_index = index;
            }
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT &&
            cur != ctx->frames.part.elts)
        {
            split_count++;

            if (min_split_pts == NGX_LIVE_INVALID_PTS) {
                min_split_pts = prev_pts;
            }
        }

        prev_pts = cur->pts;
        last_frame = cur;
    }

    if (ctx->frame_count != frame_count) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid frame count %uD expected %uD",
            ctx->frame_count, frame_count);
        ngx_debug_point();
    }

    if (ctx->split_count != split_count) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid split count %uD expected %uD",
            ctx->split_count, split_count);
        ngx_debug_point();
    }

    if (ctx->min_split_pts != min_split_pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid min split pts %L expected %L",
            ctx->min_split_pts, min_split_pts);
        ngx_debug_point();
    }

    if (ctx->last_pts != last_frame->pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid last pts %L expected %L",
            ctx->last_pts, last_frame->pts);
        ngx_debug_point();
    }

    if (ctx->last_key_pts != last_key_pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid last key pts %L expected %L",
            ctx->last_key_pts, last_key_pts);
        ngx_debug_point();
    }

    if (ctx->pending_duration != pending_duration) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid pending duration %L expected %L",
            ctx->pending_duration, pending_duration);
        ngx_debug_point();
    }

    if (ctx->key_frames.last_key_index != last_key_index) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "invalid last key index %uD expected %uD",
            ctx->key_frames.last_key_index, last_key_index);
        ngx_debug_point();
    }

    if (kf_cur < kf_last || kf_part->next != NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "key frame list has additional records");
        ngx_debug_point();
    }

    buf_chain = last_frame->data;
    for ( ;; ) {

        if (buf_chain->next == NULL) {
            break;
        }

        buf_chain = buf_chain->next;
    }

    if (ctx->frames.last_data_part != buf_chain) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: data tail part mismatch");
        ngx_debug_point();
    }

    if (ctx->last_data_ptr != buf_chain->data) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: data tail ptr mismatch");
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

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        count[cur_ctx->state]++;
    }

    if (ngx_memcmp(count, cctx->count, sizeof(count)) != 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_validate_channel_ctx: track count mismatch");
        ngx_debug_point();
    }
}
#else
#define ngx_live_segmenter_validate_track_ctx(track)
#define ngx_live_segmenter_validate_channel_ctx(channel)
#endif

static void
ngx_live_segmenter_dump_track(ngx_live_track_t *track, int64_t base_pts)
{
    int64_t                          min_split_pts;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "  track: state: %i, count: %uD, duration: %L",
        ctx->state, ctx->frame_count, ctx->pending_duration);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "  track: pts: first: %L, last: %L, last_key: %L",
        ctx->start_pts - base_pts, ctx->last_pts - base_pts,
        ctx->last_key_pts - base_pts);

    min_split_pts = ctx->min_split_pts == NGX_LIVE_INVALID_PTS ? -1 :
        ctx->min_split_pts - base_pts;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "  track: split: index: %uD, count: %uD, min_pts: %L",
        ctx->split_index, ctx->split_count, min_split_pts);

    ngx_live_segmenter_kf_list_dump(&ctx->key_frames, base_pts);
}

static void
ngx_live_segmenter_dump(ngx_live_channel_t *channel, int64_t base_pts)
{
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_dump: base: %L, last_segment_end: %L",
        base_pts, cctx->last_segment_end_pts - base_pts);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        ngx_live_segmenter_dump_track(cur_track, base_pts);
    }
}

static void
ngx_live_segmenter_remove_frames(ngx_live_track_t *track, ngx_uint_t count,
    ngx_flag_t free_data_chains)
{
    int64_t                            start_pts;
    uint32_t                           initial_split_count;
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_remove_res_t    rr;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    if (count <= 0) {
        return;
    }

    channel = track->channel;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    ctx->frame_count -= count;

    if (free_data_chains) {
        ctx->dropped_frames += count;
    }

    /* update media info */
    ngx_live_media_info_pending_remove_frames(track, count);

    /* update frame list */
    initial_split_count = ctx->split_count;

    ngx_live_segmenter_frame_list_remove(&ctx->frames, count,
        free_data_chains, &ctx->split_count, &rr);

    track->last_frame_pts = rr.last_pts;
    track->next_frame_id = rr.last_id + 1;

    if (track->media_type == KMP_MEDIA_VIDEO) {
        ngx_live_segmenter_kf_list_remove(&ctx->key_frames, count);
    }

    /* update start pts / split count / ready status */
    if (ctx->frames.part.nelts > 0) {
        start_pts = ctx->frames.part.elts[0].pts;
        ctx->pending_duration -= start_pts - ctx->start_pts -
            rr.split_duration;
        ctx->start_pts = start_pts;

        if (ctx->state == ngx_live_track_ready &&
            !ngx_live_segmenter_track_is_ready(cctx, ctx))
        {
            ngx_live_segmenter_set_state(track, ngx_live_track_pending);
        }

    } else {
        ctx->pending_duration = 0;

        if (ctx->state == ngx_live_track_ready) {
            ngx_live_segmenter_set_state(track, ngx_live_track_pending);
        }
    }

    /* if splits were removed or frames were disposed,
        enable split on the next frame */
    if (ctx->split_count != initial_split_count) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_remove_frames: "
            "splits removed, enabling split on next frame");

        ctx->min_split_pts = ctx->split_count > 0 ?
            ngx_live_segmenter_frame_list_get_min_split_pts(&ctx->frames) :
            NGX_LIVE_INVALID_PTS;

    } else if (free_data_chains) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_remove_frames: "
            "%ui frames disposed, enabling split on next frame", count);

    } else {
        goto done;
    }

    if (ctx->frames.part.nelts > 0) {
        ctx->frames.part.elts[0].flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

        if (ctx->key_frames.part.nelts > 0 &&
            ctx->key_frames.part.elts[0].index_delta == 0)
        {
            ctx->key_frames.part.elts[0].flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
        }

    } else {
        ctx->next_flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
    }

done:

    if (free_data_chains) {
        if (channel->snapshots <= 0 && track->input.ack_frames != NULL) {
            track->input.ack_frames(track, track->next_frame_id);
        }

        ngx_live_segment_cache_free_input_bufs(track);
    }

    ngx_live_segmenter_validate_track_ctx(track);
}

static void
ngx_live_segmenter_remove_all_frames(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t    *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    ngx_live_media_info_pending_free_all(track);

    ngx_live_segmenter_frame_list_free(&ctx->frames);
    ngx_live_segmenter_frame_list_reset(&ctx->frames);

    ngx_live_segmenter_kf_list_free(&ctx->key_frames);
    ngx_live_segmenter_kf_list_reset(&ctx->key_frames);

    ctx->frame_count = 0;
    ctx->split_count = 0;
    ctx->pending_duration = 0;
    ctx->min_split_pts = NGX_LIVE_INVALID_PTS;

    /* update ready status */
    if (ctx->state == ngx_live_track_ready) {
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
    }

    ngx_live_segmenter_validate_track_ctx(track);
}

static void
ngx_live_segmenter_prepare_create_segment(ngx_live_channel_t *channel,
    uint32_t *media_types_mask, int64_t *min_pts)
{
    ngx_uint_t                         split_index;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    *media_types_mask = 0;
    *min_pts = NGX_LIVE_INVALID_PTS;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count <= 0) {
            continue;
        }

        if (!cur_track->has_last_segment || cctx->force_new_period ||
            (cur_ctx->frames.part.elts[0].flags & NGX_LIVE_FRAME_FLAG_SPLIT))
        {

            /* this track did not participate in the prev segment, or we're
                starting a new period, remove any frames before the segment
                start pts */

            if (cur_track->media_type == KMP_MEDIA_VIDEO) {
                split_index = ngx_live_segmenter_kf_list_get_truncate_index(
                    &cur_ctx->key_frames, cctx->last_segment_end_pts +
                    cctx->track_add_snap_range);

            } else {
                split_index = ngx_live_segmenter_frame_list_get_truncate_index(
                    &cur_ctx->frames, cctx->last_segment_end_pts);
            }

            if (split_index > 0) {
                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_segmenter_prepare_create_segment: "
                    "removing %uD frames", split_index);

                ngx_live_segmenter_remove_frames(cur_track, split_index, 1);
                if (cur_ctx->frame_count <= 0) {
                    continue;
                }
            }
        }

        *media_types_mask |= (1 << cur_track->media_type);

        if (cur_ctx->start_pts < *min_pts) {
            *min_pts = cur_ctx->start_pts;
        }
    }
}

static void
ngx_live_segmenter_find_nearest_keyframe_pts(
    ngx_live_segmenter_track_ctx_t *ctx,
    ngx_live_segmenter_candidate_list_t *candidates,
    ngx_flag_t has_last_segment, int64_t *result)
{
    int64_t                          target;
    ngx_uint_t                       i;

    if (!has_last_segment) {

        /* Note: this track is being added, candidates before its start
            position are considered perfect */
        for (i = 0; i < candidates->nelts; i++) {
            target = candidates->elts[i].pts;
            result[i] = target <= ctx->start_pts ? target :
                NGX_LIVE_INVALID_PTS;
        }

    } else {
        for (i = 0; i < candidates->nelts; i++) {
            result[i] = NGX_LIVE_INVALID_PTS;
        }
    }

    ngx_live_segmenter_kf_list_find_nearest_pts(&ctx->key_frames, candidates,
        result);

    if (ctx->state != ngx_live_track_inactive || ctx->split_count > 0) {
        return;
    }

    /* track is inactive, treat the last frame as key frame */
    for (i = 0; i < candidates->nelts; i++) {

        target = candidates->elts[i].pts;
        if (result[i] == NGX_LIVE_INVALID_PTS ||
            ngx_abs_diff(ctx->last_pts, target) <
            ngx_abs_diff(result[i], target))
        {
            result[i] = ctx->last_pts;
        }
    }
}

static void
ngx_live_segmenter_candidates_get(ngx_live_channel_t *channel,
    int64_t boundary_pts, ngx_live_segmenter_candidate_list_t *candidates,
    int64_t *min_split_pts)
{
    int64_t                               cur_split_pts;
    uint32_t                              media_types;
    uint32_t                              min_snap_range;
    uint32_t                              cur_snap_range;
    ngx_queue_t                          *q;
    ngx_live_track_t                     *cur_track;
    ngx_live_segmenter_track_ctx_t       *cur_ctx;
    ngx_live_segmenter_channel_ctx_t     *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    candidates->channel = channel;
    candidates->boundary_pts = boundary_pts;
    candidates->min_pts = cctx->last_segment_end_pts +
        cctx->min_segment_duration;
    candidates->margin = cctx->candidate_margin;
    candidates->nelts = 0;

    media_types = 0;
    min_snap_range = 0;
    cur_snap_range = 0;
    *min_split_pts = NGX_LIVE_INVALID_PTS;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);
        if (cur_ctx->frame_count <= 0) {
            continue;
        }

        /* check for track add/remove/split */
        if ((!cur_track->has_last_segment || cctx->force_new_period) &&
            cur_ctx->start_pts > cctx->last_segment_end_pts +
            cctx->track_add_snap_range)
        {
            cur_split_pts = cur_ctx->start_pts;
            cur_snap_range = cctx->track_add_snap_range;

            ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &cur_track->log, 0,
                "ngx_live_segmenter_candidates_get: "
                "track pending add, track: %V, pts: %L, delta: %L",
                &cur_track->sn.str, cur_split_pts,
                cur_split_pts - cctx->last_segment_end_pts);

        } else if (cur_ctx->min_split_pts != NGX_LIVE_INVALID_PTS) {
            cur_split_pts = cur_ctx->min_split_pts;
            cur_snap_range = cctx->split_snap_range;
            media_types |= 1 << cur_track->media_type;

            ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &cur_track->log, 0,
                "ngx_live_segmenter_candidates_get: "
                "force split, track: %V, pts: %L, delta: %L",
                &cur_track->sn.str, cur_split_pts,
                cur_split_pts - cctx->last_segment_end_pts);

        } else if (cur_ctx->state != ngx_live_track_ready) {
            cur_split_pts = cur_ctx->last_pts;
            cur_snap_range = cctx->track_remove_snap_range;
            media_types |= 1 << cur_track->media_type;

            ngx_log_debug3(NGX_LOG_DEBUG_LIVE, &cur_track->log, 0,
                "ngx_live_segmenter_candidates_get: "
                "track pending remove, track: %V, pts: %L, delta: %L",
                &cur_track->sn.str, cur_split_pts,
                cur_split_pts - cctx->last_segment_end_pts);

        } else {
            cur_split_pts = NGX_LIVE_INVALID_PTS;
            media_types |= 1 << cur_track->media_type;
        }

        if (cur_split_pts < *min_split_pts) {
            *min_split_pts = cur_split_pts;
            min_snap_range = cur_snap_range;

            ngx_live_segmenter_candidate_list_truncate(candidates,
                *min_split_pts);
        }

        if (cur_ctx->received_key_frames >= cur_ctx->received_frames / 2) {
            /* tracks that have a gop of 1-2 frames are ignored,
                assuming they can be split anywhere, like audio */
            continue;
        }

        ngx_live_segmenter_kf_list_add_candidates(&cur_ctx->key_frames,
            candidates, *min_split_pts);
    }

    if (*min_split_pts != NGX_LIVE_INVALID_PTS) {
        ngx_live_segmenter_candidate_list_add(candidates, *min_split_pts);
    }

    if (!(media_types & (1 << KMP_MEDIA_VIDEO)) &&
        boundary_pts + min_snap_range < *min_split_pts)
    {
        ngx_live_segmenter_candidate_list_add(candidates, boundary_pts);
    }
}

static void
ngx_live_segmenter_candidates_get_span(ngx_live_channel_t *channel,
    ngx_live_segmenter_candidate_list_t *candidates,
    int64_t *min, int64_t *max)
{
    uint32_t                           i;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    int64_t  nearest[NGX_LIVE_SEGMENTER_CANDIDATE_COUNT];

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    for (i = 0; i < candidates->nelts; i++) {
        min[i] = max[i] = candidates->elts[i].pts;
    }

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->media_type != KMP_MEDIA_VIDEO) {
            break;      /* the tracks are sorted by media type */
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);
        if (cur_ctx->frame_count <= 0) {
            continue;
        }

        if (cur_ctx->received_key_frames >= cur_ctx->received_frames / 2) {
            /* tracks that have a gop of 1-2 frames are ignored,
                assuming they can be split anywhere, like audio */
            continue;
        }

        /* for each base track keyframe, find the pts of the closest keyframe
            in the current track */
        ngx_live_segmenter_find_nearest_keyframe_pts(cur_ctx, candidates,
            cur_track->has_last_segment && !cctx->force_new_period, nearest);

        /* update the min / max ptss */
        for (i = 0; i < candidates->nelts; i++) {

            if (nearest[i] < min[i]) {
                min[i] = nearest[i];
            }

            if (nearest[i] > max[i]) {
                max[i] = nearest[i];
            }
        }
    }
}

static int64_t
ngx_live_segmenter_get_segment_end_pts(ngx_live_channel_t *channel,
    int64_t min_pts, int64_t *min_split_pts)
{
    int64_t                               boundary_pts;
    int64_t                               min_target_pts;
    int64_t                               cur_diff, min_diff;
    int64_t                               cur_pts, target_pts;
    uint32_t                              i;
    ngx_live_segmenter_channel_ctx_t     *cctx;
    ngx_live_segmenter_candidate_list_t   candidates;

    int64_t  min[NGX_LIVE_SEGMENTER_CANDIDATE_COUNT];
    int64_t  max[NGX_LIVE_SEGMENTER_CANDIDATE_COUNT];

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    /* get the segment boundary pts */
    if (min_pts > cctx->last_segment_end_pts + cctx->forward_skip_threshold) {

        if (cctx->last_segment_end_pts) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_get_segment_end_pts: "
                "pts forward skip, forcing new period, "
                "min_pts: %L, last_segment_pts: %L, delta: %L",
                min_pts, cctx->last_segment_end_pts,
                min_pts - cctx->last_segment_end_pts);
        }

        cctx->last_segment_end_pts = min_pts;
        cctx->force_new_period = 1;
    }

    boundary_pts = cctx->last_segment_end_pts + cctx->segment_duration;

    /* collect candidates from all tracks */
    ngx_live_segmenter_candidates_get(channel, boundary_pts, &candidates,
        min_split_pts);
    if (candidates.nelts <= 0) {
        /* can happen if no video tracks + no splits */
        target_pts = boundary_pts;
        goto done;
    }

    /* check the span of each candidate */
    ngx_live_segmenter_candidates_get_span(channel, &candidates, min, max);

    /* find smallest pts gap */
    min_diff = LLONG_MAX;
    for (i = 0; i < candidates.nelts; i++) {

        cur_diff = max[i] - min[i];
        if (cur_diff < min_diff) {
            min_diff = cur_diff;
        }
    }

    /* allow some margin around the min diff */
    min_diff += cctx->keyframe_alignment_margin;

    /* choose the pts closest to the boundary, with span smaller than min */
    target_pts = NGX_LIVE_INVALID_PTS;
    for (i = 0; i < candidates.nelts; i++) {

        cur_diff = max[i] - min[i];

        ngx_log_debug5(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
            "ngx_live_segmenter_get_segment_end_pts: "
            "candidate, pts: %L, delta: %L, diff: %L, nsi: %uD, channel: %V",
            candidates.elts[i].pts,
            candidates.elts[i].pts - cctx->last_segment_end_pts, cur_diff,
            channel->next_segment_index, &channel->sn.str);

        if (cur_diff > min_diff) {
            continue;
        }

        cur_pts = (max[i] + min[i]) / 2;
        if (target_pts == NGX_LIVE_INVALID_PTS ||
            ngx_abs_diff(cur_pts, boundary_pts) <
            ngx_abs_diff(target_pts, boundary_pts))
        {
            target_pts = cur_pts;
        }
    }

    if (target_pts == NGX_LIVE_INVALID_PTS) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_get_segment_end_pts: no target pts");
        return NGX_LIVE_INVALID_PTS;
    }

    min_target_pts = cctx->last_segment_end_pts + cctx->min_segment_duration;
    if (target_pts < min_target_pts) {
        target_pts = min_target_pts;
    }

done:

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_get_segment_end_pts: pts %L, delta: %L",
        target_pts, target_pts - cctx->last_segment_end_pts);

    return target_pts;
}

static ngx_int_t
ngx_live_segmenter_set_split_indexes(ngx_live_channel_t *channel,
    int64_t target_pts, uint32_t *media_types_mask)
{
    int64_t                            cur_target_pts;
    int64_t                            track_add_max_pts;
    uint32_t                           duration;
    uint32_t                           split_index;
    ngx_int_t                          rc;
    ngx_flag_t                         force_new_period;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    *media_types_mask = 0;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    force_new_period = cctx->force_new_period;

    rc = NGX_OK;

    duration = target_pts - cctx->last_segment_end_pts;
    track_add_max_pts = ngx_max(target_pts - cctx->track_add_snap_range,
        target_pts - duration / 4);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count <= 0) {
            cur_ctx->split_index = 0;
            continue;
        }

        if (cur_ctx->state != ngx_live_track_ready &&
            cur_ctx->split_count <= 0 &&
            cur_ctx->last_pts <= target_pts + cctx->track_remove_snap_range)
        {
            /* track removed + last pts before target -> use all frames */
            split_index = cur_ctx->frame_count;

        } else if ((!cur_track->has_last_segment || force_new_period) &&
            cur_ctx->start_pts > track_add_max_pts)
        {
            /* track added + start pts after target -> add it next time */
            split_index = 0;

        } else {
            /* if target is close to a split -> increase it up to the split */
            cur_target_pts = target_pts + cctx->split_snap_range;
            if (cur_target_pts < cur_ctx->min_split_pts) {
                cur_target_pts = target_pts;
            }

            /* find the key frame closest to target */
            if (cur_track->media_type == KMP_MEDIA_VIDEO) {
                split_index = ngx_live_segmenter_kf_list_get_index(
                    &cur_ctx->key_frames, cur_target_pts);

            } else {
                split_index = ngx_live_segmenter_frame_list_get_index(
                    &cur_ctx->frames, cur_target_pts);
            }
        }

        cur_ctx->split_index = split_index;

        if (split_index <= 0) {

            if (force_new_period &&
                cur_ctx->start_pts > cctx->last_segment_end_pts +
                cctx->start_truncate_limit)
            {
                continue;
            }

            if (cur_track->has_last_segment || force_new_period) {
                ngx_log_error(NGX_LOG_ERR, &cur_track->log, 0,
                    "ngx_live_segmenter_set_split_indexes: "
                    "empty segment, target_pts: %L, delta: %L",
                    target_pts, target_pts - cctx->last_segment_end_pts);
                rc = NGX_ABORT;
            }
            continue;
        }

        *media_types_mask |= (1 << cur_track->media_type);

        if (cur_ctx->frames.part.elts[0].flags & NGX_LIVE_FRAME_FLAG_SPLIT &&
            cur_track->has_last_segment)
        {
            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_segmenter_set_split_indexes: "
                "split enabled, forcing new period");

            cctx->force_new_period = 1;
        }
    }

    return rc;
}

static ngx_int_t
ngx_live_segmenter_fill(ngx_live_channel_t *channel, uint32_t media_types_mask,
    int64_t min_split_pts, int64_t *target_pts)
{
    uint32_t                           min_duration;
    uint32_t                           max_duration;
    uint32_t                           fill_duration;
    uint32_t                           missing_media_types;
    ngx_int_t                          rc;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    missing_media_types = KMP_MEDIA_TYPE_MASK & ~media_types_mask;

    if (media_types_mask & (1 << KMP_MEDIA_VIDEO)) {
        /* have video tracks, force the filler to align to that */
        fill_duration = *target_pts - cctx->last_segment_end_pts;
        min_duration = max_duration = fill_duration;

    } else {

        /* no video, allow the filler to choose the segment duration */
        fill_duration = cctx->segment_duration;
        min_duration = cctx->min_segment_duration;

        if (min_split_pts != NGX_LIVE_INVALID_PTS) {
            max_duration = min_split_pts - cctx->last_segment_end_pts;
            if (min_duration > max_duration) {
                min_duration = max_duration;
            }

        } else {
            max_duration = NGX_MAX_UINT32_VALUE;
        }
    }

    rc = ngx_live_filler_fill(channel, missing_media_types,
        cctx->last_segment_end_pts, cctx->force_new_period,
        min_duration, max_duration, &fill_duration);
    switch (rc) {

    case NGX_OK:
        *target_pts = cctx->last_segment_end_pts + fill_duration;
        /* fall through */

    case NGX_DONE:
        return NGX_OK;

    default:
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_fill: fill failed %i", rc);
        return rc;
    }
}

static ngx_int_t
ngx_live_segmenter_dispose_segment(ngx_live_channel_t *channel,
    int64_t end_pts)
{
    ngx_flag_t                         removed;
    ngx_flag_t                         force_new_period;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    removed = 0;
    force_new_period = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->split_index <= 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &cur_track->log, 0,
            "ngx_live_segmenter_dispose_segment: "
            "removing %uD frames, track: %V",
            cur_ctx->split_index, &cur_track->sn.str);

        removed = 1;

        /* start a new period only if an active track was removed */
        if (cur_ctx->state == ngx_live_track_ready) {
            force_new_period = 1;
        }

        ngx_live_segmenter_remove_frames(cur_track, cur_ctx->split_index, 1);
    }

    if (!removed) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_dispose_segment: no frames removed");
        return NGX_ERROR;
    }

    if (!force_new_period) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_dispose_segment: "
        "empty segment, forcing new period");

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    cctx->last_segment_end_pts = end_pts;
    cctx->force_new_period = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_create_segment(ngx_live_track_t *track)
{
    uint32_t                           segment_index;
    ngx_int_t                          rc;
    ngx_flag_t                         changed;
    media_info_t                      *media_info;
    kmp_media_info_t                  *kmp_media_info;
    ngx_live_segment_t                *segment;
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    channel = track->channel;
    segment_index = channel->next_segment_index;
    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    /* get the media info */
    ngx_live_media_info_pending_create_segment(track, segment_index, &changed);
    if (changed) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: "
            "media info changed, forcing new period");

        cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

        cctx->force_new_period = 1;
    }

    media_info = ngx_live_media_info_queue_get_last(track, &kmp_media_info);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: no media info");
        return NGX_ERROR;
    }

    /* create the segment */
    segment = ngx_live_segment_cache_create(track, segment_index);
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: create segment failed");
        return NGX_ERROR;
    }

    segment->media_info = media_info;
    segment->kmp_media_info = kmp_media_info;

    /* add the frames */
    rc = ngx_live_segmenter_frame_list_copy(&ctx->frames, segment,
        ctx->split_index);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: copy frames failed");
        ngx_live_segment_cache_free(segment);
        return rc;
    }

    ngx_live_segmenter_remove_frames(track, ctx->split_index, 0);

    ngx_live_segment_cache_finalize(segment);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_create_segment(ngx_live_channel_t *channel)
{
    uint32_t                           media_types_mask;
    uint32_t                           missing_media_types_mask;
    ngx_int_t                          rc;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    media_types_mask = 0;
    missing_media_types_mask = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->split_index <= 0) {

            if (cur_track->type == ngx_live_track_type_filler) {
                continue;
            }

            missing_media_types_mask |= 1 << cur_track->media_type;

            if (cur_track->has_last_segment) {

                /* Note: if the iPhone player stops getting audio, it stalls
                    playback, keeps downloading segments waiting for audio to
                    arrive. starting a new period prevents this stall */

                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_segmenter_create_segment: "
                    "track removed, forcing new period");

                cctx->force_new_period = 1;
                cur_track->has_last_segment = 0;
                channel->last_modified = ngx_time();
            }

            cur_track->last_segment_bitrate = 0;
            continue;
        }

        if (!cur_track->has_last_segment) {

            if (cur_track->last_segment_bitrate) {

                /* this track used a filler in the last segment */
                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_segmenter_create_segment: "
                    "track added, forcing new period");

                cctx->force_new_period = 1;

            } else {
                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_segmenter_create_segment: track added");
            }

            cur_track->has_last_segment = 1;
            channel->last_modified = ngx_time();
        }

        if (ngx_live_segmenter_track_create_segment(cur_track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_segmenter_create_segment: create segment failed");
            return NGX_ERROR;
        }

        media_types_mask |= 1 << cur_track->media_type;
    }

    if (!media_types_mask) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_create_segment: "
            "segment does not exist on any track");
        return NGX_ERROR;
    }

    channel->last_segment_media_types = media_types_mask;

    media_types_mask |= channel->filler_media_types;
    if (media_types_mask & missing_media_types_mask) {
        rc = ngx_live_media_info_queue_fill_gaps(channel, media_types_mask);
        switch (rc) {

        case NGX_OK:
            ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
                "ngx_live_segmenter_create_segment: "
                "gaps filled, forcing new period");

            cctx->force_new_period = 1;
            break;

        case NGX_DONE:
            break;

        default:
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segment: fill gaps failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_create_segments(ngx_live_channel_t *channel)
{
    int64_t                            min_pts;
    int64_t                            end_pts;
    int64_t                            split_pts;
    int64_t                            min_split_pts;
    uint32_t                           duration;
    uint32_t                           media_types_mask;
    ngx_int_t                          rc;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    while (cctx->count[ngx_live_track_pending] <= 0) {

        /* get the min pts of all tracks */
        ngx_live_segmenter_prepare_create_segment(channel, &media_types_mask,
            &min_pts);
        if (cctx->count[ngx_live_track_pending] > 0) {
            /* can happen if some frames got stripped */
            break;
        }

        if (media_types_mask == 0) {
            ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
                "ngx_live_segmenter_create_segments: "
                "no frames, forcing new period");

            cctx->force_new_period = 1;
            break;
        }

        if (channel->next_segment_index >= NGX_LIVE_INVALID_SEGMENT_INDEX - 1)
        {
            ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
                "ngx_live_segmenter_create_segments: invalid segment index");
            return NGX_ERROR;
        }

        /* get the target pts */
        end_pts = ngx_live_segmenter_get_segment_end_pts(channel, min_pts,
            &min_split_pts);
        if (end_pts == NGX_LIVE_INVALID_PTS) {
            return NGX_ERROR;
        }

        if (media_types_mask & (1 << KMP_MEDIA_VIDEO)) {
            /* calculate the split indexes */
            if (ngx_live_segmenter_set_split_indexes(channel, end_pts,
                &media_types_mask) != NGX_OK)
            {
                ngx_live_segmenter_dump(channel, min_pts);

                if (ngx_live_segmenter_dispose_segment(channel, end_pts)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
                continue;
            }

            split_pts = end_pts;

        } else {
            split_pts = 0;
        }

        if (channel->filler_media_types) {
            /* fill missing media types */
            rc = ngx_live_segmenter_fill(channel, media_types_mask,
                min_split_pts, &end_pts);
            if (rc != NGX_OK && rc != NGX_ABORT) {
                return NGX_ERROR;
            }

        } else {
            rc = NGX_OK;
        }

        if (end_pts != split_pts) {
            /* calculate the split indexes */
            if (ngx_live_segmenter_set_split_indexes(channel, end_pts,
                &media_types_mask) != NGX_OK)
            {
                rc = NGX_ABORT;
            }
        }

        if (rc == NGX_ABORT) {
            /* free any segments that the filler may have created */
            ngx_live_segment_cache_free_by_index(channel,
                channel->next_segment_index);

            ngx_live_segmenter_dump(channel, min_pts);

            if (ngx_live_segmenter_dispose_segment(channel, end_pts)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            continue;
        }

        /* create the segment on all tracks */
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_segmenter_create_segments: pts: %L, duration: %L",
            cctx->last_segment_end_pts, end_pts - cctx->last_segment_end_pts);

        cctx->cur_ready_duration = cctx->ready_duration;

        if (ngx_live_segmenter_create_segment(channel) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: create failed");
            return NGX_ERROR;
        }

        /* add to the timeline */
        duration = end_pts - cctx->last_segment_end_pts;

        rc = ngx_live_timelines_add_segment(channel,
            cctx->last_segment_end_pts, duration, cctx->force_new_period);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: add segment failed");
            return NGX_ERROR;
        }

        channel->next_segment_index++;
        channel->last_segment_created = ngx_time();

        cctx->last_segment_end_pts = end_pts;
        cctx->force_new_period = 0;
    }

    if (cctx->count[ngx_live_track_inactive] >= channel->tracks.count) {
        ngx_live_segmenter_channel_inactive(channel);
    }

    ngx_live_segmenter_validate_channel_ctx(channel);

    return NGX_OK;
}


static ngx_int_t
ngx_live_segmenter_add_media_info(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    ngx_int_t                        rc;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    rc = ngx_live_media_info_pending_add(track, media_info, extra_data,
        extra_data_size, ctx->frame_count);
    switch (rc) {

    case NGX_OK:
        /* force a split on the next frame to arrive */
        ctx->next_flags |= NGX_LIVE_FRAME_FLAG_SPLIT |
            NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT;

        /* fall through */

    case NGX_DONE:
        return NGX_OK;

    default:
        return rc;
    }
}

static ngx_int_t
ngx_live_segmenter_add_frame(ngx_live_add_frame_req_t *req)
{
    kmp_frame_t                       *frame_info;
    ngx_live_track_t                  *track;
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_kf_t           *kf;
    ngx_live_segmenter_frame_t        *frame;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_preset_conf_t  *spcf;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    track = req->track;
    frame_info = req->frame;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    ngx_log_debug7(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_segmenter_add_frame: track: %V, created: %L, size: %uz, "
        "dts: %L, flags: 0x%uxD, ptsDelay: %D, ptsDelta: %L",
        &track->sn.str, frame_info->created, req->size, frame_info->dts,
        frame_info->flags, frame_info->pts_delay,
        frame_info->dts + frame_info->pts_delay - ctx->last_pts);

    if (frame_info->dts >= NGX_LIVE_INVALID_PTS - frame_info->pts_delay &&
        frame_info->pts_delay >= 0)
    {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_add_frame: invalid dts %L", frame_info->dts);
        return NGX_ERROR;
    }

    if (ctx->frame_count >= NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_add_frame: frame count exceeds limit");
        return NGX_ERROR;
    }

    if (frame_info->flags & KMP_FRAME_FLAG_KEY) {
        ctx->received_key_frames++;

    } else if (ctx->frame_count <= 0 && track->media_type == KMP_MEDIA_VIDEO) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_add_frame: "
            "skipping non-key frame, created: %L, dts: %L",
            frame_info->created, frame_info->dts);
        return NGX_DONE;
    }

    ctx->received_frames++;
    ctx->received_bytes += req->size;

    frame = ngx_live_segmenter_frame_list_push(&ctx->frames, req->data_head,
        req->data_tail);
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_add_frame: push frame failed");
        return NGX_ABORT;
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    frame->id = req->frame_id;
    frame->dts = frame_info->dts;
    frame->pts = frame_info->dts + frame_info->pts_delay;
    frame->flags = frame_info->flags;
    frame->size = req->size;

    if (track->media_type != KMP_MEDIA_VIDEO ||
        (frame->flags & KMP_FRAME_FLAG_KEY))
    {
        if (ctx->next_flags) {
            ngx_log_error(NGX_LOG_INFO, &track->log, 0,
                "ngx_live_segmenter_add_frame: "
                "enabling split on current frame, pts: %L, flags: 0x%uxD",
                frame->pts, ctx->next_flags);

            frame->flags |= ctx->next_flags;
            ctx->next_flags = 0;
        }

        if (ctx->frame_count > 0) {
            if (frame->pts < ctx->last_pts - cctx->backward_jump_threshold) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_segmenter_add_frame: "
                    "enabling split due to pts backward jump, "
                    "pts: %L, last_pts: %L, delta: %L",
                    frame->pts, ctx->last_pts, ctx->last_pts - frame->pts);

                frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

            } else if (frame->pts > ctx->last_pts +
                cctx->forward_jump_threshold)
            {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_segmenter_add_frame: "
                    "enabling split due to pts forward jump, "
                    "pts: %L, last_pts: %L, delta: %L",
                    frame->pts, ctx->last_pts, frame->pts - ctx->last_pts);

                frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
            }

            if (frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
                ctx->pending_duration += ctx->last_pts - ctx->last_key_pts;

            } else {
                ctx->pending_duration += frame->pts - ctx->last_key_pts;
            }
        }

        ctx->last_key_pts = frame->pts;

        if (track->media_type == KMP_MEDIA_VIDEO) {
            kf = ngx_live_segmenter_kf_list_push(&ctx->key_frames,
                ctx->frame_count);
            if (kf == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_segmenter_add_frame: push key frame failed");
                return NGX_ABORT;
            }

            kf->pts = frame->pts;
            kf->prev_pts = ctx->last_pts;
            kf->flags = frame->flags;
        }
    }

    if (ctx->frame_count <= 0) {
        ctx->start_pts = frame->pts;

    } else if (frame->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
        ctx->split_count++;

        if (ctx->min_split_pts == NGX_LIVE_INVALID_PTS) {
            ctx->min_split_pts = ctx->last_pts;
        }
    }

    ctx->last_pts = frame->pts;
    ctx->last_data_ptr = req->data_tail->data;
    ctx->last_created = frame_info->created;

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

    default:    /* pending */
        if (ngx_live_segmenter_track_is_ready(cctx, ctx)) {
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

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

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
ngx_live_segmenter_get_min_used(ngx_live_track_t *track,
    uint32_t *segment_index, u_char **ptr)
{
    ngx_live_segmenter_track_ctx_t    *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    *segment_index = track->channel->next_segment_index;
    *ptr = (ctx->frames.part.nelts > 0) ? ctx->frames.part.elts[0].data->data :
        ctx->last_data_ptr;
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

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track == track) {
            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track,
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
ngx_live_segmenter_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;
    ngx_live_segmenter_preset_conf_t  *spcf;

    channel = track->channel;
    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    ctx->state = ngx_live_track_inactive;
    ctx->min_split_pts = NGX_LIVE_INVALID_PTS;

    ngx_live_segmenter_frame_list_init(&ctx->frames, track,
        channel->block_pool, spcf->bp_idx[NGX_LIVE_BP_PENDING_FRAME_PART]);

    ngx_live_segmenter_kf_list_init(&ctx->key_frames, track,
        channel->block_pool, spcf->bp_idx[NGX_LIVE_BP_PENDING_KF_PART]);

    ctx->inactive.handler = ngx_live_segmenter_inactive_handler;
    ctx->inactive.data = track;
    ctx->inactive.log = &track->log;

    cctx->count[ctx->state]++;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);
    if (ctx->inactive.data == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }

    channel = track->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    cctx->count[ctx->state]--;

    if (ctx->state != ngx_live_track_inactive &&
        cctx->count[ngx_live_track_inactive] >= channel->tracks.count)
    {
        ngx_live_segmenter_channel_inactive(channel);
    }

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    ngx_live_segmenter_frame_list_free(&ctx->frames);

    ngx_live_segmenter_kf_list_free(&ctx->key_frames);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_channel_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->inactive.timer_set) {
        ngx_del_timer(&ctx->inactive);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_connect(ngx_live_track_t *track, void *ectx)
{
    ngx_live_segmenter_remove_all_frames(track);

    return NGX_OK;
}

static void
ngx_live_segmenter_update_segment_duration(
    ngx_live_segmenter_channel_ctx_t *cctx,
    ngx_live_segmenter_preset_conf_t *spcf)
{
    cctx->ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->ready_threshold) / 100;
    cctx->initial_ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->initial_ready_threshold) / 100;
}

static ngx_int_t
ngx_live_segmenter_channel_init(ngx_live_channel_t *channel, void *ectx)
{
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

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    cctx->conf.segment_duration = spcf->segment_duration;
    cctx->segment_duration = ngx_live_rescale_time(cctx->conf.segment_duration,
        1000, cpcf->timescale);
    ngx_live_segmenter_update_segment_duration(cctx, spcf);
    cctx->cur_ready_duration = cctx->initial_ready_duration;

    cctx->min_segment_duration = ngx_live_rescale_time(
        spcf->min_segment_duration, 1000, cpcf->timescale);
    cctx->forward_skip_threshold = ngx_live_rescale_time(
        spcf->forward_skip_threshold, 1000, cpcf->timescale);
    cctx->forward_jump_threshold = ngx_live_rescale_time(
        spcf->forward_jump_threshold, 1000, cpcf->timescale);
    cctx->backward_jump_threshold = ngx_live_rescale_time(
        spcf->backward_jump_threshold, 1000, cpcf->timescale);
    cctx->start_truncate_limit = ngx_live_rescale_time(
        spcf->start_truncate_limit, 1000, cpcf->timescale);

    cctx->track_add_snap_range = ngx_live_rescale_time(
        spcf->track_add_snap_range, 1000, cpcf->timescale);
    cctx->track_remove_snap_range = ngx_live_rescale_time(
        spcf->track_remove_snap_range, 1000, cpcf->timescale);
    cctx->split_snap_range = ngx_live_rescale_time(
        spcf->split_snap_range, 1000, cpcf->timescale);

    cctx->candidate_margin = ngx_live_rescale_time(
        spcf->candidate_margin, 1000, cpcf->timescale);
    cctx->keyframe_alignment_margin = ngx_live_rescale_time(
        spcf->keyframe_alignment_margin, 1000, cpcf->timescale);

    cctx->create.data = channel;
    cctx->create.handler = ngx_live_segmenter_create_handler;
    cctx->create.log = &channel->log;

    cctx->force_new_period = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    if (cctx != NULL && cctx->create.posted) {
        ngx_delete_posted_event(&cctx->create);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_channel_read(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_segmenter_channel_ctx_t  *cctx;
    ngx_live_segmenter_preset_conf_t  *spcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);

    cctx->last_segment_end_pts = ngx_live_timelines_get_last_time(channel);

    if (ngx_time() < channel->last_segment_created +
        (time_t) (spcf->inactive_timeout / 1000))
    {
        cctx->cur_ready_duration = cctx->ready_duration;
        cctx->force_new_period = 0;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_set_segment_duration_internal(ngx_live_channel_t *channel,
    int64_t value, ngx_log_t *log)
{
    ngx_flag_t                         initial;
    ngx_live_core_preset_conf_t       *cpcf;
    ngx_live_segmenter_preset_conf_t  *spcf;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    spcf = ngx_live_get_module_preset_conf(channel, ngx_live_segmenter_module);
    if (value < (int64_t) spcf->min_segment_duration) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_segmenter_set_segment_duration_internal: "
            "segment duration %L smaller than configured min %M",
            value, spcf->min_segment_duration);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    cctx->conf.segment_duration = value;
    cctx->segment_duration = ngx_live_rescale_time(cctx->conf.segment_duration,
        1000, cpcf->timescale);

    initial = cctx->cur_ready_duration == cctx->initial_ready_duration;
    ngx_live_segmenter_update_segment_duration(cctx, spcf);
    cctx->cur_ready_duration = initial ? cctx->initial_ready_duration :
        cctx->ready_duration;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_set_segment_duration_internal: set to %M",
        cctx->conf.segment_duration);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_set_segment_duration(void *ctx,
    ngx_live_json_command_t *cmd, ngx_json_value_t *value, ngx_pool_t *pool)
{
    return ngx_live_segmenter_set_segment_duration_internal(
        ctx, value->v.num.num, pool->log);
}


static ngx_int_t
ngx_live_segmenter_write_setup(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_channel_t                *channel = obj;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    if (ngx_persist_write(write_ctx, &cctx->conf, sizeof(cctx->conf))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_segmenter_write_setup: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_read_setup(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_channel_t             *channel = obj;
    ngx_live_segmenter_dyn_conf_t   conf;

    if (ngx_mem_rstream_read(rs, &conf, sizeof(conf)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_segmenter_read_setup: read failed");
        return NGX_BAD_DATA;
    }

    return ngx_live_segmenter_set_segment_duration_internal(
        channel, conf.segment_duration, rs->log);
}

static ngx_persist_block_t  ngx_live_segmenter_blocks[] = {
    /*
     * persist data:
     *   ngx_live_segmenter_dyn_conf_t  conf;
     */
    { NGX_LIVE_SEGMENTER_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_segmenter_write_setup,
      ngx_live_segmenter_read_setup },

    ngx_null_persist_block
};


static ngx_int_t
ngx_live_segmenter_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_segmenter_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_json_commands_add_multi(cf, ngx_live_segmenter_dyn_cmds,
        NGX_LIVE_JSON_CTX_CHANNEL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static size_t
ngx_live_segmenter_channel_json_get_size(void *obj)
{
    return sizeof("\"segment_duration\":") - 1 + NGX_INT64_LEN;
}

static u_char *
ngx_live_segmenter_channel_json_write(u_char *p, void *obj)
{
    ngx_live_channel_t                *channel = obj;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    p = ngx_copy_fix(p, "\"segment_duration\":");
    p = ngx_sprintf(p, "%M", cctx->conf.segment_duration);
    return p;
}


static size_t
ngx_live_segmenter_track_json_get_size(void *obj)
{
    return sizeof("\"last_created\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"pending_frames\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"received_bytes\":") - 1 + NGX_OFF_T_LEN +
        sizeof(",\"received_frames\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"received_key_frames\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"dropped_frames\":") - 1 + NGX_INT_T_LEN;
}

static u_char *
ngx_live_segmenter_track_json_write(u_char *p, void *obj)
{
    ngx_live_track_t                *track = obj;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_segmenter_module);

    p = ngx_copy_fix(p, "\"last_created\":");
    p = ngx_sprintf(p, "%L", ctx->last_created);

    p = ngx_copy_fix(p, ",\"pending_frames\":");
    p = ngx_sprintf(p, "%uD", ctx->frame_count);

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

    return p;
}


static ngx_live_channel_event_t    ngx_live_segmenter_channel_events[] = {
    { ngx_live_segmenter_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_segmenter_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_segmenter_channel_read, NGX_LIVE_EVENT_CHANNEL_READ },
      ngx_live_null_event
};

static ngx_live_track_event_t      ngx_live_segmenter_track_events[] = {
    { ngx_live_segmenter_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_segmenter_track_free, NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_segmenter_track_channel_free,
        NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },
    { ngx_live_segmenter_track_connect, NGX_LIVE_EVENT_TRACK_CONNECT },
      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_segmenter_json_writers[] = {
    { { ngx_live_segmenter_channel_json_get_size,
        ngx_live_segmenter_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

    { { ngx_live_segmenter_track_json_get_size,
        ngx_live_segmenter_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_segmenter_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_segmenter_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf,
        ngx_live_segmenter_track_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_segmenter_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_live_add_media_info = ngx_live_segmenter_add_media_info;
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
    conf->forward_skip_threshold = NGX_CONF_UNSET_MSEC;
    conf->forward_jump_threshold = NGX_CONF_UNSET_MSEC;
    conf->backward_jump_threshold = NGX_CONF_UNSET_MSEC;
    conf->inactive_timeout = NGX_CONF_UNSET_MSEC;
    conf->start_truncate_limit = NGX_CONF_UNSET_MSEC;

    conf->track_add_snap_range = NGX_CONF_UNSET_MSEC;
    conf->track_remove_snap_range = NGX_CONF_UNSET_MSEC;
    conf->split_snap_range = NGX_CONF_UNSET_MSEC;

    conf->candidate_margin = NGX_CONF_UNSET_MSEC;
    conf->keyframe_alignment_margin = NGX_CONF_UNSET_MSEC;

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
                              prev->min_segment_duration, 100);

    ngx_conf_merge_msec_value(conf->forward_skip_threshold,
                              prev->forward_skip_threshold, 1000);

    ngx_conf_merge_msec_value(conf->forward_jump_threshold,
                              prev->forward_jump_threshold, 10000);

    ngx_conf_merge_msec_value(conf->backward_jump_threshold,
                              prev->backward_jump_threshold, 0);

    ngx_conf_merge_msec_value(conf->inactive_timeout,
                              prev->inactive_timeout, 10000);

    ngx_conf_merge_msec_value(conf->start_truncate_limit,
                              prev->start_truncate_limit, 5000);

    ngx_conf_merge_msec_value(conf->track_add_snap_range,
                              prev->track_add_snap_range, 500);

    ngx_conf_merge_msec_value(conf->track_remove_snap_range,
                              prev->track_remove_snap_range, 500);

    ngx_conf_merge_msec_value(conf->split_snap_range,
                              prev->split_snap_range, 500);

    ngx_conf_merge_msec_value(conf->candidate_margin,
                              prev->candidate_margin, 500);

    ngx_conf_merge_msec_value(conf->keyframe_alignment_margin,
                              prev->keyframe_alignment_margin, 500);

    ngx_conf_merge_uint_value(conf->ready_threshold,
                              prev->ready_threshold, 150);

    ngx_conf_merge_uint_value(conf->initial_ready_threshold,
                              prev->initial_ready_threshold, 200);

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_PENDING_FRAME_PART],
        sizeof(ngx_live_segmenter_frame_part_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_PENDING_KF_PART],
        sizeof(ngx_live_segmenter_kf_part_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_segmenter_module,
        sizeof(ngx_live_segmenter_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
