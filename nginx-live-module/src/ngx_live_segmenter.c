#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_live.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_timeline.h"
#include "ngx_live_segmenter.h"
#include "ngx_live_media_info.h"
#include "dvr/ngx_live_dvr.h"       // XXXX remove this


#define NGX_LIVE_TEST_KF_COUNT              (4)
#define NGX_LIVE_SEGMENTER_FRAME_PART_COUNT (32)

#define NGX_LIVE_INVALID_FRAME_INDEX        (NGX_MAX_UINT32_VALUE)

#define NGX_LIVE_INVALID_PTS                (LLONG_MAX)


#define ngx_live_segmenter_track_is_ready(cctx, ctx)                        \
    ((ctx)->last_key_pts >= (ctx)->start_pts + (cctx)->cur_ready_duration   \
    || ctx->split_count > 0)


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
    ngx_msec_t                        back_shift_margin;
    ngx_msec_t                        inactive_timeout;

    ngx_uint_t                        ready_threshold;
    ngx_uint_t                        initial_ready_threshold;
    ngx_uint_t                        split_lower_bound;
    ngx_uint_t                        split_upper_bound;
    ngx_uint_t                        track_add_margin;
    ngx_uint_t                        track_remove_margin;
} ngx_live_segmenter_preset_conf_t;

typedef struct {
    ngx_msec_t                        segment_duration;
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
    ngx_live_track_t                 *track;
    ngx_block_pool_t                 *block_pool;

    ngx_live_segmenter_frame_part_t  *last;
    ngx_live_segmenter_frame_part_t   part;
    ngx_buf_chain_t                  *last_data_part;
} ngx_live_segmenter_frame_list_t;

typedef struct {
    ngx_int_t                         state;

    ngx_live_segmenter_frame_list_t   frames;
    uint32_t                          frame_count;
    int64_t                           start_pts;
    int64_t                           last_pts;
    int64_t                           last_key_pts;
    u_char                           *last_data_ptr;

    uint32_t                          split_index;      /* volatile */

    /* Note: split_count ignores the first pending frame */
    uint32_t                          split_count;

    /* Note: min_split_pts is the pts of the frame before the split */
    int64_t                           min_split_pts;

    /* stats */
    int64_t                           last_created;
    uint32_t                          last_segment_bitrate;
    ngx_uint_t                        received_frames;
    ngx_uint_t                        received_key_frames;

    ngx_event_t                       inactive;

    unsigned                          force_split:1;
} ngx_live_segmenter_track_ctx_t;

typedef struct {
    ngx_live_segmenter_dyn_conf_t     conf;
    uint32_t                          segment_duration;
    uint32_t                          min_segment_duration;
    uint32_t                          back_shift_margin;
    uint32_t                          keyframe_alignment_margin;

    uint32_t                          ready_duration;
    uint32_t                          initial_ready_duration;
    uint32_t                          cur_ready_duration;
    uint32_t                          split_lower_bound;
    uint32_t                          split_upper_bound;
    uint32_t                          track_add_margin;
    uint32_t                          track_remove_margin;

    ngx_block_pool_t                 *block_pool;

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
    ngx_live_json_command_t *cmd, ngx_json_value_t *value);


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

    { ngx_string("segmenter_back_shift_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, back_shift_margin),
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

    { ngx_string("segmenter_split_lower_bound"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, split_lower_bound),
      NULL },

    { ngx_string("segmenter_split_upper_bound"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, split_upper_bound),
      NULL },

    { ngx_string("segmenter_track_add_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, track_add_margin),
      NULL },

    { ngx_string("segmenter_track_remove_margin"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_segmenter_preset_conf_t, track_remove_margin),
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


/* frame list */
static void
ngx_live_segmenter_frame_list_init(ngx_live_segmenter_frame_list_t *list,
    ngx_live_track_t *track, ngx_block_pool_t *block_pool)
{
    list->block_pool = block_pool;
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

        ngx_block_pool_free(list->block_pool, NGX_LIVE_BP_PENDING_FRAME_PART,
            part);
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

        last = ngx_block_pool_alloc(list->block_pool,
            NGX_LIVE_BP_PENDING_FRAME_PART);
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
    ngx_uint_t count, ngx_flag_t free_data_chains, uint32_t *split_count)
{
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
    }

    if (*split_count > 0) {

        /* free whole parts and check for splits */
        last = cur + part->nelts;

        /* skip the first frame */
        cur++;
        left--;

        for (; ; cur++, left--) {

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

                if (part != &list->part) {
                    ngx_block_pool_free(list->block_pool,
                        NGX_LIVE_BP_PENDING_FRAME_PART, part);
                }

                part = next_part;
                cur = part->elts;
                last = cur + part->nelts;
            }

            if (!left) {
                break;
            }

            if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
                (*split_count)--;
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

            if (part != &list->part) {
                ngx_block_pool_free(list->block_pool,
                    NGX_LIVE_BP_PENDING_FRAME_PART, part);
            }

            part = next_part;
        }

        cur = part->elts + left;
        list->part.nelts = part->nelts - left;
    }

    /* remove frames from the last part */
    ngx_memmove(list->part.elts, cur,
        list->part.nelts * sizeof(part->elts[0]));
    list->part.next = part->next;

    if (part != &list->part) {
        ngx_block_pool_free(list->block_pool, NGX_LIVE_BP_PENDING_FRAME_PART,
            part);
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
        "ngx_live_segmenter_get_min_split_pts: split not found");
    ngx_debug_point();
    return NGX_LIVE_INVALID_PTS;
}

static ngx_uint_t
ngx_live_segmenter_frame_list_get_index(ngx_live_segmenter_frame_list_t *list,
    int64_t target_pts, uint32_t stop_flags)
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
    if (target_pts <= cur->pts) {
        return 0;
    }

    index = 0;
    diff = ngx_abs_diff(cur->pts, target_pts);
    cur++;

    for (cur_index = 1 ;; cur++, cur_index++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        cur_diff = ngx_abs_diff(cur->pts, target_pts);
        if (cur_diff <= diff) {
            index = cur_index;
            diff = cur_diff;
        }

        if (stop_flags && (cur->flags & stop_flags) == stop_flags) {
            break;
        }
    }

    /* Note: as in 'get_key_index' each frame is considered to have its own
        pts as well as the previous pts. we prefer later frames ('<=' above)
        so also need to + 1 here */

    return index + 1;
}

static ngx_uint_t
ngx_live_segmenter_frame_list_get_key_index(
    ngx_live_segmenter_frame_list_t *list, int64_t target_pts,
    uint32_t stop_flags)
{
    int64_t                           prev_pts;
    int64_t                           diff, cur_diff;
    ngx_uint_t                        index;
    ngx_uint_t                        cur_index;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    /* handle first frame */
    prev_pts = cur->pts;
    if (target_pts <= prev_pts) {
        return 0;
    }

    index = 0;
    diff = ngx_abs_diff(prev_pts, target_pts);
    cur++;

    /* Note: when comparing key frame pts, we're using the pts of the frame
        itself AND the pts of the previous frame. when we split on some frame,
        the first segment ends on the pts preceeding the key, while the second
        segment starts with the pts of the key */

    for (cur_index = 1 ;; cur++, cur_index++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (!(cur->flags & KMP_FRAME_FLAG_KEY)) {
            prev_pts = cur->pts;
            continue;
        }

        cur_diff = ngx_abs_diff(prev_pts, target_pts);
        if (cur_diff <= diff) {
            index = cur_index;
            diff = cur_diff;
        }

        prev_pts = cur->pts;
        cur_diff = ngx_abs_diff(prev_pts, target_pts);
        if (cur_diff <= diff) {
            index = cur_index;
            diff = cur_diff;
        }

        if (stop_flags && (cur->flags & stop_flags) == stop_flags) {
            break;
        }
    }

    return index;
}

static ngx_uint_t
ngx_live_segmenter_frame_list_get_key_pts(
    ngx_live_segmenter_frame_list_t *list, int64_t pts, int64_t min_pts,
    int64_t *result, uint32_t max_index)
{
    ngx_uint_t                        index;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    index = 0;

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    for (;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (!(cur->flags & KMP_FRAME_FLAG_KEY)) {
            continue;
        }

        if (cur->pts <= min_pts) {
            goto next;
        }

        if (index < max_index) {
            result[index++] = cur->pts;
            goto next;
        }

        if (ngx_abs_diff(cur->pts, pts) > ngx_abs_diff(result[0], pts)) {
            return index;
        }

        ngx_memmove(result, result + 1, (max_index - 1) * sizeof(result[0]));
        result[max_index - 1] = cur->pts;

next:

        if ((cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) &&
            cur != list->part.elts)
        {
            break;
        }
    }

    return index;
}

static void
ngx_live_segmenter_frame_list_find_nearest_key_pts(
    ngx_live_segmenter_frame_list_t *list, ngx_uint_t count, int64_t *target,
    int64_t *result)
{
    ngx_uint_t                        j;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_part_t  *part;

    for (j = 0; j < count; j++) {
        result[j] = NGX_LIVE_INVALID_PTS;
    }

    part = &list->part;
    cur = part->elts;
    last = cur + part->nelts;

    for (;; cur++) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        if (!(cur->flags & KMP_FRAME_FLAG_KEY)) {
            continue;
        }

        for (j = 0; j < count; j++) {

            if (result[j] == NGX_LIVE_INVALID_PTS ||
                ngx_abs_diff(cur->pts, target[j]) <
                ngx_abs_diff(result[j], target[j]))
            {
                result[j] = cur->pts;
            }
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            break;
        }
    }
}

static ngx_int_t
ngx_live_segmenter_frame_list_copy(ngx_live_segmenter_frame_list_t *list,
    ngx_live_segment_t *segment, uint32_t count, int64_t *last_dts)
{
    ngx_uint_t                        left;
    size_t                            size;
    input_frame_t                    *dest, *prev_dest;
    ngx_live_segmenter_frame_t       *last;
    ngx_live_segmenter_frame_t       *src, *prev_src;
    ngx_live_segmenter_frame_part_t  *part;

    prev_src = NULL;
    prev_dest = NULL;
    size = 0;

    part = &list->part;
    src = part->elts;
    last = src + part->nelts;

    segment->frame_count = count;
    segment->start_dts = src[0].dts;
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

        dest->key_frame = (src->flags & KMP_FRAME_FLAG_KEY) ? 1 : 0;
        dest->pts_delay = src->pts - src->dts;
        dest->size = src->size;
        /* duration is set when the next frame arrives */

        size += src->size;

        prev_dest = dest;
        prev_src = src;
    }

    if (src < last && !(src->flags & NGX_LIVE_FRAME_FLAG_SPLIT)) {
        *last_dts = src->dts;
        prev_dest->duration = src->dts - prev_src->dts;

    } else {
        *last_dts = prev_src->dts;
        prev_dest->duration = 0;
    }

    segment->data_tail = ngx_live_segmenter_terminate_frame_chain(prev_src);
    segment->data_size = size;

    return NGX_OK;
}


/* main */
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
    int64_t                           prev_pts;
    int64_t                           last_key_pts;
    int64_t                           min_split_pts;
    uint32_t                          frame_count;
    uint32_t                          split_count;
    ngx_buf_chain_t                  *buf_chain;
    ngx_live_segmenter_frame_t       *cur, *last;
    ngx_live_segmenter_frame_t       *last_frame;
    ngx_live_segmenter_track_ctx_t   *ctx;
    ngx_live_segmenter_frame_part_t  *part;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    if (ctx->frames.part.nelts == 0) {

        if (ctx->frame_count != 0) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "nonzero frame count %uD with no frames",
                ctx->frame_count);
            ngx_debug_point();
        }

        if (ctx->split_count != 0) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "nonzero split count %uD with no frames",
                ctx->split_count);
            ngx_debug_point();
        }

        if (ctx->min_split_pts != NGX_LIVE_INVALID_PTS) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "nonzero split pts %L with no frames",
                ctx->min_split_pts);
            ngx_debug_point();
        }

        if (ctx->frames.last_data_part != NULL) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_segmenter_validate_track_ctx: "
                "last data part is not null when no frames");
            ngx_debug_point();
        }

        return;
    }

    frame_count = 0;
    last_frame = NULL;
    last_key_pts = 0;
    split_count = 0;
    min_split_pts = NGX_LIVE_INVALID_PTS;
    prev_pts = NGX_LIVE_INVALID_PTS;

    part = &ctx->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    if (ctx->start_pts != part->elts[0].pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "start pts %L doesn't match first frame pts %L",
            ctx->start_pts, part->elts[0].pts);
        ngx_debug_point();
    }

    for (;; cur++) {

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
            last_key_pts = cur->pts;
        }

        if (cur->flags & NGX_LIVE_FRAME_FLAG_SPLIT &&
            prev_pts != NGX_LIVE_INVALID_PTS)
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
            "frame count %uD different than actual %uD",
            ctx->frame_count, frame_count);
        ngx_debug_point();
    }

    if (ctx->split_count != split_count) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "split count %uD different than actual %uD",
            ctx->split_count, split_count);
        ngx_debug_point();
    }

    if (ctx->min_split_pts != min_split_pts) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_segmenter_validate_track_ctx: "
            "min split pts %L different than actual %L",
            ctx->min_split_pts, min_split_pts);
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
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
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
ngx_live_segmenter_remove_frames(ngx_live_track_t *track, ngx_uint_t count,
    ngx_flag_t free_data_chains)
{
    uint32_t                           initial_split_count;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    if (count <= 0) {
        return;
    }

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_segmenter_module);

    // XXXXXXX postpone to after saving state + dvr
    if (track->input.ack_frames != NULL) {
        track->input.ack_frames(track, count);
    }

    ctx->frame_count -= count;

    /* update media info */
    ngx_live_media_info_pending_remove_frames(track, count);

    /* update frame list */
    initial_split_count = ctx->split_count;

    ngx_live_segmenter_frame_list_remove(&ctx->frames, count, free_data_chains,
        &ctx->split_count);

    /* update start pts / split count / ready status */
    if (ctx->frames.part.nelts > 0) {
        ctx->start_pts = ctx->frames.part.elts[0].pts;

        if (ctx->frames.part.elts[0].flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            ctx->split_count--;
        }

        if (ctx->state == ngx_live_track_ready &&
            !ngx_live_segmenter_track_is_ready(cctx, ctx))
        {
            ngx_live_segmenter_set_state(track, ngx_live_track_pending);
        }

    } else if (ctx->state == ngx_live_track_ready) {
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
    }

    /* if splits were removed, enable split on the next frame */
    if (ctx->split_count != initial_split_count) {

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_remove_frames: "
            "splits removed, enabling split on next frame");

        if (ctx->frames.part.nelts > 0) {
            ctx->frames.part.elts[0].flags |= NGX_LIVE_FRAME_FLAG_SPLIT;

        } else {
            ctx->force_split = 1;
        }
    }

    /* update split pts */
    if (ctx->split_count != initial_split_count) {
        ctx->min_split_pts = ctx->split_count > 0 ?
            ngx_live_segmenter_frame_list_get_min_split_pts(&ctx->frames) :
            NGX_LIVE_INVALID_PTS;
    }

    /* update ready status */

    ngx_live_segmenter_validate_track_ctx(track);
}

static void
ngx_live_segmenter_remove_all_frames(ngx_live_track_t *track)
{
    ngx_live_segmenter_track_ctx_t    *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    ngx_live_media_info_pending_free_all(track);

    ngx_live_segmenter_frame_list_free(&ctx->frames);
    ngx_live_segmenter_frame_list_reset(&ctx->frames);

    ctx->frame_count = 0;
    ctx->split_count = 0;
    ctx->min_split_pts = NGX_LIVE_INVALID_PTS;

    /* update ready status */
    if (ctx->state == ngx_live_track_ready) {
        ngx_live_segmenter_set_state(track, ngx_live_track_pending);
    }

    ngx_live_segmenter_validate_track_ctx(track);
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

    *min_pts = NGX_LIVE_INVALID_PTS;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
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

            if (cur_track->media_type == MEDIA_TYPE_VIDEO) {
                split_index = ngx_live_segmenter_frame_list_get_key_index(
                    &cur_ctx->frames, cctx->last_segment_end_pts, 0);

            } else {
                split_index = ngx_live_segmenter_frame_list_get_index(
                    &cur_ctx->frames, cctx->last_segment_end_pts, 0);
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

        if (cur_ctx->start_pts < *min_pts) {
            *min_pts = cur_ctx->start_pts;
        }
    }
}


static ngx_live_track_t*
ngx_live_segmenter_get_base_track(ngx_live_channel_t *channel,
    int64_t min_split_pts, int64_t max_split_pts, int64_t *split_pts)
{
    ngx_queue_t                         *q;

    struct {
        int64_t                          split_pts;
        ngx_live_track_t                *track;
        ngx_live_segmenter_track_ctx_t  *ctx;
    } cur, base;

    ngx_memzero(&base, sizeof(base));

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur.track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur.ctx = ngx_live_track_get_module_ctx(cur.track,
            ngx_live_segmenter_module);

        if (cur.ctx->frame_count <= 0) {
            continue;
        }

        /* check for splits - can be due to:
            1. media info change
            2. pts jump (flagged by syncer)
            3. track added
            4. track removed */

        if (!cur.track->has_last_segment &&
            cur.ctx->start_pts > min_split_pts &&
            cur.ctx->start_pts < max_split_pts)
        {
            cur.split_pts = cur.ctx->start_pts;

        } else if (cur.ctx->min_split_pts < max_split_pts) {
            cur.split_pts = cur.ctx->min_split_pts;

        } else if (cur.ctx->state != ngx_live_track_ready &&
            cur.ctx->last_pts > min_split_pts &&
            cur.ctx->last_pts < max_split_pts)
        {
            cur.split_pts = cur.ctx->last_pts;

        } else {
            cur.split_pts = NGX_LIVE_INVALID_PTS;
        }

        if (base.track == NULL) {
            base = cur;
            continue;
        }

        /* if there are splits within this segment, prefer the max split pts */
        if (cur.split_pts != NGX_LIVE_INVALID_PTS ||
            base.split_pts != NGX_LIVE_INVALID_PTS)
        {
            if (cur.split_pts != NGX_LIVE_INVALID_PTS &&
                (base.split_pts == NGX_LIVE_INVALID_PTS ||
                cur.split_pts > base.split_pts))
            {
                base = cur;
            }
            continue;
        }

        /* prefer video tracks */
        if (base.track->media_type != cur.track->media_type) {

            if (cur.track->media_type < base.track->media_type) {
                base = cur;
            }
            continue;
        }
    }

    *split_pts = base.split_pts;

    return base.track;
}

static ngx_uint_t
ngx_live_segmenter_get_keyframe_pts(ngx_live_segmenter_track_ctx_t *ctx,
    int64_t pts, int64_t *result, uint32_t max_index)
{
    ngx_uint_t  index;

    index = ngx_live_segmenter_frame_list_get_key_pts(&ctx->frames, pts,
        ctx->start_pts, result, max_index);

    if (ctx->state != ngx_live_track_inactive || ctx->split_count > 0) {
        return index;
    }

    /* track is inactive, treat the last frame as key frame */
    if (index < max_index) {
        result[index++] = ctx->last_pts;

    } else if (ngx_abs_diff(ctx->last_pts, pts) <=
        ngx_abs_diff(result[0], pts))
    {
        ngx_memmove(result, result + 1, (max_index - 1) * sizeof(result[0]));
        result[max_index - 1] = ctx->last_pts;
    }

    return index;
}

static void
ngx_live_segmenter_find_nearest_keyframe_pts(
    ngx_live_segmenter_track_ctx_t *ctx, ngx_uint_t count, int64_t *target,
    int64_t *result)
{
    ngx_uint_t  j;

    ngx_live_segmenter_frame_list_find_nearest_key_pts(&ctx->frames, count,
        target, result);

    if (ctx->state != ngx_live_track_inactive || ctx->split_count > 0) {
        return;
    }

    /* track is inactive, treat the last frame as key frame */
    for (j = 0; j < count; j++) {

        if (result[j] == NGX_LIVE_INVALID_PTS ||
            ngx_abs_diff(ctx->last_pts, target[j]) <
            ngx_abs_diff(result[j], target[j]))
        {
            result[j] = ctx->last_pts;
        }
    }
}

static int64_t
ngx_live_segmenter_track_get_segment_end_pts(ngx_live_track_t *base_track,
    int64_t boundary_pts)
{
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

    if (base_track->media_type != KMP_MEDIA_VIDEO) {
        return boundary_pts;
    }

    /* find the keyframes of the base track closest to boundary */
    kf_count = ngx_live_segmenter_get_keyframe_pts(ctx, boundary_pts,
        kf_pts, sizeof(kf_pts) / sizeof(kf_pts[0]));
    if (kf_count <= 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_track_get_segment_end_pts: no key frames");
        return NGX_LIVE_INVALID_PTS;
    }

    ngx_memcpy(kf_min, kf_pts, sizeof(kf_min));
    ngx_memcpy(kf_max, kf_pts, sizeof(kf_max));

    for (q = ngx_queue_next(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
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
        for (j = 0; j < kf_count; j++) {

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
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    min_diff *= 2;
    min_diff += cctx->keyframe_alignment_margin;

    /* choose the pts closest to the boundary, with span smaller than min */
    target_pts = NGX_LIVE_INVALID_PTS;
    for (j = 0; j < kf_count; j++) {

        cur_diff = kf_max[j] - kf_min[j];
        if (cur_diff > min_diff) {
            continue;
        }

        cur_pts = (kf_max[j] + kf_min[j]) / 2;
        if (target_pts == NGX_LIVE_INVALID_PTS ||
            ngx_abs_diff(cur_pts, boundary_pts) <
            ngx_abs_diff(target_pts, boundary_pts))
        {
            target_pts = cur_pts;
        }
    }

    if (target_pts == NGX_LIVE_INVALID_PTS) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_track_get_segment_end_pts: no target pts");
        return NGX_LIVE_INVALID_PTS;
    }

    return target_pts;
}

static int64_t
ngx_live_segmenter_get_segment_end_pts(ngx_live_channel_t *channel,
    int64_t min_pts)
{
    int64_t                            target_pts;
    int64_t                            boundary_pts;
    int64_t                            min_split_pts;
    int64_t                            max_split_pts;
    int64_t                            min_target_pts;
    ngx_live_track_t                  *base_track;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    /* get the segment boundary pts */
    boundary_pts = cctx->last_segment_end_pts + cctx->segment_duration;
    if (min_pts > boundary_pts) {

        if (cctx->last_segment_end_pts) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: "
                "pts forward jump, forcing new period, "
                "min_pts: %L, boundary_pts: %L",
                min_pts, boundary_pts);
        }

        cctx->last_segment_end_pts = min_pts;
        cctx->force_new_period = 1;

        boundary_pts = min_pts + cctx->segment_duration;
    }

    /* find the base track, consider only splits between the bounds */
    min_split_pts = cctx->last_segment_end_pts + cctx->split_lower_bound;
    max_split_pts = cctx->last_segment_end_pts + cctx->split_upper_bound;

    base_track = ngx_live_segmenter_get_base_track(channel,
        min_split_pts, max_split_pts, &target_pts);
    if (base_track == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_get_segment_end_pts: no base track");
        return NGX_LIVE_INVALID_PTS;
    }

    if (target_pts == NGX_LIVE_INVALID_PTS) {
        /* use the base track to determine the target pts */
        target_pts = ngx_live_segmenter_track_get_segment_end_pts(base_track,
            boundary_pts);
        if (target_pts == NGX_LIVE_INVALID_PTS) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_get_segment_end_pts: "
                "failed to get end pts");
            return NGX_LIVE_INVALID_PTS;
        }
    }

    min_target_pts = cctx->last_segment_end_pts + cctx->min_segment_duration;
    if (target_pts < min_target_pts) {
        target_pts = min_target_pts;
    }

    ngx_log_error(NGX_LOG_INFO, &base_track->log, 0,
        "ngx_live_segmenter_get_segment_end_pts: duration: %uD, pts %L",
        (uint32_t) (target_pts - cctx->last_segment_end_pts), target_pts);

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

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    rc = NGX_OK;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->frame_count <= 0) {
            cur_ctx->split_index = 0;
            continue;
        }

        /* track removed + last pts before target -> use all frames */
        if (cur_ctx->state != ngx_live_track_ready &&
            cur_ctx->split_count <= 0 &&
            cur_ctx->last_pts <= target_pts + cctx->track_remove_margin)
        {
            cur_ctx->split_index = cur_ctx->frame_count;
            continue;
        }

        /* track added + start pts after target -> add it next time */
        if (!cur_track->has_last_segment &&
            cur_ctx->start_pts > target_pts - cctx->track_add_margin)
        {
            cur_ctx->split_index = 0;
            continue;
        }

        /* find the key frame closest to target */
        if (cur_track->media_type == MEDIA_TYPE_VIDEO) {
            cur_ctx->split_index = ngx_live_segmenter_frame_list_get_key_index(
                &cur_ctx->frames, target_pts, NGX_LIVE_FRAME_FLAG_SPLIT);

        } else {
            cur_ctx->split_index = ngx_live_segmenter_frame_list_get_index(
                &cur_ctx->frames, target_pts, NGX_LIVE_FRAME_FLAG_SPLIT);
        }

        if (cur_ctx->split_index <= 0 &&
            (cur_track->has_last_segment || cctx->force_new_period))
        {
            ngx_log_error(NGX_LOG_ERR, &cur_track->log, 0,
                "ngx_live_segmenter_set_split_indexes: "
                "empty segment, target_pts: %L", target_pts);
            rc = NGX_ERROR;
            continue;
        }
    }

    return rc;
}

static ngx_int_t
ngx_live_segmenter_dispose_segment(ngx_live_channel_t *channel)
{
    ngx_flag_t                       removed;
    ngx_queue_t                     *q;
    ngx_live_track_t                *cur_track;
    ngx_live_segmenter_track_ctx_t  *cur_ctx;

    removed = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->split_index <= 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, &cur_track->log, 0,
            "ngx_live_segmenter_dispose_segment: "
            "removing %uD frames, track: %V",
            cur_ctx->split_index, &cur_track->sn.str);

        ngx_live_segmenter_remove_frames(cur_track, cur_ctx->split_index, 1);

        removed = 1;
    }

    if (!removed) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_segmenter_dispose_segment: no frames removed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_create_segment(ngx_live_track_t *track,
    uint32_t segment_index)
{
    int64_t                          last_dts;
    ngx_int_t                        rc;
    media_info_t                    *media_info;
    kmp_media_info_t                *kmp_media_info;
    ngx_live_segment_t              *segment;
    ngx_live_core_preset_conf_t     *cpcf;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    /* get the media info */
    ngx_live_media_info_pending_create_segment(track, segment_index);

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
        ctx->split_index, &last_dts);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_track_create_segment: copy frames failed");
        ngx_live_segment_cache_free(track, segment);
        return rc;
    }

    ngx_live_segment_cache_validate(segment);

    if (last_dts > segment->start_dts) {
        cpcf = ngx_live_get_module_preset_conf(track->channel,
            ngx_live_core_module);

        ctx->last_segment_bitrate = (segment->data_size * 8 * cpcf->timescale)
            / (last_dts - segment->start_dts);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, &track->log, 0,
        "ngx_live_segmenter_track_create_segment: "
        "created segment %uD with %uD frames, track: %V",
        segment_index, ctx->split_index, &track->sn.str);

    ngx_live_segmenter_remove_frames(track, ctx->split_index, 0);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_create_segment(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    uint32_t                           last_segment_media_types;
    ngx_int_t                          rc;
    ngx_flag_t                         missing;
    ngx_queue_t                       *q;
    ngx_live_track_t                  *cur_track;
    ngx_live_segmenter_track_ctx_t    *cur_ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    missing = 0;
    last_segment_media_types = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_segmenter_module);

        if (cur_ctx->split_index <= 0) {
            missing = 1;

            if (cur_track->has_last_segment) {
                ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                    "ngx_live_segmenter_create_segment: track removed");

                cur_track->has_last_segment = 0;
                channel->last_modified = ngx_time();
            }
            continue;
        }

        if (cur_ctx->frames.part.elts[0].flags & NGX_LIVE_FRAME_FLAG_SPLIT) {
            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_segmenter_create_segment: "
                "split enabled, forcing new period");

            cctx->force_new_period = 1;
        }

        if (ngx_live_segmenter_track_create_segment(cur_track, segment_index)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_segmenter_create_segment: create segment failed");
            return NGX_ERROR;
        }

        if (!cur_track->has_last_segment) {
            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
                "ngx_live_segmenter_create_segment: track added");

            cur_track->has_last_segment = 1;
            channel->last_modified = ngx_time();
        }

        last_segment_media_types |= 1 << cur_track->media_type;
    }

    channel->last_segment_media_types = last_segment_media_types;

    if (missing) {
        rc = ngx_live_media_info_queue_fill_gaps(channel, segment_index);
        switch (rc) {

        case NGX_OK:
            ngx_log_error(NGX_LOG_INFO, &cur_track->log, 0,
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
    uint32_t                           duration;
    uint32_t                           segment_index;
    ngx_int_t                          rc;
    ngx_flag_t                         exists;
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

        if (min_pts == NGX_LIVE_INVALID_PTS) {
            ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
                "ngx_live_segmenter_create_segments: "
                "no frames, forcing new period");

            cctx->force_new_period = 1;
            break;
        }

        end_pts = ngx_live_segmenter_get_segment_end_pts(channel, min_pts);
        if (end_pts == NGX_LIVE_INVALID_PTS) {
            return NGX_ERROR;
        }

        segment_index = channel->next_segment_index;

        /* calculate the split indexes */
        if (ngx_live_segmenter_set_split_indexes(channel, end_pts)
            != NGX_OK)
        {
            if (ngx_live_segmenter_dispose_segment(channel) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
                "ngx_live_segmenter_create_segments: "
                "empty segment, forcing new period");

            cctx->force_new_period = 1;
            cctx->last_segment_end_pts = end_pts;
            continue;
        }

        /* create the segment on all tracks */
        cctx->cur_ready_duration = cctx->ready_duration;

        if (ngx_live_segmenter_create_segment(channel, segment_index)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_segmenter_create_segments: create failed");
            return NGX_ERROR;
        }

        /* add to the timeline */
        duration = end_pts - cctx->last_segment_end_pts;

        rc = ngx_live_timelines_add_segment(channel, segment_index,
            cctx->last_segment_end_pts, duration, cctx->force_new_period);
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

        channel->next_segment_index = segment_index + 1;
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

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    rc = ngx_live_media_info_pending_add(track, media_info, extra_data,
        extra_data_size, ctx->frame_count);
    switch (rc) {

    case NGX_OK:
        ctx->force_split = 1;   /* force a split on the next frame to arrive */

        /* fall through */

    case NGX_DONE:
        return NGX_OK;

    default:
        return rc;
    }
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

    if (frame_info->dts >= NGX_LIVE_INVALID_PTS - frame_info->pts_delay) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_add_frame: invalid dts %L", frame_info->dts);
        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, &track->log, 0,
        "ngx_live_segmenter_add_frame: track: %V, created: %L, size: %uz, "
        "dts: %L, flags: 0x%uxD, ptsDelay: %uD",
        &track->sn.str, frame_info->created, size, frame_info->dts,
        frame_info->flags, frame_info->pts_delay);

    channel = track->channel;
    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_segmenter_module);

    ctx->received_frames++;

    if (frame_info->flags & KMP_FRAME_FLAG_KEY) {
        ctx->received_key_frames++;
    }

    if (ctx->frame_count >= NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_segmenter_add_frame: frame count exceeds limit");
        return NGX_ERROR;
    }

    frame = ngx_live_segmenter_frame_list_push(&ctx->frames, data_head,
        data_tail);
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_segmenter_add_frame: push frame failed");
        return NGX_ABORT;
    }

    frame->dts = frame_info->dts;
    frame->pts = frame_info->dts + frame_info->pts_delay;
    frame->flags = frame_info->flags;
    frame->size = size;

    if (ctx->force_split) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_live_segmenter_add_frame: "
            "enabling split on current frame, pts: %L", frame->pts);

        frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
        ctx->force_split = 0;
    }

    if (track->media_type != KMP_MEDIA_VIDEO ||
        (frame->flags & KMP_FRAME_FLAG_KEY))
    {
        if (frame->pts < ctx->last_pts - cctx->back_shift_margin) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_segmenter_add_frame: "
                "pts backward jump, pts: %L, last_pts: %L",
                frame->pts, ctx->last_pts);

            frame->flags |= NGX_LIVE_FRAME_FLAG_SPLIT;
        }

        ctx->last_key_pts = frame->pts;
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
    ctx->last_data_ptr = data_tail->data;
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
ngx_live_segmenter_get_min_used(ngx_live_track_t *track,
    uint32_t *segment_index, u_char **ptr)
{
    ngx_live_segmenter_track_ctx_t    *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

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
    ctx->min_split_pts = NGX_LIVE_INVALID_PTS;

    ngx_live_segmenter_frame_list_init(&ctx->frames, track, cctx->block_pool);

    ctx->inactive.handler = ngx_live_segmenter_inactive_handler;
    ctx->inactive.data = track;
    ctx->inactive.log = &track->log;

    cctx->count[ctx->state]++;

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_track_free(ngx_live_track_t *track)
{
    ngx_live_channel_t                *channel;
    ngx_live_segmenter_track_ctx_t    *ctx;
    ngx_live_segmenter_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);
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

static void
ngx_live_segmenter_update_segment_duration(
    ngx_live_segmenter_channel_ctx_t *cctx,
    ngx_live_segmenter_preset_conf_t *spcf)
{
    cctx->ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->ready_threshold) / 100;
    cctx->initial_ready_duration = ((uint64_t) cctx->segment_duration *
        spcf->initial_ready_threshold) / 100;
    cctx->split_lower_bound = ((uint64_t) cctx->segment_duration *
        spcf->split_lower_bound) / 100;
    cctx->split_upper_bound = ((uint64_t) cctx->segment_duration *
        spcf->split_upper_bound) / 100;
    cctx->track_add_margin = ((uint64_t) cctx->segment_duration *
        spcf->track_add_margin) / 100;
    cctx->track_remove_margin = ((uint64_t) cctx->segment_duration *
        spcf->track_remove_margin) / 100;
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
    ngx_live_segmenter_update_segment_duration(cctx, spcf);
    cctx->cur_ready_duration = cctx->initial_ready_duration;

    cctx->min_segment_duration = ngx_live_rescale_time(
        spcf->min_segment_duration, 1000, cpcf->timescale);
    cctx->back_shift_margin = ngx_live_rescale_time(
        spcf->back_shift_margin, 1000, cpcf->timescale);
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
    ngx_live_segmenter_update_segment_duration(cctx, spcf);
    cctx->cur_ready_duration = initial ? cctx->initial_ready_duration :
        cctx->ready_duration;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_segmenter_set_segment_duration: set to %M",
        cctx->conf.segment_duration);

    return NGX_OK;
}

static ngx_int_t
ngx_live_segmenter_preconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_command_t  *cmd, *c;

    for (c = ngx_live_segmenter_dyn_cmds; c->name.len; c++) {
        cmd = ngx_live_json_commands_add(cf, &c->name,
            NGX_LIVE_JSON_CTX_CHANNEL);
        if (cmd == NULL) {
            return NGX_ERROR;
        }

        cmd->set_handler = c->set_handler;
        cmd->type = c->type;
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
        sizeof(",\"last_segment_bitrate\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"pending_frames\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"received_frames\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"received_key_frames\":") - 1 + NGX_INT_T_LEN;
}

static u_char *
ngx_live_segmenter_track_json_write(u_char *p, void *obj)
{
    ngx_live_track_t                *track = obj;
    ngx_live_segmenter_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_segmenter_module);

    p = ngx_copy_fix(p, "\"last_created\":");
    p = ngx_sprintf(p, "%L", ctx->last_created);

    p = ngx_copy_fix(p, ",\"last_segment_bitrate\":");
    p = ngx_sprintf(p, "%uD", ctx->last_segment_bitrate);

    p = ngx_copy_fix(p, ",\"pending_frames\":");
    p = ngx_sprintf(p, "%uD", ctx->frame_count);

    p = ngx_copy_fix(p, ",\"received_frames\":");
    p = ngx_sprintf(p, "%ui", ctx->received_frames);

    if (track->media_type == KMP_MEDIA_VIDEO) {
        p = ngx_copy_fix(p, ",\"received_key_frames\":");
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
    writer->get_size = ngx_live_segmenter_track_json_get_size;
    writer->write = ngx_live_segmenter_track_json_write;

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
    conf->back_shift_margin = NGX_CONF_UNSET_MSEC;
    conf->inactive_timeout = NGX_CONF_UNSET_MSEC;
    conf->ready_threshold = NGX_CONF_UNSET_UINT;
    conf->initial_ready_threshold = NGX_CONF_UNSET_UINT;
    conf->split_lower_bound = NGX_CONF_UNSET_UINT;
    conf->split_upper_bound = NGX_CONF_UNSET_UINT;
    conf->track_add_margin = NGX_CONF_UNSET_UINT;
    conf->track_remove_margin = NGX_CONF_UNSET_UINT;

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

    ngx_conf_merge_msec_value(conf->back_shift_margin,
                              prev->back_shift_margin, 0);

    ngx_conf_merge_msec_value(conf->inactive_timeout,
                              prev->inactive_timeout, 10000);

    ngx_conf_merge_uint_value(conf->ready_threshold,
                              prev->ready_threshold, 150);

    ngx_conf_merge_uint_value(conf->initial_ready_threshold,
                              prev->initial_ready_threshold, 200);

    ngx_conf_merge_uint_value(conf->split_lower_bound,
                              prev->split_lower_bound, 25);

    ngx_conf_merge_uint_value(conf->split_upper_bound,
                              prev->split_upper_bound, 150);

    ngx_conf_merge_uint_value(conf->track_add_margin,
                              prev->track_add_margin, 10);

    ngx_conf_merge_uint_value(conf->track_remove_margin,
                              prev->track_remove_margin, 10);

    return NGX_CONF_OK;
}
