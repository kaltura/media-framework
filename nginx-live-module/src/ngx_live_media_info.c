#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_media_info.h"
#include "ngx_live_segment_info.h"
#include "ngx_live_segment_cache.h"
#include "ngx_live_timeline.h"


#define NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_QUEUE                              \
    NGX_KSMP_BLOCK_MEDIA_INFO_QUEUE

#define NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SETUP   (0x7073696d)    /* misp */

#define NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SOURCE  (0x6372736d)    /* msrc */


#define NGX_LIVE_TRACK_MAX_GROUP_ID_LEN  (32)
#define NGX_LIVE_MEDIA_INFO_FREE_PERIOD  (64)


enum {
    NGX_LIVE_BP_MEDIA_INFO_NODE,
    NGX_LIVE_BP_COUNT
};


typedef void *(*ngx_live_media_info_alloc_pt)(void *ctx, size_t size);

struct ngx_live_media_info_node_s {
    ngx_rbtree_node_t             node;
    ngx_queue_t                   queue;
    ngx_live_media_info_t         media_info;
    uint32_t                      track_id;
    uint32_t                      frame_index_delta;    /* used when pending */
    ngx_ksmp_media_info_stats_t   stats;
};


typedef struct {
    ngx_queue_t                   pending;
    uint32_t                      delta_sum;

    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   active;
    uint32_t                      added;
    uint32_t                      removed;

    ngx_json_str_t                group_id;
    u_char                        group_id_buf
                                            [NGX_LIVE_TRACK_MAX_GROUP_ID_LEN];

    ngx_live_track_t             *source;
    uint32_t                      source_refs;
} ngx_live_media_info_track_ctx_t;

typedef struct {
    uint32_t                      min_free_index;
} ngx_live_media_info_channel_ctx_t;


typedef struct {
    ngx_queue_t                  *q;
    ngx_queue_t                  *sentinel;
    uint32_t                      track_id;
} ngx_live_media_info_own_iter_t;


typedef struct {
    uint32_t                      track_id;
    uint32_t                      source_id;
} ngx_live_media_info_snap_t;


typedef struct {
    ngx_uint_t                    bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_media_info_preset_conf_t;


#include "ngx_live_media_info_json.h"


static ngx_int_t ngx_live_media_info_queue_copy(ngx_live_track_t *track,
    kmp_media_info_t *target_media_info, uint32_t segment_index);

static ngx_int_t ngx_live_media_info_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_media_info_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_media_info_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_media_info_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_live_media_info_set_group_id(
    ngx_live_json_cmds_ctx_t *jctx, ngx_live_json_cmd_t *cmd,
    ngx_json_value_t *value);


static ngx_live_module_t  ngx_live_media_info_module_ctx = {
    ngx_live_media_info_preconfiguration,     /* preconfiguration */
    ngx_live_media_info_postconfiguration,    /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_media_info_create_preset_conf,   /* create preset configuration */
    ngx_live_media_info_merge_preset_conf,    /* merge preset configuration */
};

ngx_module_t  ngx_live_media_info_module = {
    NGX_MODULE_V1,
    &ngx_live_media_info_module_ctx,          /* module context */
    NULL,                                     /* module directives */
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


static ngx_live_json_cmd_t  ngx_live_media_info_dyn_cmds[] = {

    { ngx_string("group_id"), NGX_JSON_STRING,
      ngx_live_media_info_set_group_id },

      ngx_live_null_json_cmd
};


/* utility */

ngx_int_t
ngx_live_media_info_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_media_info_persist_t *mp, ngx_live_media_info_t *media_info)
{
    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (mp != NULL &&
        ngx_persist_write(write_ctx, mp, sizeof(*mp)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_persist_write(write_ctx, &media_info->info,
        sizeof(media_info->info)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    if (ngx_persist_write(write_ctx, media_info->extra.data,
        media_info->extra.len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);  /* media info */

    return NGX_OK;
}


/* node */

static void
ngx_live_media_info_node_free(ngx_live_channel_t *channel,
    ngx_live_media_info_node_t *node)
{
    ngx_live_media_info_preset_conf_t  *mipcf;

    mipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_media_info_module);

    if (node->media_info.extra.data != NULL) {
        ngx_live_channel_auto_free(channel, node->media_info.extra.data);
    }

    if (node->queue.next != NULL) {
        ngx_queue_remove(&node->queue);
    }

    ngx_block_pool_free(channel->block_pool,
        mipcf->bp_idx[NGX_LIVE_BP_MEDIA_INFO_NODE], node);
}

static ngx_int_t
ngx_live_media_info_node_create(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, ngx_live_media_info_node_t **result)
{
    ngx_live_channel_t                 *channel;
    ngx_live_media_info_node_t         *node;
    ngx_live_media_info_preset_conf_t  *mipcf;

    if (media_info->media_type != track->media_type) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "attempt to change media type from %uD to %uD",
            track->media_type, media_info->media_type);
        return NGX_BAD_DATA;
    }

    channel = track->channel;

    if (media_info->timescale != channel->timescale) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "input timescale %uD doesn't match channel timescale %ui",
            media_info->timescale, channel->timescale);
        return NGX_BAD_DATA;
    }


    mipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_media_info_module);

    node = ngx_block_pool_calloc(channel->block_pool,
        mipcf->bp_idx[NGX_LIVE_BP_MEDIA_INFO_NODE]);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: alloc failed");
        return NGX_ERROR;
    }

    node->media_info.info = *media_info;

    if (extra_data_size > 0) {

        node->media_info.extra.data = ngx_live_channel_auto_alloc(channel,
            extra_data_size);
        if (node->media_info.extra.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_node_create: alloc failed, size: %uD",
                extra_data_size);
            ngx_live_media_info_node_free(channel, node);
            return NGX_ERROR;
        }

        if (ngx_buf_chain_copy(&extra_data, node->media_info.extra.data,
            extra_data_size) == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_media_info_node_create: failed to copy extra data");
            ngx_live_media_info_node_free(channel, node);
            return NGX_ERROR;
        }

    } else {
        node->media_info.extra.data = NULL;
    }

    node->media_info.extra.len = extra_data_size;

    node->track_id = track->in.key;

    *result = node;

    return NGX_OK;
}

static ngx_live_media_info_node_t *
ngx_live_media_info_node_clone(ngx_live_channel_t *channel,
    ngx_live_media_info_node_t *src)
{
    ngx_live_media_info_node_t         *node;
    ngx_live_media_info_preset_conf_t  *mipcf;

    mipcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_media_info_module);

    node = ngx_block_pool_alloc(channel->block_pool,
        mipcf->bp_idx[NGX_LIVE_BP_MEDIA_INFO_NODE]);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_node_clone: alloc failed (1)");
        return NULL;
    }

    *node = *src;

    node->queue.next = NULL;

    if (src->media_info.extra.len <= 0) {
        node->media_info.extra.data = NULL;
        return node;
    }

    node->media_info.extra.data = ngx_live_channel_auto_alloc(channel,
        src->media_info.extra.len);
    if (node->media_info.extra.data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_node_clone: alloc failed (2)");
        ngx_block_pool_free(channel->block_pool,
            mipcf->bp_idx[NGX_LIVE_BP_MEDIA_INFO_NODE], node);
        return NULL;
    }

    ngx_memcpy(node->media_info.extra.data, src->media_info.extra.data,
        src->media_info.extra.len);

    return node;
}

static ngx_flag_t
ngx_live_media_info_node_compare(ngx_live_media_info_node_t *node,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    return ngx_memcmp(&node->media_info.info, media_info,
        sizeof(node->media_info.info)) == 0 &&
        node->media_info.extra.len == extra_data_size &&
        ngx_buf_chain_compare(extra_data, node->media_info.extra.data,
            extra_data_size) == 0;
}

static ngx_int_t
ngx_live_media_info_node_write(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_media_info_node_t *node)
{
    ngx_live_media_info_persist_t  mp;

    mp.track_id = node->track_id;
    mp.segment_index = node->node.key;
    mp.stats = node->stats;

    return ngx_live_media_info_write(write_ctx, &mp, &node->media_info);
}


/* active */

static void
ngx_live_media_info_queue_push(ngx_live_track_t *track,
    ngx_live_media_info_node_t *node, uint32_t segment_index)
{
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    node->node.key = segment_index;

    ngx_rbtree_insert(&ctx->rbtree, &node->node);
    ngx_queue_insert_tail(&ctx->active, &node->queue);
    ctx->added++;

    track->channel->last_modified = ngx_time();
}

void
ngx_live_media_info_update_stats(ngx_live_segment_t *segment, uint32_t bitrate)
{
    int64_t                           duration;
    uint32_t                          frame_rate;
    ngx_queue_t                      *q;
    ngx_live_track_t                 *track;
    ngx_live_media_info_node_t       *node;
    ngx_ksmp_media_info_stats_t      *stats;
    ngx_live_media_info_track_ctx_t  *ctx;

    track = segment->track;
    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
    stats = &node->stats;

    /* bitrate */
    if (bitrate != NGX_LIVE_SEGMENT_NO_BITRATE) {
        stats->bitrate_sum += bitrate;
        stats->bitrate_count++;

        if (stats->bitrate_max < bitrate) {
            stats->bitrate_max = bitrate;
        }
    }

    /* frame rate */
    duration = segment->end_dts - segment->start_dts;
    if (duration > 0) {
        stats->duration += duration;
        stats->frame_count += segment->frame_count;

        frame_rate = segment->frame_count * 100 * track->channel->timescale
            / duration;

        if (!stats->frame_rate_min || frame_rate < stats->frame_rate_min) {
            stats->frame_rate_min = frame_rate;
        }

        if (frame_rate > stats->frame_rate_max) {
            stats->frame_rate_max = frame_rate;
        }
    }
}

static void
ngx_live_media_info_queue_track_segment_free(ngx_live_track_t *track,
    uint32_t min_segment_index)
{
    ngx_queue_t                      *q;
    ngx_queue_t                      *next;
    ngx_live_media_info_node_t       *next_node;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->active);
    for ( ;; ) {

        next = ngx_queue_next(q);
        if (next == ngx_queue_sentinel(&ctx->active)) {
            break;
        }

        next_node = ngx_queue_data(next, ngx_live_media_info_node_t, queue);
        if (min_segment_index < next_node->node.key) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        ngx_rbtree_delete(&ctx->rbtree, &node->node);
        ngx_live_media_info_node_free(track->channel, node);
        ctx->removed++;

        q = next;
    }
}

static ngx_int_t
ngx_live_media_info_queue_segment_free(ngx_live_channel_t *channel,
    void *ectx)
{
    uint32_t                            min_segment_index = (uintptr_t) ectx;
    ngx_queue_t                        *q;
    ngx_live_track_t                   *cur_track;
    ngx_live_media_info_channel_ctx_t  *cctx;

    /* no need to look for nodes to free on each segment */
    cctx = ngx_live_get_module_ctx(channel, ngx_live_media_info_module);

    if (min_segment_index < cctx->min_free_index) {
        return NGX_OK;
    }

    cctx->min_free_index = min_segment_index + NGX_LIVE_MEDIA_INFO_FREE_PERIOD;

    /* free unused media info nodes */
    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        ngx_live_media_info_queue_track_segment_free(cur_track,
            min_segment_index);
    }

    return NGX_OK;
}

static void
ngx_live_media_info_queue_free_all(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->active);
    if (q == NULL) {
        /* init wasn't called */
        return;
    }

    channel = track->channel;

    while (q != ngx_queue_sentinel(&ctx->active)) {

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_media_info_node_free(channel, node);
    }

#if 0   /* skipping since the track is freed */
    ngx_rbtree_reset(&ctx->rbtree);
    ctx->removed = ctx->added;
#endif
}


static ngx_live_media_info_node_t *
ngx_live_media_info_queue_get_before(ngx_live_media_info_track_ctx_t *ctx,
    uint32_t segment_index)
{
    ngx_queue_t                 *prev;
    ngx_rbtree_t                *rbtree;
    ngx_rbtree_node_t           *rbnode;
    ngx_rbtree_node_t           *sentinel;
    ngx_rbtree_node_t           *next_node;
    ngx_live_media_info_node_t  *node;

    rbtree = &ctx->rbtree;
    rbnode = rbtree->root;
    sentinel = rbtree->sentinel;

    if (rbnode == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        if (segment_index < rbnode->key) {
            next_node = rbnode->left;
            if (next_node != sentinel) {
                goto next;
            }

            /* Note: since we don't know the end index of each node, it is
                possible that we made a wrong right turn, in that case, we
                need to go back one node */

            node = (ngx_live_media_info_node_t *) rbnode;

            prev = ngx_queue_prev(&node->queue);
            if (prev == ngx_queue_sentinel(&ctx->active)) {
                return NULL;
            }

            node = ngx_queue_data(prev, ngx_live_media_info_node_t, queue);

        } else {
            next_node = rbnode->right;
            if (next_node != sentinel) {
                goto next;
            }

            node = (ngx_live_media_info_node_t *) rbnode;
        }

        break;

    next:

        rbnode = next_node;
    }

    return node;
}

#if 0
static ngx_live_media_info_node_t *
ngx_live_media_info_queue_get_after(ngx_live_media_info_track_ctx_t *ctx,
    uint32_t segment_index)
{
    ngx_queue_t                 *next;
    ngx_rbtree_t                *rbtree;
    ngx_rbtree_node_t           *rbnode;
    ngx_rbtree_node_t           *sentinel;
    ngx_rbtree_node_t           *next_node;
    ngx_live_media_info_node_t  *node;

    rbtree = &ctx->rbtree;
    rbnode = rbtree->root;
    sentinel = rbtree->sentinel;

    if (rbnode == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        if (segment_index < rbnode->key) {
            next_node = rbnode->left;
            if (next_node != sentinel) {
                goto next;
            }

            node = (ngx_live_media_info_node_t *) rbnode;
            break;

        } else if (segment_index > rbnode->key) {
            next_node = rbnode->right;
            if (next_node != sentinel) {
                goto next;
            }

            node = (ngx_live_media_info_node_t *) rbnode;

            next = ngx_queue_next(&node->queue);
            if (next == ngx_queue_sentinel(&ctx->active)) {
                return NULL;
            }

            node = ngx_queue_data(next, ngx_live_media_info_node_t, queue);
            break;

        } else {
            node = (ngx_live_media_info_node_t *) rbnode;
            break;
        }

    next:

        rbnode = next_node;
    }

    return node;
}
#endif

ngx_live_media_info_node_t *
ngx_live_media_info_queue_get_node(ngx_live_track_t *track,
    uint32_t segment_index, uint32_t *track_id)
{
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    node = ngx_live_media_info_queue_get_before(ctx, segment_index);
    if (node == NULL) {
        return NULL;
    }

    *track_id = node->track_id;
    return node;
}

ngx_live_media_info_t *
ngx_live_media_info_queue_get_last(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->active);
    if (q == ngx_queue_sentinel(&ctx->active)) {
        return NULL;
    }

    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    return &node->media_info;
}

ngx_int_t
ngx_live_media_info_queue_copy_last(ngx_live_track_t *dst,
    ngx_live_track_t *src, uint32_t segment_index)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(src, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->active);
    if (q == ngx_queue_sentinel(&ctx->active)) {
        ngx_log_error(NGX_LOG_ERR, &src->log, 0,
            "ngx_live_media_info_queue_copy_last: no media info");
        return NGX_ERROR;
    }

    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    node = ngx_live_media_info_node_clone(dst->channel, node);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &dst->log, 0,
            "ngx_live_media_info_queue_copy_last: clone failed");
        return NGX_ERROR;
    }

    node->track_id = dst->in.key;

    ngx_live_media_info_queue_push(dst, node, segment_index);

    return NGX_OK;
}


/* source */

static kmp_media_info_t *
ngx_live_media_info_source_get_target(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->pending);
    if (q != ngx_queue_sentinel(&ctx->pending)) {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        return &node->media_info.info;
    }

    for (q = ngx_queue_last(&ctx->active);
        q != ngx_queue_sentinel(&ctx->active);
        q = ngx_queue_prev(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        if (node->track_id != track->in.key) {
            continue;
        }

        return &node->media_info.info;
    }

    return NULL;
}

static ngx_int_t
ngx_live_media_info_source_compare(kmp_media_info_t *target,
    kmp_media_info_t *mi1, kmp_media_info_t *mi2)
{
    /* return: -1 = mi1 is closer to target, 1 = mi2 is closer to target */

    /* prefer a matching codec */
    if (mi1->codec_id != mi2->codec_id) {
        if (mi1->codec_id == target->codec_id) {
            return -1;
        }

        if (mi2->codec_id == target->codec_id) {
            return 1;
        }
    }

    switch (target->media_type) {

    case KMP_MEDIA_VIDEO:
        /* prefer closest video height */
        if (mi1->u.video.height != mi2->u.video.height) {
            if (ngx_abs_diff(mi1->u.video.height, target->u.video.height) <=
                ngx_abs_diff(mi2->u.video.height, target->u.video.height))
            {
                return -1;
            }

            return 1;
        }
        break;

    case KMP_MEDIA_AUDIO:
        /* prefer matching audio channels */
        if (mi1->u.audio.channels != mi2->u.audio.channels) {
            if (mi1->u.audio.channels == target->u.audio.channels) {
                return -1;
            }

            if (mi2->u.audio.channels == target->u.audio.channels) {
                return 1;
            }
        }

        /* prefer matching audio sample rate */
        if (mi1->u.audio.sample_rate != mi2->u.audio.sample_rate) {
            if (mi1->u.audio.sample_rate == target->u.audio.sample_rate) {
                return -1;
            }

            if (mi2->u.audio.sample_rate == target->u.audio.sample_rate) {
                return 1;
            }
        }

        /* prefer matching audio sample size */
        if (mi1->u.audio.bits_per_sample != mi2->u.audio.bits_per_sample) {
            if (mi1->u.audio.bits_per_sample ==
                target->u.audio.bits_per_sample)
            {
                return -1;
            }

            if (mi2->u.audio.bits_per_sample ==
                target->u.audio.bits_per_sample)
            {
                return 1;
            }
        }
        break;
    }

    /* prefer a bitrate lower than target */
    if (mi1->bitrate <= target->bitrate) {

        if (mi2->bitrate > target->bitrate) {
            return -1;
        }

    } else {

        if (mi2->bitrate <= target->bitrate) {
            return 1;
        }
    }

    /* prefer closest bitrate */
    if (ngx_abs_diff(mi1->bitrate, target->bitrate) <=
        ngx_abs_diff(mi2->bitrate, target->bitrate))
    {
        return -1;
    }

    return 1;
}

static ngx_live_track_t *
ngx_live_media_info_source_get(ngx_live_track_t *track,
    kmp_media_info_t *target_media_info, ngx_flag_t require_last_segment)
{
    ngx_queue_t                      *q, *cq;
    kmp_media_info_t                 *cur_media_info;
    kmp_media_info_t                 *source_media_info;
    ngx_live_track_t                 *source;
    ngx_live_track_t                 *cur_track;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx, *cur_ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    source = NULL;
    source_media_info = NULL;   /* silence warning */
    channel = track->channel;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track->media_type != track->media_type || cur_track == track) {
            continue;
        }

        if (require_last_segment && !cur_track->has_last_segment) {
            continue;
        }

        /* if the group id matches, use current track */
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        cq = ngx_queue_last(&cur_ctx->active);
        if (cq == ngx_queue_sentinel(&cur_ctx->active)) {
            if (cur_track->has_last_segment) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_media_info_source_get: no media info");
            }

            continue;
        }

        if (ctx->group_id.s.len &&
            ctx->group_id.s.len == cur_ctx->group_id.s.len &&
            ngx_memcmp(ctx->group_id.s.data, cur_ctx->group_id.s.data,
                ctx->group_id.s.len) == 0)
        {
            return cur_track;
        }

        node = ngx_queue_data(cq, ngx_live_media_info_node_t, queue);
        cur_media_info = &node->media_info.info;

        if (source == NULL ||
            source->type > cur_track->type ||   /* prefer non-filler */
            ngx_live_media_info_source_compare(target_media_info,
                source_media_info, cur_media_info) > 0)
        {
            source = cur_track;
            source_media_info = cur_media_info;
        }
    }

    return source;
}

static ngx_int_t
ngx_live_media_info_source_set(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    kmp_media_info_t                 *target_media_info;
    ngx_live_track_t                 *source;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *source_ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);
    if (ngx_queue_empty(&ctx->active)) {
        return NGX_DONE;
    }

    channel = track->channel;

    if (ngx_queue_empty(&ctx->pending)) {

        q = ngx_queue_last(&ctx->active);
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (node->track_id == track->in.key) {

            /* save the latest media info as pending, if the track becomes
                active later, it will need to use this media info */

            node = ngx_live_media_info_node_clone(channel, node);
            if (node == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_live_media_info_source_set: clone failed (1)");
                return NGX_ERROR;
            }

            node->frame_index_delta = 0;

            ngx_queue_insert_tail(&ctx->pending, &node->queue);
        }
    }

    target_media_info = ngx_live_media_info_source_get_target(track);
    if (target_media_info == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_media_info_source_set: failed to get media info");
        return NGX_DONE;
    }

    source = ngx_live_media_info_source_get(track, target_media_info, 1);
    if (source == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_media_info_source_set: failed to get source");
        return NGX_DONE;
    }

    source_ctx = ngx_live_get_module_ctx(source, ngx_live_media_info_module);
    q = ngx_queue_last(&source_ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    node = ngx_live_media_info_node_clone(channel, node);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_source_set: clone failed (2)");
        return NGX_ERROR;
    }

    ngx_live_media_info_queue_push(track, node, channel->next_segment_index);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_media_info_source_set: "
        "setting source to \"%V\"", &source->sn.str);

    ctx->source = source;
    source_ctx->source_refs++;

    return NGX_OK;
}

static void
ngx_live_media_info_source_clear(ngx_live_media_info_track_ctx_t *ctx)
{
    ngx_live_media_info_track_ctx_t  *source_ctx;

    source_ctx = ngx_live_get_module_ctx(ctx->source,
        ngx_live_media_info_module);

    source_ctx->source_refs--;
    ctx->source = NULL;
}

static void
ngx_live_media_info_source_remove_refs(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel;
    ngx_live_track_t                 *cur_track;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *cur_ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);
    if (ctx->source_refs <= 0) {
        return;
    }

    channel = track->channel;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        if (cur_ctx->source == track) {
            cur_ctx->source = NULL;
        }
    }

    ctx->source_refs = 0;
}


/* pending */

ngx_int_t
ngx_live_media_info_pending_add(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, uint32_t frame_index)
{
    ngx_int_t                         rc;
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->pending);
    if (q != ngx_queue_sentinel(&ctx->pending)) {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (ngx_live_media_info_node_compare(node, media_info, extra_data,
            extra_data_size))
        {
            /* no change - ignore */
            return NGX_DONE;
        }

    } else {
        q = ngx_queue_last(&ctx->active);
        if (q != ngx_queue_sentinel(&ctx->active)) {
            node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

            if (ngx_live_media_info_node_compare(node, media_info, extra_data,
                extra_data_size) && node->track_id == track->in.key)
            {
                /* no change - ignore */
                return NGX_DONE;
            }
        }
    }

    rc = ngx_live_media_info_node_create(track, media_info, extra_data,
        extra_data_size, &node);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_pending_add: create node failed");
        return rc;
    }

    node->frame_index_delta = frame_index - ctx->delta_sum;
    ctx->delta_sum = frame_index;

    ngx_queue_insert_tail(&ctx->pending, &node->queue);

    return NGX_OK;
}

void
ngx_live_media_info_pending_remove_frames(ngx_live_track_t *track,
    ngx_uint_t frame_count)
{
    ngx_uint_t                        left;
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    if (frame_count >= ctx->delta_sum) {
        ctx->delta_sum = 0;

    } else {
        ctx->delta_sum -= frame_count;
    }

    left = frame_count;
    for (q = ngx_queue_head(&ctx->pending);
        q != ngx_queue_sentinel(&ctx->pending);
        q = ngx_queue_next(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (left <= node->frame_index_delta) {
            node->frame_index_delta -= left;
            break;
        }

        left -= node->frame_index_delta;
        node->frame_index_delta = 0;
    }
}

ngx_int_t
ngx_live_media_info_pending_create_segment(ngx_live_track_t *track,
    uint32_t segment_index)
{
    ngx_int_t                         rc;
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_node_t       *cur;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    node = NULL;

    /* Note: it is possible to have multiple media info nodes with zero delta
        in case some segments were disposed */

    q = ngx_queue_head(&ctx->pending);
    while (q != ngx_queue_sentinel(&ctx->pending)) {
        cur = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (cur->frame_index_delta > 0) {
            break;
        }

        q = ngx_queue_next(q);      /* move to next before remove */

        ngx_queue_remove(&cur->queue);

        if (node != NULL) {
            node->queue.next = NULL;    /* was already removed from list */
            ngx_live_media_info_node_free(track->channel, node);
        }

        node = cur;
    }

    if (node == NULL) {
        return NGX_DONE;
    }

    if (ngx_queue_empty(&ctx->active)) {
        track->initial_segment_index = segment_index;

        rc = ngx_live_media_info_queue_copy(track, &node->media_info.info,
            segment_index);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_pending_create_segment: copy failed");
            return rc;
        }
    }

    ngx_live_media_info_queue_push(track, node, segment_index);

    ngx_live_media_info_source_remove_refs(track);

    return NGX_OK;
}

void
ngx_live_media_info_pending_free_all(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->pending);
    if (q == NULL) {
        /* init wasn't called */
        return;
    }

    channel = track->channel;

    while (q != ngx_queue_sentinel(&ctx->pending)) {

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_live_media_info_node_free(channel, node);
    }

    ctx->delta_sum = 0;
}


/* gap filling */

static ngx_int_t
ngx_live_media_info_queue_copy(ngx_live_track_t *track,
    kmp_media_info_t *target_media_info, uint32_t segment_index)
{
    ngx_int_t                         rc;
    ngx_queue_t                      *q;
    ngx_live_track_t                 *source;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *source_ctx;

    channel = track->channel;
    if (channel->next_segment_index == channel->conf.initial_segment_index) {
        return NGX_OK;
    }

    source = ngx_live_media_info_source_get(track, target_media_info, 0);
    if (source == NULL) {
        return NGX_OK;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);
    source_ctx = ngx_live_get_module_ctx(source, ngx_live_media_info_module);

    for (q = ngx_queue_head(&source_ctx->active);
        q != ngx_queue_sentinel(&source_ctx->active);
        q = ngx_queue_next(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        /* Note: must not add nodes that come after the node that is about to
            be added. if the source is a filler that was just added, it will
            have a node with an index equal to next_segment_index. */

        if (node->node.key >= segment_index) {
            break;
        }

        node = ngx_live_media_info_node_clone(channel, node);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_queue_copy: clone failed");
            return NGX_ERROR;
        }

        ngx_rbtree_insert(&ctx->rbtree, &node->node);
        ngx_queue_insert_tail(&ctx->active, &node->queue);
        ctx->added++;
    }

    if (!ctx->added) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_media_info_queue_copy: copied %uD nodes from \"%V\"",
        ctx->added, &source->sn.str);

    rc = ngx_live_core_track_event(track, NGX_LIVE_EVENT_TRACK_COPY, source);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_HISTORY_CHANGED, NULL);
}

ngx_int_t
ngx_live_media_info_queue_fill_gaps(ngx_live_channel_t *channel,
    uint32_t media_types_mask)
{
    uint32_t                          media_type_flag;
    ngx_int_t                         rc;
    ngx_flag_t                        updated;
    ngx_queue_t                      *q;
    ngx_live_track_t                 *cur_track;
    ngx_live_media_info_track_ctx_t  *cur_ctx;

    updated = 0;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track->type == ngx_live_track_type_filler) {
            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        if (cur_track->has_last_segment) {
            if (cur_ctx->source != NULL) {
                ngx_live_media_info_source_clear(cur_ctx);
            }

            continue;
        }

        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        if (cur_ctx->source != NULL) {
            if (cur_ctx->source->has_last_segment) {
                cur_track->last_segment_bitrate =
                    cur_ctx->source->last_segment_bitrate;
                continue;
            }

            ngx_live_media_info_source_clear(cur_ctx);
        }

        media_type_flag = 1 << cur_track->media_type;
        if (!(media_types_mask & media_type_flag)) {
            continue;
        }

        rc = ngx_live_media_info_source_set(cur_track);
        switch (rc) {

        case NGX_OK:
            cur_track->last_segment_bitrate =
                cur_ctx->source->last_segment_bitrate;
            break;

        case NGX_DONE:
            continue;

        default:
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_media_info_queue_fill_gaps: fill gap failed");
            return NGX_ERROR;
        }

        updated = 1;
    }

    return updated ? NGX_OK : NGX_DONE;
}


static void
ngx_live_media_info_own_iter_init(ngx_live_media_info_own_iter_t *iter,
    ngx_live_track_t *track, uint32_t start_index)
{
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    node = ngx_live_media_info_queue_get_before(ctx, start_index);

    iter->q = node != NULL ? &node->queue : ngx_queue_head(&ctx->active);
    iter->sentinel = ngx_queue_sentinel(&ctx->active);
    iter->track_id = track->in.key;
}

static ngx_flag_t
ngx_live_media_info_own_iter_next(ngx_live_media_info_own_iter_t *iter,
    uint32_t *start, uint32_t *end)
{
    ngx_live_media_info_node_t  *node;

    if (iter->q == iter->sentinel) {
        return 0;
    }

    node = ngx_queue_data(iter->q, ngx_live_media_info_node_t, queue);

    while (node->track_id != iter->track_id) {
        iter->q = ngx_queue_next(iter->q);
        if (iter->q == iter->sentinel) {
            return 0;
        }

        node = ngx_queue_data(iter->q, ngx_live_media_info_node_t, queue);
    }

    *start = node->node.key;

    for ( ;; ) {
        iter->q = ngx_queue_next(iter->q);
        if (iter->q == iter->sentinel) {
            *end = NGX_MAX_UINT32_VALUE;
            return 1;
        }

        node = ngx_queue_data(iter->q, ngx_live_media_info_node_t, queue);

        if (node->track_id != iter->track_id) {
            *end = node->node.key;
            return 1;
        }
    }
}


ngx_flag_t
ngx_live_media_info_track_exists(ngx_live_timeline_t *timeline,
    ngx_live_track_t *track)
{
    uint32_t                         start, end;
    uint32_t                         own_start, own_end;
    uint32_t                         period_start, period_end;
    ngx_queue_t                     *q;
    ngx_live_period_t               *period;
    ngx_live_media_info_own_iter_t   iter;

    q = ngx_queue_head(&timeline->periods);
    if (q == ngx_queue_sentinel(&timeline->periods)) {
        return 0;
    }

    period = ngx_queue_data(q, ngx_live_period_t, queue);

    ngx_live_media_info_own_iter_init(&iter, track, period->node.key);

    if (!ngx_live_media_info_own_iter_next(&iter, &own_start, &own_end)) {
        return 0;
    }

    period_start = period->node.key;
    period_end = period_start + period->segment_count;

    for ( ;; ) {

        if (period_start < own_end && own_start < period_end) {

            start = ngx_max(own_start, period_start);
            end = ngx_min(own_end, period_end);

            if (ngx_live_segment_info_segment_exists(track, start, end)) {
                return 1;
            }
        }

        if (own_end < period_end) {
            if (!ngx_live_media_info_own_iter_next(&iter, &own_start,
                &own_end))
            {
                return 0;
            }

        } else {
            q = ngx_queue_next(q);
            if (q == ngx_queue_sentinel(&timeline->periods)) {
                return 0;
            }

            period = ngx_queue_data(q, ngx_live_period_t, queue);

            period_start = period->node.key;
            period_end = period_start + period->segment_count;
        }
    }
}


static ngx_int_t
ngx_live_media_info_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_media_info_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_media_info_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    ngx_queue_init(&ctx->pending);

    ngx_queue_init(&ctx->active);
    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, ngx_rbtree_insert_value);

    ctx->group_id.s.data = ctx->group_id_buf;

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_media_info_queue_free_all(track);

    ngx_live_media_info_pending_free_all(track);

    ngx_live_media_info_source_remove_refs(track);

    return NGX_OK;
}

static size_t
ngx_live_media_info_track_json_get_size(void *obj)
{
    size_t                            result;
    ngx_queue_t                      *q;
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    result = sizeof("\"group_id\":\"") - 1 +
        ngx_json_str_get_size(&ctx->group_id) +
        sizeof("\",\"media_info\":{\"added\":,\"removed\":}") - 1 +
        2 * NGX_INT32_LEN;

    if (ngx_queue_empty(&ctx->active)) {
        return result;
    }

    if (ctx->source) {
        result += sizeof(",\"source\":\"\"") - 1 +
            ctx->source->sn.str.len + ctx->source->id_escape;
    }

    q = ngx_queue_last(&ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    result += sizeof(",\"last\":") - 1;

    switch (node->media_info.info.media_type) {

    case KMP_MEDIA_VIDEO:
        result += ngx_live_media_info_json_video_get_size(node);
        break;

    case KMP_MEDIA_AUDIO:
        result += ngx_live_media_info_json_audio_get_size(node);
        break;
    }

    return result;
}

static u_char *
ngx_live_media_info_track_json_write(u_char *p, void *obj)
{
    ngx_queue_t                      *q;
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    p = ngx_copy_fix(p, "\"group_id\":\"");
    p = ngx_json_str_write(p, &ctx->group_id);
    p = ngx_copy_fix(p, "\",\"media_info\":{\"added\":");
    p = ngx_sprintf(p, "%uD", ctx->added);
    p = ngx_copy_fix(p, ",\"removed\":");
    p = ngx_sprintf(p, "%uD", ctx->removed);

    if (ngx_queue_empty(&ctx->active)) {
        *p++ = '}';
        return p;
    }

    if (ctx->source) {
        p = ngx_copy_fix(p, ",\"source\":\"");
        p = ngx_json_str_write_escape(p, &ctx->source->sn.str,
            ctx->source->id_escape);
        *p++ = '\"';
    }

    q = ngx_queue_last(&ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    p = ngx_copy_fix(p, ",\"last\":");

    switch (node->media_info.info.media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_live_media_info_json_video_write(p, node);
        break;

    case KMP_MEDIA_AUDIO:
        p = ngx_live_media_info_json_audio_write(p, node);
        break;
    }

    *p++ = '}';
    return p;
}

static ngx_int_t
ngx_live_media_info_set_group_id(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value)
{
    ngx_str_t                         group_id;
    ngx_live_track_t                 *track = jctx->obj;
    ngx_live_media_info_track_ctx_t  *ctx;

    u_char  group_id_buf[NGX_LIVE_TRACK_MAX_GROUP_ID_LEN];

    if (value->v.str.s.len > NGX_LIVE_TRACK_MAX_GROUP_ID_LEN) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_media_info_set_group_id: group id \"%V\" too long",
            &value->v.str.s);
        return NGX_ERROR;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    group_id.data = group_id_buf;
    group_id.len = 0;

    if (ngx_json_decode_string(&group_id, &value->v.str.s) != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_media_info_set_group_id: invalid group id \"%V\"",
            &value->v.str.s);
        return NGX_ERROR;
    }

    ngx_memcpy(ctx->group_id.s.data, group_id_buf, group_id.len);
    ctx->group_id.s.len = group_id.len;
    ngx_json_str_set_escape(&ctx->group_id);

    /* remove any source references to/from this track */
    if (ctx->source) {
        ngx_live_media_info_source_clear(ctx);
    }

    ngx_live_media_info_source_remove_refs(track);

    return NGX_OK;
}


static ngx_int_t
ngx_live_media_info_write_setup(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t                    *ws;
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    if (ctx->group_id.s.len == 0) {
        return NGX_OK;
    }

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SETUP) != NGX_OK ||
        ngx_wstream_str(ws, &ctx->group_id.s) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_write_setup: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_read_setup(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    if (ngx_mem_rstream_str_fixed(rs, &ctx->group_id.s,
        sizeof(ctx->group_id_buf)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_setup: read failed");
        return NGX_BAD_DATA;
    }

    ngx_json_str_set_escape(&ctx->group_id);

    return NGX_OK;
}


static ngx_int_t
ngx_live_media_info_channel_index_snap(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                      *q;
    ngx_live_track_t                 *cur_track;
    ngx_live_media_info_snap_t       *ms;
    ngx_live_persist_snap_index_t    *snap = ectx;
    ngx_live_media_info_track_ctx_t  *cur_ctx;

    ms = ngx_palloc(snap->base.pool,
        sizeof(*ms) * (channel->tracks.count + 1));
    if (ms == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_channel_index_snap: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(snap, ms, ngx_live_media_info_module);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        cur_ctx = ngx_live_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        ms->track_id = cur_track->in.key;
        ms->source_id = cur_ctx->source != NULL ? cur_ctx->source->in.key :
            NGX_LIVE_INVALID_TRACK_ID;
        ms++;
    }

    ms->track_id = NGX_LIVE_INVALID_TRACK_ID;

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_write_index_source(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                        source_id;
    ngx_live_track_t               *track = obj;
    ngx_live_media_info_snap_t     *ms;
    ngx_live_persist_snap_index_t  *snap;

    snap = ngx_persist_write_ctx(write_ctx);
    ms = ngx_live_get_module_ctx(snap, ngx_live_media_info_module);

    for (; ms->track_id != track->in.key; ms++) {
        if (ms->track_id == NGX_LIVE_INVALID_TRACK_ID) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_media_info_write_index_source: "
                "track %ui not found in snapshot", track->in.key);
            goto done;
        }
    }

    source_id = ms->source_id;
    ms++;

    if (source_id == NGX_LIVE_INVALID_TRACK_ID) {
        goto done;
    }

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SOURCE) != NGX_OK ||
        ngx_persist_write(write_ctx, &source_id, sizeof(source_id))
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

done:

    ngx_live_set_ctx(snap, ms, ngx_live_media_info_module);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_read_index_source(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                          source_id;
    ngx_live_track_t                 *track = obj;
    ngx_live_track_t                 *source;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *source_ctx;

    if (ngx_mem_rstream_read(rs, &source_id, sizeof(source_id)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_index_source: read failed");
        return NGX_BAD_DATA;
    }

    if (source_id == track->in.key) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_index_source: "
            "source pointing to self, id: %uD", source_id);
        return NGX_BAD_DATA;
    }

    source = ngx_live_track_get_by_int(track->channel, source_id);
    if (source == NULL) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_media_info_read_index_source: "
            "source %uD not found", source_id);
        return NGX_OK;
    }

    if (source->media_type != track->media_type) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_index_source: "
            "media type mismatch, track: %uD, source: %uD",
            track->media_type, source->media_type);
        return NGX_BAD_DATA;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);
    source_ctx = ngx_live_get_module_ctx(source, ngx_live_media_info_module);

    if (ctx->source != NULL) {
        ngx_live_media_info_source_clear(ctx);
    }

    ctx->source = source;
    source_ctx->source_refs++;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_media_info_read_index_source: "
        "setting source to \"%V\"", &source->sn.str);

    return NGX_OK;
}


static ngx_int_t
ngx_live_media_info_write_index_queue(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_track_t  *track = obj;

    if (track->type == ngx_live_track_type_filler) {
        /* handled by the filler module */
        return NGX_OK;
    }

    return ngx_live_persist_write_blocks(track->channel, write_ctx,
        NGX_LIVE_PERSIST_CTX_INDEX_MEDIA_INFO, track);
}

static ngx_int_t
ngx_live_media_info_read_index_queue(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                          min_index;
    ngx_int_t                         rc;
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_node_t       *node;
    ngx_live_persist_index_scope_t   *scope;
    ngx_live_media_info_track_ctx_t  *ctx;

    if (track->type == ngx_live_track_type_filler) {
        /* handled by the filler module */
        return NGX_OK;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_media_info_read_index_queue: skip header failed");
        return NGX_BAD_DATA;
    }


    scope = ngx_mem_rstream_scope(rs);

    min_index = scope->min_index;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    if (!ngx_queue_empty(&ctx->active)) {
        node = ngx_queue_data(ngx_queue_last(&ctx->active),
            ngx_live_media_info_node_t, queue);
        if (node->node.key >= min_index) {
            /* can happen due to duplicate block */
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_media_info_read_index_queue: "
                "last index %uD exceeds min index %uD",
                node->node.key, min_index);
            return NGX_BAD_DATA;
        }
    }

    rc = ngx_live_persist_read_blocks(track->channel,
        NGX_LIVE_PERSIST_CTX_INDEX_MEDIA_INFO, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_media_info_read_index_queue: read blocks failed");
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_media_info_write_index(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                      *q;
    ngx_live_track_t                 *track = obj;
    ngx_live_persist_snap_t          *snap;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);
    snap = ngx_persist_write_ctx(write_ctx);

    node = ngx_live_media_info_queue_get_before(ctx, snap->scope.min_index);
    if (node == NULL) {
        q = ngx_queue_head(&ctx->active);
        if (q == ngx_queue_sentinel(&ctx->active)) {
            return NGX_OK;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    } else {
        q = &node->queue;
    }

    if (node->node.key > snap->scope.max_index) {
        return NGX_OK;
    }

    for ( ;; ) {

        /* Note: the bitrate stats may include some segments added after
            max_index, but since it's only used for reporting in the manifest
            it is acceptable */

        if (ngx_live_media_info_node_write(write_ctx, node) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_write_index: write failed");
            return NGX_ERROR;
        }

        q = ngx_queue_next(q);
        if (q == ngx_queue_sentinel(&ctx->active)) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        if (node->node.key > snap->scope.max_index) {
            break;
        }
    }

    return NGX_OK;
}


/* TODO: remove this! */
typedef struct {
    uint32_t    track_id;
    uint32_t    segment_index;
    uint64_t    bitrate_sum;
    uint32_t    bitrate_count;
    uint32_t    bitrate_max;
} ngx_ksmp_media_info_header_v1_t;

static ngx_int_t
ngx_live_media_info_read_index(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                         rc;
    ngx_str_t                         data;
    ngx_queue_t                      *q;
    ngx_buf_chain_t                   chain;
    ngx_live_track_t                 *track = obj;
    kmp_media_info_t                 *media_info;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_persist_t    *mp;
    ngx_live_persist_index_scope_t   *scope;
    ngx_ksmp_media_info_header_v1_t  *mp1;
    ngx_live_media_info_track_ctx_t  *ctx;

    if (rs->version >= 7) {
        mp = ngx_mem_rstream_get_ptr(rs, sizeof(*mp) + sizeof(*media_info));

    } else {
        mp = ngx_mem_rstream_get_ptr(rs, sizeof(*mp1) + sizeof(*media_info));
    }

    if (mp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_index: read failed");
        return NGX_BAD_DATA;
    }

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    scope = ngx_mem_rstream_scope(rs);

    q = ngx_queue_last(&ctx->active);
    if (q != ngx_queue_sentinel(&ctx->active)) {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (mp->segment_index < scope->min_index) {
            if (mp->segment_index != node->node.key) {
                ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                    "ngx_live_media_info_read_index: "
                    "index %uD is before min %uD and does not match last %ui",
                    mp->segment_index, scope->min_index, node->node.key);
                return NGX_BAD_DATA;
            }

            /* update stats */
            if (rs->version >= 7) {
                node->stats = mp->stats;

            } else {
                mp1 = (void *) mp;
                node->stats.bitrate_sum = mp1->bitrate_sum;
                node->stats.bitrate_count = mp1->bitrate_count;
                node->stats.bitrate_max = mp1->bitrate_max;
            }

            return NGX_OK;
        }

        if (mp->segment_index <= node->node.key) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_media_info_read_index: index %uD is before last %ui",
                mp->segment_index, node->node.key);
            return NGX_BAD_DATA;
        }
    }

    if (mp->segment_index > scope->max_index) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_index: "
            "segment index %uD greater than max segment index %uD",
            mp->segment_index, scope->max_index);
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    if (rs->version >= 7) {
        media_info = (void *) (mp + 1);

    } else {
        mp1 = (void *) mp;
        media_info = (void *) (mp1 + 1);
    }

    ngx_mem_rstream_get_left(rs, &data);

    chain.data = data.data;
    chain.size = data.len;
    chain.next = NULL;

    rc = ngx_live_media_info_node_create(track, media_info, &chain,
        data.len, &node);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_media_info_read_index: create node failed");
        return rc;
    }

    node->track_id = mp->track_id;

    if (rs->version >= 7) {
        node->stats = mp->stats;

    } else {
        mp1 = (void *) mp;
        node->stats.bitrate_sum = mp1->bitrate_sum;
        node->stats.bitrate_count = mp1->bitrate_count;
        node->stats.bitrate_max = mp1->bitrate_max;
    }

    ngx_live_media_info_queue_push(track, node, mp->segment_index);

    return NGX_OK;
}


static ngx_int_t
ngx_live_media_info_write_media_segment(
    ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_segment_t            *segment;
    ngx_live_segment_write_ctx_t  *ctx = obj;

    segment = ctx->segment;

    return ngx_live_media_info_write(write_ctx, NULL, segment->media_info);
}

static ngx_int_t
ngx_live_media_info_read_media_segment(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_segment_t     *segment = obj;
    ngx_live_media_info_t  *media_info;

    media_info = ngx_palloc(segment->pool, sizeof(*media_info));
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_media_info_read_media_segment: alloc failed");
        return NGX_ERROR;
    }

    if (ngx_mem_rstream_read(rs, &media_info->info, sizeof(media_info->info))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_media_info_read_media_segment: read header failed");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &media_info->extra);

    segment->media_info = media_info;

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_write_serve_queue(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_track_t                    *track;
    ngx_persist_write_marker_t           marker;
    ngx_live_persist_serve_scope_t      *scope;
    ngx_ksmp_media_info_queue_header_t   header;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_MEDIA_INFO)) {
        return NGX_OK;
    }

    track = obj;
    scope->ctx = &header;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_MEDIA_INFO_QUEUE) != NGX_OK ||
        ngx_persist_write_reserve(write_ctx, sizeof(header), &marker)
            != NGX_OK ||
        ngx_live_persist_write_blocks(track->channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_MEDIA_INFO, track) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_write_serve_queue: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_marker_write(&marker, &header, sizeof(header));

    ngx_persist_write_block_close(write_ctx);

    scope->ctx = NULL;

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_write_serve(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_uint_t                           count;
    ngx_queue_t                         *q;
    ngx_live_track_t                    *track = obj;
    ngx_live_media_info_node_t          *node;
    ngx_live_persist_serve_scope_t      *scope;
    ngx_live_media_info_track_ctx_t     *ctx;
    ngx_ksmp_media_info_queue_header_t  *header;

    scope = ngx_persist_write_ctx(write_ctx);
    header = scope->ctx;

    if (scope->si.index != NGX_LIVE_INVALID_SEGMENT_INDEX) {
        header->count = 1;
        return ngx_live_media_info_node_write(write_ctx,
            track->media_info_node);
    }

    /* TODO: save only the minimum according to the manifest timeline in scope,
        (need to save one node before each period). */

    ctx = ngx_live_get_module_ctx(track, ngx_live_media_info_module);

    node = ngx_live_media_info_queue_get_before(ctx, scope->min_index);
    if (node == NULL) {
        q = ngx_queue_head(&ctx->active);
        if (q == ngx_queue_sentinel(&ctx->active)) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_media_info_write_serve: active queue is empty");
            return NGX_ERROR;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        if (node->node.key > scope->max_index) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_media_info_write_serve: "
                "no nodes in scope, scope: %uD..%uD, first: %ui",
                scope->min_index, scope->max_index, node->node.key);
            return NGX_ERROR;
        }

    } else {
        q = &node->queue;
    }

    count = 0;

    for ( ;; ) {

        if (ngx_live_media_info_node_write(write_ctx, node) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_write_serve: write failed");
            return NGX_ERROR;
        }

        count++;

        q = ngx_queue_next(q);
        if (q == ngx_queue_sentinel(&ctx->active)) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        if (node->node.key > scope->max_index) {
            break;
        }
    }

    header->count = count;

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_media_info_blocks[] = {
    /*
     * persist data:
     *   ngx_str_t  group_id;
     */
    { NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SETUP,
      NGX_LIVE_PERSIST_CTX_SETUP_TRACK, 0,
      ngx_live_media_info_write_setup,
      ngx_live_media_info_read_setup },

    { NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_QUEUE,
      NGX_LIVE_PERSIST_CTX_INDEX_TRACK, NGX_PERSIST_FLAG_SINGLE,
      ngx_live_media_info_write_index_queue,
      ngx_live_media_info_read_index_queue },

    /*
     * persist header:
     *   ngx_live_media_info_persist_t  p;
     *   kmp_media_info_t               kmp;
     */
    { NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO,
      NGX_LIVE_PERSIST_CTX_INDEX_MEDIA_INFO, 0,
      ngx_live_media_info_write_index,
      ngx_live_media_info_read_index },

    /*
     * persist data:
     *   uint32_t  source_id;
     */
    { NGX_LIVE_MEDIA_INFO_PERSIST_BLOCK_SOURCE,
      NGX_LIVE_PERSIST_CTX_INDEX_TRACK, 0,
      ngx_live_media_info_write_index_source,
      ngx_live_media_info_read_index_source },

    /*
     * persist header:
     *   kmp_media_info_t  kmp;
     */
    { NGX_KSMP_BLOCK_MEDIA_INFO, NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER, 0,
      NULL, ngx_live_media_info_read_media_segment },

    /*
     * persist header:
     *   kmp_media_info_t  kmp;
     */
    { NGX_KSMP_BLOCK_MEDIA_INFO, NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER, 0,
      ngx_live_media_info_write_media_segment, NULL },

    /*
     * persist header:
     *   ngx_ksmp_media_info_queue_header_t  p;
     */
    { NGX_KSMP_BLOCK_MEDIA_INFO_QUEUE,
      NGX_LIVE_PERSIST_CTX_SERVE_TRACK, 0,
      ngx_live_media_info_write_serve_queue, NULL },

    /*
     * persist header:
     *   ngx_ksmp_media_info_header_t  p;
     *   kmp_media_info_t              kmp;
     */
    { NGX_KSMP_BLOCK_MEDIA_INFO,
      NGX_LIVE_PERSIST_CTX_SERVE_MEDIA_INFO, 0,
      ngx_live_media_info_write_serve, NULL },

    ngx_null_persist_block
};


static ngx_int_t
ngx_live_media_info_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_media_info_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_json_cmds_add_multi(cf, ngx_live_media_info_dyn_cmds,
        NGX_LIVE_JSON_CTX_TRACK) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t    ngx_live_media_info_channel_events[] = {
    { ngx_live_media_info_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_media_info_queue_segment_free,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE },
    { ngx_live_media_info_channel_index_snap,
        NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP },

      ngx_live_null_event
};

static ngx_live_track_event_t      ngx_live_media_info_track_events[] = {
    { ngx_live_media_info_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_media_info_track_free, NGX_LIVE_EVENT_TRACK_FREE },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_media_info_json_writers[] = {
    { { ngx_live_media_info_track_json_get_size,
        ngx_live_media_info_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_media_info_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_media_info_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf, ngx_live_media_info_track_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_media_info_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_live_media_info_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_media_info_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_media_info_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_live_media_info_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_media_info_preset_conf_t  *conf = child;

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_MEDIA_INFO_NODE],
        sizeof(ngx_live_media_info_node_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_media_info_module,
        sizeof(ngx_live_media_info_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
