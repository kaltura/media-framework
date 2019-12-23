#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_media_info.h"
#include "ngx_live.h"
#include "media/mp4/mp4_defs.h"

#include "ngx_live_media_info_json.h"


enum {
    NGX_LIVE_BP_MEDIA_INFO_NODE,
    NGX_LIVE_BP_COUNT
};


struct ngx_live_media_info_node_s {
    ngx_queue_t         queue;
    kmp_media_info_t    kmp_media_info;
    media_info_t        media_info;
    u_char              codec_name[MAX_CODEC_NAME_SIZE];
    uint32_t            track_id;

    union {
        uint32_t        frame_index_delta;     /* used when pending */
        uint32_t        start_segment_index;
    } u;
};


typedef struct {
    ngx_queue_t         pending;
    uint32_t            delta_sum;

    ngx_queue_t         active;
    uint32_t            count;

    ngx_live_track_t   *source;
    uint32_t            source_refs;
} ngx_live_media_info_track_ctx_t;

typedef struct {
    ngx_block_pool_t   *block_pool;
} ngx_live_media_info_channel_ctx_t;


static ngx_int_t ngx_live_media_info_queue_copy(ngx_live_track_t *track);

static ngx_int_t ngx_live_media_info_postconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_media_info_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_media_info_postconfiguration,    /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    NULL,                                     /* merge preset configuration */
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


/* utility */

static ngx_int_t
ngx_live_media_info_copy_str(ngx_live_channel_t *channel, ngx_str_t *dst,
    ngx_str_t *src)
{
    if (src->data == NULL) {
        return NGX_OK;
    }

    dst->data = ngx_live_channel_auto_alloc(channel, src->len);
    if (dst->data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_copy_str: alloc failed");
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);

    return NGX_OK;
}

ngx_int_t
ngx_live_media_info_parse(ngx_log_t *log, ngx_live_media_info_alloc_pt alloc,
    void *alloc_ctx, kmp_media_info_t *src, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, media_info_t *dest)
{
    u_char        *p;
    size_t         size;
    vod_status_t   rc;

    /* Note: returns NGX_ABORT on allocation error, NGX_ERROR on any other */

    dest->extra_data.len = extra_data_size;
    if (dest->extra_data.len > 0) {

        dest->extra_data.data = alloc(alloc_ctx, dest->extra_data.len);
        if (dest->extra_data.data == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_media_info_parse: alloc failed");
            return NGX_ABORT;
        }

        if (ngx_buf_chain_copy(&extra_data, dest->extra_data.data,
            dest->extra_data.len) == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                "ngx_live_media_info_parse: failed to copy extra data");
            return NGX_ERROR;
        }

    } else {
        dest->extra_data.data = NULL;
    }

    dest->media_type = src->media_type;
    dest->bitrate = src->bitrate;
    dest->timescale = src->timescale;
    dest->frames_timescale = src->timescale;
    dest->parsed_extra_data.data = NULL;

    switch (dest->media_type) {

    case KMP_MEDIA_VIDEO:
        if (src->codec_id != KMP_CODEC_VIDEO_H264) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_media_info_parse: invalid video codec id %uD",
                src->codec_id);
            return NGX_ERROR;
        }

        if (src->u.video.frame_rate.denom == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_media_info_parse: invalid video frame rate");
            return NGX_ERROR;
        }

        dest->codec_id = VOD_CODEC_ID_AVC;

        dest->format = FORMAT_AVC1;
        dest->u.video.width = src->u.video.width;
        dest->u.video.height = src->u.video.height;
        dest->u.video.frame_rate_num = src->u.video.frame_rate.num;
        dest->u.video.frame_rate_denom = src->u.video.frame_rate.denom;

        // XXXX initial pts delay

        // XXXX transfer_characteristics

        size = codec_config_avcc_nal_units_get_size(log, &dest->extra_data,
            &dest->u.video.nal_packet_size_length);
        if (size == 0) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_media_info_parse: failed to parse avc extra data");
            return NGX_ERROR;
        }

        p = alloc(alloc_ctx, size);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_media_info_parse: alloc parsed failed");
            return NGX_ABORT;
        }

        dest->parsed_extra_data.data = p;
        p = codec_config_avcc_nal_units_write(p, &dest->extra_data);
        dest->parsed_extra_data.len = p - dest->parsed_extra_data.data;

        if (dest->parsed_extra_data.len != size) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                "ngx_live_media_info_parse: "
                "actual extra data size %uz different from calculated %uz",
                dest->parsed_extra_data.len, size);
            return NGX_ERROR;
        }

        vod_log_buffer(VOD_LOG_DEBUG_LEVEL, log, 0,
            "ngx_live_media_info_parse: parsed extra data ",
            dest->parsed_extra_data.data, dest->parsed_extra_data.len);

        if (codec_config_get_video_codec_name(log, dest) != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_media_info_parse: failed to get video codec name");
            return NGX_ERROR;
        }
        break;

    case KMP_MEDIA_AUDIO:
        switch (src->codec_id) {

        case KMP_CODEC_AUDIO_AAC:
            dest->codec_id = VOD_CODEC_ID_AAC;
            dest->format = FORMAT_MP4A;
            dest->u.audio.object_type_id = 0x40;

            rc = codec_config_mp4a_config_parse(log, &dest->extra_data,
                &dest->u.audio.codec_config);
            if (rc != VOD_OK) {
                ngx_log_error(NGX_LOG_NOTICE, log, 0,
                    "ngx_live_media_info_parse: failed to parse mp4a config");
                return NGX_ERROR;
            }

            break;

        case KMP_CODEC_AUDIO_MP3:
            dest->codec_id = VOD_CODEC_ID_MP3;
            dest->format = FORMAT_MP4A;
            dest->u.audio.object_type_id = src->u.audio.sample_rate > 24000 ?
                0x6B : 0x69;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_media_info_parse: invalid audio codec id %uD",
                src->codec_id);
            return NGX_ERROR;
        }

        dest->u.audio.channels = src->u.audio.channels;
        dest->u.audio.bits_per_sample = src->u.audio.bits_per_sample;
        dest->u.audio.packet_size = 0;
        dest->u.audio.sample_rate = src->u.audio.sample_rate;

        if (codec_config_get_audio_codec_name(log, dest) != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_media_info_parse: failed to get audio codec name");
            return NGX_ERROR;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_media_info_parse: invalid media type %uD",
            dest->media_type);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* node */

static void
ngx_live_media_info_node_free(ngx_live_channel_t *channel,
    ngx_live_media_info_node_t *node)
{
    ngx_live_media_info_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_media_info_module);

    if (node->media_info.extra_data.data != NULL) {
        ngx_live_channel_auto_free(channel, node->media_info.extra_data.data);
    }

    if (node->media_info.parsed_extra_data.data != NULL) {
        ngx_live_channel_auto_free(channel,
            node->media_info.parsed_extra_data.data);
    }

    if (node->queue.next != NULL) {
        ngx_queue_remove(&node->queue);
    }

    ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_MEDIA_INFO_NODE, node);
}

static ngx_int_t
ngx_live_media_info_node_create(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size, ngx_live_media_info_node_t **result)
{
    ngx_int_t                           rc;
    ngx_live_channel_t                 *channel;
    ngx_live_media_info_node_t         *node;
    ngx_live_core_preset_conf_t        *cpcf;
    ngx_live_media_info_channel_ctx_t  *cctx;

    if (media_info->media_type != track->media_type) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "attempt to change media type from %uD to %uD",
            track->media_type, media_info->media_type);
        return NGX_ERROR;
    }

    channel = track->channel;
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    if (media_info->timescale != cpcf->timescale) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "input timescale %uD doesn't match channel timescale %ui",
            media_info->timescale, cpcf->timescale);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_media_info_module);

    node = ngx_block_pool_calloc(cctx->block_pool,
        NGX_LIVE_BP_MEDIA_INFO_NODE);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: alloc failed");
        return NGX_ABORT;
    }

    node->media_info.codec_name.data = node->codec_name;

    rc = ngx_live_media_info_parse(&track->log,
        (ngx_live_media_info_alloc_pt) ngx_live_channel_auto_alloc, channel,
        media_info, extra_data, extra_data_size, &node->media_info);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: failed to parse media info");
        ngx_live_media_info_node_free(channel, node);
        return rc;
    }

    node->kmp_media_info = *media_info;

    node->track_id = track->in.key;

    *result = node;

    return NGX_OK;
}

static ngx_live_media_info_node_t *
ngx_live_media_info_node_clone(ngx_live_channel_t *channel,
    ngx_live_media_info_node_t *src)
{
    ngx_live_media_info_node_t         *node;
    ngx_live_media_info_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_media_info_module);

    node = ngx_block_pool_calloc(cctx->block_pool,
        NGX_LIVE_BP_MEDIA_INFO_NODE);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_node_clone: alloc failed");
        return NULL;
    }

    *node = *src;

    node->queue.next = NULL;
    node->media_info.extra_data.data = NULL;
    node->media_info.parsed_extra_data.data = NULL;

    if (ngx_live_media_info_copy_str(channel, &node->media_info.extra_data,
        &src->media_info.extra_data) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_node_clone: copy extra data failed");
        goto error;
    }

    if (ngx_live_media_info_copy_str(channel,
        &node->media_info.parsed_extra_data,
        &src->media_info.parsed_extra_data) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_node_clone: copy parsed extra data failed");
        goto error;
    }

    return node;

error:

    ngx_live_media_info_node_free(channel, node);

    return NULL;
}

static ngx_flag_t
ngx_live_media_info_node_compare(ngx_live_media_info_node_t *node,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    return ngx_memcmp(&node->kmp_media_info, media_info,
        sizeof(node->kmp_media_info)) == 0 &&
        node->media_info.extra_data.len == extra_data_size &&
        ngx_buf_chain_compare(extra_data, node->media_info.extra_data.data,
            extra_data_size) == 0;
}


/* active */

static void
ngx_live_media_info_queue_push(ngx_live_track_t *track,
    ngx_live_media_info_node_t *node, uint32_t segment_index)
{
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    node->u.start_segment_index = segment_index;

    ngx_queue_insert_tail(&ctx->active, &node->queue);
    ctx->count++;

    track->channel->last_modified = ngx_time();
}

void
ngx_live_media_info_queue_free(ngx_live_track_t *track,
    uint32_t min_segment_index)
{
    ngx_queue_t                      *q;
    ngx_queue_t                      *next;
    ngx_live_media_info_node_t       *next_node;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->active);
    for ( ;; ) {

        next = ngx_queue_next(q);
        if (next == ngx_queue_sentinel(&ctx->active)) {
            break;
        }

        next_node = ngx_queue_data(next, ngx_live_media_info_node_t, queue);
        if (min_segment_index < next_node->u.start_segment_index) {
            break;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        ngx_live_media_info_node_free(track->channel, node);
        ctx->count--;

        q = next;
    }
}

static void
ngx_live_media_info_queue_free_all(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

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

    ctx->count = 0;
}

media_info_t *
ngx_live_media_info_queue_get(ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    for (q = ngx_queue_last(&ctx->active);
        q != ngx_queue_sentinel(&ctx->active);
        q = ngx_queue_prev(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (segment_index >= node->u.start_segment_index) {
            return &node->media_info;
        }
    }

    return NULL;
}

media_info_t*
ngx_live_media_info_queue_get_last(ngx_live_track_t *track,
    kmp_media_info_t **kmp_media_info)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->active);
    if (q == ngx_queue_sentinel(&ctx->active)) {
        return NULL;
    }

    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    if (kmp_media_info != NULL) {
        *kmp_media_info = &node->kmp_media_info;
    }
    return &node->media_info;
}


/* source */

static ngx_live_track_t *
ngx_live_media_info_source_get(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    media_info_t                     *cur_media_info;
    media_info_t                     *target_media_info;
    media_info_t                     *source_media_info;
    ngx_live_track_t                 *source;
    ngx_live_track_t                 *cur_track;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    /* Note: assuming pending queue is not empty */

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_last(&ctx->pending);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
    target_media_info = &node->media_info;

    source = NULL;
    channel = track->channel;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track->media_type != track->media_type ||
            !cur_track->has_last_segment)
        {
            continue;
        }

        cur_media_info = ngx_live_media_info_queue_get_last(cur_track, NULL);
        if (cur_media_info == NULL) {
            ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                "ngx_live_media_info_source_get: no media info");
            continue;
        }

        if (source == NULL) {
            source = cur_track;
            source_media_info = cur_media_info;
            continue;
        }

        /* prefer a matching codec */
        if (source_media_info->codec_id != cur_media_info->codec_id) {
            if (cur_media_info->codec_id == target_media_info->codec_id) {
                source = cur_track;
                source_media_info = cur_media_info;
                continue;
            }

            if (source_media_info->codec_id == target_media_info->codec_id) {
                continue;
            }
        }

        /* prefer a lower bitrate */
        if (cur_media_info->bitrate <= target_media_info->bitrate) {

            if (source_media_info->bitrate > target_media_info->bitrate) {
                source = cur_track;
                source_media_info = cur_media_info;
                continue;
            }

        } else {

            if (source_media_info->bitrate <= target_media_info->bitrate) {
                continue;
            }
        }

        /* prefer closest bitrate */
        if (ngx_abs_diff(cur_media_info->bitrate,
                target_media_info->bitrate) <
            ngx_abs_diff(source_media_info->bitrate,
                target_media_info->bitrate))
        {
            source = cur_track;
            source_media_info = cur_media_info;
        }
    }

    return source;
}

static ngx_int_t
ngx_live_media_info_source_set(ngx_live_track_t *track, uint32_t segment_index)
{
    ngx_queue_t                      *q;
    ngx_live_track_t                 *source;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *source_ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    if (ngx_queue_empty(&ctx->pending)) {

        q = ngx_queue_last(&ctx->active);
        if (q == ngx_queue_sentinel(&ctx->active)) {
            return NGX_DONE;
        }

        /* save the latest media info as pending, if the track becomes active
            later, it will need to use this media info */

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
        node = ngx_live_media_info_node_clone(track->channel, node);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_source_set: clone failed (1)");
            return NGX_ERROR;
        }

        node->u.frame_index_delta = 0;

        ngx_queue_insert_tail(&ctx->pending, &node->queue);
    }

    source = ngx_live_media_info_source_get(track);
    if (source == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_live_media_info_source_set: failed to get source");
        return NGX_DONE;
    }

    source_ctx = ngx_live_track_get_module_ctx(source,
        ngx_live_media_info_module);
    q = ngx_queue_last(&source_ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

    node = ngx_live_media_info_node_clone(track->channel, node);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_source_set: clone failed (2)");
        return NGX_ERROR;
    }

    ngx_live_media_info_queue_push(track, node, segment_index);

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

    source_ctx = ngx_live_track_get_module_ctx(ctx->source,
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

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);
    if (ctx->source_refs <= 0) {
        return;
    }

    channel = track->channel;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
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
    ngx_flag_t                        first;
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    first = 0;

    q = ngx_queue_last(&ctx->pending);
    if (q != ngx_queue_sentinel(&ctx->pending)) {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (ngx_live_media_info_node_compare(node, media_info, extra_data,
            extra_data_size)) {
            /* no change - ignore */
            return NGX_DONE;
        }

    } else {
        q = ngx_queue_last(&ctx->active);
        if (q != ngx_queue_sentinel(&ctx->active)) {
            node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

            if (ngx_live_media_info_node_compare(node, media_info, extra_data,
                extra_data_size)) {
                /* no change - ignore */
                return NGX_DONE;
            }

        } else {
            first = 1;
        }
    }

    rc = ngx_live_media_info_node_create(track, media_info, extra_data,
        extra_data_size, &node);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_pending_add: create node failed");
        return rc;
    }

    node->u.frame_index_delta = frame_index - ctx->delta_sum;
    ctx->delta_sum = frame_index;

    ngx_queue_insert_tail(&ctx->pending, &node->queue);

    if (first) {
        rc = ngx_live_media_info_queue_copy(track);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_pending_add: copy queue failed");
            return rc;
        }
    }

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

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

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

        if (left <= node->u.frame_index_delta) {
            node->u.frame_index_delta -= left;
            break;
        }

        left -= node->u.frame_index_delta;
        node->u.frame_index_delta = 0;
    }
}

void
ngx_live_media_info_pending_create_segment(ngx_live_track_t *track,
    uint32_t segment_index)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_node_t       *cur;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    if (ctx->source != NULL) {
        ngx_live_media_info_source_clear(ctx);
    }

    node = NULL;

    /* Note: it is possible to have multiple media info nodes with zero delta
        in case some segments were disposed */

    q = ngx_queue_head(&ctx->pending);
    while (q != ngx_queue_sentinel(&ctx->pending)) {
        cur = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (cur->u.frame_index_delta > 0) {
            break;
        }

        q = ngx_queue_next(q);

        ngx_queue_remove(&cur->queue);

        if (node != NULL) {
            node->queue.next = NULL;    /* was already removed from list */
            ngx_live_media_info_node_free(track->channel, node);
        }

        node = cur;
    }

    if (node == NULL) {
        return;
    }

    ngx_live_media_info_queue_push(track, node, segment_index);

    ngx_live_media_info_source_remove_refs(track);
}

void
ngx_live_media_info_pending_free_all(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

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
ngx_live_media_info_queue_copy(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_track_t                 *source;
    ngx_live_channel_t               *channel;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;
    ngx_live_media_info_track_ctx_t  *source_ctx;

    channel = track->channel;
    if (channel->next_segment_index == 0) {
        return NGX_OK;
    }

    source = ngx_live_media_info_source_get(track);
    if (source == NULL) {
        return NGX_OK;
    }

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);
    source_ctx = ngx_live_track_get_module_ctx(source,
        ngx_live_media_info_module);

    for (q = ngx_queue_head(&source_ctx->active);
        q != ngx_queue_sentinel(&source_ctx->active);
        q = ngx_queue_next(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        node = ngx_live_media_info_node_clone(channel, node);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_media_info_queue_copy: clone failed");
            return NGX_ERROR;
        }

        ngx_queue_insert_tail(&ctx->active, &node->queue);
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_media_info_queue_copy: "
        "setting source to \"%V\"", &source->sn.str);

    ctx->source = source;
    ctx->count = source_ctx->count;
    source_ctx->source_refs++;

    return NGX_OK;
}

ngx_int_t
ngx_live_media_info_queue_fill_gaps(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    uint32_t                          media_type_flag;
    ngx_int_t                         rc;
    ngx_flag_t                        updated;
    ngx_queue_t                      *q;
    ngx_live_track_t                 *cur_track;
    ngx_live_media_info_track_ctx_t  *cur_ctx;

    updated = 0;

    for (q = ngx_queue_head(&channel->tracks_queue);
        q != ngx_queue_sentinel(&channel->tracks_queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);
        if (cur_track->has_last_segment) {
            continue;
        }

        cur_ctx = ngx_live_track_get_module_ctx(cur_track,
            ngx_live_media_info_module);

        if (cur_ctx->source != NULL) {
            if (cur_ctx->source->has_last_segment) {
                continue;
            }

            ngx_live_media_info_source_clear(cur_ctx);
        }

        media_type_flag = 1 << cur_track->media_type;
        if (!(channel->last_segment_media_types & media_type_flag)) {
            continue;
        }

        rc = ngx_live_media_info_source_set(cur_track, segment_index);
        switch (rc) {

        case NGX_DONE:
            continue;

        case NGX_OK:
            break;

        default:
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_media_info_source_sets: fill gap failed");
            return NGX_ERROR;
        }

        updated = 1;
    }

    return updated ? NGX_OK : NGX_DONE;
}

void
ngx_live_media_info_queue_get_segment_track(ngx_live_track_t *track,
    uint32_t segment_index, ngx_live_track_ref_t *ref)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    for (q = ngx_queue_last(&ctx->active) ;; q = ngx_queue_prev(q)) {

        if (q == ngx_queue_sentinel(&ctx->active)) {
            ref->id = track->in.key;
            ref->track = track;
            return;
        }

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (segment_index >= node->u.start_segment_index) {
            break;
        }
    }

    ref->id = node->track_id;
    if (node->track_id == track->in.key) {
        ref->track = track;

    } else {
        ref->track = ngx_live_track_get_by_int(track->channel, ref->id);
    }
}


/* iterator */

ngx_flag_t
ngx_live_media_info_iterator_init(ngx_live_media_info_iterator_t *iterator,
    ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->active);
    if (q == ngx_queue_sentinel(&ctx->active)) {
        return 0;
    }

    iterator->cur = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
    iterator->sentinel = ngx_queue_sentinel(&ctx->active);

    return 1;
}

uint32_t
ngx_live_media_info_iterator_next(ngx_live_media_info_iterator_t *iterator,
    uint32_t segment_index)
{
    ngx_queue_t                 *q;
    ngx_live_media_info_node_t  *next;

    for ( ;; ) {

        q = ngx_queue_next(&iterator->cur->queue);
        if (q == iterator->sentinel) {
            break;
        }

        next = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (segment_index < next->u.start_segment_index) {
            break;
        }

        iterator->cur = next;
    }

    return iterator->cur->u.start_segment_index;
}


static ngx_int_t
ngx_live_media_info_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size)
{
    size_t                              block_sizes[NGX_LIVE_BP_COUNT];
    ngx_live_media_info_channel_ctx_t  *ctx;

    ctx = ngx_pcalloc(channel->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, ctx, ngx_live_media_info_module);

    block_sizes[NGX_LIVE_BP_MEDIA_INFO_NODE] =
        sizeof(ngx_live_media_info_node_t);

    ctx->block_pool = ngx_live_channel_create_block_pool(channel, block_sizes,
        NGX_LIVE_BP_COUNT);
    if (ctx->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_media_info_channel_init: create block pool failed");
        return NGX_ERROR;
    }

    ngx_live_reserve_track_ctx_size(channel, ngx_live_media_info_module,
        sizeof(ngx_live_media_info_track_ctx_t), track_ctx_size);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_track_init(ngx_live_track_t *track)
{
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    ngx_queue_init(&ctx->pending);

    ngx_queue_init(&ctx->active);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_track_free(ngx_live_track_t *track)
{
    ngx_live_media_info_queue_free_all(track);

    ngx_live_media_info_pending_free_all(track);

    ngx_live_media_info_source_remove_refs(track);

    return NGX_OK;
}

static size_t
ngx_live_media_info_track_json_get_size(void *obj)
{
    size_t             result;
    media_info_t      *media_info;
    ngx_live_track_t  *track = obj;

    result = sizeof("\"media_info_count\":") - 1 + NGX_INT32_LEN;

    media_info = ngx_live_media_info_queue_get_last(track, NULL);
    if (media_info == NULL) {
        return result;
    }

    result += sizeof(",\"media_info\":") - 1;

    switch (media_info->media_type) {

    case KMP_MEDIA_VIDEO:
        result += ngx_live_media_info_json_video_get_size(media_info);
        break;

    case KMP_MEDIA_AUDIO:
        result += ngx_live_media_info_json_audio_get_size(media_info);
        break;
    }

    return result;
}

static u_char *
ngx_live_media_info_track_json_write(u_char *p, void *obj)
{
    ngx_queue_t                      *q;
    media_info_t                     *media_info;
    ngx_live_track_t                 *track = obj;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    p = ngx_copy_fix(p, "\"media_info_count\":");
    p = ngx_sprintf(p, "%uD", ctx->count);

    if (ngx_queue_empty(&ctx->active)) {
        return p;
    }

    q = ngx_queue_last(&ctx->active);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
    media_info = &node->media_info;

    p = ngx_copy_fix(p, ",\"media_info\":");

    switch (media_info->media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_live_media_info_json_video_write(p, media_info);
        break;

    case KMP_MEDIA_AUDIO:
        p = ngx_live_media_info_json_audio_write(p, media_info);
        break;
    }

    return p;
}

static ngx_int_t
ngx_live_media_info_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_writer_t            *writer;
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_track_handler_pt         *th;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_media_info_channel_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_INIT]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_media_info_track_init;

    th = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_TRACK_FREE]);
    if (th == NULL) {
        return NGX_ERROR;
    }
    *th = ngx_live_media_info_track_free;

    writer = ngx_array_push(&cmcf->json_writers[NGX_LIVE_JSON_CTX_TRACK]);
    if (writer == NULL) {
        return NGX_ERROR;
    }
    writer->get_size = ngx_live_media_info_track_json_get_size;
    writer->write = ngx_live_media_info_track_json_write;

    return NGX_OK;
}
