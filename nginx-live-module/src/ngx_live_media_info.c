#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_media_info.h"
#include "ngx_live_segmenter.h"
#include "ngx_live.h"
#include "media/mp4/mp4_defs.h"

#include "ngx_live_media_info_json.h"


enum {
    NGX_LIVE_BP_MEDIA_INFO_NODE,
    NGX_LIVE_BP_COUNT
};


struct ngx_live_media_info_node_s {
    ngx_queue_t         queue;
    uint32_t            start_segment_index;
    kmp_media_info_t    kmp_media_info;
    media_info_t        media_info;
    u_char              codec_name[MAX_CODEC_NAME_SIZE];
};

typedef struct {
    ngx_queue_t         queue;    /* ngx_live_media_info_node_t */
    uint32_t            count;
} ngx_live_media_info_track_ctx_t;

typedef struct {
    ngx_block_pool_t   *block_pool;
} ngx_live_media_info_channel_ctx_t;


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

    ngx_queue_remove(&node->queue);
    ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_MEDIA_INFO_NODE, node);
}

static ngx_int_t
ngx_live_media_info_node_create(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    uint32_t                            start_segment_index;
    ngx_int_t                           rc;
    ngx_live_channel_t                 *channel = track->channel;
    ngx_live_media_info_node_t         *node;
    ngx_live_core_preset_conf_t        *cpcf;
    ngx_live_media_info_track_ctx_t    *ctx;
    ngx_live_media_info_channel_ctx_t  *cctx;

    if (media_info->media_type != track->media_type) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "attempt to change media type from %uD to %uD",
            track->media_type, media_info->media_type);
        return NGX_ERROR;
    }

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    if (media_info->timescale != cpcf->timescale) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: "
            "input timescale %uD doesn't match channel timescale %ui",
            media_info->timescale, cpcf->timescale);
        return NGX_ERROR;
    }

    if (ngx_live_segmenter_force_split(track, &start_segment_index)
        != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: force split failed");
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_media_info_module);

    node = ngx_block_pool_alloc(cctx->block_pool, NGX_LIVE_BP_MEDIA_INFO_NODE);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_media_info_node_create: alloc failed");
        return NGX_ABORT;
    }

    node->media_info.extra_data.data = NULL;
    node->media_info.parsed_extra_data.data = NULL;
    node->media_info.codec_name.data = node->codec_name;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    ngx_queue_insert_tail(&ctx->queue, &node->queue);

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
    node->start_segment_index = start_segment_index;

    track->channel->last_modified = ngx_time();
    ctx->count++;

    return NGX_OK;
}

void
ngx_live_media_info_queue_free(ngx_live_track_t *track,
    uint32_t min_segment_index)
{
    ngx_queue_t                      *head;
    ngx_queue_t                      *next;
    ngx_live_media_info_node_t       *next_node;
    ngx_live_media_info_node_t       *head_node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);
    while (!ngx_queue_empty(&ctx->queue))
    {
        head = ngx_queue_head(&ctx->queue);

        next = ngx_queue_next(head);
        if (next == ngx_queue_sentinel(&ctx->queue)) {
            break;
        }

        next_node = ngx_queue_data(next, ngx_live_media_info_node_t, queue);
        if (min_segment_index < next_node->start_segment_index) {
            break;
        }

        head_node = ngx_queue_data(head, ngx_live_media_info_node_t, queue);
        ngx_live_media_info_node_free(track->channel, head_node);
        ctx->count--;
    }
}

ngx_int_t
ngx_live_media_info_queue_push(ngx_live_track_t *track,
    kmp_media_info_t *media_info_ptr, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *last;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    if (!ngx_queue_empty(&ctx->queue)) {
        q = ngx_queue_last(&ctx->queue);
        last = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (ngx_memcmp(&last->kmp_media_info, media_info_ptr,
            sizeof(last->kmp_media_info)) == 0 &&
            last->media_info.extra_data.len == extra_data_size &&
            ngx_buf_chain_compare(extra_data, last->media_info.extra_data.data,
                extra_data_size) == 0)
        {
            /* no change - ignore */
            return NGX_OK;
        }
    }

    return ngx_live_media_info_node_create(track, media_info_ptr, extra_data,
        extra_data_size);
}

media_info_t *
ngx_live_media_info_queue_get(ngx_live_track_t *track, uint32_t segment_index,
    kmp_media_info_t **kmp_media_info)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    for (q = ngx_queue_last(&ctx->queue);
        q != ngx_queue_sentinel(&ctx->queue);
        q = ngx_queue_prev(q))
    {
        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        if (segment_index < node->start_segment_index) {
            continue;
        }

        *kmp_media_info = &node->kmp_media_info;
        return &node->media_info;
    }

    return NULL;
}

media_info_t*
ngx_live_media_info_queue_get_last(ngx_live_track_t *track)
{
    ngx_queue_t                      *q;
    ngx_live_media_info_node_t       *node;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    if (ngx_queue_empty(&ctx->queue)) {
        return NULL;
    }

    q = ngx_queue_last(&ctx->queue);
    node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);
    return &node->media_info;
}


ngx_flag_t
ngx_live_media_info_iterator_init(ngx_live_media_info_iterator_t *iterator,
    ngx_live_track_t *track)
{
    ngx_queue_t                      *head;
    ngx_live_media_info_track_ctx_t  *ctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    if (ngx_queue_empty(&ctx->queue)) {
        return 0;
    }

    head = ngx_queue_head(&ctx->queue);
    iterator->cur = ngx_queue_data(head, ngx_live_media_info_node_t, queue);
    iterator->sentinel = ngx_queue_sentinel(&ctx->queue);

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

        if (segment_index < next->start_segment_index) {
            break;
        }

        iterator->cur = next;
    }

    return iterator->cur->start_segment_index;
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

    ngx_queue_init(&ctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_media_info_track_free(ngx_live_track_t *track)
{
    ngx_queue_t                        *q;
    ngx_live_media_info_node_t         *node;
    ngx_live_media_info_track_ctx_t    *ctx;
    ngx_live_media_info_channel_ctx_t  *cctx;

    ctx = ngx_live_track_get_module_ctx(track, ngx_live_media_info_module);

    q = ngx_queue_head(&ctx->queue);
    if (q == NULL) {
        /* init wasn't called */
        return NGX_OK;
    }

    cctx = ngx_live_get_module_ctx(track->channel, ngx_live_media_info_module);

    while (q != ngx_queue_sentinel(&ctx->queue)) {

        node = ngx_queue_data(q, ngx_live_media_info_node_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_MEDIA_INFO_NODE,
            node);
    }

    return NGX_OK;
}

static size_t
ngx_live_media_info_track_json_get_size(void *obj)
{
    size_t             result;
    media_info_t      *media_info;
    ngx_live_track_t  *track = obj;

    result = sizeof("\"media_info_count\":") - 1 + NGX_INT32_LEN;

    media_info = ngx_live_media_info_queue_get_last(track);
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

    if (ngx_queue_empty(&ctx->queue)) {
        return p;
    }

    q = ngx_queue_last(&ctx->queue);
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
