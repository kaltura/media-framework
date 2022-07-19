#include "ngx_pckg_ksmp_sgts.h"


/* sgts is the format in which media is persisted. This module provides the
    ability to read the media files directly for recovery purposes.
    It can be useful if the recording timeline is deleted, for example. */


typedef struct {
    kmp_media_info_t  kmp_media_info;
    ngx_str_t         extra_data;
} ngx_pckg_ksmp_sgts_ctx_t;


static ngx_int_t
ngx_pckg_ksmp_sgts_init(ngx_pckg_channel_t *channel)
{
    ngx_ksmp_channel_header_t   *ch;
    ngx_ksmp_timeline_header_t  *th;

    ch = &channel->header;

    ch->req_media_types = channel->media->media_type_mask;
    ch->last_modified = ngx_time();
    ch->now = ngx_time();

    th = &channel->timeline.header;

    th->last_modified = ngx_time();
    th->end_list = 1;

    channel->timeline.channel = channel;

    if (ngx_array_init(&channel->timeline.periods, channel->pool,
        1, sizeof(ngx_pckg_period_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_init: periods array init failed");
        return NGX_ERROR;
    }

    if (ngx_array_init(&channel->variants, channel->pool,
        1, sizeof(ngx_pckg_variant_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_init: variants array init failed");
        return NGX_ERROR;
    }

    if (ngx_array_init(&channel->tracks, channel->pool,
        1, sizeof(ngx_pckg_track_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_init: tracks array init failed");
        return NGX_ERROR;
    }

    if (channel->media->segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX) {
        channel->segment_index = ngx_pcalloc(channel->pool,
            sizeof(*channel->segment_index));
        if (channel->segment_index == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                "ngx_pckg_ksmp_sgts_init: alloc index failed");
            return NGX_ERROR;
        }

        channel->segment_index->index = channel->media->segment_index;
    }

    return NGX_OK;
}


static ngx_pckg_track_t *
ngx_pckg_ksmp_sgts_get_track(ngx_pckg_channel_t *channel, uint32_t id)
{
    ngx_uint_t         i;
    ngx_pckg_track_t  *track, *tracks;

    tracks = channel->tracks.elts;
    for (i = 0; i < channel->tracks.nelts; i++) {
        if (tracks[i].header.id == id) {
            return &tracks[i];
        }
    }

    track = ngx_array_push(&channel->tracks);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_get_track: push track failed");
        return NULL;
    }

    ngx_memzero(track, sizeof(*track));

    if (ngx_array_init(&track->media_info, channel->pool, 1,
        sizeof(ngx_pckg_media_info_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_get_track: array init failed");
        return NULL;
    }

    track->segment_info.elts = ngx_pcalloc(channel->pool,
        sizeof(*track->segment_info.elts));
    if (track->segment_info.elts == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_get_track: alloc info failed");
        return NULL;
    }

    track->segment_info.elts[0].bitrate = NGX_KSMP_SEGMENT_NO_BITRATE;
    track->segment_info.nelts = 1;

    track->header.id = id;
    track->header.media_type = KMP_MEDIA_COUNT;

    track->channel = channel;

    channel->header.track_count++;

    return track;
}


static ngx_int_t
ngx_pckg_ksmp_sgts_read_media_info(ngx_persist_block_hdr_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_pckg_ksmp_sgts_ctx_t  *ctx = obj;

    if (ctx->kmp_media_info.timescale != 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_media_info: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_read(rs, &ctx->kmp_media_info,
        sizeof(ctx->kmp_media_info)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_media_info: read header failed");
        return NGX_BAD_DATA;
    }

    if (ctx->kmp_media_info.timescale <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_media_info: invalid timescale");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &ctx->extra_data);

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_sgts_track_set_media_type(ngx_pckg_track_t *track)
{
    u_char              *p;
    uint32_t             media_type;
    ngx_pckg_variant_t  *variant;
    ngx_pckg_channel_t  *channel;

    if (track->header.media_type != KMP_MEDIA_COUNT) {
        /* already set */
        return NGX_OK;
    }

    channel = track->channel;

    media_type = track->last_media_info->media_info.media_type;

    track->header.media_type = media_type;

    channel->header.res_media_types |= 1 << media_type;

    /* create a variant */

    variant = ngx_array_push(&channel->variants);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_track_set_media_type: "
            "push variant failed");
        return NGX_ERROR;
    }

    ngx_memzero(variant, sizeof(*variant));

    p = ngx_pnalloc(channel->pool, NGX_INT32_LEN);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_track_set_media_type: "
            "variant id alloc failed");
        return NGX_ERROR;
    }

    variant->id.data = p;
    variant->id.len = ngx_sprintf(p, "%uD", track->header.id) - p;

    variant->tracks[media_type] = track;
    variant->track_count = 1;

    variant->channel = channel;

    channel->header.variant_count++;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_sgts_add_media_info(ngx_pckg_track_t *track,
    uint32_t segment_index, ngx_pckg_ksmp_sgts_ctx_t *ctx)
{
    uint32_t                       timescale;
    ngx_int_t                      rc;
    ngx_pckg_channel_t            *channel;
    ngx_pckg_media_info_t         *media_info;
    ngx_pckg_media_info_t         *last_media_info;
    ngx_ksmp_media_info_header_t  *h;

    channel = track->channel;

    last_media_info = track->last_media_info;
    if (last_media_info != NULL) {

        if (segment_index <= last_media_info->header.segment_index) {
            ngx_log_error(NGX_LOG_ERR, channel->log, 0,
                "ngx_pckg_ksmp_sgts_add_media_info: "
                "segment index %uD less than previous segment index %uD",
                segment_index, last_media_info->header.segment_index);
            return NGX_BAD_DATA;
        }

        if (ngx_memcmp(&ctx->kmp_media_info, &last_media_info->kmp_media_info,
                sizeof(ctx->kmp_media_info)) == 0
            && ctx->extra_data.len == last_media_info->extra_data.len
            && ngx_memcmp(ctx->extra_data.data,
                last_media_info->extra_data.data, ctx->extra_data.len) == 0)
        {
            return NGX_OK;
        }

        if (ctx->kmp_media_info.media_type != track->header.media_type) {
            ngx_log_error(NGX_LOG_ERR, channel->log, 0,
                "ngx_pckg_ksmp_sgts_add_media_info: "
                "media info type %uD doesn't match track %uD",
                ctx->kmp_media_info.media_type, track->header.media_type);
            return NGX_BAD_DATA;
        }
    }

    media_info = ngx_array_push(&track->media_info);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_add_media_info: push failed");
        return NGX_ERROR;
    }

    h = &media_info->header;

    h->track_id = track->header.id;
    h->segment_index = segment_index;

    media_info->kmp_media_info = ctx->kmp_media_info;


    ngx_memzero(&media_info->media_info, sizeof(media_info->media_info));
    media_info->media_info.codec_name.data = media_info->codec_name;

    media_info->extra_data = ctx->extra_data;

    rc = ngx_pckg_ksmp_parse_media_info(track->channel, media_info);
    if (rc != NGX_OK) {
        return rc;
    }

    track->last_media_info = media_info;

    ngx_pckg_media_info_iter_reset(&track->media_info_iter, track);

    timescale = media_info->media_info.timescale;

    if (channel->header.timescale == 0) {
        channel->header.timescale = timescale;

    } else if (channel->header.timescale != timescale) {
        ngx_log_error(NGX_LOG_ERR, channel->log, 0,
            "ngx_pckg_ksmp_sgts_add_media_info: "
            "inconsistent timescale, prev: %uD, cur: %uD",
            channel->header.timescale, timescale);
        return NGX_BAD_DATA;
    }

    rc = ngx_pckg_ksmp_sgts_track_set_media_type(track);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_sgts_update_timeline(ngx_pckg_channel_t *channel,
    ngx_pckg_segment_t *segment)
{
    int64_t               start_pts, end_pts;
    uint32_t              duration;
    uint32_t              segment_index;
    ngx_uint_t            i;
    ngx_pckg_period_t    *period;
    ngx_pckg_timeline_t  *timeline;

    timeline = &channel->timeline;
    segment_index = segment->header.index;

    if (segment_index + 1 == timeline->last_segment) {
        return NGX_OK;
    }

    if (segment_index < timeline->last_segment) {
        ngx_log_error(NGX_LOG_ERR, channel->log, 0,
            "ngx_pckg_ksmp_sgts_update_timeline: "
            "segment index %uD before last %uD",
            segment_index, timeline->last_segment);
        return NGX_BAD_DATA;
    }

    start_pts = segment->header.start_dts + segment->frames[0].pts_delay;

    end_pts = start_pts;
    for (i = 0; i < segment->header.frame_count; i++) {
        end_pts += segment->frames[i].duration;
    }

    if (start_pts < timeline->last_time) {
        start_pts = timeline->last_time;
    }

    if (start_pts >= end_pts) {
        ngx_log_error(NGX_LOG_ERR, channel->log, 0,
            "ngx_pckg_ksmp_sgts_update_timeline: "
            "start pts %L after end %L", start_pts, end_pts);
        return NGX_BAD_DATA;
    }

    duration = end_pts - start_pts;

    period = ngx_array_push(&timeline->periods);
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_update_timeline: push period failed");
        return NGX_ERROR;
    }

    ngx_memzero(period, sizeof(*period));

    period->elts = ngx_pcalloc(channel->pool, sizeof(*period->elts));
    if (period->elts == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_update_timeline: alloc period elts failed");
        return NGX_ERROR;
    }

    period->timeline = timeline;

    period->header.segment_index = segment_index;
    period->header.time = start_pts;

    period->elts[0].count = 1;
    period->elts[0].duration = duration;

    period->nelts = 1;
    period->segment_count = 1;
    period->duration = duration;

    if (duration > timeline->header.target_duration) {
        timeline->header.target_duration = duration;
    }

    if (timeline->periods.nelts == 1) {
        timeline->header.first_period_initial_time = start_pts;
        timeline->header.first_period_initial_segment_index = segment_index;
    }

    timeline->header.period_count++;

    timeline->segment_count++;
    timeline->duration += duration;

    timeline->last_time = end_pts;
    timeline->last_segment = segment_index + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_sgts_read_segment(ngx_persist_block_hdr_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                   rc;
    ngx_pckg_track_t           *track;
    ngx_mem_rstream_t           save;
    ngx_pckg_channel_t         *channel = obj;
    ngx_pckg_segment_t         *segment;
    ngx_pckg_ksmp_sgts_ctx_t    ctx;
    ngx_pckg_channel_media_t   *media;
    ngx_ksmp_segment_header_t   h;

    if (ngx_mem_rstream_read(rs, &h, sizeof(h)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: read header failed");
        return NGX_BAD_DATA;
    }

    media = channel->media;

    if (media->min_segment_index > h.index) {
        media->min_segment_index = h.index;
    }

    if (media->max_segment_index < h.index) {
        media->max_segment_index = h.index;
    }

    if (media->min_track_id > h.track_id) {
        media->min_track_id = h.track_id;
    }

    if (media->max_track_id < h.track_id) {
        media->max_track_id = h.track_id;
    }

    if (media->track_id && h.track_id != media->track_id) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: "
            "skipping track, track: %uD, index: %uD",
            h.track_id, h.index);
        return NGX_OK;
    }

    if (media->segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX
        && h.index != media->segment_index)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: "
            "skipping segment, track: %uD, index: %uD",
            h.track_id, h.index);
        return NGX_OK;
    }

    if (h.frame_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: invalid frame count");
        return NGX_BAD_DATA;
    }


    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    segment = ngx_pcalloc(channel->pool, sizeof(*segment));
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: alloc segment failed");
        return NGX_ERROR;
    }

    segment->channel = channel;
    segment->header = h;


    save = *rs;

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_SEGMENT, rs, segment);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: read blocks failed (1) %i", rc);
        return rc;
    }

    if (segment->frames == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: missing frame list block");
        return NGX_BAD_DATA;
    }

    if (segment->media.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: missing frame data block");
        return NGX_BAD_DATA;
    }

    ngx_memzero(&ctx, sizeof(ctx));

    *rs = save;

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_SGTS_SEGMENT, rs, &ctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: read blocks failed (2) %i", rc);
        return rc;
    }

    if (ctx.kmp_media_info.timescale == 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_sgts_read_segment: missing media info block");
        return NGX_BAD_DATA;
    }

    if (!(media->media_type_mask & (1 << ctx.kmp_media_info.media_type))) {
        return NGX_OK;
    }

    if (channel->timeline.channel == NULL) {
        if (ngx_pckg_ksmp_sgts_init(channel) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    track = ngx_pckg_ksmp_sgts_get_track(channel, h.track_id);
    if (track == NULL) {
        return NGX_ERROR;
    }

    if (channel->flags & NGX_KSMP_FLAG_MEDIA) {
        if (track->segment != NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_sgts_read_segment: "
                "multiple segments match the filter");
            return NGX_BAD_DATA;
        }

        track->segment = segment;
    }

    rc = ngx_pckg_ksmp_sgts_add_media_info(track, h.index, &ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_pckg_ksmp_sgts_update_timeline(channel, segment);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static ngx_persist_block_t  ngx_pckg_ksmp_sgts_blocks[] = {

    { NGX_KSMP_BLOCK_SEGMENT, NGX_PCKG_KSMP_CTX_SGTS_MAIN, 0, NULL,
      ngx_pckg_ksmp_sgts_read_segment },

    { NGX_KSMP_BLOCK_MEDIA_INFO, NGX_PCKG_KSMP_CTX_SGTS_SEGMENT, 0, NULL,
      ngx_pckg_ksmp_sgts_read_media_info },

      ngx_null_persist_block
};


ngx_int_t
ngx_pckg_ksmp_sgts_add_blocks(ngx_conf_t *cf, ngx_persist_conf_t *persist)
{
    if (ngx_persist_conf_add_blocks(cf, persist, ngx_pckg_ksmp_sgts_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
