#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"

#include "media/mp4/mp4_defs.h"
#include "media/avc_hevc_parser.h"
#include "media/avc_parser.h"
#include "media/hevc_parser.h"


enum {
    NGX_PCKG_KSMP_CTX_MAIN = 0,
    NGX_PCKG_KSMP_CTX_CHANNEL,
    NGX_PCKG_KSMP_CTX_TIMELINE,
    NGX_PCKG_KSMP_CTX_TRACK,
    NGX_PCKG_KSMP_CTX_MEDIA_INFO,
    NGX_PCKG_KSMP_CTX_SEGMENT,

    NGX_PCKG_KSMP_CTX_COUNT
};


static ngx_int_t
ngx_pckg_ksmp_read_channel(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                   rc;
    ngx_pckg_channel_t         *channel = obj;
    ngx_ksmp_channel_header_t  *header;

    if (channel->header != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &channel->id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: read id failed");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: read header failed");
        return NGX_BAD_DATA;
    }

    if (header->timescale < 1000) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: invalid timescale %uD",
            header->timescale);
        return NGX_BAD_DATA;
    }

    if (header->track_count <= 0 ||
        header->track_count > NGX_KSMP_MAX_TRACKS)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: invalid track count %uD",
            header->track_count);
        return NGX_BAD_DATA;
    }

    if (header->variant_count <= 0 ||
        header->variant_count > NGX_KSMP_MAX_VARIANTS)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: invalid variant count %uD",
            header->variant_count);
        return NGX_BAD_DATA;
    }

    if (ngx_array_init(&channel->tracks, channel->pool,
        header->track_count, sizeof(ngx_pckg_track_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: array init failed (1)");
        return NGX_ERROR;
    }

    if (ngx_array_init(&channel->variants, channel->pool,
        header->variant_count, sizeof(ngx_pckg_variant_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: array init failed (2)");
        return NGX_ERROR;
    }

    channel->header = header;


    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_CHANNEL, rs, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: read blocks failed %i", rc);
        return rc;
    }

    if (channel->err_code != NGX_KSMP_ERR_SUCCESS) {
        return NGX_OK;
    }


    if (channel->tracks.nelts != channel->header->track_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: track count mismatch"
            ", expected: %uD, actual: %ui",
            channel->header->track_count, channel->tracks.nelts);
        return NGX_BAD_DATA;
    }

    if (channel->variants.nelts != channel->header->variant_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: variant count mismatch"
            ", expected: %uD, actual: %ui",
            channel->header->variant_count, channel->variants.nelts);
        return NGX_BAD_DATA;
    }

    if (channel->timeline.header == NULL &&
        (channel->flags & NGX_KSMP_FLAG_TIMELINE))
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: missing timeline block");
        return NGX_BAD_DATA;
    }

    if (channel->segment_index == NULL &&
        (channel->flags & NGX_KSMP_FLAG_MEDIA))
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_channel: missing segment index block");
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_timeline(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                     period_count;
    ngx_int_t                    rc;
    ngx_pckg_channel_t          *channel = obj;
    ngx_pckg_timeline_t         *timeline;
    ngx_ksmp_timeline_header_t  *header;

    timeline = &channel->timeline;

    if (timeline->header != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &timeline->id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: read id failed");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: read header failed");
        return NGX_BAD_DATA;
    }

    if (channel->flags & NGX_KSMP_FLAG_PERIODS) {
        period_count = header->period_count;

        if (period_count <= 0 || period_count > NGX_KSMP_MAX_PERIODS) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_timeline: invalid period count %uD",
                period_count);
            return NGX_BAD_DATA;
        }

    } else {
        period_count = 0;
    }

    if (header->target_duration <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: invalid target duration %uD",
            header->target_duration);
        return NGX_BAD_DATA;
    }

    if (ngx_array_init(&timeline->periods, channel->pool,
        period_count, sizeof(ngx_pckg_period_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: array init failed");
        return NGX_ERROR;
    }

    timeline->channel = channel;
    timeline->header = header;


    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_TIMELINE, rs, timeline);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: read blocks failed %i", rc);
        return rc;
    }


    if (timeline->periods.nelts != period_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_timeline: period count mismatch"
            ", expected: %uD, actual: %ui",
            period_count, timeline->periods.nelts);
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_period(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint64_t                    count;
    uint64_t                    duration;
    ngx_str_t                   segments;
    ngx_uint_t                  i;
    ngx_pckg_period_t          *period;
    ngx_pckg_timeline_t        *timeline = obj;
    ngx_ksmp_period_header_t   *header;
    ngx_ksmp_segment_repeat_t  *elt;

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: read header failed");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    if (header->time < timeline->last_time) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: period time %L before last time %L",
            header->time, timeline->last_time);
        return NGX_BAD_DATA;
    }

    if (header->segment_index < timeline->last_segment) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: "
            "period index %uD before last index %uD",
            header->segment_index, timeline->last_segment);
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &segments);

    period = ngx_array_push(&timeline->periods);
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_period: push failed");
        return NGX_ERROR;
    }

    period->timeline = timeline;

    period->elts = (void *) segments.data;
    period->nelts = segments.len / sizeof(period->elts[0]);

    if (period->nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: no segments");
        return NGX_BAD_DATA;
    }

    count = 0;
    duration = 0;
    for (i = 0; i < period->nelts; i++) {
        elt = &period->elts[i];

        if (elt->count <= 0 || elt->duration <= 0) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_period: zero repeat/duration");
            return NGX_BAD_DATA;
        }

        count += elt->count;
        duration += (uint64_t) elt->count * elt->duration;
    }

    if (count > NGX_KSMP_INVALID_SEGMENT_INDEX - header->segment_index) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: segment index overflow"
            ", index: %uD, count: %uL", header->segment_index, count);
        return NGX_BAD_DATA;
    }

    if (duration > (uint64_t) (LLONG_MAX - header->time)) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_period: segment time overflow"
            ", time: %L, duration: %uL", header->time, duration);
        return NGX_BAD_DATA;
    }

    period->header = header;
    period->segment_count = count;
    period->duration = duration;

    timeline->duration += duration;
    timeline->last_time = header->time + duration;
    timeline->last_segment = header->segment_index + count;
    timeline->segment_count += period->segment_count;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_track(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                 rc;
    ngx_pckg_track_t         *track;
    ngx_pckg_channel_t       *channel = obj;
    ngx_ksmp_track_header_t  *header;

    if (channel->sorted_tracks != NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_track: got track after variant");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_track: read header failed");
        return NGX_BAD_DATA;
    }

    if (header->media_type >= KMP_MEDIA_COUNT) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_track: invalid media type %uD",
            header->media_type);
        return NGX_BAD_DATA;
    }

    track = ngx_array_push(&channel->tracks);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_track: push failed");
        return NGX_ERROR;
    }

    ngx_memzero(track, sizeof(*track));
    track->channel = channel;

    track->header = header;


    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_TRACK, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_track: read blocks failed %i", rc);
        return rc;
    }


    if (channel->flags & NGX_KSMP_FLAG_MEDIA_INFO) {
        if (track->media_info.nelts <= 0) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_track: missing media info block");
            return NGX_BAD_DATA;
        }

        ngx_pckg_media_info_iter_reset(&track->media_info_iter, track);
    }

    if (track->segment_info.nelts <= 0 &&
        (channel->flags & NGX_KSMP_FLAG_SEGMENT_INFO))
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_track: missing segment info block");
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_pckg_ksmp_track_ptr_compare(const void *one, const void *two)
{
    ngx_pckg_track_t  *first = *(ngx_pckg_track_t **) one;
    ngx_pckg_track_t  *second = *(ngx_pckg_track_t **) two;

    return (int) first->header->id - (int) second->header->id;
}


static ngx_int_t
ngx_pckg_ksmp_track_create_index(ngx_pckg_channel_t *channel)
{
    ngx_uint_t          i, n;
    ngx_pckg_track_t   *tracks;
    ngx_pckg_track_t  **sorted;

    n = channel->tracks.nelts;

    sorted = ngx_palloc(channel->pool, sizeof(sorted[0]) * n);
    if (sorted == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_track_create_index: alloc failed");
        return NGX_ERROR;
    }

    tracks = channel->tracks.elts;
    for (i = 0; i < n; i++) {
        sorted[i] = &tracks[i];
    }

    ngx_qsort(sorted, n, sizeof(ngx_pckg_track_t *),
        ngx_pckg_ksmp_track_ptr_compare);

    channel->sorted_tracks = sorted;

    return NGX_OK;
}


static ngx_pckg_track_t *
ngx_pckg_ksmp_track_get(ngx_pckg_channel_t *channel, uint32_t id)
{
    ngx_int_t          left, right, index;
    ngx_pckg_track_t  *track;

    left = 0;
    right = channel->tracks.nelts - 1;
    for ( ;; ) {

        if (left > right) {
            return NULL;
        }

        index = (left + right) / 2;
        track = channel->sorted_tracks[index];

        if (track->header->id < id) {
            left = index + 1;

        } else if (track->header->id > id) {
            right = index - 1;

        } else {
            break;
        }
    }

    return track;
}


static ngx_int_t
ngx_pckg_ksmp_read_segment_info(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_str_t          info;
    ngx_pckg_track_t  *track = obj;

    if (track->segment_info.elts != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_segment_info: duplicate block");
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &info);

    track->segment_info.elts = (void *) info.data;
    track->segment_info.nelts = info.len / sizeof(track->segment_info.elts[0]);

    if (track->segment_info.nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment_info: no segments");
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_media_info_queue(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                            rc;
    ngx_pckg_track_t                    *track = obj;
    ngx_pckg_channel_t                  *channel;
    ngx_ksmp_media_info_queue_header_t  *header;

    if (track->media_info.elts) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: duplicate block");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: read header failed");
        return NGX_BAD_DATA;
    }

    if (header->count <= 0 || header->count > NGX_KSMP_MAX_MEDIA_INFOS) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: invalid count %uD",
            header->count);
        return NGX_BAD_DATA;
    }

    channel = track->channel;
    if (ngx_array_init(&track->media_info, channel->pool, header->count,
        sizeof(ngx_pckg_media_info_t)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: array init failed");
        return NGX_ERROR;
    }


    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_MEDIA_INFO, rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: read blocks failed %i", rc);
        return rc;
    }


    if (track->media_info.nelts != header->count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info_queue: media info count mismatch"
            ", expected: %uD, actual: %ui",
            header->count, track->media_info.nelts);
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_parse_media_info(ngx_pckg_channel_t *channel,
    ngx_pckg_media_info_t *node)
{
    void               *parser_ctx;
    u_char             *p;
    size_t              size;
    vod_status_t        rc;
    media_info_t       *dest = &node->media_info;
    kmp_media_info_t   *src = node->kmp_media_info;
    request_context_t   request_context;

    dest->extra_data = node->extra_data;
    dest->parsed_extra_data.data = NULL;

    switch (src->media_type) {

    case KMP_MEDIA_VIDEO:
        if (src->codec_id != KMP_CODEC_VIDEO_H264) {
            ngx_log_error(NGX_LOG_ERR, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: invalid video codec id %uD",
                src->codec_id);
            return NGX_BAD_DATA;
        }

        if (src->u.video.frame_rate.denom <= 0) {
            ngx_log_error(NGX_LOG_ERR, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: invalid video frame rate");
            return NGX_BAD_DATA;
        }

        /* TODO: parse extra data only if needed for the specific request */

        ngx_memzero(&request_context, sizeof(request_context));
        request_context.pool = channel->pool;
        request_context.log = channel->log;

        rc = avc_hevc_parser_init_ctx(&request_context, &parser_ctx);
        if (rc != VOD_OK) {
            return rc;
        }

        rc = avc_parser_parse_extra_data(parser_ctx, &dest->extra_data, NULL,
            NULL);
        if (rc != VOD_OK) {
            return rc;
        }

        dest->u.video.transfer_characteristics =
            avc_parser_get_transfer_characteristics(parser_ctx);

        size = codec_config_avcc_nal_units_get_size(channel->log,
            &dest->extra_data, &dest->u.video.nal_packet_size_length);
        if (size <= 0) {
            ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: "
                "failed to parse avc extra data");
            return NGX_BAD_DATA;
        }

        p = ngx_pnalloc(channel->pool, size);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: alloc parsed failed");
            return NGX_ERROR;
        }

        dest->parsed_extra_data.data = p;
        p = codec_config_avcc_nal_units_write(p, &dest->extra_data);
        dest->parsed_extra_data.len = p - dest->parsed_extra_data.data;

        if (dest->parsed_extra_data.len != size) {
            ngx_log_error(NGX_LOG_ALERT, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: "
                "actual extra data size %uz different from calculated %uz",
                dest->parsed_extra_data.len, size);
            return NGX_ERROR;
        }

        vod_log_buffer(VOD_LOG_DEBUG_LEVEL, channel->log, 0,
            "ngx_pckg_ksmp_parse_media_info: parsed extra data ",
            dest->parsed_extra_data.data, dest->parsed_extra_data.len);

        dest->media_type = MEDIA_TYPE_VIDEO;
        dest->codec_id = VOD_CODEC_ID_AVC;
        dest->format = FORMAT_AVC1;

        dest->u.video.width = src->u.video.width;
        dest->u.video.height = src->u.video.height;
        dest->u.video.frame_rate_num = src->u.video.frame_rate.num;
        dest->u.video.frame_rate_denom = src->u.video.frame_rate.denom;
        dest->u.video.cea_captions = src->u.video.cea_captions;

        if (codec_config_get_video_codec_name(channel->log, dest) != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: "
                "failed to get video codec name");
            return NGX_BAD_DATA;
        }
        break;

    case KMP_MEDIA_AUDIO:

        switch (src->codec_id) {

        case KMP_CODEC_AUDIO_AAC:

            rc = codec_config_mp4a_config_parse(channel->log,
                &dest->extra_data, &dest->u.audio.codec_config);
            if (rc != VOD_OK) {
                ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                    "ngx_pckg_ksmp_parse_media_info: "
                    "failed to parse mp4a config");
                return NGX_BAD_DATA;
            }

            dest->codec_id = VOD_CODEC_ID_AAC;
            dest->format = FORMAT_MP4A;
            dest->u.audio.object_type_id = 0x40;
            break;

        case KMP_CODEC_AUDIO_MP3:
            dest->codec_id = VOD_CODEC_ID_MP3;
            dest->format = FORMAT_MP4A;
            dest->u.audio.object_type_id = src->u.audio.sample_rate > 24000 ?
                0x6B : 0x69;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: invalid audio codec id %uD",
                src->codec_id);
            return NGX_BAD_DATA;
        }

        dest->media_type = MEDIA_TYPE_AUDIO;
        dest->u.audio.channels = src->u.audio.channels;
        dest->u.audio.channel_layout = src->u.audio.channel_layout;
        dest->u.audio.bits_per_sample = src->u.audio.bits_per_sample;
        dest->u.audio.packet_size = 0;
        dest->u.audio.sample_rate = src->u.audio.sample_rate;

        if (codec_config_get_audio_codec_name(channel->log, dest) != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                "ngx_pckg_ksmp_parse_media_info: "
                "failed to get audio codec name");
            return NGX_BAD_DATA;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, channel->log, 0,
            "ngx_pckg_ksmp_parse_media_info: invalid media type %uD",
            src->media_type);
        return NGX_BAD_DATA;
    }

    dest->bitrate = src->bitrate;
    dest->timescale = src->timescale;
    dest->frames_timescale = src->timescale;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_media_info(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                      rc;
    ngx_pckg_track_t              *track = obj;
    ngx_pckg_media_info_t         *media_info;
    ngx_ksmp_media_info_header_t  *header;

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header) +
        sizeof(*media_info->kmp_media_info));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info: read header failed");
        return NGX_BAD_DATA;
    }

    if (track->last_media_info != NULL &&
        header->segment_index <=
            track->last_media_info->header->segment_index)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info: "
            "segment index %uD less than previous segment index %uD",
            header->segment_index,
            track->last_media_info->header->segment_index);
        return NGX_BAD_DATA;
    }

    if (header->bitrate_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info: invalid bitrate count");
        return NGX_BAD_DATA;
    }

    media_info = ngx_array_push(&track->media_info);
    if (media_info == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info: push failed");
        return NGX_ERROR;
    }

    media_info->header = header;
    media_info->kmp_media_info = (void *) (header + 1);

    if (media_info->kmp_media_info->media_type != track->header->media_type) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_media_info: "
            "media info type %uD doesn't match track %uD",
            media_info->kmp_media_info->media_type, track->header->media_type);
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &media_info->extra_data);

    ngx_memzero(&media_info->media_info, sizeof(media_info->media_info));
    media_info->media_info.codec_name.data = media_info->codec_name;

    rc = ngx_pckg_ksmp_parse_media_info(track->channel, media_info);
    if (rc != NGX_OK) {
        return rc;
    }

    track->last_media_info = media_info;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_variant(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t             i;
    uint32_t             track_id;
    ngx_str_t            id;
    ngx_pckg_track_t    *track;
    ngx_ksmp_variant_t  *header;
    ngx_pckg_variant_t  *variant;
    ngx_pckg_channel_t  *channel = obj;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: read id failed");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: read header failed");
        return NGX_BAD_DATA;
    }

    if (header->role > ngx_ksmp_variant_role_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: invalid role %uD",
            header->role);
        return NGX_BAD_DATA;
    }

    if (header->track_count <= 0 || header->track_count > KMP_MEDIA_COUNT) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: invalid track count %uD",
            header->track_count);
        return NGX_BAD_DATA;
    }

    variant = ngx_array_push(&channel->variants);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: push failed");
        return NGX_ERROR;
    }

    if (ngx_mem_rstream_str_get(rs, &variant->label) != NGX_OK ||
        ngx_mem_rstream_str_get(rs, &variant->lang) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_variant: read label/lang failed");
        return NGX_BAD_DATA;
    }

    if (header->role == ngx_ksmp_variant_role_main) {
        variant->label.len = 0;
    }

    if (channel->sorted_tracks == NULL) {
        if (ngx_pckg_ksmp_track_create_index(channel) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_memzero(variant->tracks, sizeof(variant->tracks));

    for (i = 0; i < header->track_count; i++) {
        if (ngx_mem_rstream_read(rs, &track_id, sizeof(track_id)) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_variant: read track id failed");
            return NGX_BAD_DATA;
        }

        track = ngx_pckg_ksmp_track_get(channel, track_id);
        if (track == NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_variant: failed to get track %uD",
                track_id);
            return NGX_BAD_DATA;
        }

        if (variant->tracks[track->header->media_type] != NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_variant: media type %uD already assigned",
                track->header->media_type);
            return NGX_BAD_DATA;
        }

        variant->tracks[track->header->media_type] = track;
    }

    variant->id = id;
    variant->header = header;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_segment_index(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_pckg_channel_t        *channel = obj;
    ngx_ksmp_segment_index_t  *header;

    if (channel->segment_index != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_segment_index: duplicate block");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment_index: read header failed");
        return NGX_BAD_DATA;
    }

    channel->segment_index = header;

    return NGX_OK;
}

static ngx_int_t
ngx_pckg_ksmp_read_dynamic_var(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                 hash;
    ngx_pckg_channel_t      *channel = obj;
    ngx_pckg_dynamic_var_t  *var;

    var = ngx_palloc(channel->pool, sizeof(*var));
    if (var == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_dynamic_var: alloc failed");
        return NGX_ERROR;
    }

    if (ngx_mem_rstream_str_get(rs, &var->sn.str) != NGX_OK ||
        ngx_mem_rstream_str_get(rs, &var->value) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_dynamic_var: read key/value failed");
        return NGX_BAD_DATA;
    }

    hash = ngx_crc32_short(var->sn.str.data, var->sn.str.len);
    var->sn.node.key = hash;
    ngx_rbtree_insert(&channel->vars.rbtree, &var->sn.node);

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_segment(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, n;
    ngx_flag_t                  found;
    ngx_pckg_track_t           *cur_track, *tracks;
    ngx_pckg_channel_t         *channel = obj;
    ngx_pckg_segment_t         *segment;
    ngx_ksmp_segment_header_t  *header;

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: read header failed");
        return NGX_BAD_DATA;
    }

    if (header->frame_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: invalid frame count");
        return NGX_BAD_DATA;
    }

    segment = ngx_pcalloc(channel->pool, sizeof(*segment));
    if (segment == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: alloc failed");
        return NGX_ERROR;
    }

    segment->header = header;


    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_SEGMENT, rs, segment);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: read blocks failed %i", rc);
        return rc;
    }


    if (segment->frames == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: missing frame list block");
        return NGX_BAD_DATA;
    }

    if (segment->media.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: missing frame data block");
        return NGX_BAD_DATA;
    }

    found = 0;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;
    for (i = 0; i < n; i++) {

        cur_track = &tracks[i];
        if (cur_track->last_media_info->header->track_id != header->track_id) {
            continue;
        }

        if (cur_track->segment != NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_pckg_ksmp_read_segment: track %uD already has a segment",
                cur_track->header->id);
            return NGX_BAD_DATA;
        }

        cur_track->segment = segment;
        found = 1;
    }

    if (!found) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_pckg_ksmp_read_segment: unused segment for track %uD",
            header->track_id);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_frame_list(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_str_t            frames;
    ngx_uint_t           frame_count;
    ngx_pckg_segment_t  *segment = obj;

    if (segment->frames != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_frame_list: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &frames);

    frame_count = frames.len / sizeof(segment->frames[0]);
    if (frame_count != segment->header->frame_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_frame_list: frame count mismatch"
            ", expected: %uD, actual: %ui",
            segment->header->frame_count, frame_count);
        return NGX_BAD_DATA;
    }

    segment->frames = (void *) frames.data;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_frame_data(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_pckg_segment_t  *segment = obj;

    if (segment->media.data != NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_pckg_ksmp_read_frame_data: duplicate block");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_get_left(rs, &segment->media);

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_ksmp_read_error(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_pckg_channel_t  *channel = obj;

    if (ngx_mem_rstream_read(rs, &channel->err_code, sizeof(channel->err_code))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_error: read code failed");
        return NGX_BAD_DATA;
    }

    if (ngx_mem_rstream_str_get(rs, &channel->err_message) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_pckg_ksmp_read_error: read message failed");
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}


ngx_int_t
ngx_pckg_ksmp_parse(ngx_pckg_channel_t *channel, ngx_str_t *buf,
    size_t max_size)
{
    ngx_int_t                   rc;
    ngx_mem_rstream_t           rs;
    ngx_persist_file_header_t  *header;

    rc = ngx_persist_read_file_header(buf, NGX_KSMP_PERSIST_TYPE, channel->log,
        NULL, &rs);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_parse: read header failed");
        return NGX_BAD_DATA;
    }

    rc = ngx_persist_read_inflate(buf, max_size, &rs, channel->pool, NULL);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_parse: inflate failed %i", rc);
        return rc;
    }

    rc = ngx_persist_conf_read_blocks(channel->persist, NGX_PCKG_KSMP_CTX_MAIN,
        &rs, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_parse: read blocks failed (1) %i", rc);
        return rc;
    }

    if (channel->err_code != NGX_KSMP_ERR_SUCCESS) {
        return NGX_OK;
    }

    if (channel->header == NULL) {
        ngx_log_error(NGX_LOG_ERR, channel->log, 0,
            "ngx_pckg_ksmp_parse: missing channel block");
        return NGX_BAD_DATA;
    }

    header = (void *) buf->data;
    if (header->size >= buf->len) {
        return NGX_OK;
    }

    ngx_mem_rstream_set(&rs, buf->data + header->size,
        buf->data + buf->len, channel->log, NULL);

    rc = ngx_persist_conf_read_blocks(channel->persist,
        NGX_PCKG_KSMP_CTX_MAIN, &rs, channel);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_ksmp_parse: read blocks failed (2) %i", rc);
        return rc;
    }

    return NGX_OK;
}


static ngx_persist_block_t  ngx_pckg_ksmp_blocks[] = {
    { NGX_KSMP_BLOCK_CHANNEL, NGX_PCKG_KSMP_CTX_MAIN, 0, NULL,
      ngx_pckg_ksmp_read_channel },

    { NGX_KSMP_BLOCK_TIMELINE, NGX_PCKG_KSMP_CTX_CHANNEL, 0, NULL,
      ngx_pckg_ksmp_read_timeline },

    { NGX_KSMP_BLOCK_PERIOD, NGX_PCKG_KSMP_CTX_TIMELINE, 0, NULL,
      ngx_pckg_ksmp_read_period },

    { NGX_KSMP_BLOCK_TRACK, NGX_PCKG_KSMP_CTX_CHANNEL, 0, NULL,
      ngx_pckg_ksmp_read_track },

    { NGX_KSMP_BLOCK_MEDIA_INFO_QUEUE, NGX_PCKG_KSMP_CTX_TRACK, 0, NULL,
      ngx_pckg_ksmp_read_media_info_queue },

    { NGX_KSMP_BLOCK_MEDIA_INFO, NGX_PCKG_KSMP_CTX_MEDIA_INFO, 0, NULL,
      ngx_pckg_ksmp_read_media_info },

    { NGX_KSMP_BLOCK_SEGMENT_INFO, NGX_PCKG_KSMP_CTX_TRACK, 0, NULL,
      ngx_pckg_ksmp_read_segment_info },

    { NGX_KSMP_BLOCK_VARIANT, NGX_PCKG_KSMP_CTX_CHANNEL, 0, NULL,
      ngx_pckg_ksmp_read_variant },

    { NGX_KSMP_BLOCK_SEGMENT_INDEX, NGX_PCKG_KSMP_CTX_CHANNEL, 0, NULL,
      ngx_pckg_ksmp_read_segment_index },

    { NGX_KSMP_BLOCK_DYNAMIC_VAR, NGX_PCKG_KSMP_CTX_CHANNEL, 0, NULL,
      ngx_pckg_ksmp_read_dynamic_var },


    { NGX_KSMP_BLOCK_SEGMENT, NGX_PCKG_KSMP_CTX_MAIN, 0, NULL,
      ngx_pckg_ksmp_read_segment },

    { NGX_KSMP_BLOCK_FRAME_LIST, NGX_PCKG_KSMP_CTX_SEGMENT, 0, NULL,
      ngx_pckg_ksmp_read_frame_list },

    { NGX_KSMP_BLOCK_FRAME_DATA, NGX_PCKG_KSMP_CTX_SEGMENT, 0, NULL,
      ngx_pckg_ksmp_read_frame_data },


    { NGX_KSMP_BLOCK_ERROR, NGX_PCKG_KSMP_CTX_MAIN, 0, NULL,
      ngx_pckg_ksmp_read_error },


    ngx_null_persist_block
};


ngx_persist_conf_t *
ngx_pckg_ksmp_conf_create(ngx_conf_t *cf)
{
    ngx_persist_conf_t  *persist;

    persist = ngx_persist_conf_create(cf, NGX_PCKG_KSMP_CTX_COUNT);
    if (persist == NULL) {
        return NULL;
    }

    if (ngx_persist_conf_add_blocks(cf, persist, ngx_pckg_ksmp_blocks)
        != NGX_OK)
    {
        return NULL;
    }

    return persist;
}


ngx_int_t
ngx_pckg_ksmp_create_request(ngx_pool_t *pool, ngx_pckg_ksmp_req_t *req,
    ngx_str_t *result)
{
    u_char     *p;
    size_t      size;
    uintptr_t   channel_escape;
    uintptr_t   timeline_escape;
    uintptr_t   variants_escape;

    channel_escape = ngx_escape_uri(NULL, req->channel_id.data,
        req->channel_id.len, NGX_ESCAPE_ARGS);

    timeline_escape = ngx_escape_uri(NULL, req->timeline_id.data,
        req->timeline_id.len, NGX_ESCAPE_ARGS);

    size = sizeof("channel_id=") - 1 + req->channel_id.len + channel_escape +
        sizeof("&timeline_id=") - 1 + req->timeline_id.len + timeline_escape +
        sizeof("&flags=") - 1 + NGX_INT32_HEX_LEN;

    if (req->variant_ids.data != NULL) {
        variants_escape = ngx_escape_uri(NULL, req->variant_ids.data,
            req->variant_ids.len, NGX_ESCAPE_ARGS);

        size += sizeof("&variant_ids=") - 1 + req->variant_ids.len +
            variants_escape;

    } else {
        variants_escape = 0;    /* suppress warning */
    }

    if (req->segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX) {
        size += sizeof("&segment_index=") - 1 + NGX_INT32_LEN;
    }

    req->media_type_mask &= KMP_MEDIA_TYPE_MASK;
    if ((req->media_type_mask & KMP_MEDIA_TYPE_MASK) ==
        KMP_MEDIA_TYPE_MASK)
    {
        req->media_type_mask = 0;

    } else {
        size += sizeof("&media_type_mask=") - 1 + NGX_INT32_HEX_LEN;
    }

    p = ngx_pnalloc(pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_pckg_ksmp_create_request: alloc failed");
        return NGX_ERROR;
    }

    result->data = p;

    p = ngx_copy(p, "channel_id=", sizeof("channel_id=") - 1);
    if (channel_escape) {
        p = (u_char *) ngx_escape_uri(p, req->channel_id.data,
            req->channel_id.len, NGX_ESCAPE_ARGS);

    } else {
        p = ngx_copy(p, req->channel_id.data, req->channel_id.len);
    }

    p = ngx_copy(p, "&timeline_id=", sizeof("&timeline_id=") - 1);
    if (timeline_escape) {
        p = (u_char *) ngx_escape_uri(p, req->timeline_id.data,
            req->timeline_id.len, NGX_ESCAPE_ARGS);

    } else {
        p = ngx_copy(p, req->timeline_id.data, req->timeline_id.len);
    }

    p = ngx_copy(p, "&flags=", sizeof("&flags=") - 1);
    p = ngx_sprintf(p, "%uxD", (uint32_t) req->flags);

    if (req->variant_ids.data != NULL) {
        p = ngx_copy(p, "&variant_ids=", sizeof("&variant_ids=") - 1);
        if (variants_escape) {
            p = (u_char *) ngx_escape_uri(p, req->variant_ids.data,
                req->variant_ids.len, NGX_ESCAPE_ARGS);

        } else {
            p = ngx_copy(p, req->variant_ids.data, req->variant_ids.len);
        }
    }

    if (req->segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX) {
        p = ngx_copy(p, "&segment_index=", sizeof("&segment_index=") - 1);
        p = ngx_sprintf(p, "%uD", (uint32_t) req->segment_index);
    }

    if (req->media_type_mask) {
        p = ngx_copy(p, "&media_type_mask=", sizeof("&media_type_mask=") - 1);
        p = ngx_sprintf(p, "%uxD", (uint32_t) req->media_type_mask);
    }

    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_pckg_ksmp_create_request: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}
