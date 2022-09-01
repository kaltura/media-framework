#include "ttml_builder.h"
#include "webvtt_builder.h"
#include "../frames_source_memory.h"

// constants
#define TTML_TIMESTAMP_FORMAT "%02uD:%02uD:%02uD.%03uD"
#define TTML_TIMESTAMP_MAX_SIZE (VOD_INT32_LEN + sizeof(":00:00.000") - 1)

#define TTML_HEADER                                                          \
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"                           \
    "<tt xmlns=\"http://www.w3.org/ns/ttml\">\n"                             \
    "  <head/>\n"                                                            \
    "  <body>\n"                                                             \
    "    <div>\n"

#define TTML_FOOTER                                                          \
    "    </div>\n"                                                           \
    "  </body>\n"                                                            \
    "</tt>\n"

#define TTML_P_HEADER_PART1 "      <p begin=\""
#define TTML_P_HEADER_PART2 "\" end=\""
#define TTML_P_HEADER_PART3 "\">"
#define TTML_P_FOOTER "</p>\n"

#define TTML_P_MAX_SIZE                                                      \
    (sizeof(TTML_P_HEADER_PART1) - 1 +                                       \
    sizeof(TTML_P_HEADER_PART2) - 1 +                                        \
    sizeof(TTML_P_HEADER_PART3) - 1 +                                        \
    TTML_TIMESTAMP_MAX_SIZE * 2 +                                            \
    sizeof(TTML_P_FOOTER) - 1)


static vod_inline u_char*
ttml_builder_write_timestamp(u_char* p, uint64_t ts, uint32_t timescale)
{
    ts = rescale_time(ts, timescale, 1000);

    return vod_sprintf(p, TTML_TIMESTAMP_FORMAT,
        (uint32_t)(ts / 3600000),
        (uint32_t)((ts / 60000) % 60),
        (uint32_t)((ts / 1000) % 60),
        (uint32_t)(ts % 1000));
}


static u_char*
ttml_builder_strip_tags(u_char* p, u_char* src, uint32_t len)
{
    u_char* end = src + len;
    u_char* next_lt;

    for (;;)
    {
        // copy up to next lt
        next_lt = memchr(src, '<', end - src);
        if (next_lt == NULL)
        {
            p = vod_copy(p, src, end - src);
            break;
        }

        p = vod_copy(p, src, next_lt - src);

        // skip up to next gt
        src = memchr(next_lt, '>', end - next_lt);
        if (src == NULL)
        {
            break;
        }

        src++;
    }

    return p;
}


static size_t
ttml_builder_get_max_size(media_segment_track_t* track)
{
    return sizeof(TTML_HEADER) - 1 +
        TTML_P_MAX_SIZE * track->frame_count +
        media_segment_track_get_total_size(track) +
        sizeof(TTML_FOOTER) - 1;
}


static vod_status_t
ttml_builder_write(request_context_t* request_context, media_segment_track_t* track, vod_str_t* buf)
{
    vod_list_part_t* part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;
    vod_status_t rc;
    webvtt_cue_t cue;
    uint32_t timescale;
    uint32_t size;
    int64_t cur_pts;
    int64_t cue_start;
    int64_t cue_end;
    u_char* data;
    u_char* p;
    bool_t frame_done;

    p = vod_copy(buf->data, TTML_HEADER, sizeof(TTML_HEADER) - 1);

    cur_pts = track->start_dts;
    timescale = track->media_info->timescale;

    part = &track->frames.part;
    cur_frame = part->elts;
    last_frame = cur_frame + part->nelts;

    for (;; cur_frame++)
    {
        if (cur_frame >= last_frame)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            cur_frame = part->elts;
            last_frame = cur_frame + part->nelts;
        }

        rc = track->frames_source->start_frame(track->frames_source_context, cur_frame);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "ttml_builder_write: start frame failed %i", rc);
            return rc;
        }

        rc = track->frames_source->read(track->frames_source_context, &data, &size, &frame_done);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "ttml_builder_write: read frame failed %i", rc);
            return rc;
        }

        if (!frame_done)
        {
            vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                "ttml_builder_write: frame not done");
            return VOD_UNEXPECTED;
        }

        cue_start = cur_pts;
        cue_end = cur_pts + cur_frame->pts_delay;

        cur_pts += cur_frame->duration;

        if (webvtt_parse_cue(request_context, data, size, &cue) != VOD_OK || cue.payload.len <= 0)
        {
            continue;
        }

        // open p tag
        p = vod_copy(p, TTML_P_HEADER_PART1, sizeof(TTML_P_HEADER_PART1) - 1);
        p = ttml_builder_write_timestamp(p, cue_start, timescale);
        p = vod_copy(p, TTML_P_HEADER_PART2, sizeof(TTML_P_HEADER_PART2) - 1);
        p = ttml_builder_write_timestamp(p, cue_end, timescale);
        p = vod_copy(p, TTML_P_HEADER_PART3, sizeof(TTML_P_HEADER_PART3) - 1);

        // cue body
        p = ttml_builder_strip_tags(p, cue.payload.data, cue.payload.len);

        // close p tag
        p = vod_copy(p, TTML_P_FOOTER, sizeof(TTML_P_FOOTER) - 1);
    }

    p = vod_copy(p, TTML_FOOTER, sizeof(TTML_FOOTER) - 1);

    buf->len = p - buf->data;

    return VOD_OK;
}


vod_status_t
ttml_builder_convert_segment(request_context_t* request_context, media_segment_t* segment)
{
    media_segment_track_t* track;
    input_frame_t* frame;
    vod_status_t rc;
    vod_str_t buf;
    size_t size;

    for (track = segment->tracks; track < segment->tracks_end; track++)
    {
        if (track->media_info->codec_id != VOD_CODEC_ID_WEBVTT)
        {
            continue;
        }

        size = ttml_builder_get_max_size(track);

        buf.data = vod_alloc(request_context->pool, size);
        if (buf.data == NULL)
        {
            vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "ttml_builder_convert_segment: alloc failed");
            return VOD_ALLOC_FAILED;
        }

        rc = ttml_builder_write(request_context, track, &buf);
        if (rc != VOD_OK)
        {
            return rc;
        }

        frame = vod_alloc(request_context->pool, sizeof(*frame));
        if (frame == NULL)
        {
            vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "ttml_builder_convert_segment: alloc frame failed");
            return VOD_ALLOC_FAILED;
        }

        vod_memzero(frame, sizeof(*frame));

        frame->size = buf.len;
        frame->duration = segment->duration;

        track->frames.part.elts = frame;
        track->frames.part.nelts = 1;
        track->frames.part.next = NULL;

        track->frame_count = 1;

        track->start_dts = segment->start;

        rc = frames_source_memory_init(request_context, buf.data, buf.len, &track->frames_source_context);
        if (rc != VOD_OK)
        {
            return rc;
        }

        track->frames_source = &frames_source_memory;

        track->media_info->codec_id = VOD_CODEC_ID_TTML;
        track->media_info->extra_data.len = 0;
    }

    return VOD_OK;
}


vod_status_t
ttml_builder_convert_init_segment(request_context_t* request_context, media_init_segment_t* segment)
{
    media_init_segment_track_t* track;

    for (track = segment->first; track < segment->last; track++)
    {
        if (track->media_info->codec_id != VOD_CODEC_ID_WEBVTT)
        {
            continue;
        }

        track->media_info->codec_id = VOD_CODEC_ID_TTML;
        track->media_info->extra_data.len = 0;
    }

    return VOD_OK;
}
