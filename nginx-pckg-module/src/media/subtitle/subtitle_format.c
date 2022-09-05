#include "subtitle_format.h"


typedef struct {
    vod_log_t* log;
    void** pos;
    void** end;
    size_t frame_size;
} multi_buf_frame_source_t;


static multi_buf_frame_source_t*
multi_buf_frame_source_init(vod_pool_t* pool, uint32_t frame_count)
{
    multi_buf_frame_source_t* state;

    state = vod_alloc(pool, sizeof(*state));
    if (state == NULL)
    {
        vod_log_error(VOD_LOG_NOTICE, pool->log, 0,
            "multi_buf_frame_source_init: alloc state failed");
        return NULL;
    }

    state->pos = vod_alloc(pool, sizeof(state->pos[0]) * frame_count);
    if (state->pos == NULL)
    {
        vod_log_error(VOD_LOG_NOTICE, pool->log, 0,
            "multi_buf_frame_source_init: alloc failed");
        return NULL;
    }

    state->log = pool->log;
    state->end = state->pos;

    return state;
}

static void
multi_buf_frame_source_push(multi_buf_frame_source_t* state, void* buf)
{
    *state->end++ = buf;
}


static vod_status_t
multi_buf_frame_source_start_frame(void* ctx, input_frame_t* frame)
{
    multi_buf_frame_source_t* state = ctx;

    state->frame_size = frame->size;

    return VOD_OK;
}


static vod_status_t
multi_buf_frame_source_read(void* ctx, u_char** buffer, uint32_t* size,
    bool_t* frame_done)
{
    multi_buf_frame_source_t* state = ctx;

    if (state->pos >= state->end)
    {
        vod_log_error(VOD_LOG_ERR, state->log, 0,
            "multi_buf_frame_source_read: no more frames");
        return VOD_BAD_DATA;
    }

    *buffer = *state->pos;
    *size = state->frame_size;
    *frame_done = TRUE;

    state->pos++;

    return VOD_OK;
}


static frames_source_t multi_buf_frame_source = {
    multi_buf_frame_source_start_frame,
    multi_buf_frame_source_read,
};


static vod_status_t
subtitle_trim_timestamps_track(request_context_t* request_context, media_segment_t* segment, media_segment_track_t* track)
{
    multi_buf_frame_source_t* frame_src;
    vod_list_part_t* part;
    input_frame_t* src_cur;
    input_frame_t* src_last;
    input_frame_t* dst_frames;
    input_frame_t* dst_cur;
    vod_status_t rc;
    uint32_t size;
    int64_t segment_start;
    int64_t segment_end;
    int64_t cur_pts;
    int64_t last_cue_start;
    int64_t cue_start;
    int64_t cue_end;
    u_char* data;
    bool_t frame_done;

    frame_src = multi_buf_frame_source_init(request_context->pool, track->frame_count);
    if (frame_src == NULL)
    {
        return VOD_ALLOC_FAILED;
    }

    dst_frames = vod_alloc(request_context->pool, sizeof(dst_frames[0]) * track->frame_count);
    if (dst_frames == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "subtitle_trim_timestamps_track: alloc frames failed");
        return VOD_ALLOC_FAILED;
    }

    last_cue_start = 0;     /* suppress warning */
    dst_cur = dst_frames;

    segment_start = segment->start;
    segment_end = segment_start + segment->duration;

    cur_pts = track->start_dts;

    part = &track->frames.part;
    src_cur = part->elts;
    src_last = src_cur + part->nelts;

    for (;; src_cur++)
    {
        if (src_cur >= src_last)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            src_cur = part->elts;
            src_last = src_cur + part->nelts;
        }

        if (cur_pts >= segment_end)
        {
            break;
        }

        // get the frame buffer
        rc = track->frames_source->start_frame(track->frames_source_context, src_cur);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "subtitle_trim_timestamps_track: start frame failed %i", rc);
            return rc;
        }

        rc = track->frames_source->read(track->frames_source_context, &data, &size, &frame_done);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "subtitle_trim_timestamps_track: read frame failed %i", rc);
            return rc;
        }

        if (!frame_done)
        {
            vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                "subtitle_trim_timestamps_track: frame not done");
            return VOD_UNEXPECTED;
        }

        // trim the timestamps
        cue_start = cur_pts;
        if (cue_start < segment_start)
        {
            cue_start = segment_start;
        }

        cue_end = cur_pts + src_cur->pts_delay;
        if (cue_end > segment_end)
        {
            cue_end = segment_end;
        }

        cur_pts += src_cur->duration;

        if (cue_start >= cue_end)
        {
            continue;
        }

        // add the frame
        if (dst_cur == dst_frames)
        {
            track->start_dts = cue_start;
        }
        else
        {
            dst_cur[-1].duration = cue_start - last_cue_start;
        }

        dst_cur->pts_delay = cue_end - cue_start;
        dst_cur->size = src_cur->size;
        dst_cur->key_frame = 0;
        dst_cur->duration = 0;

        dst_cur++;

        multi_buf_frame_source_push(frame_src, data);

        last_cue_start = cue_start;
    }

    track->frame_count = dst_cur - dst_frames;
    if (track->frame_count <= 0)
    {
        track->start_dts = segment_start;
    }

    track->frames.part.elts = dst_frames;
    track->frames.part.nelts = track->frame_count;
    track->frames.part.next = NULL;

    track->frames_source = &multi_buf_frame_source;
    track->frames_source_context = frame_src;

    return VOD_OK;
}


vod_status_t
subtitle_trim_timestamps(request_context_t* request_context, media_segment_t* segment)
{
    media_segment_track_t* track;
    vod_status_t rc;

    if (segment->duration <= 0)
    {
        return VOD_OK;
    }

    for (track = segment->tracks; track < segment->tracks_end; track++)
    {
        if (track->media_info->media_type != MEDIA_TYPE_SUBTITLE)
        {
            continue;
        }

        rc = subtitle_trim_timestamps_track(request_context, segment, track);
        if (rc != VOD_OK)
        {
            return rc;
        }
    }

    return VOD_OK;
}
