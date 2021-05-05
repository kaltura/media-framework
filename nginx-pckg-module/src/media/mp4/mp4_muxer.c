#include "mp4_muxer.h"
#include "../mp4/mp4_defs.h"
#include "../mp4/mp4_fragment.h"

// constants
#define MDAT_HEADER_SIZE (ATOM_HEADER_SIZE)

// macros
#define mp4_rescale_millis(millis, timescale) (millis * ((timescale) / 1000))

// state
typedef struct {
    // fixed
    write_callback_t write_callback;
    void* write_context;
    uint32_t timescale;
    int media_type;
    uint32_t frame_count;
    uint32_t index;

    uint64_t first_frame_time_offset;
    uint64_t next_frame_time_offset;
    uint64_t total_frames_duration;

    // input frames
    vod_list_part_t* first_frame_part;
    vod_list_part_t* cur_frame_part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;
    uint32_t last_frame_size;

    frames_source_t* frames_source;
    void* frames_source_context;

    // frame output offsets
    uint32_t* first_frame_output_offset;
    uint32_t* cur_frame_output_offset;
} mp4_muxer_stream_state_t;

struct mp4_muxer_state_s {
    // fixed
    request_context_t* request_context;
    bool_t reuse_buffers;
    media_segment_t* segment;
    bool_t per_stream_writer;

    mp4_muxer_stream_state_t* first_stream;
    mp4_muxer_stream_state_t* last_stream;

    mp4_muxer_stream_state_t* selected_stream;
    input_frame_t* cur_frame;
    int cache_slot_id;
    frames_source_t* frames_source;
    void* frames_source_context;
    bool_t first_time;
};

typedef struct {
    u_char version[1];
    u_char flags[3];
    u_char reference_id[4];
    u_char timescale[4];
    u_char earliest_pres_time[4];
    u_char first_offset[4];
    u_char reserved[2];
    u_char reference_count[2];
    u_char reference_size[4];            // Note: from this point forward, assuming reference_count == 1
    u_char subsegment_duration[4];
    u_char sap_type[1];
    u_char sap_delta_time[3];
} sidx_atom_t;

typedef struct {
    u_char version[1];
    u_char flags[3];
    u_char reference_id[4];
    u_char timescale[4];
    u_char earliest_pres_time[8];
    u_char first_offset[8];
    u_char reserved[2];
    u_char reference_count[2];
    u_char reference_size[4];            // Note: from this point forward, assuming reference_count == 1
    u_char subsegment_duration[4];
    u_char sap_type[1];
    u_char sap_delta_time[3];
} sidx64_atom_t;

static const u_char styp_atom[] = {
    0x00, 0x00, 0x00, 0x18,        // atom size
    0x73, 0x74, 0x79, 0x70,        // styp
    0x6d, 0x73, 0x64, 0x68,        // major brand (msdh)
    0x00, 0x00, 0x00, 0x00,        // minor version
    0x6d, 0x73, 0x64, 0x68,        // compatible brand (msdh)
    0x6d, 0x73, 0x69, 0x78,        // compatible brand (msix)
};

static vod_status_t mp4_muxer_start_frame(mp4_muxer_state_t* state);

// trun write functions
static u_char*
mp4_muxer_write_trun_header(
    u_char* p,
    uint32_t offset,
    uint32_t frame_count,
    uint32_t frame_size,
    uint32_t flags)
{
    size_t atom_size;

    atom_size = ATOM_HEADER_SIZE + sizeof(trun_atom_t) + frame_size * frame_count;

    write_atom_header(p, atom_size, 't', 'r', 'u', 'n');
    write_be32(p, flags);                // flags
    write_be32(p, frame_count);            // frame count
    write_be32(p, offset);                // offset from mdat start to frame raw data (excluding the tag)

    return p;
}

static u_char*
mp4_muxer_write_video_trun_frame(u_char* p, input_frame_t* frame, uint32_t initial_pts_delay)
{
    int32_t pts_delay = frame->pts_delay - initial_pts_delay;

    write_be32(p, frame->duration);
    write_be32(p, frame->size);
    if (frame->key_frame)
    {
        write_be32(p, 0x02000000);        // I-frame
    }
    else
    {
        write_be32(p, 0x01010000);        // not I-frame + non key sample
    }
    write_be32(p, pts_delay);
    return p;
}

static u_char*
mp4_muxer_write_audio_trun_frame(u_char* p, input_frame_t* frame)
{
    write_be32(p, frame->duration);
    write_be32(p, frame->size);
    return p;
}

static u_char*
mp4_muxer_write_video_trun_atoms(
    u_char* p,
    media_segment_t* segment,
    mp4_muxer_stream_state_t* cur_stream,
    uint32_t base_offset)
{
    media_segment_track_t* cur_track;
    vod_list_part_t* part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;
    uint32_t initial_pts_delay;
    uint32_t* output_offset = cur_stream->first_frame_output_offset;
    uint32_t start_offset = 0;
    uint32_t cur_offset = UINT_MAX;
    uint32_t frame_count = 0;
    u_char* trun_header = NULL;

    cur_track = &segment->tracks[cur_stream->index];
    part = &cur_track->frames.part;
    cur_frame = part->elts;

    if (part->nelts > 0)
    {
        initial_pts_delay = cur_frame->pts_delay;
    }
    else
    {
        initial_pts_delay = 0;
    }

    for (last_frame = cur_frame + part->nelts; ; cur_frame++, output_offset++)
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

        if (*output_offset != cur_offset)
        {
            if (trun_header != NULL)
            {
                // close current trun atom
                mp4_muxer_write_trun_header(
                    trun_header,
                    base_offset + start_offset,
                    frame_count,
                    sizeof(trun_video_frame_t),
                    (1 << 24) | TRUN_VIDEO_FLAGS);        // version = 1
            }

            // start a new trun atom
            trun_header = p;
            p += ATOM_HEADER_SIZE + sizeof(trun_atom_t);
            cur_offset = start_offset = *output_offset;
            frame_count = 0;
        }

        // add the frame to the trun atom
        p = mp4_muxer_write_video_trun_frame(p, cur_frame, initial_pts_delay);
        frame_count++;
        cur_offset += cur_frame->size;
    }

    if (trun_header != NULL)
    {
        // close current trun atom
        mp4_muxer_write_trun_header(
            trun_header,
            base_offset + start_offset,
            frame_count,
            sizeof(trun_video_frame_t),
            (1 << 24) | TRUN_VIDEO_FLAGS);        // version = 1
    }

    return p;
}

static u_char*
mp4_muxer_write_audio_trun_atoms(
    u_char* p,
    media_segment_t* segment,
    mp4_muxer_stream_state_t* cur_stream,
    uint32_t base_offset)
{
    media_segment_track_t* cur_track;
    vod_list_part_t* part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;
    uint32_t* output_offset = cur_stream->first_frame_output_offset;
    uint32_t start_offset = 0;
    uint32_t cur_offset = UINT_MAX;
    uint32_t frame_count = 0;
    u_char* trun_header = NULL;

    cur_track = &segment->tracks[cur_stream->index];

    part = &cur_track->frames.part;
    for (cur_frame = part->elts, last_frame = cur_frame + part->nelts;
        ;
        cur_frame++, output_offset++)
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

        if (*output_offset != cur_offset)
        {
            if (trun_header != NULL)
            {
                // close current trun atom
                mp4_muxer_write_trun_header(
                    trun_header,
                    base_offset + start_offset,
                    frame_count,
                    sizeof(trun_audio_frame_t),
                    TRUN_AUDIO_FLAGS);
            }

            // add the frame to the trun atom
            trun_header = p;
            p += ATOM_HEADER_SIZE + sizeof(trun_atom_t);
            cur_offset = start_offset = *output_offset;
            frame_count = 0;
        }

        // add the frame to the trun atom
        p = mp4_muxer_write_audio_trun_frame(p, cur_frame);
        frame_count++;
        cur_offset += cur_frame->size;
    }

    if (trun_header != NULL)
    {
        // close current trun atom
        mp4_muxer_write_trun_header(
            trun_header,
            base_offset + start_offset,
            frame_count,
            sizeof(trun_audio_frame_t),
            TRUN_AUDIO_FLAGS);
    }

    return p;
}

////// Muxer

static void
mp4_muxer_init_track(
    mp4_muxer_state_t* state,
    mp4_muxer_stream_state_t* cur_stream,
    media_segment_track_t* cur_track)
{
    cur_stream->timescale = cur_track->media_info->timescale;
    cur_stream->media_type = cur_track->media_info->media_type;
    cur_stream->first_frame_part = &cur_track->frames.part;
    cur_stream->cur_frame_part = &cur_track->frames.part;
    cur_stream->cur_frame = cur_track->frames.part.elts;
    cur_stream->last_frame = cur_stream->cur_frame + cur_track->frames.part.nelts;
    cur_stream->frames_source = cur_track->frames_source;
    cur_stream->frames_source_context = cur_track->frames_source_context;

    cur_stream->first_frame_time_offset = cur_track->start_dts;
    cur_stream->next_frame_time_offset = cur_stream->first_frame_time_offset;
}

static vod_status_t
mp4_muxer_choose_stream(mp4_muxer_state_t* state)
{
    mp4_muxer_stream_state_t* cur_stream;
    mp4_muxer_stream_state_t* min_dts = NULL;
    uint64_t min_time_offset = 0;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        if (cur_stream->cur_frame >= cur_stream->last_frame)
        {
            if (cur_stream->cur_frame_part->next == NULL)
            {
                continue;
            }

            cur_stream->cur_frame_part = cur_stream->cur_frame_part->next;
            cur_stream->cur_frame = cur_stream->cur_frame_part->elts;
            cur_stream->last_frame = cur_stream->cur_frame + cur_stream->cur_frame_part->nelts;
            state->first_time = TRUE;
        }

        if (min_dts == NULL ||
            cur_stream->next_frame_time_offset < min_time_offset)
        {
            min_dts = cur_stream;

            min_time_offset = min_dts->next_frame_time_offset;
            if (min_dts != state->selected_stream)
            {
                min_time_offset += min_dts->timescale / 4;        // prefer the last selected stream, allow 0.25s delay
            }
        }
    }

    if (min_dts != NULL)
    {
        state->selected_stream = min_dts;
        return VOD_OK;
    }

    return VOD_NOT_FOUND;
}

static vod_status_t
mp4_calculate_output_offsets(
    mp4_muxer_state_t* state,
    size_t* frames_size,
    uint32_t* trun_atom_count)
{
    mp4_muxer_stream_state_t* selected_stream;
    mp4_muxer_stream_state_t* cur_stream;
    uint32_t cur_offset = 0;
    vod_status_t rc;

    *trun_atom_count = 0;

    for (;;)
    {
        // choose a stream
        rc = mp4_muxer_choose_stream(state);
        if (rc != VOD_OK)
        {
            if (rc == VOD_NOT_FOUND)
            {
                break;        // done
            }
            return rc;
        }

        selected_stream = state->selected_stream;

        // check for a stream switch
        if (selected_stream->last_frame_size == UINT_MAX ||
            cur_offset != selected_stream->cur_frame_output_offset[-1] + selected_stream->last_frame_size)
        {
            (*trun_atom_count)++;
        }
        selected_stream->last_frame_size = selected_stream->cur_frame->size;

        // set the offset (points to the beginning of the actual data)
        *selected_stream->cur_frame_output_offset = cur_offset;
        selected_stream->cur_frame_output_offset++;

        // update the offset
        cur_offset += selected_stream->last_frame_size;

        // move to the next frame
        selected_stream->next_frame_time_offset += selected_stream->cur_frame->duration;
        selected_stream->cur_frame++;
    }

    // reset the state
    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        cur_stream->total_frames_duration = cur_stream->next_frame_time_offset - cur_stream->first_frame_time_offset;

        cur_stream->cur_frame_part = cur_stream->first_frame_part;
        cur_stream->cur_frame = cur_stream->cur_frame_part->elts;
        cur_stream->last_frame = cur_stream->cur_frame + cur_stream->cur_frame_part->nelts;
        cur_stream->cur_frame_output_offset = cur_stream->first_frame_output_offset;
        cur_stream->next_frame_time_offset = cur_stream->first_frame_time_offset;
    }

    state->selected_stream = NULL;

    *frames_size = cur_offset;

    return VOD_OK;
}

static vod_status_t
mp4_muxer_init_state(
    request_context_t* request_context,
    media_segment_t* segment,
    segment_writer_t* track_writers,
    bool_t per_stream_writer,
    bool_t reuse_buffers,
    mp4_muxer_state_t** result)
{
    media_segment_track_t* cur_track;
    mp4_muxer_stream_state_t* cur_stream;
    mp4_muxer_state_t* state;
    uint32_t index;

    // allocate the state and stream states
    state = vod_alloc(request_context->pool, sizeof(*state));
    if (state == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_muxer_init_state: vod_alloc failed (1)");
        return VOD_ALLOC_FAILED;
    }

    state->first_stream = vod_alloc(
        request_context->pool,
        sizeof(state->first_stream[0]) * segment->track_count);
    if (state->first_stream == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_muxer_init_state: vod_alloc failed (2)");
        return VOD_ALLOC_FAILED;
    }

    state->last_stream = state->first_stream + segment->track_count;
    state->request_context = request_context;
    state->reuse_buffers = reuse_buffers;
    state->segment = segment;
    state->per_stream_writer = per_stream_writer;
    state->cur_frame = NULL;
    state->selected_stream = NULL;
    state->first_time = TRUE;

    index = 0;
    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++, index++)
    {
        cur_track = &segment->tracks[index];
        cur_stream->index = index;
        cur_stream->write_callback = track_writers->write_tail;
        cur_stream->write_context = track_writers->context;
        if (per_stream_writer)
        {
            track_writers++;
        }

        // get total frame count for this stream
        cur_stream->frame_count = cur_track->frame_count;

        // allocate the output offset
        cur_stream->first_frame_output_offset = vod_alloc(
            request_context->pool,
            cur_stream->frame_count * sizeof(cur_stream->first_frame_output_offset[0]));
        if (cur_stream->first_frame_output_offset == NULL)
        {
            vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "mp4_muxer_init_state: vod_alloc failed (3)");
            return VOD_ALLOC_FAILED;
        }
        cur_stream->cur_frame_output_offset = cur_stream->first_frame_output_offset;
        cur_stream->last_frame_size = UINT_MAX;

        // init the stream
        mp4_muxer_init_track(state, cur_stream, cur_track);
    }

    *result = state;

    return VOD_OK;
}

static int64_t
mp4_muxer_get_earliest_pres_time(media_segment_t* segment, uint32_t index)
{
    media_segment_track_t* track;
    input_frame_t* first_frame;
    int64_t result;

    track = &segment->tracks[index];

    result = track->start_dts;

    if (track->frame_count > 0 && track->media_info->media_type == MEDIA_TYPE_VIDEO)
    {
        first_frame = track->frames.part.elts;
        result += first_frame[0].pts_delay;
    }

    return result;
}

static u_char*
dash_packager_write_sidx_atom(
    u_char* p,
    mp4_muxer_stream_state_t* stream,
    int64_t earliest_pres_time,
    uint32_t reference_size)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sidx_atom_t);

    write_atom_header(p, atom_size, 's', 'i', 'd', 'x');
    write_be32(p, 0);                    // version + flags
    write_be32(p, 1);                    // reference id
    write_be32(p, stream->timescale);    // timescale
    write_be32(p, earliest_pres_time);   // earliest presentation time
    write_be32(p, 0);                    // first offset
    write_be32(p, 1);                    // reserved + reference count
    write_be32(p, reference_size);       // referenced size
    write_be32(p, stream->total_frames_duration);    // subsegment duration
    write_be32(p, 0x90000000);           // starts with SAP / SAP type
    return p;
}

static u_char*
dash_packager_write_sidx64_atom(
    u_char* p,
    mp4_muxer_stream_state_t* stream,
    int64_t earliest_pres_time,
    uint32_t reference_size)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sidx64_atom_t);

    write_atom_header(p, atom_size, 's', 'i', 'd', 'x');
    write_be32(p, 0x01000000);           // version + flags
    write_be32(p, 1);                    // reference id
    write_be32(p, stream->timescale);    // timescale
    write_be64(p, earliest_pres_time);   // earliest presentation time
    write_be64(p, 0LL);                  // first offset
    write_be32(p, 1);                    // reserved + reference count
    write_be32(p, reference_size);       // referenced size
    write_be32(p, stream->total_frames_duration);    // subsegment duration
    write_be32(p, 0x90000000);           // starts with SAP / SAP type
    return p;
}

vod_status_t
mp4_muxer_init_fragment(
    request_context_t* request_context,
    media_segment_t* segment,
    segment_writer_t* track_writers,
    bool_t per_stream_writer,
    bool_t reuse_buffers,
    bool_t size_only,
    vod_str_t* header,
    size_t* total_fragment_size,
    mp4_muxer_state_t** processor_state)
{
    mp4_muxer_stream_state_t* cur_stream;
    mp4_muxer_state_t* state;
    vod_status_t rc;
    uint32_t trun_atom_count;
    int64_t earliest_pres_time;
    size_t styp_atom_size;
    size_t sidx_atom_size;
    size_t moof_atom_size;
    size_t traf_atom_size;
    size_t mdat_atom_size = 0;
    size_t result_size;
    u_char* traf_header;
    u_char* p;

    // initialize the muxer state
    rc = mp4_muxer_init_state(
        request_context,
        segment,
        track_writers,
        per_stream_writer,
        reuse_buffers,
        &state);
    if (rc != VOD_OK)
    {
        vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_muxer_init_fragment: mp4_muxer_init_state failed %i", rc);
        return rc;
    }

    // init output offsets and get the mdat size
    rc = mp4_calculate_output_offsets(state, &mdat_atom_size, &trun_atom_count);
    if (rc != VOD_OK)
    {
        return rc;
    }
    mdat_atom_size += MDAT_HEADER_SIZE;

    // get the moof size
    moof_atom_size =
        ATOM_HEADER_SIZE +        // moof
        ATOM_HEADER_SIZE + sizeof(mfhd_atom_t) +
        (ATOM_HEADER_SIZE +        // traf
        ATOM_HEADER_SIZE + sizeof(tfhd_atom_t) + sizeof(uint32_t) +
        ATOM_HEADER_SIZE + sizeof(tfdt64_atom_t)) * segment->track_count +
        (ATOM_HEADER_SIZE + sizeof(trun_atom_t)) * trun_atom_count;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        switch (cur_stream->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            moof_atom_size += cur_stream->frame_count * sizeof(trun_video_frame_t);
            break;
        case MEDIA_TYPE_AUDIO:
            moof_atom_size += cur_stream->frame_count * sizeof(trun_audio_frame_t);
            break;
        }
    }

    if (segment->track_count == 1)
    {
        styp_atom_size = sizeof(styp_atom);

        earliest_pres_time = mp4_muxer_get_earliest_pres_time(segment, 0);
        sidx_atom_size = ATOM_HEADER_SIZE + (earliest_pres_time > UINT_MAX ? sizeof(sidx64_atom_t) : sizeof(sidx_atom_t));
    }
    else
    {
        styp_atom_size = 0;

        earliest_pres_time = 0;
        sidx_atom_size = 0;
    }

    *total_fragment_size =
        styp_atom_size +
        sidx_atom_size +
        moof_atom_size +
        mdat_atom_size;

    // head request optimization
    if (size_only)
    {
        return VOD_OK;
    }

    // allocate the response
    result_size =
        styp_atom_size +
        sidx_atom_size +
        moof_atom_size +
        MDAT_HEADER_SIZE;

    header->data = vod_alloc(request_context->pool, result_size);
    if (header->data == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_muxer_init_fragment: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    p = header->data;

    if (styp_atom_size > 0)
    {
        p = ngx_copy(p, styp_atom, sizeof(styp_atom));
    }

    // sidx
    if (sidx_atom_size > 0)
    {
        if (earliest_pres_time > UINT_MAX)
        {
            p = dash_packager_write_sidx64_atom(p, state->first_stream, earliest_pres_time, moof_atom_size + mdat_atom_size);
        }
        else
        {
            p = dash_packager_write_sidx_atom(p, state->first_stream, earliest_pres_time, moof_atom_size + mdat_atom_size);
        }
    }

    // moof
    write_atom_header(p, moof_atom_size, 'm', 'o', 'o', 'f');

    // moof.mfhd
    p = mp4_fragment_write_mfhd_atom(p, segment->segment_index);

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        // skip moof.traf
        traf_header = p;
        p += ATOM_HEADER_SIZE;

        // moof.traf.tfhd
        p = mp4_fragment_write_tfhd_atom(p, cur_stream->index + 1, 1);

        // Note: according to spec, tfdt has the dts time, however, since we force pts delay to 0
        //      on the first frame, we are effectively shifting the dts forward, and need to use
        //      pts here.

        // moof.traf.tfdt
        earliest_pres_time = mp4_muxer_get_earliest_pres_time(
            segment,
            cur_stream->index);
        p = mp4_fragment_write_tfdt64_atom(p, earliest_pres_time);

        // moof.traf.trun
        switch (cur_stream->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            p = mp4_muxer_write_video_trun_atoms(
                p,
                segment,
                cur_stream,
                moof_atom_size + MDAT_HEADER_SIZE);
            break;

        case MEDIA_TYPE_AUDIO:
            p = mp4_muxer_write_audio_trun_atoms(
                p,
                segment,
                cur_stream,
                moof_atom_size + MDAT_HEADER_SIZE);
            break;
        }

        // moof.traf
        traf_atom_size = p - traf_header;
        write_atom_header(traf_header, traf_atom_size, 't', 'r', 'a', 'f');
    }

    // mdat
    write_atom_header(p, mdat_atom_size, 'm', 'd', 'a', 't');

    header->len = p - header->data;

    if (header->len != result_size)
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_muxer_init_fragment: result length %uz exceeded allocated length %uz",
            header->len, result_size);
        return VOD_UNEXPECTED;
    }

    rc = mp4_muxer_start_frame(state);
    if (rc != VOD_OK)
    {
        if (rc == VOD_NOT_FOUND)
        {
            *processor_state = NULL;        // no frames, nothing to do
            return VOD_OK;
        }

        vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_muxer_init_fragment: mp4_muxer_start_frame failed %i", rc);
        return rc;
    }

    *processor_state = state;
    return VOD_OK;
}

static vod_status_t
mp4_muxer_start_frame(mp4_muxer_state_t* state)
{
    mp4_muxer_stream_state_t* selected_stream;
    vod_status_t rc;

    rc = mp4_muxer_choose_stream(state);
    if (rc != VOD_OK)
    {
        return rc;
    }
    selected_stream = state->selected_stream;

    // init the frame
    state->cur_frame = selected_stream->cur_frame;
    state->frames_source = selected_stream->frames_source;
    state->frames_source_context = selected_stream->frames_source_context;
    selected_stream->cur_frame++;
    selected_stream->cur_frame_output_offset++;

    selected_stream->next_frame_time_offset += state->cur_frame->duration;

    state->cache_slot_id = selected_stream->media_type;

    rc = state->frames_source->start_frame(state->frames_source_context, state->cur_frame);
    if (rc != VOD_OK)
    {
        return rc;
    }

    return VOD_OK;
}

vod_status_t
mp4_muxer_process_frames(mp4_muxer_state_t* state)
{
    mp4_muxer_stream_state_t* selected_stream = state->selected_stream;
    mp4_muxer_stream_state_t* last_stream = NULL;
    u_char* read_buffer;
    uint32_t read_size;
    u_char* write_buffer = NULL;
    uint32_t write_buffer_size = 0;
    vod_status_t rc;
    bool_t processed_data = FALSE;
    bool_t frame_done;

    for (;;)
    {
        // read some data from the frame
        rc = state->frames_source->read(state->frames_source_context, &read_buffer, &read_size, &frame_done);
        if (rc != VOD_OK)
        {
            if (rc != VOD_AGAIN)
            {
                return rc;
            }

            if (write_buffer_size != 0)
            {
                // flush the write buffer
                rc = last_stream->write_callback(last_stream->write_context, write_buffer, write_buffer_size);
                if (rc != VOD_OK)
                {
                    return rc;
                }
            }
            else if (!processed_data && !state->first_time)
            {
                vod_log_error(VOD_LOG_ERR, state->request_context->log, 0,
                    "mp4_muxer_process_frames: no data was handled, probably a truncated file");
                return VOD_BAD_DATA;
            }

            state->first_time = FALSE;
            return VOD_AGAIN;
        }

        processed_data = TRUE;

        if (state->reuse_buffers)
        {
            rc = selected_stream->write_callback(selected_stream->write_context, read_buffer, read_size);
            if (rc != VOD_OK)
            {
                return rc;
            }
        }
        else if (write_buffer_size != 0)
        {
            // if the buffers are contiguous, just increment the size
            if (write_buffer + write_buffer_size == read_buffer &&
                (last_stream == selected_stream || !state->per_stream_writer))
            {
                write_buffer_size += read_size;
            }
            else
            {
                // buffers not contiguous, flush the write buffer
                rc = last_stream->write_callback(last_stream->write_context, write_buffer, write_buffer_size);
                if (rc != VOD_OK)
                {
                    return rc;
                }

                // reset the write buffer
                write_buffer = read_buffer;
                write_buffer_size = read_size;
                last_stream = selected_stream;
            }
        }
        else
        {
            // reset the write buffer
            write_buffer = read_buffer;
            write_buffer_size = read_size;
            last_stream = selected_stream;
        }

        if (!frame_done)
        {
            continue;
        }

        if (selected_stream->cur_frame >= selected_stream->last_frame)
        {
            if (write_buffer_size != 0)
            {
                // flush the write buffer
                rc = last_stream->write_callback(last_stream->write_context, write_buffer, write_buffer_size);
                if (rc != VOD_OK)
                {
                    return rc;
                }

                write_buffer_size = 0;
            }
        }

        // start a new frame
        rc = mp4_muxer_start_frame(state);
        if (rc != VOD_OK)
        {
            if (rc == VOD_NOT_FOUND)
            {
                break;        // done
            }

            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, state->request_context->log, 0,
                "mp4_muxer_process_frames: mp4_muxer_start_frame failed %i", rc);
            return rc;
        }

        selected_stream = state->selected_stream;
    }

    return VOD_OK;
}

void
mp4_muxer_get_bitrate_estimator(
    media_info_t** media_infos,
    uint32_t count,
    media_bitrate_estimator_t* result)
{
    media_info_t* cur;
    uint32_t samples_per_frame;
    uint32_t muxing_overhead;
    uint32_t base_size;
    uint32_t i;

    base_size = ATOM_HEADER_SIZE +        // moof
        ATOM_HEADER_SIZE + sizeof(mfhd_atom_t) +
        ATOM_HEADER_SIZE;                 // mdat

    if (count > 1 && media_infos[0] != NULL && media_infos[1] != NULL)
    {
        // Note: 4 truns per second since the muxing delay is 0.25 sec
        muxing_overhead = 8 * 4 * (ATOM_HEADER_SIZE + sizeof(trun_atom_t));
    }
    else
    {
        muxing_overhead = 0;
    }

    for (i = 0; i < count; i++, result++)
    {
        cur = media_infos[i];

        result->k1.num = 1;
        result->k1.den = 1;

        base_size += ATOM_HEADER_SIZE +        // traf
            ATOM_HEADER_SIZE + sizeof(tfhd_atom_t) + sizeof(uint32_t) +
            ATOM_HEADER_SIZE + sizeof(tfdt64_atom_t) +
            ATOM_HEADER_SIZE + sizeof(trun_atom_t);

        result->k2 = 8 * base_size;
        base_size = 0;

        result->k3 = muxing_overhead;

        if (cur == NULL)
        {
            continue;
        }

        switch (cur->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            result->k3 += (uint64_t)8 * sizeof(trun_video_frame_t) * cur->u.video.frame_rate_num /
                cur->u.video.frame_rate_denom;
            break;

        case MEDIA_TYPE_AUDIO:
            samples_per_frame = codec_config_get_audio_frame_size(cur);
            if (samples_per_frame == 0)
            {
                break;
            }

            result->k3 += (uint64_t)8 * sizeof(trun_audio_frame_t) * cur->u.audio.sample_rate /
                samples_per_frame;
            break;
        }
    }
}
