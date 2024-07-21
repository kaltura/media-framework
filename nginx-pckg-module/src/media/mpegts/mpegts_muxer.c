#include "frame_joiner_filter.h"
#include "id3_encoder_filter.h"
#include "mpegts_muxer.h"
#include "../frames_source_memory.h"

#if (VOD_HAVE_OPENSSL_EVP)
#include "frame_encrypt_filter.h"
#include "eac3_encrypt_filter.h"
#endif // VOD_HAVE_OPENSSL_EVP

// from ffmpeg mpegtsenc
#define DEFAULT_PES_HEADER_FREQ 16
#define DEFAULT_PES_PAYLOAD_SIZE ((DEFAULT_PES_HEADER_FREQ - 1) * 184 + 170)

// typedefs
typedef struct {
    media_segment_track_t track;
    input_frame_t frame;
} id3_track_t;

struct id3_context_s {
    id3_encoder_state_t encoder;
    id3_track_t* first_track;
    id3_track_t* cur_track;
};

// forward decls
static vod_status_t mpegts_muxer_start_frame(mpegts_muxer_state_t* state);
static vod_status_t mpegts_muxer_simulate_get_segment_size(mpegts_muxer_state_t* state, size_t* result);
static void mpegts_muxer_simulation_reset(mpegts_muxer_state_t* state);
static vod_status_t mpegts_muxer_choose_stream(mpegts_muxer_state_t* state, mpegts_muxer_stream_state_t** result);

static vod_status_t
mpegts_muxer_init_track(
    mpegts_muxer_stream_state_t* cur_stream,
    media_segment_track_t* track)
{
    media_info_t* media_info = track->media_info;
    vod_status_t rc;

    cur_stream->media_type = media_info->media_type;
    cur_stream->first_frame_part = &track->frames.part;
    cur_stream->cur_frame_part = &track->frames.part;
    cur_stream->cur_frame = track->frames.part.elts;
    cur_stream->last_part_frame = cur_stream->cur_frame + track->frames.part.nelts;
    cur_stream->first_frame_time_offset = track->start_dts;
    cur_stream->next_frame_time_offset = cur_stream->first_frame_time_offset;
    cur_stream->frames_source = track->frames_source;
    cur_stream->frames_source_context = track->frames_source_context;

    switch (media_info->media_type)
    {
    case MEDIA_TYPE_VIDEO:
        rc = mp4_to_annexb_set_media_info(
            &cur_stream->filter_context,
            media_info);
        if (rc != VOD_OK)
        {
            return rc;
        }
        break;

    case MEDIA_TYPE_AUDIO:
        if (media_info->codec_id == VOD_CODEC_ID_AAC)
        {
            rc = adts_encoder_set_media_info(
                &cur_stream->filter_context,
                media_info);
            if (rc != VOD_OK)
            {
                return rc;
            }
        }
        break;
    }

    return VOD_OK;
}


static bool_t
mpegts_muxer_simulation_supported(
    media_segment_t* media_segment,
    hls_encryption_params_t* encryption_params)
{
    media_segment_track_t* track;

    /* In sample AES every encrypted NAL unit has to go through emulation prevention, so it is not
    possible to know the exact size of the unit in advance */
    if (encryption_params->type == HLS_ENC_SAMPLE_AES)
    {
        return FALSE;
    }

    for (track = media_segment->tracks; track < media_segment->tracks_end; track++)
    {
        if (track->media_info->media_type != MEDIA_TYPE_VIDEO)
        {
            continue;
        }

        if (!mp4_to_annexb_simulation_supported(track->media_info))
        {
            return FALSE;
        }
    }

    return TRUE;
}


static vod_status_t
mpegts_muxer_init_stream(
    mpegts_muxer_state_t* state,
    mpegts_muxer_conf_t* conf,
    mpegts_muxer_stream_state_t* stream,
    media_segment_track_t* track,
    mpegts_encoder_init_streams_state_t* init_streams_state)
{
    vod_status_t rc;

    stream->segment_limit = ULLONG_MAX;
    stream->filter_context.request_context = state->request_context;
    stream->filter_context.context[MEDIA_FILTER_MPEGTS] = &stream->mpegts_encoder_state;
    stream->filter_context.context[MEDIA_FILTER_BUFFER] = NULL;

    rc = mpegts_encoder_init(
        &stream->filter,
        &stream->mpegts_encoder_state,
        init_streams_state,
        track != NULL ? track->media_info : NULL,
        &state->queue,
        conf->interleave_frames,
        conf->align_frames);
    if (rc != VOD_OK)
    {
        return rc;
    }

    return VOD_OK;
}


static vod_status_t
mpegts_muxer_init_id3_stream(
    mpegts_muxer_state_t* state,
    mpegts_muxer_conf_t* conf,
    media_segment_t* media_segment,
    mpegts_encoder_init_streams_state_t* init_streams_state)
{
    mpegts_muxer_stream_state_t* cur_stream;
    media_segment_track_t* dest_track;
    media_segment_track_t* ref_track;
    id3_context_t* context;
    id3_track_t* cur_track;
    vod_status_t rc;
    void* frames_source_context;

    cur_stream = state->last_stream;

    rc = mpegts_muxer_init_stream(
        state,
        conf,
        cur_stream,
        NULL,
        init_streams_state);
    if (rc != VOD_OK)
    {
        return rc;
    }

    if (media_segment->metadata.len == 0)
    {
        state->id3_context = NULL;
        return VOD_OK;
    }

    // allocate the context
    context = vod_alloc(state->request_context->pool,
        sizeof(*context) + sizeof(context->first_track[0]) + sizeof(media_info_t));
    if (context == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, state->request_context->log, 0,
            "mpegts_muxer_init_id3_stream: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    context->first_track = (void*)(context + 1);

    // init the tracks
    cur_track = context->first_track;
    dest_track = &cur_track->track;
    ref_track = media_segment->tracks;

    dest_track->media_info = (void*)(context->first_track + 1);
    dest_track->media_info->media_type = MEDIA_TYPE_NONE;

    // init the frame
    cur_track->frame.size = media_segment->metadata.len;
    cur_track->frame.duration = 0;
    cur_track->frame.key_frame = 1;
    cur_track->frame.pts_delay = 0;

    // init the frame part
    rc = frames_source_memory_init(state->request_context, media_segment->metadata.data, cur_track->frame.size, &frames_source_context);
    if (rc != VOD_OK)
    {
        return rc;
    }

    dest_track->frames.part.next = NULL;
    dest_track->frames.part.elts = &cur_track->frame;
    dest_track->frames.part.nelts = (ref_track->frame_count > 0) ? 1 : 0;
    dest_track->frames_source = &frames_source_memory;
    dest_track->frames_source_context = frames_source_context;

    // init the track
    dest_track->start_dts = ref_track->start_dts;
    dest_track->frame_count = dest_track->frames.part.nelts;

    // init the first track
    rc = mpegts_muxer_init_track(cur_stream, &context->first_track[0].track);
    if (rc != VOD_OK)
    {
        return rc;
    }

    context->cur_track = context->first_track + 1;

    // init the id3 encoder
    id3_encoder_init(&context->encoder, &cur_stream->filter, &cur_stream->filter_context);

    // update the state
    state->last_stream++;
    state->id3_context = context;

    return VOD_OK;
}


static vod_status_t
mpegts_muxer_init_base(
    mpegts_muxer_state_t* state,
    request_context_t* request_context,
    mpegts_muxer_conf_t* conf,
    hls_encryption_params_t* encryption_params,
    media_segment_t* media_segment,
    bool_t* simulation_supported,
    vod_str_t* response_header)
{
    mpegts_encoder_init_streams_state_t init_streams_state;
    media_segment_track_t* track;
    mpegts_muxer_stream_state_t* cur_stream;
    vod_status_t rc;

    *simulation_supported = mpegts_muxer_simulation_supported(media_segment, encryption_params);

    state->request_context = request_context;
    state->cur_frame = NULL;
    state->first_time = TRUE;

    state->segment = media_segment;

    // init the packetizer streams and get the packet ids / stream ids
    rc = mpegts_encoder_init_streams(
        request_context,
        encryption_params,
        &init_streams_state,
        media_segment->segment_index);
    if (rc != VOD_OK)
    {
        return rc;
    }

    // allocate the streams
    state->first_stream = vod_alloc(request_context->pool,
        sizeof(*state->first_stream) * (media_segment->track_count + 1));
    if (state->first_stream == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mpegts_muxer_init_base: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    state->last_stream = state->first_stream + media_segment->track_count;

    track = media_segment->tracks;
    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++, track++)
    {
        rc = mpegts_muxer_init_stream(
            state,
            conf,
            cur_stream,
            track,
            &init_streams_state);
        if (rc != VOD_OK)
        {
            return rc;
        }

        switch (track->media_info->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            rc = mp4_to_annexb_init(
                &cur_stream->filter,
                &cur_stream->filter_context,
                encryption_params);
            if (rc != VOD_OK)
            {
                return rc;
            }
            break;

        case MEDIA_TYPE_AUDIO:
            if (conf->interleave_frames)
            {
                // frame interleaving enabled, just join several audio frames according to timestamp
                rc = frame_joiner_init(
                    &cur_stream->filter,
                    &cur_stream->filter_context);
                if (rc != VOD_OK)
                {
                    return rc;
                }
            }
            else
            {
                // no frame interleaving, buffer the audio until it reaches a certain size / delay from video
                rc = buffer_filter_init(
                    &cur_stream->filter,
                    &cur_stream->filter_context,
                    conf->align_frames,
                    DEFAULT_PES_PAYLOAD_SIZE);
                if (rc != VOD_OK)
                {
                    return rc;
                }
            }

            if (track->media_info->codec_id == VOD_CODEC_ID_AAC)
            {
                rc = adts_encoder_init(
                    &cur_stream->filter,
                    &cur_stream->filter_context);
                if (rc != VOD_OK)
                {
                    return rc;
                }
            }

#if (VOD_HAVE_OPENSSL_EVP)
            if (encryption_params->type == HLS_ENC_SAMPLE_AES)
            {
                switch (track->media_info->codec_id)
                {
                case VOD_CODEC_ID_AAC:
                case VOD_CODEC_ID_AC3:
                case VOD_CODEC_ID_EAC3:
                    break;

                default:
                    vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                        "mpegts_muxer_init_base: sample aes encryption is supported only for aac/ac3/eac3");
                    return VOD_BAD_REQUEST;
                }

                rc = frame_encrypt_filter_init(
                    &cur_stream->filter,
                    &cur_stream->filter_context,
                    encryption_params);
                if (rc != VOD_OK)
                {
                    return rc;
                }

                if (track->media_info->codec_id == VOD_CODEC_ID_EAC3)
                {
                    rc = eac3_encrypt_filter_init(
                        &cur_stream->filter,
                        &cur_stream->filter_context);
                    if (rc != VOD_OK)
                    {
                        return rc;
                    }
                }
            }
#endif // VOD_HAVE_OPENSSL_EVP
            break;
        }

        rc = mpegts_muxer_init_track(cur_stream, track);
        if (rc != VOD_OK)
        {
            return rc;
        }
    }

    // init the id3 stream
    rc = mpegts_muxer_init_id3_stream(state, conf, media_segment, &init_streams_state);
    if (rc != VOD_OK)
    {
        return rc;
    }

    mpegts_encoder_finalize_streams(&init_streams_state, response_header);

    return VOD_OK;
}

vod_status_t
mpegts_muxer_init_segment(
    request_context_t* request_context,
    mpegts_muxer_conf_t* conf,
    hls_encryption_params_t* encryption_params,
    media_segment_t* media_segment,
    write_callback_t write_callback,
    void* write_context,
    bool_t reuse_buffers,
    size_t* response_size,
    vod_str_t* response_header,
    mpegts_muxer_state_t** processor_state)
{
    mpegts_muxer_state_t* state;
    bool_t simulation_supported;
    vod_status_t rc;

    state = vod_alloc(request_context->pool, sizeof(*state));
    if (state == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mpegts_muxer_init_segment: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    // init the write queue
    write_buffer_queue_init(
        &state->queue,
        request_context,
        write_callback,
        write_context,
        reuse_buffers);

    rc = mpegts_muxer_init_base(
        state,
        request_context,
        conf,
        encryption_params,
        media_segment,
        &simulation_supported,
        response_header);
    if (rc != VOD_OK)
    {
        return rc;
    }

    if (simulation_supported)
    {
        rc = mpegts_muxer_simulate_get_segment_size(state, response_size);
        if (rc != VOD_OK)
        {
            return rc;
        }

        mpegts_muxer_simulation_reset(state);
    }

    rc = mpegts_muxer_start_frame(state);
    if (rc != VOD_OK)
    {
        if (rc != VOD_NOT_FOUND)
        {
            return rc;
        }

        *processor_state = NULL;        // no frames, nothing to do
    }
    else
    {
        *processor_state = state;
    }

    return VOD_OK;
}


static vod_status_t
mpegts_muxer_choose_stream(mpegts_muxer_state_t* state, mpegts_muxer_stream_state_t** result)
{
    mpegts_muxer_stream_state_t* cur_stream;
    mpegts_muxer_stream_state_t* min_dts = NULL;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        if (cur_stream->cur_frame >= cur_stream->last_part_frame)
        {
            if (cur_stream->cur_frame_part->next == NULL)
            {
                continue;
            }
            cur_stream->cur_frame_part = cur_stream->cur_frame_part->next;
            cur_stream->cur_frame = cur_stream->cur_frame_part->elts;
            cur_stream->last_part_frame = cur_stream->cur_frame + cur_stream->cur_frame_part->nelts;
            state->first_time = TRUE;
        }

        if (cur_stream->next_frame_time_offset >= cur_stream->segment_limit)
        {
            continue;
        }

        if (min_dts == NULL || cur_stream->next_frame_time_offset < min_dts->next_frame_time_offset)
        {
            min_dts = cur_stream;
        }
    }

    if (min_dts != NULL)
    {
        *result = min_dts;
        return VOD_OK;
    }

    return VOD_NOT_FOUND;
}


static vod_status_t
mpegts_muxer_start_frame(mpegts_muxer_state_t* state)
{
    mpegts_muxer_stream_state_t* cur_stream;
    mpegts_muxer_stream_state_t* selected_stream;
    output_frame_t output_frame;
    uint64_t cur_frame_time_offset;
    uint64_t cur_frame_dts;
    uint64_t buffer_dts;
    vod_status_t rc;

    rc = mpegts_muxer_choose_stream(state, &selected_stream);
    if (rc != VOD_OK)
    {
        return rc;
    }

    // init the frame
    state->cur_frame = selected_stream->cur_frame;
    selected_stream->cur_frame++;
    state->frames_source = selected_stream->frames_source;
    state->frames_source_context = selected_stream->frames_source_context;
    cur_frame_time_offset = selected_stream->next_frame_time_offset;
    cur_frame_dts = selected_stream->next_frame_time_offset;
    selected_stream->next_frame_time_offset += state->cur_frame->duration;

    // TODO: in the case of multi clip without discontinuity, the test below is not sufficient
    state->last_stream_frame = selected_stream->cur_frame >= selected_stream->last_part_frame &&
        selected_stream->cur_frame_part->next == NULL;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        if (selected_stream == cur_stream)
        {
            continue;
        }

        // flush any buffered frames if their delay becomes too big
        if (cur_stream->filter_context.context[MEDIA_FILTER_BUFFER] != NULL)
        {
            if (buffer_filter_get_dts(&cur_stream->filter_context, &buffer_dts) &&
                cur_frame_dts > buffer_dts + MPEGTS_DELAY / 2)
            {
                rc = buffer_filter_force_flush(&cur_stream->filter_context, FALSE);
                if (rc != VOD_OK)
                {
                    return rc;
                }
            }
        }
    }

    // set the current top_filter
    state->cur_writer = &selected_stream->filter;
    state->cur_writer_context = &selected_stream->filter_context;

    // initialize the mpeg ts frame info
    output_frame.pts = cur_frame_time_offset + state->cur_frame->pts_delay;
    output_frame.dts = cur_frame_dts;
    output_frame.key = state->cur_frame->key_frame;
    output_frame.size = state->cur_frame->size;
    output_frame.header_size = 0;

    state->cache_slot_id = selected_stream->mpegts_encoder_state.stream_info.pid;

    // start the frame
    rc = state->frames_source->start_frame(state->frames_source_context, state->cur_frame);
    if (rc != VOD_OK)
    {
        return rc;
    }

    rc = state->cur_writer->start_frame(state->cur_writer_context, &output_frame);
    if (rc != VOD_OK)
    {
        return rc;
    }

    return VOD_OK;
}


static vod_status_t
mpegts_muxer_send(mpegts_muxer_state_t* state)
{
    mpegts_muxer_stream_state_t* cur_stream;
    off_t min_offset = state->queue.cur_offset;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        if (cur_stream->mpegts_encoder_state.send_queue_offset < min_offset)
        {
            min_offset = cur_stream->mpegts_encoder_state.send_queue_offset;
        }
    }

    return write_buffer_queue_send(&state->queue, min_offset);
}

vod_status_t
mpegts_muxer_process(mpegts_muxer_state_t* state)
{
    u_char* read_buffer;
    uint32_t read_size;
    vod_status_t rc;
    bool_t wrote_data = FALSE;
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

            if (!wrote_data && !state->first_time)
            {
                vod_log_error(VOD_LOG_ERR, state->request_context->log, 0,
                    "mpegts_muxer_process: no data was handled, probably a truncated file");
                return VOD_BAD_DATA;
            }

            rc = mpegts_muxer_send(state);
            if (rc != VOD_OK)
            {
                return rc;
            }

            state->first_time = FALSE;

            return VOD_AGAIN;
        }

        wrote_data = TRUE;

        // write the frame
        rc = state->cur_writer->write(state->cur_writer_context, read_buffer, read_size);
        if (rc != VOD_OK)
        {
            return rc;
        }

        // if frame not done, try to read more data from the cache
        if (!frame_done)
        {
            continue;
        }

        // flush the frame and start a new one
        rc = state->cur_writer->flush_frame(state->cur_writer_context, state->last_stream_frame);
        if (rc != VOD_OK)
        {
            return rc;
        }

        rc = mpegts_muxer_start_frame(state);
        if (rc != VOD_OK)
        {
            if (rc == VOD_NOT_FOUND)
            {
                break;        // done
            }

            return rc;
        }
    }

    // flush the buffer queue
    rc = write_buffer_queue_flush(&state->queue);
    if (rc != VOD_OK)
    {
        return rc;
    }

    return VOD_OK;
}


static void
mpegts_muxer_simulation_flush_delayed_streams(
    mpegts_muxer_state_t* state,
    mpegts_muxer_stream_state_t* selected_stream,
    uint64_t frame_dts)
{
    mpegts_muxer_stream_state_t* cur_stream;
    uint64_t buffer_dts;

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        if (selected_stream == cur_stream || cur_stream->filter_context.context[MEDIA_FILTER_BUFFER] == NULL)
        {
            continue;
        }

        if (buffer_filter_get_dts(&cur_stream->filter_context, &buffer_dts) &&
            frame_dts > buffer_dts + MPEGTS_DELAY / 2)
        {
            vod_log_debug2(VOD_LOG_DEBUG_LEVEL, state->request_context->log, 0,
                "mpegts_muxer_simulation_flush_delayed_streams: flushing buffered frames buffer dts %L frame dts %L",
                buffer_dts,
                frame_dts);
            buffer_filter_simulated_force_flush(&cur_stream->filter_context, FALSE);
        }
    }
}


static void
mpegts_muxer_simulation_write_frame(mpegts_muxer_stream_state_t* selected_stream, input_frame_t* cur_frame, uint64_t cur_frame_dts, bool_t last_frame)
{
    output_frame_t output_frame;

    // initialize the mpeg ts frame info
    // Note: no need to initialize the pts or original size
    output_frame.dts = cur_frame_dts;
    output_frame.key = cur_frame->key_frame;
    output_frame.header_size = 0;

    selected_stream->filter.simulated_start_frame(&selected_stream->filter_context, &output_frame);
    selected_stream->filter.simulated_write(&selected_stream->filter_context, cur_frame->size);
    selected_stream->filter.simulated_flush_frame(&selected_stream->filter_context, last_frame);
}


static vod_status_t
mpegts_muxer_simulate_get_segment_size(mpegts_muxer_state_t* state, size_t* result)
{
    mpegts_muxer_stream_state_t* selected_stream;
    input_frame_t* cur_frame;
    uint64_t cur_frame_dts;
    off_t segment_size;
    vod_status_t rc;
#if (VOD_DEBUG)
    off_t cur_frame_start;
#endif // VOD_DEBUG

    mpegts_encoder_simulated_start_segment(&state->queue);

    for (;;)
    {
        // get a frame
        rc = mpegts_muxer_choose_stream(state, &selected_stream);
        if (rc != VOD_OK)
        {
            if (rc == VOD_NOT_FOUND)
            {
                break;        // done
            }
            return rc;
        }

        cur_frame = selected_stream->cur_frame;
        selected_stream->cur_frame++;
        cur_frame_dts = selected_stream->next_frame_time_offset;
        selected_stream->next_frame_time_offset += cur_frame->duration;

        // flush any buffered frames if their delay becomes too big
        mpegts_muxer_simulation_flush_delayed_streams(state, selected_stream, cur_frame_dts);

#if (VOD_DEBUG)
        cur_frame_start = state->queue.cur_offset;
#endif // VOD_DEBUG

        // write the frame
        mpegts_muxer_simulation_write_frame(
            selected_stream,
            cur_frame,
            cur_frame_dts,
            selected_stream->cur_frame >= selected_stream->last_part_frame &&
                selected_stream->cur_frame_part->next == NULL);

#if (VOD_DEBUG)
        if (cur_frame_start != state->queue.cur_offset)
        {
            vod_log_debug4(VOD_LOG_DEBUG_LEVEL, state->request_context->log, 0,
                "mpegts_muxer_simulate_get_segment_size: wrote frame in packets %uD-%uD, dts %L, pid %ud",
                (uint32_t)(cur_frame_start / MPEGTS_PACKET_SIZE + 1),
                (uint32_t)(state->queue.cur_offset / MPEGTS_PACKET_SIZE + 1),
                cur_frame_dts,
                selected_stream->mpegts_encoder_state.stream_info.pid);
        }
#endif // VOD_DEBUG
    }

    segment_size = state->queue.cur_offset;

    *result = segment_size;

    return VOD_OK;
}


static void
mpegts_muxer_simulation_reset(mpegts_muxer_state_t* state)
{
    mpegts_muxer_stream_state_t* cur_stream;

    mpegts_encoder_simulated_start_segment(&state->queue);

    for (cur_stream = state->first_stream; cur_stream < state->last_stream; cur_stream++)
    {
        cur_stream->cur_frame_part = cur_stream->first_frame_part;
        cur_stream->cur_frame = cur_stream->cur_frame_part->elts;
        cur_stream->last_part_frame = cur_stream->cur_frame + cur_stream->cur_frame_part->nelts;
        cur_stream->next_frame_time_offset = cur_stream->first_frame_time_offset;
    }

    state->cur_frame = NULL;
}

void
mpegts_muxer_get_bitrate_estimator(
    mpegts_muxer_conf_t* conf,
    media_info_t** media_infos,
    uint32_t count,
    media_bitrate_estimator_t* result)
{
    mpegts_encoder_get_bitrate_estimator(
        conf->align_frames,
        conf->interleave_frames ? 0 : DEFAULT_PES_PAYLOAD_SIZE,
        media_infos,
        count,
        result);
}
