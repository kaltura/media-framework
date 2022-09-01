#include "webvtt_builder.h"
#include "../mp4/mp4_parser_base.h"

// constants
#define WEBVTT_TIMESTAMP_MAP "\r\nX-TIMESTAMP-MAP=MPEGTS:0,LOCAL:00:00:00.000\r\n"
#define WEBVTT_TIMESTAMP_FORMAT "%02uD:%02uD:%02uD.%03uD"
#define WEBVTT_TIMESTAMP_DELIM " --> "
#define WEBVTT_TIMESTAMP_MAX_SIZE (VOD_INT32_LEN + sizeof(":00:00.000") - 1)
#define WEBVTT_CUE_TIMINGS_MAX_SIZE (WEBVTT_TIMESTAMP_MAX_SIZE * 2 + sizeof(WEBVTT_TIMESTAMP_DELIM) - 1)

#define MPEGTS_MAX_TIMESTAMP (1ULL << 33)    // 33 bit


typedef struct {
    mp4_atom_t payload;
} webvtt_cue_atoms_t;

static mp4_get_atom_t webvtt_vttc_atoms[] = {
    { ATOM_NAME_PAYL, offsetof(webvtt_cue_atoms_t, payload), NULL },
    { ATOM_NAME_NULL, 0, NULL }
};

static mp4_get_atom_t webvtt_cue_atoms[] = {
    { ATOM_NAME_VTTC, 0, webvtt_vttc_atoms },
    { ATOM_NAME_NULL, 0, NULL }
};


vod_status_t
webvtt_parse_cue(request_context_t* request_context, u_char* buf, size_t size, webvtt_cue_t* cue)
{
    mp4_get_atoms_ctx_t get_ctx;
    webvtt_cue_atoms_t atoms;
    vod_status_t rc;

    vod_memzero(&atoms, sizeof(atoms));

    get_ctx.request_context = request_context;
    get_ctx.atoms = webvtt_cue_atoms;
    get_ctx.result = &atoms;

    rc = mp4_parser_parse_atoms(request_context, buf, size, mp4_parser_get_atoms_callback, &get_ctx);

    cue->payload.data = atoms.payload.ptr;
    cue->payload.len = atoms.payload.size;

    return rc;
}


static vod_inline u_char*
webvtt_builder_write_timestamp(u_char* p, uint64_t ts, uint32_t timescale)
{
    ts = rescale_time(ts, timescale, 1000);

    return vod_sprintf(p, WEBVTT_TIMESTAMP_FORMAT,
        (uint32_t)(ts / 3600000),
        (uint32_t)((ts / 60000) % 60),
        (uint32_t)((ts / 1000) % 60),
        (uint32_t)(ts % 1000));
}


static void
webvtt_split_first_line(vod_str_t* str, vod_str_t* first, vod_str_t* rest)
{
    u_char* end;
    u_char* p;

    p = str->data;
    first->data = p;
    for (end = p + str->len; p < end; p++)
    {
        switch (*p)
        {
        case '\r':
            if (p + 1 < end && p[1] == '\n')
            {
                rest->data = p + 2;
                goto found;
            }

            // fall through

        case '\n':
            rest->data = p + 1;
            goto found;
        }
    }

    rest->data = p;

found:

    first->len = p - first->data;
    rest->len = end - rest->data;
}


vod_status_t
webvtt_builder_build(
    request_context_t* request_context,
    media_segment_t* segment,
    vod_str_t* result)
{
    media_segment_track_t* track = segment->tracks;
    vod_list_part_t* part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;
    media_info_t* media_info;
    webvtt_cue_t cue;
    vod_status_t rc;
    vod_str_t header_first;
    vod_str_t header_rest;
    uint32_t timescale;
    uint32_t size;
    int64_t cur_time;
    int64_t base_time;
    int64_t cue_start;
    int64_t cue_end;
    size_t result_size;
    bool_t frame_done;
    u_char* data;
    u_char* p;

    // get the result size
    media_info = track->media_info;

    result_size = media_info->extra_data.len + sizeof(WEBVTT_TIMESTAMP_MAP) - 1 + sizeof("\r\n") - 1 +
        media_segment_track_get_total_size(track) +
        (WEBVTT_CUE_TIMINGS_MAX_SIZE + sizeof("\n\n\n") - 1) * track->frame_count;

    // allocate the buffer
    p = vod_alloc(request_context->pool, result_size);
    if (p == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "webvtt_builder_build: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    result->data = p;

    // webvtt header
    webvtt_split_first_line(&media_info->extra_data, &header_first, &header_rest);

    p = vod_copy(p, header_first.data, header_first.len);
    p = vod_copy(p, WEBVTT_TIMESTAMP_MAP, sizeof(WEBVTT_TIMESTAMP_MAP) - 1);
    p = vod_copy(p, header_rest.data, header_rest.len);
    *p++ = '\r';
    *p++ = '\n';

    // calculate the start time
    base_time = (track->start_dts / MPEGTS_MAX_TIMESTAMP) * MPEGTS_MAX_TIMESTAMP;
    cur_time = track->start_dts - base_time;
    timescale = media_info->timescale;

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
                "webvtt_builder_build: start frame failed %i", rc);
            return rc;
        }

        rc = track->frames_source->read(track->frames_source_context, &data, &size, &frame_done);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "webvtt_builder_build: read frame failed %i", rc);
            return rc;
        }

        if (!frame_done)
        {
            vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                "webvtt_builder_build: frame not done");
            return VOD_UNEXPECTED;
        }

        cue_start = cur_time;
        cue_end = cur_time + cur_frame->pts_delay;

        cur_time += cur_frame->duration;

        if (webvtt_parse_cue(request_context, data, size, &cue) != VOD_OK || cue.payload.len <= 0)
        {
            continue;
        }

        // cue timings
        p = webvtt_builder_write_timestamp(p, cue_start, timescale);
        p = vod_copy(p, WEBVTT_TIMESTAMP_DELIM, sizeof(WEBVTT_TIMESTAMP_DELIM) - 1);
        p = webvtt_builder_write_timestamp(p, cue_end, timescale);

        *p++ = '\n';

        // cue payload
        p = vod_copy(p, cue.payload.data, cue.payload.len);

        *p++ = '\n';
        *p++ = '\n';
    }

    result->len = p - result->data;

    if (result->len > result_size)
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "webvtt_builder_build: result length %uz exceeded allocated length %uz",
            result->len, result_size);
        return VOD_UNEXPECTED;
    }

    return VOD_OK;
}
