#ifndef __MPEGTS_MUXER_H__
#define __MPEGTS_MUXER_H__

// includes
#include "mp4_to_annexb_filter.h"
#include "adts_encoder_filter.h"
#include "mpegts_encoder_filter.h"
#include "buffer_filter.h"
#include "../media_format.h"

// typedefs
struct id3_context_s;
typedef struct id3_context_s id3_context_t;

typedef struct {
    bool_t interleave_frames;
    bool_t align_frames;
} mpegts_muxer_conf_t;

typedef struct {
    int media_type;

    // input frames
    vod_list_part_t* cur_frame_part;
    vod_list_part_t* first_frame_part;
    input_frame_t* cur_frame;
    input_frame_t* last_part_frame;

    frames_source_t* frames_source;
    void* frames_source_context;

    // time offsets
    uint64_t first_frame_time_offset;
    uint64_t next_frame_time_offset;

    // iframes simulation only
    uint64_t segment_limit;
    bool_t is_first_segment_frame;
    uint32_t prev_key_frame;
    uint64_t prev_frame_pts;

    // top filter
    media_filter_t filter;
    media_filter_context_t filter_context;

    // mpegts
    mpegts_encoder_state_t mpegts_encoder_state;
} mpegts_muxer_stream_state_t;

typedef struct {
    request_context_t* request_context;

    // fixed
    mpegts_muxer_stream_state_t* first_stream;
    mpegts_muxer_stream_state_t* last_stream;

    // child states
    write_buffer_queue_t queue;
    struct id3_context_s* id3_context;

    // cur clip state
    media_segment_t* segment;

    // cur frame state
    input_frame_t* cur_frame;
    bool_t last_stream_frame;
    const media_filter_t* cur_writer;
    media_filter_context_t* cur_writer_context;
    int cache_slot_id;
    frames_source_t* frames_source;
    void* frames_source_context;
    bool_t first_time;
} mpegts_muxer_state_t;

// functions
vod_status_t mpegts_muxer_init_segment(
    request_context_t* request_context,
    mpegts_muxer_conf_t* conf,
    hls_encryption_params_t* encryption_params,
    media_segment_t* segment,
    write_callback_t write_callback,
    void* write_context,
    bool_t reuse_buffers,
    size_t* response_size,
    vod_str_t* response_header,
    mpegts_muxer_state_t** processor_state);

vod_status_t mpegts_muxer_process(mpegts_muxer_state_t* state);

void mpegts_muxer_get_bitrate_estimator(
    mpegts_muxer_conf_t* conf,
    media_info_t** media_infos,
    uint32_t count,
    media_bitrate_estimator_t* result);

#endif // __MPEGTS_MUXER_H__
