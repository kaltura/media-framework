#ifndef __MP4_MUXER_H__
#define __MP4_MUXER_H__

// includes
#include "../media_format.h"
#include "../common.h"

// typedefs
struct mp4_muxer_state_s;
typedef struct mp4_muxer_state_s mp4_muxer_state_t;

// functions
vod_status_t mp4_muxer_init_fragment(
    request_context_t* request_context,
    media_segment_t* segment,
    segment_writer_t* writers,
    bool_t per_stream_writer,
    bool_t reuse_buffers,
    bool_t size_only,
    vod_str_t* header,
    size_t* total_fragment_size,
    mp4_muxer_state_t** processor_state);

vod_status_t mp4_muxer_process_frames(mp4_muxer_state_t* state);

void mp4_muxer_get_bitrate_estimator(
    media_info_t** media_infos,
    uint32_t count,
    media_bitrate_estimator_t* result);

#endif // __MP4_MUXER_H__
