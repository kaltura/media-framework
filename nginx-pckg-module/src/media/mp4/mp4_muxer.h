#ifndef __MP4_MUXER_H__
#define __MP4_MUXER_H__

// includes
#include "../media_format.h"
#include "../common.h"

// typedefs
typedef struct mp4_muxer_state_s mp4_muxer_state_t;

typedef u_char* (*mp4_muxer_write_traf_atoms_callback_t)(void* context, u_char* p, size_t mdat_atom_start);

typedef struct {
    size_t extra_traf_atoms_size;
    mp4_muxer_write_traf_atoms_callback_t write_extra_traf_atoms_callback;
    void* write_extra_traf_atoms_context;
} mp4_muxer_header_extensions_t;

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

// internal
vod_status_t mp4_muxer_init_state(
    request_context_t* request_context,
    media_segment_t* segment,
    bool_t reuse_buffers,
    mp4_muxer_state_t** result);

vod_status_t mp4_muxer_build_fragment_header(
    request_context_t* request_context,
    mp4_muxer_state_t* state,
    uint32_t sample_description_index,
    mp4_muxer_header_extensions_t* extensions,
    bool_t size_only,
    vod_str_t* header,
    size_t* total_fragment_size);

vod_status_t mp4_muxer_start(
    mp4_muxer_state_t* state,
    segment_writer_t* track_writers,
    bool_t per_stream_writer,
    mp4_muxer_state_t** processor_state);

void mp4_muxer_reset(mp4_muxer_state_t* state);

#endif // __MP4_MUXER_H__
