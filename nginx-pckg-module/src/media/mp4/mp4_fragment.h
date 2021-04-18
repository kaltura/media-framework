#ifndef __MP4_FRAGMENT_H__
#define __MP4_FRAGMENT_H__

// includes
#include "mp4_write_stream.h"
#include "mp4_defs.h"
#include "../media_format.h"

// constants
#define TRUN_VIDEO_FLAGS (0xF01)        // = data offset, duration, size, key, delay
#define TRUN_AUDIO_FLAGS (0x301)        // = data offset, duration, size

// typedefs
typedef struct {
    u_char version[1];
    u_char flags[3];
    u_char sample_count[4];
    u_char data_offset[4];
} trun_atom_t;

typedef struct {
    u_char duration[4];
    u_char size[4];
    u_char flags[4];
    u_char pts_delay[4];
} trun_video_frame_t;

typedef struct {
    u_char duration[4];
    u_char size[4];
} trun_audio_frame_t;

typedef struct {
    u_char version[1];
    u_char flags[3];
    u_char sequence_number[4];
} mfhd_atom_t;

typedef struct {
    request_context_t* request_context;
    write_callback_t write_callback;
    void* write_context;
    bool_t reuse_buffers;

    vod_list_part_t* first_frame_part;
    vod_list_part_t* cur_frame_part;
    input_frame_t* cur_frame;
    input_frame_t* last_frame;

    frames_source_t* frames_source;
    void* frames_source_context;

    bool_t first_time;
    bool_t frame_started;
} fragment_writer_state_t;

// functions
u_char* mp4_fragment_write_mfhd_atom(u_char* p, uint32_t segment_index);

u_char* mp4_fragment_write_tfhd_atom(u_char* p, uint32_t track_id, uint32_t sample_description_index);

u_char* mp4_fragment_write_tfdt_atom(u_char* p, uint32_t earliest_pres_time);

u_char* mp4_fragment_write_tfdt64_atom(u_char* p, uint64_t earliest_pres_time);

size_t mp4_fragment_get_trun_atom_size(uint32_t media_type, uint32_t frame_count);

u_char* mp4_fragment_write_trun_atom(
    u_char* p,
    media_segment_track_t* track,
    uint32_t first_frame_offset,
    uint32_t version);

vod_status_t mp4_fragment_frame_writer_init(
    request_context_t* request_context,
    media_segment_track_t* track,
    write_callback_t write_callback,
    void* write_context,
    bool_t reuse_buffers,
    fragment_writer_state_t** result);

vod_status_t mp4_fragment_frame_writer_process(fragment_writer_state_t* state);

void mp4_fragment_get_content_type(
    bool_t video,
    vod_str_t* content_type);

#endif // __MP4_FRAGMENT_H__
