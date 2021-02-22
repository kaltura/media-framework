#ifndef __FRAMES_SOURCE_H__
#define __FRAMES_SOURCE_H__

// includes
#include "common.h"

// typedefs
typedef struct {
    uint32_t size;
    uint32_t key_frame;
    uint32_t duration;
    uint32_t pts_delay;
} input_frame_t;

typedef struct {
    vod_status_t(*start_frame)(void* context, input_frame_t* frame);
    vod_status_t(*read)(void* context, u_char** buffer, uint32_t* size, bool_t* frame_done);
} frames_source_t;

#endif // __FRAMES_SOURCE_H__
