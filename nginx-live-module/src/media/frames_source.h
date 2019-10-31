#ifndef __FRAMES_SOURCE_H__
#define __FRAMES_SOURCE_H__

// includes
#include "common.h"

// typedefs
struct input_frame_s;

typedef struct {
    vod_status_t(*start_frame)(void* context, struct input_frame_s* frame);
    vod_status_t(*read)(void* context, u_char** buffer, uint32_t* size, bool_t* frame_done);
} frames_source_t;

#endif // __FRAMES_SOURCE_H__
