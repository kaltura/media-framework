#ifndef __FRAMES_SOURCE_H__
#define __FRAMES_SOURCE_H__

// includes
#include <ngx_ksmp.h>
#include "common.h"

typedef ngx_ksmp_frame_t  input_frame_t;

// typedefs
typedef struct {
    vod_status_t(*start_frame)(void* context, input_frame_t* frame);
    vod_status_t(*read)(void* context, u_char** buffer, uint32_t* size, bool_t* frame_done);
} frames_source_t;

#endif // __FRAMES_SOURCE_H__
