#ifndef __THUMB_GRABBER_H__
#define __THUMB_GRABBER_H__

// includes
#include "../media_format.h"


typedef struct {
    int64_t time;
    uint32_t width;
    uint32_t height;
} thumb_grabber_params_t;

// functions
void thumb_grabber_process_init(vod_log_t* log);

vod_status_t thumb_grabber_init_state(
    request_context_t* request_context,
    media_segment_track_t* track,
    thumb_grabber_params_t* params,
    write_callback_t write_callback,
    void* write_context,
    void** result);

vod_status_t thumb_grabber_process(void* context);

#endif //__THUMB_GRABBER_H__
