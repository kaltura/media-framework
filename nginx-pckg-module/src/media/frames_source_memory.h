#ifndef __FRAMES_SOURCE_MEMORY_H__
#define __FRAMES_SOURCE_MEMORY_H__

// includes
#include "frames_source.h"

// functions
vod_status_t frames_source_memory_init(
    request_context_t* request_context,
    u_char* buffer,
    size_t size,
    void** result);

// globals
extern frames_source_t frames_source_memory;

#endif // __FRAMES_SOURCE_MEMORY_H__
