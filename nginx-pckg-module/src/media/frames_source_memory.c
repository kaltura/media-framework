#include "frames_source_memory.h"

typedef struct {
    u_char* buffer;
    size_t size;
} frames_source_memory_state_t;


vod_status_t
frames_source_memory_init(
    request_context_t* request_context,
    u_char* buffer,
    size_t size,
    void** result)
{
    frames_source_memory_state_t* state;

    state = vod_alloc(request_context->pool, sizeof(*state));
    if (state == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "frames_source_memory_init: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    state->buffer = buffer;
    state->size = size;

    *result = state;

    return VOD_OK;
}


static vod_status_t
frames_source_memory_start_frame(void* ctx, input_frame_t* frame)
{
    return VOD_OK;
}


static vod_status_t
frames_source_memory_read(void* ctx, u_char** buffer, uint32_t* size, bool_t* frame_done)
{
    frames_source_memory_state_t* state = ctx;

    *buffer = state->buffer;
    *size = state->size;
    *frame_done = TRUE;

    return VOD_OK;
}

// globals
frames_source_t frames_source_memory = {
    frames_source_memory_start_frame,
    frames_source_memory_read,
};
