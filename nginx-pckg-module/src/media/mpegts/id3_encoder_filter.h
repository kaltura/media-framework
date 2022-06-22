#ifndef __ID3_ENCODER_FILTER_H__
#define __ID3_ENCODER_FILTER_H__

// includes
#include "media_filter.h"
#include "../media_format.h"
#include "../id3_defs.h"
#include "../common.h"

typedef struct {
    // input
    media_filter_start_frame_t start_frame;
    media_filter_write_t write;
    media_filter_simulated_start_frame_t simulated_start_frame;
    media_filter_simulated_write_t simulated_write;

    // fixed
    id3_text_frame_t header;
} id3_encoder_state_t;

// functions
void id3_encoder_init(
    id3_encoder_state_t* state,
    media_filter_t* filter,
    media_filter_context_t* context);

#endif // __ID3_ENCODER_FILTER_H__
