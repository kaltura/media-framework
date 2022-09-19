#ifndef __WEBVTT_BUILDER_H__
#define __WEBVTT_BUILDER_H__

// includes
#include "../media_format.h"

// structs
typedef struct {
    vod_str_t payload;
    vod_str_t settings;
} webvtt_cue_t;

// functions
vod_status_t webvtt_parse_cue(
    request_context_t* request_context,
    u_char* buf,
    size_t size,
    webvtt_cue_t* cue);

vod_status_t webvtt_builder_build(
    request_context_t* request_context,
    media_segment_t* segment,
    vod_str_t* result);

#endif //__WEBVTT_BUILDER_H__
