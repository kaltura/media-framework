#ifndef __TTML_BUILDER_H__
#define __TTML_BUILDER_H__

// includes
#include "../media_format.h"

// functions
vod_status_t ttml_builder_convert_init_segment(request_context_t* request_context, media_init_segment_t* segment);

vod_status_t ttml_builder_convert_segment(request_context_t* request_context, media_segment_t* segment);

#endif //__TTML_BUILDER_H__
