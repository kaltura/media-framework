#ifndef __MP4_CBCS_ENCRYPT_H__
#define __MP4_CBCS_ENCRYPT_H__

// includes
#include "../media_format.h"

// functions
vod_status_t mp4_cbcs_encrypt_get_writers(
    request_context_t* request_context,
    media_segment_t* segment,
    segment_writer_t* segment_writer,
    const u_char* key,
    const u_char* iv,
    segment_writer_t** result);

#endif //__MP4_CBCS_ENCRYPT_H__
