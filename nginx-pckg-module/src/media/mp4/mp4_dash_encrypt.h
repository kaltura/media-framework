#ifndef __MP4_DASH_ENCRYPT_H__
#define __MP4_DASH_ENCRYPT_H__

// includes
#include "../media_format.h"
#include "mp4_muxer.h"

// functions
vod_status_t mp4_dash_encrypt_get_fragment_writer(
    segment_writer_t* segment_writer,
    request_context_t* request_context,
    media_segment_t* segment,
    bool_t single_nalu_per_frame,
    bool_t size_only,
    vod_str_t* fragment_header,
    size_t* total_fragment_size,
    mp4_muxer_state_t** processor_state);

size_t mp4_dash_encrypt_base64_pssh_get_size(media_enc_sys_t* sys);
u_char* mp4_dash_encrypt_base64_pssh_write(u_char* p, media_enc_sys_t* sys);

size_t mp4_dash_encrypt_base64_psshs_get_size(media_enc_t* enc);
u_char* mp4_dash_encrypt_base64_psshs_write(u_char* p, media_enc_t* enc);

#endif // __MP4_DASH_ENCRYPT_H__
