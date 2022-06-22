#ifndef __ID3_DEFS_H__
#define __ID3_DEFS_H__

// includes
#include "common.h"

// macros
#define write_be32_synchsafe(p, dw) \
    {                               \
    *(p)++ = ((dw) >> 21) & 0x7f;   \
    *(p)++ = ((dw) >> 14) & 0x7f;   \
    *(p)++ = ((dw) >> 7) & 0x7f;    \
    *(p)++ = (dw) & 0x7f;           \
    }

// typedefs
typedef struct {
    u_char file_identifier[4];
    u_char version[1];
    u_char flags[1];
    u_char size[4];
} id3_file_header_t;

typedef struct {
    u_char id[4];
    u_char size[4];
    u_char flags[2];
} id3_frame_header_t;

typedef struct {
    u_char encoding[1];
} id3_text_frame_header_t;

typedef struct {
    id3_file_header_t file_header;
    id3_frame_header_t frame_header;
    id3_text_frame_header_t text_frame_header;
} id3_text_frame_t;

// globals
extern u_char id3_text_frame_template[sizeof(id3_text_frame_t)];

#endif // __ID3_DEFS_H__
