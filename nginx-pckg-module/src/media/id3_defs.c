#include "id3_defs.h"

// constants
u_char id3_text_frame_template[sizeof(id3_text_frame_t)] = {
    // id3 header
    0x49, 0x44, 0x33, 0x04,     // file identifier
    0x00,                       // version
    0x00,                       // flags
    0x00, 0x00, 0x00, 0x00,     // size

    // frame header
    0x54, 0x45, 0x58, 0x54,     // frame id
    0x00, 0x00, 0x00, 0x00,     // size
    0x00, 0x00,                 // flags

    // text frame
    0x03,                       // encoding    (=utf8, null term)
};
