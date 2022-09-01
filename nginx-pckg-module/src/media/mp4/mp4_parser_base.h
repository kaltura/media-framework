#ifndef __MP4_PARSER_BASE_H__
#define __MP4_PARSER_BASE_H__

#include "../media_format.h"
#include "mp4_defs.h"

// atom parsing types
typedef uint32_t mp4_atom_name_t;

typedef struct {
    u_char* ptr;
    uint64_t size;
    mp4_atom_name_t name;
    uint8_t header_size;
} mp4_atom_t;

typedef vod_status_t(*mp4_parse_callback_t)(void* data, mp4_atom_t* atom_info);

// atom get
typedef struct mp4_get_atom_s mp4_get_atom_t;

struct mp4_get_atom_s {
    mp4_atom_name_t atom_name;
    int target_offset;
    mp4_get_atom_t* children;
};

typedef struct {
    request_context_t* request_context;
    mp4_get_atom_t* atoms;
    void* result;
} mp4_get_atoms_ctx_t;

// functions
vod_status_t mp4_parser_parse_atoms(
    request_context_t* request_context,
    u_char* buf,
    uint64_t size,
    mp4_parse_callback_t callback,
    void* data);

vod_status_t mp4_parser_get_atoms_callback(void* data, mp4_atom_t* atom_info);

#endif // __MP4_PARSER_BASE_H__
