#ifndef __MP4_INIT_SEGMENT_H__
#define __MP4_INIT_SEGMENT_H__

// includes
#include "../media_format.h"

// typedefs
typedef u_char* (*atom_writer_func_t)(void* context, u_char* p);

typedef struct {
    size_t atom_size;
    atom_writer_func_t write;
    void* context;
} atom_writer_t;

// functions
vod_status_t mp4_init_segment_build(
    request_context_t* request_context,
    media_init_segment_t* segment,
    bool_t size_only,
    atom_writer_t* extra_moov_atoms_writer,
    atom_writer_t* stsd_atom_writers,
    vod_str_t* result);

vod_status_t mp4_init_segment_get_encrypted_stsd_writers(
    request_context_t* request_context,
    media_init_segment_t* segment,
    uint32_t scheme_type,
    bool_t has_clear_lead,
    atom_writer_t** result);

#endif // __MP4_INIT_SEGMENT_H__
