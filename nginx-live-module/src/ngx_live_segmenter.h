#ifndef _NGX_LIVE_SEGMENTER_H_INCLUDED_
#define _NGX_LIVE_SEGMENTER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_kmp.h>
#include "ngx_buf_chain.h"
#include "ngx_live.h"


#define NGX_LIVE_INVALID_SEGMENT_INDEX      (NGX_MAX_UINT32_VALUE)
#define NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT  (16384)


typedef ngx_int_t (*ngx_live_add_frame_pt)(ngx_live_track_t *track,
    kmp_frame_t *frame, ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail,
    size_t size);

typedef void (*ngx_live_end_of_stream_pt)(ngx_live_track_t *track);


ngx_int_t ngx_live_segmenter_force_split(ngx_live_track_t *track,
    uint32_t *segment_index);

void ngx_live_segmenter_get_oldest_data_ptr(ngx_live_track_t *track,
    u_char **ptr);


extern ngx_live_add_frame_pt      ngx_live_add_frame;

extern ngx_live_end_of_stream_pt  ngx_live_end_of_stream;

#endif /* _NGX_LIVE_SEGMENTER_H_INCLUDED_ */
