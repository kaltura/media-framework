#ifndef _NGX_LIVE_SEGMENTER_H_INCLUDED_
#define _NGX_LIVE_SEGMENTER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>
#include "ngx_live.h"


#define NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT   (16384)

/* KMP_FRAME_FLAG_KEY = 0x01 */
#define NGX_LIVE_FRAME_FLAG_SPLIT            (0x10)
#define NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT  (0x20)


typedef struct {
    ngx_live_track_t  *track;

    uint64_t           frame_id;
    kmp_frame_t       *frame;

    ngx_buf_chain_t   *data_head;
    ngx_buf_chain_t   *data_tail;
    size_t             size;
} ngx_live_add_frame_req_t;


typedef ngx_int_t (*ngx_live_add_frame_pt)(ngx_live_add_frame_req_t *req);

typedef ngx_int_t (*ngx_live_add_media_info_pt)(ngx_live_track_t *track,
    kmp_media_info_t *media_info, ngx_buf_chain_t *extra_data,
    uint32_t extra_data_size);

typedef void (*ngx_live_end_of_stream_pt)(ngx_live_track_t *track);


void ngx_live_segmenter_get_min_used(ngx_live_track_t *track,
    uint32_t *segment_index, u_char **ptr);


extern ngx_live_add_media_info_pt  ngx_live_add_media_info;

extern ngx_live_add_frame_pt       ngx_live_add_frame;

extern ngx_live_end_of_stream_pt   ngx_live_end_of_stream;

#endif /* _NGX_LIVE_SEGMENTER_H_INCLUDED_ */
