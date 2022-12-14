#ifndef _NGX_LIVE_SEGMENTER_H_INCLUDED_
#define _NGX_LIVE_SEGMENTER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_kmp.h>
#include <ngx_buf_chain.h>
#include "ngx_live.h"


#define NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT       (16384)
#define NGX_LIVE_SEGMENTER_MAX_SEGMENT_DURATION  (600000)
#define NGX_LIVE_SEGMENTER_MAX_INPUT_DELAY       (600000)

#define NGX_LIVE_SEGMENTER_FLAG_PARTS_CAP        (0x01)

/* KMP_FRAME_FLAG_KEY = 0x01 */
#define NGX_LIVE_FRAME_FLAG_SPLIT                (0x10)
#define NGX_LIVE_FRAME_FLAG_RESET_DTS_SHIFT      (0x20)


typedef struct {
    ngx_live_track_t      *track;
    kmp_connect_packet_t  *header;

    uint64_t               skip_count;
    unsigned               skip_wait_key:1;
} ngx_live_stream_stream_req_t;


typedef ngx_int_t (*ngx_live_start_stream_pt)(
    ngx_live_stream_stream_req_t *req);

typedef void      (*ngx_live_end_stream_pt)(ngx_live_track_t *track);

typedef void      (*ngx_live_get_min_used_pt)(ngx_live_track_t *track,
    uint32_t *segment_index, u_char **ptr);


typedef struct {
    uint32_t                    id;
    uint32_t                    flags;
    ngx_live_start_stream_pt    start_stream;
    ngx_kmp_in_end_stream_pt    end_stream;
    ngx_kmp_in_media_info_pt    add_media_info;
    ngx_kmp_in_frame_pt         add_frame;
    ngx_live_get_min_used_pt    get_min_used;
} ngx_live_segmenter_t;

#endif /* _NGX_LIVE_SEGMENTER_H_INCLUDED_ */
