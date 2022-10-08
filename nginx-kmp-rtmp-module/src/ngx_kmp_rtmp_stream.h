#ifndef _NGX_KMP_RTMP_STREAM_H_INCLUDED_
#define _NGX_KMP_RTMP_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_kmp_rtmp.h"
#include "ngx_kmp_rtmp_encoder.h"


struct ngx_kmp_rtmp_stream_s {
    ngx_str_node_t              sn;        /* must be first */
    ngx_queue_t                 queue;
    uintptr_t                   id_escape;

    ngx_log_t                   log;
    ngx_msec_t                  created;
    ngx_kmp_rtmp_upstream_t    *upstream;

    ngx_kmp_rtmp_stream_ctx_t   ctx;
    int64_t                     last_onfi_time;

    ngx_kmp_rtmp_track_t       *tracks[NGX_KMP_RTMP_MEDIA_COUNT];
    uint32_t                    active_tracks;

    ngx_event_t                 write_meta;

    unsigned                    wrote_meta:1;
};


ngx_kmp_rtmp_stream_t *ngx_kmp_rtmp_stream_get_or_create(
    ngx_kmp_rtmp_upstream_t *u, ngx_str_t *name);
void ngx_kmp_rtmp_stream_free(ngx_kmp_rtmp_stream_t *stream);

void ngx_kmp_rtmp_stream_attach_track(ngx_kmp_rtmp_stream_t *stream,
    ngx_kmp_rtmp_track_t *track, ngx_uint_t media_type);
void ngx_kmp_rtmp_stream_detach_track(ngx_kmp_rtmp_stream_t *stream,
    ngx_uint_t media_type);

ngx_int_t ngx_kmp_rtmp_stream_write_frame(ngx_kmp_rtmp_stream_t *stream,
    ngx_kmp_rtmp_frame_t *frame, uint32_t codec_id);

size_t ngx_kmp_rtmp_stream_json_get_size(ngx_kmp_rtmp_stream_t *stream);
u_char *ngx_kmp_rtmp_stream_json_write(u_char *p,
    ngx_kmp_rtmp_stream_t *stream);

#endif /* _NGX_KMP_RTMP_STREAM_H_INCLUDED_ */
