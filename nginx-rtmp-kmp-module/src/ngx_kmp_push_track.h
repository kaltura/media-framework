#ifndef _NGX_KMP_PUSH_TRACK_H_INCLUDED_
#define _NGX_KMP_PUSH_TRACK_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_kmp_push_track_s ngx_kmp_push_track_t;

typedef struct {
    ngx_url_t       *ctrl_publish_url;
    ngx_url_t       *ctrl_republish_url;
    ngx_url_t       *ctrl_unpublish_url;
    ngx_array_t     *ctrl_headers;
    ngx_msec_t       ctrl_timeout;
    ngx_msec_t       ctrl_read_timeout;
    size_t           ctrl_buffer_size;
    ngx_uint_t       ctrl_retries;
    ngx_msec_t       ctrl_retry_interval;

    ngx_uint_t       timescale;
    ngx_msec_t       timeout;
    ngx_uint_t       max_free_buffers;
    size_t           video_buffer_size;
    size_t           video_mem_limit;
    size_t           audio_buffer_size;
    size_t           audio_mem_limit;
    ngx_msec_t       flush_timeout;

    time_t           republish_interval;
    ngx_uint_t       max_republishes;
} ngx_kmp_push_track_conf_t;


void ngx_kmp_push_track_init_conf(ngx_kmp_push_track_conf_t *conf);

void ngx_kmp_push_track_merge_conf(ngx_kmp_push_track_conf_t *conf,
    ngx_kmp_push_track_conf_t *prev);


ngx_kmp_push_track_t *ngx_kmp_push_track_create(
    ngx_kmp_push_track_conf_t *conf, ngx_uint_t media_type);

ngx_int_t ngx_kmp_push_track_publish(ngx_kmp_push_track_t *track);

void ngx_kmp_push_track_detach(ngx_kmp_push_track_t *track, char *reason);

void ngx_kmp_push_track_error(ngx_kmp_push_track_t *track, char *code);

#endif /* _NGX_KMP_PUSH_TRACK_H_INCLUDED_ */
