#ifndef _NGX_KMP_OUT_TRACK_H_INCLUDED_
#define _NGX_KMP_OUT_TRACK_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_lba.h>
#include <ngx_live_kmp.h>
#include <ngx_json_parser.h>


typedef struct ngx_kmp_out_track_s  ngx_kmp_out_track_t;

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
    ngx_uint_t       buffer_bin_count;
    ngx_uint_t       mem_high_watermark;
    ngx_uint_t       mem_low_watermark;
    size_t           buffer_size[KMP_MEDIA_COUNT];
    size_t           mem_limit[KMP_MEDIA_COUNT];
    ngx_lba_t       *lba[KMP_MEDIA_COUNT];

    ngx_msec_t       flush_timeout;
    ngx_flag_t       log_frames;

    time_t           republish_interval;
    ngx_uint_t       max_republishes;
} ngx_kmp_out_track_conf_t;


void ngx_kmp_out_track_init_conf(ngx_kmp_out_track_conf_t *conf);

ngx_int_t ngx_kmp_out_track_merge_conf(ngx_conf_t *cf,
    ngx_kmp_out_track_conf_t *conf, ngx_kmp_out_track_conf_t *prev);


ngx_kmp_out_track_t *ngx_kmp_out_track_create(
    ngx_kmp_out_track_conf_t *conf, ngx_uint_t media_type);

ngx_int_t ngx_kmp_out_track_publish(ngx_kmp_out_track_t *track);

ngx_int_t ngx_kmp_out_track_publish_json(ngx_kmp_out_track_t *track,
    ngx_json_object_t *obj, ngx_pool_t *temp_pool);

void ngx_kmp_out_track_detach(ngx_kmp_out_track_t *track, char *reason);

void ngx_kmp_out_track_error(ngx_kmp_out_track_t *track, char *code);


size_t ngx_kmp_out_track_json_get_size(ngx_kmp_out_track_t *obj);

u_char *ngx_kmp_out_track_json_write(u_char *p, ngx_kmp_out_track_t *obj);

#endif /* _NGX_KMP_OUT_TRACK_H_INCLUDED_ */
