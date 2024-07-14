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
    ngx_msec_t       audio_sync_margin;

    ngx_msec_t       flush_timeout;
    ngx_msec_t       keepalive_interval;
    ngx_uint_t       log_frames;

    ngx_msec_t       republish_interval;
    ngx_uint_t       max_republishes;
} ngx_kmp_out_track_conf_t;


void ngx_kmp_out_track_init_conf(ngx_kmp_out_track_conf_t *conf);

ngx_int_t ngx_kmp_out_track_merge_conf(ngx_conf_t *cf,
    ngx_kmp_out_track_conf_t *conf, ngx_kmp_out_track_conf_t *prev);


ngx_kmp_out_track_t *ngx_kmp_out_track_get(ngx_str_t *id);
ngx_kmp_out_track_t *ngx_kmp_out_track_create(
    ngx_kmp_out_track_conf_t *conf, ngx_uint_t media_type);

ngx_int_t ngx_kmp_out_track_publish(ngx_kmp_out_track_t *track);
ngx_int_t ngx_kmp_out_track_publish_json(ngx_kmp_out_track_t *track,
    ngx_json_object_t *obj, ngx_pool_t *temp_pool);
void ngx_kmp_out_track_detach(ngx_kmp_out_track_t *track, char *reason);
void ngx_kmp_out_track_error(ngx_kmp_out_track_t *track, char *code);

/*
 * NGX_DECLINED - failed to get source upstream
 * NGX_ERROR - bad json
 * NGX_ABORT - memory error
 */
ngx_int_t ngx_kmp_out_track_add_upstream(ngx_pool_t *temp_pool,
    ngx_kmp_out_track_t *track, ngx_str_t *src_id, ngx_json_object_t *obj);
ngx_int_t ngx_kmp_out_track_del_upstream(ngx_kmp_out_track_t *track,
    ngx_str_t *id, ngx_log_t *log);

size_t ngx_kmp_out_track_upstreams_json_get_size(ngx_kmp_out_track_t *obj);
u_char *ngx_kmp_out_track_upstreams_json_write(u_char *p,
    ngx_kmp_out_track_t *obj);

size_t ngx_kmp_out_track_upstream_ids_json_get_size(ngx_kmp_out_track_t *obj);
u_char *ngx_kmp_out_track_upstream_ids_json_write(u_char *p,
    ngx_kmp_out_track_t *obj);

size_t ngx_kmp_out_track_json_get_size(ngx_kmp_out_track_t *obj);
u_char *ngx_kmp_out_track_json_write(u_char *p, ngx_kmp_out_track_t *obj);

size_t ngx_kmp_out_tracks_json_get_size(void *obj);
u_char *ngx_kmp_out_tracks_json_write(u_char *p, void *obj);

size_t ngx_kmp_out_track_ids_json_get_size(void *obj);
u_char *ngx_kmp_out_track_ids_json_write(u_char *p, void *obj);


extern ngx_conf_enum_t  ngx_kmp_out_log_frames[];

#endif /* _NGX_KMP_OUT_TRACK_H_INCLUDED_ */
