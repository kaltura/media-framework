#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_ts_stream.h>
#include <ngx_http_call.h>
#include <ngx_http_ts_module.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_ts_kmp_track.h"


static void *ngx_http_ts_kmp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ts_kmp_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_ts_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


typedef struct {
    ngx_ts_kmp_conf_t  kmp;
} ngx_http_ts_kmp_loc_conf_t;


static ngx_command_t  ngx_http_ts_kmp_commands[] = {

    { ngx_string("ts_kmp"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ts_kmp,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },


    { ngx_string("ts_kmp_ctrl_connect_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.ctrl_connect_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_publish_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_publish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_unpublish_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_unpublish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_republish_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_republish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_add_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_headers),
      NULL },

    { ngx_string("ts_kmp_ctrl_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_timeout),
      NULL },

    { ngx_string("ts_kmp_ctrl_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_read_timeout),
      NULL },

    { ngx_string("ts_kmp_ctrl_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_buffer_size),
      NULL },

    { ngx_string("ts_kmp_ctrl_retries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_retries),
      NULL },

    { ngx_string("ts_kmp_ctrl_retry_interval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.ctrl_retry_interval),
      NULL },


    { ngx_string("ts_kmp_timescale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.timescale),
      NULL },

    { ngx_string("ts_kmp_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.timeout),
      NULL },

    { ngx_string("ts_kmp_max_free_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.max_free_buffers),
      NULL },

    { ngx_string("ts_kmp_buffer_bin_count"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.buffer_bin_count),
      NULL },

    { ngx_string("ts_kmp_mem_high_watermark"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.mem_high_watermark),
      NULL },

    { ngx_string("ts_kmp_mem_low_watermark"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.mem_low_watermark),
      NULL },

    { ngx_string("ts_kmp_video_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t,
          kmp.t.buffer_size[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("ts_kmp_video_mem_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t,
          kmp.t.mem_limit[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("ts_kmp_audio_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t,
          kmp.t.buffer_size[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("ts_kmp_audio_mem_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t,
          kmp.t.mem_limit[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("ts_kmp_flush_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.flush_timeout),
      NULL },

    { ngx_string("ts_kmp_log_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.log_frames),
      NULL },

    { ngx_string("ts_kmp_republish_interval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.republish_interval),
      NULL },

    { ngx_string("ts_kmp_max_republishes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_kmp_loc_conf_t, kmp.t.max_republishes),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ts_kmp_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* init server configuration */

    ngx_http_ts_kmp_create_loc_conf,        /* create location configuration */
    ngx_http_ts_kmp_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_ts_kmp_module = {
    NGX_MODULE_V1,
    &ngx_http_ts_kmp_module_ctx,            /* module context */
    ngx_http_ts_kmp_commands,               /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_ts_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ts_kmp_loc_conf_t  *klcf;

    klcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_ts_kmp_module);

    if (ngx_http_ts_add_init_handler(cf, ngx_ts_kmp_init_handler, &klcf->kmp)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_ts_kmp_finalize(ngx_connection_t *c)
{
    ngx_http_request_t  *r;

    r = c->data;

    ngx_http_finalize_request(r, NGX_ERROR);
}


static void *
ngx_http_ts_kmp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ts_kmp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ts_kmp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->kmp.ctrl_connect_url = NGX_CONF_UNSET_PTR;
    ngx_kmp_out_track_init_conf(&conf->kmp.t);

    return conf;
}


static char *
ngx_http_ts_kmp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_kmp_loc_conf_t  *prev = parent;
    ngx_http_ts_kmp_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->kmp.ctrl_connect_url,
                             prev->kmp.ctrl_connect_url, NULL);

    if (ngx_kmp_out_track_merge_conf(cf, &conf->kmp.t, &prev->kmp.t)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    conf->kmp.finalize = ngx_http_ts_kmp_finalize;

    return NGX_CONF_OK;
}
