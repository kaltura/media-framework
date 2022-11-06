#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_ts_stream.h>
#include <ngx_http_call.h>
#include <ngx_stream_ts_module.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_ts_kmp_track.h"


static ngx_stream_core_main_conf_t *ngx_stream_ts_kmp_get_core_main_conf(void);

static void *ngx_stream_ts_kmp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ts_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_ts_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


typedef struct {
    ngx_ts_kmp_conf_t  kmp;
} ngx_stream_ts_kmp_srv_conf_t;


static ngx_command_t  ngx_stream_ts_kmp_commands[] = {

    { ngx_string("ts_kmp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_ts_kmp,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },


    { ngx_string("ts_kmp_ctrl_connect_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.ctrl_connect_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_publish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_publish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_unpublish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_unpublish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_republish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_republish_url),
      NULL },

    { ngx_string("ts_kmp_ctrl_add_header"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_headers),
      NULL },

    { ngx_string("ts_kmp_ctrl_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_timeout),
      NULL },

    { ngx_string("ts_kmp_ctrl_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_read_timeout),
      NULL },

    { ngx_string("ts_kmp_ctrl_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_buffer_size),
      NULL },

    { ngx_string("ts_kmp_ctrl_retries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_retries),
      NULL },

    { ngx_string("ts_kmp_ctrl_retry_interval"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.ctrl_retry_interval),
      NULL },


    { ngx_string("ts_kmp_timescale"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.timescale),
      NULL },

    { ngx_string("ts_kmp_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.timeout),
      NULL },

    { ngx_string("ts_kmp_max_free_buffers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.max_free_buffers),
      NULL },

    { ngx_string("ts_kmp_buffer_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.buffer_bin_count),
      NULL },

    { ngx_string("ts_kmp_mem_high_watermark"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.mem_high_watermark),
      NULL },

    { ngx_string("ts_kmp_mem_low_watermark"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.mem_low_watermark),
      NULL },

    { ngx_string("ts_kmp_video_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t,
          kmp.t.buffer_size[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("ts_kmp_video_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t,
          kmp.t.mem_limit[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("ts_kmp_audio_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t,
          kmp.t.buffer_size[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("ts_kmp_audio_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t,
          kmp.t.mem_limit[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("ts_kmp_flush_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.flush_timeout),
      NULL },

    { ngx_string("ts_kmp_log_frames"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.log_frames),
      NULL },

    { ngx_string("ts_kmp_republish_interval"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.republish_interval),
      NULL },

    { ngx_string("ts_kmp_max_republishes"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ts_kmp_srv_conf_t, kmp.t.max_republishes),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_ts_kmp_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_stream_ts_kmp_create_srv_conf,      /* create server configuration */
    ngx_stream_ts_kmp_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_ts_kmp_module = {
    NGX_MODULE_V1,
    &ngx_stream_ts_kmp_module_ctx,          /* module context */
    ngx_stream_ts_kmp_commands,             /* module directives */
    NGX_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


#include "ngx_stream_ts_kmp_module_json.h"


static ngx_stream_core_main_conf_t *
ngx_stream_ts_kmp_get_core_main_conf(void)
{
    ngx_stream_conf_ctx_t        *stream_ctx;
    ngx_stream_core_main_conf_t  *cmcf;

    stream_ctx = (ngx_stream_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
        ngx_stream_module);
    if (stream_ctx == NULL) {
        return NULL;
    }

    cmcf = ngx_stream_get_module_main_conf(stream_ctx, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NULL;
    }

    return cmcf;
}


static ngx_stream_session_t *
ngx_stream_ts_kmp_server_get_session(ngx_stream_conf_ctx_t *conf,
    ngx_uint_t connection)
{
    ngx_queue_t                   *q;
    ngx_connection_t              *c;
    ngx_ts_kmp_ctx_t              *cur;
    ngx_stream_ts_kmp_srv_conf_t  *tscf;

    tscf = ngx_stream_get_module_srv_conf(conf, ngx_stream_ts_kmp_module);

    for (q = ngx_queue_head(&tscf->kmp.sessions);
        q != ngx_queue_sentinel(&tscf->kmp.sessions);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_ts_kmp_ctx_t, queue);

        c = cur->connection;
        if (c->number == connection) {
            return c->data;
        }
    }

    return NULL;
}


static ngx_stream_session_t *
ngx_stream_ts_kmp_get_session(ngx_stream_core_main_conf_t *cmcf,
    ngx_uint_t connection)
{
    ngx_uint_t                    n;
    ngx_stream_session_t         *s;
    ngx_stream_core_srv_conf_t  **cscfp;

    cscfp = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; n++) {
        s = ngx_stream_ts_kmp_server_get_session(cscfp[n]->ctx, connection);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


ngx_int_t
ngx_stream_ts_kmp_finalize_session(ngx_uint_t connection, ngx_log_t *log)
{
    ngx_stream_session_t         *s;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_ts_kmp_get_core_main_conf();
    if (cmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_stream_ts_kmp_finalize_session: "
            "failed to get stream conf");
        return NGX_ERROR;
    }

    s = ngx_stream_ts_kmp_get_session(cmcf, connection);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_stream_ts_kmp_finalize_session: "
            "connection %ui not found", connection);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_stream_ts_kmp_finalize_session: "
        "dropping connection %ui", connection);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);

    return NGX_OK;
}


static char *
ngx_stream_ts_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_ts_kmp_srv_conf_t  *kscf;

    kscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_ts_kmp_module);

    if (ngx_stream_ts_add_init_handler(cf, ngx_ts_kmp_init_handler, kscf)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_stream_ts_kmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_ts_kmp_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ts_kmp_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_queue_init(&conf->kmp.sessions);
    conf->kmp.ctrl_connect_url = NGX_CONF_UNSET_PTR;
    ngx_kmp_out_track_init_conf(&conf->kmp.t);

    return conf;
}


static char *
ngx_stream_ts_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_ts_kmp_srv_conf_t  *prev = parent;
    ngx_stream_ts_kmp_srv_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->kmp.ctrl_connect_url,
                             prev->kmp.ctrl_connect_url, NULL);

    if (ngx_kmp_out_track_merge_conf(cf, &conf->kmp.t, &prev->kmp.t)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
