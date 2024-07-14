#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include <ngx_rtmp_streams.h>

#include <ngx_live_kmp.h>
#include <ngx_http_call.h>
#include <ngx_json_parser.h>
#include <ngx_lba.h>
#include <ngx_kmp_out_utils.h>
#include "ngx_rtmp_kmp_module.h"


#define ngx_json_str_from_c(dst, src) {                                      \
        dst.s.data = src;                                                    \
        dst.s.len = ngx_strlen(dst.s.data);                                  \
        ngx_json_str_set_escape(&dst);                                       \
    }


static ngx_rtmp_connect_pt       next_connect;
static ngx_rtmp_publish_pt       next_publish;
static ngx_rtmp_close_stream_pt  next_close_stream;
static ngx_rtmp_disconnect_pt    next_disconnect;


typedef struct {
    ngx_msec_t      idle_timeout;
} ngx_rtmp_kmp_srv_conf_t;


/* Note: an ngx_json_str_t version of ngx_rtmp_connect_t */
typedef struct {
    ngx_json_str_t  app;
    ngx_json_str_t  args;
    ngx_json_str_t  flashver;
    ngx_json_str_t  swf_url;
    ngx_json_str_t  tc_url;
    ngx_json_str_t  page_url;
} ngx_rtmp_kmp_connect_t;

#include "ngx_rtmp_kmp_json.h"


static ngx_int_t ngx_rtmp_kmp_postconfiguration(ngx_conf_t *cf);

static void *ngx_rtmp_kmp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static void *ngx_rtmp_kmp_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_kmp_merge_app_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    ngx_rtmp_session_t       *s;
    ngx_rtmp_kmp_app_conf_t  *kacf;
    ngx_rtmp_connect_t        connect;
    ngx_uint_t                retries_left;
} ngx_rtmp_kmp_connect_call_ctx_t;


static ngx_command_t  ngx_rtmp_kmp_commands[] = {

    { ngx_string("kmp_idle_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_SRV_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_srv_conf_t, idle_timeout),
      NULL },

    { ngx_string("kmp_ctrl_connect_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, ctrl_connect_url),
      NULL },

    { ngx_string("kmp_ctrl_publish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_publish_url),
      NULL },

    { ngx_string("kmp_ctrl_unpublish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_unpublish_url),
      NULL },

    { ngx_string("kmp_ctrl_republish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_http_call_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_republish_url),
      NULL },

    { ngx_string("kmp_ctrl_add_header"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_headers),
      NULL },

    { ngx_string("kmp_ctrl_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_timeout),
      NULL },

    { ngx_string("kmp_ctrl_read_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_read_timeout),
      NULL },

    { ngx_string("kmp_ctrl_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_buffer_size),
      NULL },

    { ngx_string("kmp_ctrl_retries"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_retries),
      NULL },

    { ngx_string("kmp_ctrl_retry_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_retry_interval),
      NULL },


    { ngx_string("kmp_timescale"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.timescale),
      NULL },

    { ngx_string("kmp_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.timeout),
      NULL },

    { ngx_string("kmp_max_free_buffers"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.max_free_buffers),
      NULL },

    { ngx_string("kmp_buffer_bin_count"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.buffer_bin_count),
      NULL },

    { ngx_string("kmp_mem_high_watermark"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.mem_high_watermark),
      NULL },

    { ngx_string("kmp_mem_low_watermark"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.mem_low_watermark),
      NULL },

    { ngx_string("kmp_video_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.buffer_size[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("kmp_video_mem_limit"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.mem_limit[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("kmp_audio_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.buffer_size[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("kmp_audio_mem_limit"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.mem_limit[KMP_MEDIA_AUDIO]),
      NULL },

    { ngx_string("kmp_audio_sync_margin"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.audio_sync_margin),
      NULL },

    { ngx_string("kmp_flush_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.flush_timeout),
      NULL },

    { ngx_string("kmp_log_frames"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.log_frames),
      &ngx_kmp_out_log_frames },

    { ngx_string("kmp_republish_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.republish_interval),
      NULL },

    { ngx_string("kmp_max_republishes"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.max_republishes),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_kmp_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_kmp_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_rtmp_kmp_create_srv_conf,           /* create server configuration */
    ngx_rtmp_kmp_merge_srv_conf,            /* merge server configuration */
    ngx_rtmp_kmp_create_app_conf,           /* create app configuration */
    ngx_rtmp_kmp_merge_app_conf             /* merge app configuration */
};


ngx_module_t  ngx_rtmp_kmp_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_kmp_module_ctx,               /* module context */
    ngx_rtmp_kmp_commands,                  /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_kmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_kmp_srv_conf_t  *kscf;

    kscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_kmp_srv_conf_t));
    if (kscf == NULL) {
        return NULL;
    }

    kscf->idle_timeout = NGX_CONF_UNSET_MSEC;

    return kscf;
}


static char *
ngx_rtmp_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_kmp_srv_conf_t  *prev = parent;
    ngx_rtmp_kmp_srv_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->idle_timeout,
                              prev->idle_timeout, 30000);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_kmp_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_kmp_app_conf_t  *kacf;

    kacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_kmp_app_conf_t));
    if (kacf == NULL) {
        return NULL;
    }

    ngx_queue_init(&kacf->sessions);
    kacf->ctrl_connect_url = NGX_CONF_UNSET_PTR;

    ngx_kmp_out_track_init_conf(&kacf->t);

    return kacf;
}


static char *
ngx_rtmp_kmp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_kmp_app_conf_t  *prev = parent;
    ngx_rtmp_kmp_app_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->ctrl_connect_url,
                             prev->ctrl_connect_url, NULL);

    if (ngx_kmp_out_track_merge_conf(cf, &conf->t, &prev->t) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->t.timescale % NGX_RTMP_TIMESCALE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "configured timescale %ui is not a multiple of rtmp timescale",
            conf->t.timescale);
    }

    return NGX_CONF_OK;
}


static void
ngx_rtmp_kmp_get_publish_info(ngx_rtmp_kmp_publish_t *kp,
    ngx_rtmp_publish_t *v)
{
    ngx_json_str_from_c(kp->name, v->name);
    ngx_json_str_from_c(kp->args, v->args);
    ngx_json_str_from_c(kp->type, v->type);
}


static void
ngx_rtmp_kmp_get_connect_info(ngx_rtmp_kmp_connect_t *kc,
    ngx_rtmp_connect_t *v)
{
    ngx_json_str_from_c(kc->app, v->app);
    ngx_json_str_from_c(kc->args, v->args);
    ngx_json_str_from_c(kc->flashver, v->flashver);
    ngx_json_str_from_c(kc->swf_url, v->swf_url);
    ngx_json_str_from_c(kc->tc_url, v->tc_url);
    ngx_json_str_from_c(kc->page_url, v->page_url);
}


static void
ngx_rtmp_kmp_idle(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_rtmp_session_t  *s;

    c = ev->data;
    s = c->data;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "ngx_rtmp_kmp_idle: closing idle connection");

    ngx_rtmp_finalize_session(s);
}


static ngx_int_t
ngx_rtmp_kmp_socket_connect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_event_t              *e;
    ngx_connection_t         *c;
    ngx_rtmp_kmp_ctx_t       *ctx;
    ngx_rtmp_kmp_srv_conf_t  *kscf;

    c = s->connection;

    kscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_kmp_module);
    if (kscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
            "ngx_rtmp_kmp_socket_connect: failed to get srv conf");
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_rtmp_kmp_socket_connect: alloc failed");
        return NGX_ERROR;
    }

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_kmp_module);

    ctx->s = s;

    /* get the address name with port */
    ctx->remote_addr.s.data = ctx->remote_addr_buf;
    ctx->remote_addr.s.len = ngx_sock_ntop(c->sockaddr, c->socklen,
        ctx->remote_addr_buf, NGX_SOCKADDR_STRLEN, 1);
    if (ctx->remote_addr.s.len == 0) {
        ctx->remote_addr.s = c->addr_text;
    }

    ngx_json_str_set_escape(&ctx->remote_addr);

    /* start the idle timeout */
    ctx->idle_timeout = kscf->idle_timeout;
    if (ctx->idle_timeout) {
        e = &ctx->idle;

        e->data = c;
        e->log = c->log;
        e->handler = ngx_rtmp_kmp_idle;

        ngx_add_timer(e, ctx->idle_timeout);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_kmp_send_error(ngx_rtmp_session_t *s, double in_trans)
{
    static double              trans;

    static ngx_rtmp_amf_elt_t  out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "error", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetConnection.Connect.Rejected", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Connection failed: Application rejected connection.", 0 },
    };

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_error", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    ngx_rtmp_header_t          h;

    trans = in_trans;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
        sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_kmp_connect_error(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v,
    u_char *desc)
{
    ngx_int_t                  rc;
    ngx_rtmp_core_srv_conf_t  *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    rc = ngx_rtmp_send_chunk_size(s, cscf->chunk_size);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_connect_error: send chunk size failed %i", rc);
        return NGX_ERROR;
    }

    rc = ngx_rtmp_send_stream_begin(s, s->in_msid);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_connect_error: send stream begin failed %i", rc);
        return NGX_ERROR;
    }

    rc = ngx_rtmp_send_status(s, "NetStream.Play.Failed", "error",
        (char *) desc);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_connect_error: send status failed %i", rc);
        return NGX_ERROR;
    }

    rc = ngx_rtmp_kmp_send_error(s, v->trans);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_connect_error: send error failed %i", rc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_chain_t *
ngx_rtmp_kmp_connect_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    size_t                            size;
    ngx_buf_t                        *b;
    ngx_chain_t                      *cl;
    ngx_rtmp_session_t               *s;
    ngx_rtmp_kmp_connect_t            connect;
    ngx_rtmp_kmp_app_conf_t          *kacf;
    ngx_rtmp_kmp_connect_call_ctx_t  *ctx = arg;

    s = ctx->s;

    ngx_rtmp_kmp_get_connect_info(&connect, &ctx->connect);

    size = ngx_rtmp_kmp_connect_json_get_size(&connect, s);

    cl = ngx_http_call_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_rtmp_kmp_connect_create: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;

    b->last = ngx_rtmp_kmp_connect_json_write(b->last, &connect, s);

    if ((size_t) (b->last - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_rtmp_kmp_connect_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (b->last - b->pos), size);
        return NULL;
    }

    kacf = ctx->kacf;
    return ngx_http_call_format_json_post(pool,
        &kacf->ctrl_connect_url->host, &kacf->ctrl_connect_url->uri,
        kacf->t.ctrl_headers, cl);
}


static ngx_int_t
ngx_rtmp_kmp_connect_handle(ngx_pool_t *temp_pool, void *arg, ngx_uint_t code,
    ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_int_t                         rc;
    ngx_log_t                        *log;
    ngx_str_t                         desc;
    ngx_rtmp_session_t               *s;
    ngx_rtmp_kmp_connect_call_ctx_t  *cctx;

    cctx = arg;
    s = cctx->s;

    log = s->connection->log;

    rc = ngx_kmp_out_connect_parse(temp_pool, log, code, content_type,
        body, &desc);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DECLINED:
        goto error;

    default:    /* NGX_ERROR */
        if (cctx->retries_left > 0) {
            cctx->retries_left--;
            return NGX_AGAIN;
        }

        desc.data = (u_char *) "Internal server error";
        goto error;
    }

    if (next_connect(s, &cctx->connect) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_rtmp_kmp_connect_handle: next connect failed");
        ngx_rtmp_finalize_session(s);
    }

    return NGX_OK;

error:

    if (ngx_rtmp_kmp_connect_error(s, &cctx->connect, desc.data) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_rtmp_kmp_connect_handle: failed to send error");
        ngx_rtmp_finalize_session(s);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_kmp_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_url_t                        *url;
    ngx_connection_t                 *c;
    ngx_rtmp_kmp_ctx_t               *ctx;
    ngx_http_call_init_t              ci;
    ngx_rtmp_kmp_app_conf_t          *kacf;
    ngx_rtmp_kmp_connect_call_ctx_t   create_ctx;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    c = s->connection;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
            "ngx_rtmp_kmp_connect: failed to get module ctx");
        return NGX_ERROR;
    }

#if (nginx_version >= 1017006)
    u_char                *p;
    ngx_proxy_protocol_t  *pp;

    pp = c->proxy_protocol;
    if (pp && pp->src_addr.len <
        NGX_SOCKADDR_STRLEN - (sizeof(":65535") - 1))
    {
        p = ngx_copy(ctx->remote_addr_buf, pp->src_addr.data,
            pp->src_addr.len);
        p = ngx_sprintf(p, ":%uD", (uint32_t) pp->src_port);
        ctx->remote_addr.s.len = p - ctx->remote_addr_buf;

        ngx_json_str_set_escape(&ctx->remote_addr);
    }
#endif

    kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
            "ngx_rtmp_kmp_connect: failed to get app conf");
        return NGX_ERROR;
    }

    if (ngx_queue_next(&ctx->queue) == NULL) {
        ngx_queue_insert_tail(&kacf->sessions, &ctx->queue);
    }

    url = kacf->ctrl_connect_url;
    if (url == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, c->log, 0,
            "ngx_rtmp_kmp_connect: no connect url set in conf");
        goto next;
    }

    create_ctx.s = s;
    create_ctx.connect = *v;
    create_ctx.kacf = kacf;
    create_ctx.retries_left = kacf->t.ctrl_retries;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_kmp_connect_create;
    ci.handle = ngx_rtmp_kmp_connect_handle;
    ci.handler_pool = c->pool;
    ci.arg = &create_ctx;
    ci.argsize = sizeof(create_ctx);
    ci.timeout = kacf->t.ctrl_timeout;
    ci.read_timeout = kacf->t.ctrl_read_timeout;
    ci.buffer_size = kacf->t.ctrl_buffer_size;
    ci.retry_interval = kacf->t.ctrl_retry_interval;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "ngx_rtmp_kmp_connect: sending connect request to \"%V\"", &url->url);

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_rtmp_kmp_connect: http call to \"%V\" failed", &url->url);
        return NGX_ERROR;
    }

    return NGX_OK;

next:

    return next_connect(s, v);
}


static ngx_int_t
ngx_rtmp_kmp_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_kmp_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx != NULL) {

        if (ngx_queue_next(&ctx->queue) != NULL) {
            ngx_queue_remove(&ctx->queue);
            ctx->queue.next = NULL;
        }

        if (ctx->idle.timer_set) {
            ngx_del_timer(&ctx->idle);
        }
    }

    return next_disconnect(s);
}


static ngx_int_t
ngx_rtmp_kmp_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_connection_t           *c;
    ngx_rtmp_kmp_ctx_t         *ctx;
    ngx_rtmp_kmp_app_conf_t    *kacf;
    ngx_rtmp_kmp_stream_ctx_t  *sctx;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    c = s->connection;

    kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
            "ngx_rtmp_kmp_publish: failed to get app conf");
        return NGX_ERROR;
    }

    if (kacf->t.ctrl_publish_url == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, c->log, 0,
            "ngx_rtmp_kmp_publish: no publish url set in conf");
        goto next;
    }

    if (!s->in_stream) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_rtmp_kmp_publish: no stream context");
        return NGX_ERROR;
    }

    sctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (sctx == NULL) {

        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                "ngx_rtmp_kmp_publish: failed to get module ctx");
            return NGX_ERROR;
        }

        sctx = ngx_pcalloc(c->pool, sizeof(*sctx));
        if (sctx == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_rtmp_kmp_publish: alloc failed");
            return NGX_ERROR;
        }

        ngx_rtmp_stream_set_ctx(s, sctx, ngx_rtmp_kmp_module);
    }

    sctx->publish_buf = *v;
    ngx_rtmp_kmp_get_publish_info(&sctx->publish, &sctx->publish_buf);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "ngx_rtmp_kmp_publish: called, name: %V, args: %V, type: %V",
        &sctx->publish.name.s, &sctx->publish.args.s, &sctx->publish.type.s);

next:

    return next_publish(s, v);
}


static void
ngx_rtmp_kmp_detach_tracks(ngx_rtmp_kmp_stream_ctx_t *sctx, char *reason)
{
    ngx_uint_t            media_type;
    ngx_kmp_out_track_t  *track;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        track = sctx->tracks[media_type];
        if (track == NULL) {
            continue;
        }

        sctx->tracks[media_type] = NULL;

        ngx_kmp_out_track_detach(track, reason);
    }
}


static ngx_int_t
ngx_rtmp_kmp_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    char                       *reason;
    ngx_rtmp_kmp_ctx_t         *ctx;
    ngx_rtmp_kmp_stream_ctx_t  *sctx;

    sctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (sctx == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "ngx_rtmp_kmp_close_stream: called, name: %V, args: %V, type: %V",
        &sctx->publish.name.s, &sctx->publish.args.s, &sctx->publish.type.s);

    ngx_memzero(&sctx->publish, sizeof(sctx->publish));

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);

    if (ctx && ctx->error) {
        reason = "rtmp_kmp_error";

    } else if (v->disconnect) {
        reason = "rtmp_disconnect";

    } else {
        reason = "rtmp_close";
    }

    ngx_rtmp_kmp_detach_tracks(sctx, reason);

next:

    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_kmp_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_uint_t                  media_type;
    ngx_rtmp_kmp_ctx_t         *ctx;
    ngx_kmp_out_track_t        *track;
    ngx_rtmp_kmp_app_conf_t    *kacf;
    ngx_rtmp_kmp_stream_ctx_t  *sctx;

    sctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (sctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, s->connection->log, 0,
            "ngx_rtmp_kmp_av: no context");
        return NGX_OK;
    }

    /* get media type */
    switch (h->type) {

    case NGX_RTMP_MSG_VIDEO:
        media_type = KMP_MEDIA_VIDEO;
        break;

    case NGX_RTMP_MSG_AUDIO:
        media_type = KMP_MEDIA_AUDIO;
        break;

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_KMP, s->connection->log, 0,
            "ngx_rtmp_kmp_av: unknown message type %uD", (uint32_t) h->type);
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);

    if (ctx->idle_timeout) {
        ngx_add_timer(&ctx->idle, ctx->idle_timeout);
    }

    /* get track */
    track = sctx->tracks[media_type];
    if (track == NULL) {

        kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
        if (kacf == NULL) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                "ngx_rtmp_kmp_av: failed to get app conf");
            ctx->error = 1;
            return NGX_ERROR;
        }

        track = ngx_rtmp_kmp_track_create(&kacf->t, s, &sctx->publish, h, in);
        if (track == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                "ngx_rtmp_kmp_av: failed to create track");
            ctx->error = 1;
            return NGX_ERROR;
        }

        sctx->tracks[media_type] = track;
    }

    /* forward to track */
    if (ngx_rtmp_kmp_track_av(track, h, in) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_av: track handler failed");
        ctx->error = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_kmp_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_handler_pt        *h;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_kmp_connect;

    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_kmp_disconnect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_kmp_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_kmp_close_stream;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_CONNECT]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_kmp_socket_connect;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_kmp_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_kmp_av;

    return NGX_OK;
}
