#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include <ngx_rtmp_streams.h>

#include <ngx_live_kmp.h>
#include <ngx_http_call.h>
#include <ngx_json_parser.h>
#include "ngx_kmp_push_utils.h"
#include "ngx_rtmp_kmp_module.h"


#define ngx_str_from_c(dst, src) {       \
        dst.data = src;                  \
        dst.len = ngx_strlen(dst.data);  \
    }


static ngx_rtmp_connect_pt       next_connect;
static ngx_rtmp_publish_pt       next_publish;
static ngx_rtmp_close_stream_pt  next_close_stream;
static ngx_rtmp_disconnect_pt    next_disconnect;


/* Note: an ngx_str_t version of ngx_rtmp_connect_t */
typedef struct {
    ngx_str_t  app;
    ngx_str_t  args;
    ngx_str_t  flashver;
    ngx_str_t  swf_url;
    ngx_str_t  tc_url;
    ngx_str_t  page_url;
} ngx_rtmp_kmp_connect_t;

#include "ngx_rtmp_kmp_json.h"


static char *ngx_rtmp_kmp_url_slot(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_kmp_headers_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_rtmp_kmp_postconfiguration(ngx_conf_t *cf);
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

    { ngx_string("kmp_ctrl_connect_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_kmp_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, ctrl_connect_url),
      NULL },

    { ngx_string("kmp_ctrl_publish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_kmp_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_publish_url),
      NULL },

    { ngx_string("kmp_ctrl_unpublish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_kmp_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_unpublish_url),
      NULL },

    { ngx_string("kmp_ctrl_republish_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_kmp_url_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.ctrl_republish_url),
      NULL },

    { ngx_string("kmp_ctrl_add_header"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
      ngx_rtmp_kmp_headers_add,
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
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF| NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.max_free_buffers),
      NULL },

    { ngx_string("kmp_video_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.video_buffer_size),
      NULL },

    { ngx_string("kmp_video_mem_limit"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.video_mem_limit),
      NULL },

    { ngx_string("kmp_audio_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.audio_buffer_size),
      NULL },

    { ngx_string("kmp_audio_mem_limit"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.audio_mem_limit),
      NULL },

    { ngx_string("kmp_flush_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_kmp_app_conf_t, t.flush_timeout),
      NULL },

    { ngx_string("kmp_republish_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
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
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
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


enum {
    CONNECT_JSON_CODE,
    CONNECT_JSON_MESSAGE,
    CONNECT_JSON_PARAM_COUNT
};

static ngx_json_object_key_def_t connect_json_params[] = {
    { ngx_string("code"),       NGX_JSON_STRING,    CONNECT_JSON_CODE },
    { ngx_string("message"),    NGX_JSON_STRING,    CONNECT_JSON_MESSAGE },
    { ngx_null_string, 0, 0 }
};


static ngx_str_t  ngx_rtmp_kmp_code_ok = ngx_string("ok");


static ngx_url_t *
ngx_rtmp_kmp_parse_url(ngx_conf_t *cf, ngx_str_t *url)
{
    size_t      add;
    ngx_url_t  *u;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    add = 0;
    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }

    return u;
}

static char *
ngx_rtmp_kmp_url_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t   *value;
    ngx_url_t  **u;

    u = (ngx_url_t **) (p + cmd->offset);
    if (*u != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *u = ngx_rtmp_kmp_parse_url(cf, &value[1]);
    if (*u == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_kmp_headers_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t      *value;
    ngx_array_t   **headers;
    ngx_keyval_t   *kv;

    value = cf->args->elts;

    headers = (ngx_array_t **) ((char *) conf + cmd->offset);

    if (*headers == NULL) {
        *headers = ngx_array_create(cf->pool, 1, sizeof(ngx_keyval_t));
        if (*headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    kv = ngx_array_push(*headers);
    if (kv == NULL) {
        return NGX_CONF_ERROR;
    }

    kv->key = value[1];
    kv->value = value[2];

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

    ngx_kmp_push_track_init_conf(&kacf->t);

    return kacf;
}


static char *
ngx_rtmp_kmp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_kmp_app_conf_t  *prev = parent;
    ngx_rtmp_kmp_app_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->ctrl_connect_url,
                             prev->ctrl_connect_url, NULL);

    ngx_kmp_push_track_merge_conf(&conf->t, &prev->t);

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
    ngx_str_from_c(kp->name, v->name);
    ngx_str_from_c(kp->args, v->args);
    ngx_str_from_c(kp->type, v->type);
}

static void
ngx_rtmp_kmp_get_connect_info(ngx_rtmp_kmp_connect_t *kc,
    ngx_rtmp_connect_t *v)
{
    ngx_str_from_c(kc->app, v->app);
    ngx_str_from_c(kc->args, v->args);
    ngx_str_from_c(kc->flashver, v->flashver);
    ngx_str_from_c(kc->swf_url, v->swf_url);
    ngx_str_from_c(kc->tc_url, v->tc_url);
    ngx_str_from_c(kc->page_url, v->page_url);
}


static ngx_int_t
ngx_rtmp_kmp_send_error(ngx_rtmp_session_t *s, double in_trans)
{
    static double               trans;

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
    ngx_int_t  rc;

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

    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
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
    return ngx_kmp_push_format_json_http_request(pool,
        &kacf->ctrl_connect_url->host, &kacf->ctrl_connect_url->uri,
        kacf->t.ctrl_headers, cl);
}

static ngx_int_t
ngx_rtmp_kmp_connect_handle(ngx_pool_t *temp_pool, void *arg, ngx_uint_t code,
    ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_log_t                        *log;
    ngx_str_t                         desc;
    ngx_str_t                         code_str;
    ngx_json_value_t                  json;
    ngx_json_value_t                 *values[CONNECT_JSON_PARAM_COUNT];
    ngx_rtmp_session_t               *s;
    ngx_rtmp_kmp_connect_call_ctx_t  *ctx;

    ctx = arg;
    s = ctx->s;

    log = s->connection->log;

    if (ngx_kmp_push_parse_json_response(temp_pool, log,
        code, content_type, body, &json) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_rtmp_kmp_connect_handle: parse response failed");
        goto retry;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&json.v.obj, connect_json_params, values);

    if (values[CONNECT_JSON_CODE] == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_connect_handle: missing \"code\" element in json");
        goto retry;
    }

    code_str = values[CONNECT_JSON_CODE]->v.str;
    if (code_str.len != ngx_rtmp_kmp_code_ok.len ||
        ngx_strncasecmp(code_str.data, ngx_rtmp_kmp_code_ok.data,
            ngx_rtmp_kmp_code_ok.len) != 0) {

        if (values[CONNECT_JSON_MESSAGE] != NULL) {
            desc = values[CONNECT_JSON_MESSAGE]->v.str;
            desc.data[desc.len] = '\0';

        } else {
            desc.len = 0;
            desc.data = NULL;
        }

        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_connect_handle: "
            "bad code \"%V\" in json, message=\"%V\"", &code_str, &desc);

        goto error;
    }

    if (next_connect(s, &ctx->connect) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_rtmp_kmp_connect_handle: next connect failed");
        ngx_rtmp_finalize_session(s);
    }

    return NGX_OK;

retry:

    if (ctx->retries_left > 0) {
        ctx->retries_left--;
        return NGX_AGAIN;
    }

    desc.data = (u_char *) "Internal server error";

error:

    if (ngx_rtmp_kmp_connect_error(s, &ctx->connect, desc.data) != NGX_OK) {
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
    ngx_rtmp_kmp_ctx_t               *ctx;
    ngx_http_call_init_t              ci;
    ngx_rtmp_kmp_app_conf_t          *kacf;
    ngx_rtmp_kmp_connect_call_ctx_t   create_ctx;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "ngx_rtmp_kmp_connect: failed to get app conf");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(*ctx));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                "ngx_rtmp_kmp_connect: alloc failed");
            return NGX_ERROR;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_kmp_module);

        ctx->s = s;

        /* get the address name with port */
        ctx->remote_addr.data = ctx->remote_addr_buf;
        ctx->remote_addr.len = ngx_sock_ntop(s->connection->sockaddr,
            s->connection->socklen, ctx->remote_addr_buf,
            NGX_SOCKADDR_STRLEN, 1);
        if (ctx->remote_addr.len == 0) {
            ctx->remote_addr = s->connection->addr_text;
        }

        ngx_queue_insert_tail(&kacf->sessions, &ctx->queue);
    }

    url = kacf->ctrl_connect_url;
    if (url == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, s->connection->log, 0,
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
    ci.handler_pool = s->connection->pool;
    ci.arg = &create_ctx;
    ci.argsize = sizeof(create_ctx);
    ci.timeout = kacf->t.ctrl_timeout;
    ci.read_timeout = kacf->t.ctrl_read_timeout;
    ci.buffer_size = kacf->t.ctrl_buffer_size;
    ci.retry_interval = kacf->t.ctrl_retry_interval;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "ngx_rtmp_kmp_connect: sending connect request to \"%V\"", &url->url);

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_kmp_connect: http call to \"%V\" failed",
            &url->url);
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
        ngx_queue_remove(&ctx->queue);
        ngx_rtmp_delete_ctx(s, ngx_rtmp_kmp_module);
    }

    return next_disconnect(s);
}

static ngx_int_t
ngx_rtmp_kmp_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_kmp_app_conf_t    *kacf;
    ngx_rtmp_kmp_stream_ctx_t  *ctx;

    if (s->auto_pushed || s->relay) {
        goto next;
    }

    kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "ngx_rtmp_kmp_publish: failed to get app conf");
        return NGX_ERROR;
    }

    if (kacf->t.ctrl_publish_url == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, s->connection->log, 0,
            "ngx_rtmp_kmp_publish: no publish url set in conf");
        goto next;
    }

    if (!s->in_stream) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "ngx_rtmp_kmp_publish: no stream context");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(*ctx));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                "ngx_rtmp_kmp_publish: alloc failed");
            return NGX_ERROR;
        }

        ngx_rtmp_stream_set_ctx(s, ctx, ngx_rtmp_kmp_module);
    }

    ctx->publish_buf = *v;
    ngx_rtmp_kmp_get_publish_info(&ctx->publish, &ctx->publish_buf);

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "ngx_rtmp_kmp_publish: called, name: %V, args: %V, type: %V",
        &ctx->publish.name, &ctx->publish.args, &ctx->publish.type);

next:
    return next_publish(s, v);
}

static void
ngx_rtmp_kmp_detach_tracks(ngx_rtmp_kmp_stream_ctx_t *ctx, char *reason)
{
    ngx_uint_t             media_type;
    ngx_kmp_push_track_t  *track;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        track = ctx->tracks[media_type];
        if (track == NULL) {
            continue;
        }

        ctx->tracks[media_type] = NULL;

        ngx_kmp_push_track_detach(track, reason);
    }
}

static ngx_int_t
ngx_rtmp_kmp_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_kmp_stream_ctx_t  *ctx;

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "ngx_rtmp_kmp_close_stream: called, name: %V, args: %V, type: %V",
        &ctx->publish.name, &ctx->publish.args, &ctx->publish.type);

    ngx_memzero(&ctx->publish, sizeof(ctx->publish));

    ngx_rtmp_kmp_detach_tracks(ctx, v->disconnect ? "rtmp_disconnect" :
        "rtmp_close");

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_kmp_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_uint_t                        media_type;
    ngx_kmp_push_track_t             *track;
    ngx_rtmp_kmp_app_conf_t          *kacf;
    ngx_rtmp_kmp_stream_ctx_t        *ctx;

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_kmp_module);
    if (ctx == NULL) {
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

    /* get track */
    track = ctx->tracks[media_type];
    if (track == NULL) {

        kacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_kmp_module);
        if (kacf == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "ngx_rtmp_kmp_av: failed to get app conf");
            return NGX_ERROR;
        }

        track = ngx_rtmp_kmp_track_create(&kacf->t, s, &ctx->publish, h, in);
        if (track == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                "ngx_rtmp_kmp_av: failed to create track");
            return NGX_ERROR;
        }

        ctx->tracks[media_type] = track;
        return NGX_OK;
    }

    /* forward to track */
    return ngx_rtmp_kmp_track_av(track, h, in, 0);
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

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_kmp_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_kmp_av;

    return NGX_OK;
}
