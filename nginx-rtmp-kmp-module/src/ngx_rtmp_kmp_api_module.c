#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_version.h>
#include <ngx_http_api.h>
#include "ngx_rtmp_kmp_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_kmp_out_track.h"
#include "ngx_kmp_out_upstream.h"
#include "ngx_rtmp_kmp_version.h"

/* routes */
static ngx_int_t ngx_rtmp_kmp_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response);

static ngx_int_t ngx_rtmp_kmp_api_session_delete(ngx_http_request_t *r,
    ngx_str_t *params, ngx_str_t *response);

#include "ngx_rtmp_kmp_api_routes.h"

/* json */
static size_t ngx_rtmp_kmp_api_streams_json_get_size(ngx_rtmp_session_t *s);
static u_char *ngx_rtmp_kmp_api_streams_json_write(u_char *p,
    ngx_rtmp_session_t *s);

static size_t ngx_rtmp_kmp_api_tracks_json_get_size(
    ngx_kmp_out_track_t **tracks);
static u_char *ngx_rtmp_kmp_api_tracks_json_write(u_char *p,
    ngx_kmp_out_track_t **tracks);

static ngx_str_t  ngx_rtmp_kmp_version = ngx_string(NGX_RTMP_KMP_VERSION);
static ngx_str_t  ngx_rtmp_kmp_nginx_version = ngx_string(NGINX_VERSION);
static ngx_str_t  ngx_rtmp_kmp_rtmp_version = ngx_string(NGINX_RTMP_VERSION);
static ngx_str_t  ngx_rtmp_kmp_compiler = ngx_string(NGX_COMPILER);
static ngx_str_t  ngx_rtmp_kmp_built = ngx_string(__DATE__ " " __TIME__);
static time_t     ngx_rtmp_kmp_start_time = 0;

/* must match NGX_RTMP_TYPE3_EXT_TS_XXX */
ngx_str_t  ngx_rtmp_type3_ext_ts_str[] = {
    ngx_string("off"),
    ngx_string("on"),
    ngx_string("unknown"),
    ngx_null_string
};

#include "ngx_rtmp_kmp_api_json.h"

/* module */
static ngx_int_t ngx_rtmp_kmp_api_postconfiguration(ngx_conf_t *cf);

static char *ngx_rtmp_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_rtmp_kmp_api_commands[] = {

    { ngx_string("rtmp_kmp_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_rtmp_kmp_api,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_rtmp_kmp_api_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_rtmp_kmp_api_postconfiguration, /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};


ngx_module_t ngx_rtmp_kmp_api_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_kmp_api_module_ctx,       /* module context */
    ngx_rtmp_kmp_api_commands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static size_t
ngx_rtmp_kmp_api_streams_json_get_size(ngx_rtmp_session_t *s)
{
    size_t                      result = 0;
    ngx_int_t                   i;
    ngx_rtmp_stream_t          *in_stream;
    ngx_rtmp_live_ctx_t        *live_ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_kmp_stream_ctx_t  *kmp_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cscf->max_streams; i++) {

        in_stream = &s->in_streams[i];
        if (in_stream->ctx == NULL) {
            continue;
        }

        kmp_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_kmp_module);
        if (kmp_ctx == NULL) {
            continue;
        }

        live_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_live_module);
        if (live_ctx == NULL || live_ctx->stream == NULL) {
            continue;
        }

        result += ngx_rtmp_kmp_api_stream_json_get_size(kmp_ctx,
            live_ctx->stream) + 1;
    }

    return result;
}


static u_char *
ngx_rtmp_kmp_api_streams_json_write(u_char *p, ngx_rtmp_session_t *s)
{
    u_char                     *start = p;
    ngx_int_t                   i;
    ngx_rtmp_stream_t          *in_stream;
    ngx_rtmp_live_ctx_t        *live_ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_kmp_stream_ctx_t  *kmp_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cscf->max_streams; i++) {

        in_stream = &s->in_streams[i];
        if (in_stream->ctx == NULL) {
            continue;
        }

        kmp_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_kmp_module);
        if (kmp_ctx == NULL) {
            continue;
        }

        live_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_live_module);
        if (live_ctx == NULL || live_ctx->stream == NULL) {
            continue;
        }

        if (p > start) {
            *p++ = ',';
        }

        p = ngx_rtmp_kmp_api_stream_json_write(p, kmp_ctx, live_ctx->stream);
    }

    return p;
}


static size_t
ngx_rtmp_kmp_api_tracks_json_get_size(ngx_kmp_out_track_t **tracks)
{
    size_t                result = 0;
    ngx_kmp_out_track_t  *track;

    track = tracks[KMP_MEDIA_VIDEO];
    if (track != NULL) {
        result += sizeof("\"video\":") - 1;
        result += ngx_kmp_out_track_json_get_size(track);
    }

    track = tracks[KMP_MEDIA_AUDIO];
    if (track != NULL) {
        result++;      /* ',' */

        result += sizeof("\"audio\":") - 1;
        result += ngx_kmp_out_track_json_get_size(track);
    }

    return result;
}


static u_char *
ngx_rtmp_kmp_api_tracks_json_write(u_char *p, ngx_kmp_out_track_t **tracks)
{
    u_char               *start = p;
    ngx_kmp_out_track_t  *track;

    track = tracks[KMP_MEDIA_VIDEO];
    if (track != NULL) {
        p = ngx_copy_fix(p, "\"video\":");
        p = ngx_kmp_out_track_json_write(p, track);
    }

    track = tracks[KMP_MEDIA_AUDIO];
    if (track != NULL) {
        if (p > start) {
            *p++ = ',';
        }

        p = ngx_copy_fix(p, "\"audio\":");
        p = ngx_kmp_out_track_json_write(p, track);
    }

    return p;
}


static ngx_int_t
ngx_rtmp_kmp_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    u_char  *p;
    size_t   size;

    if (ngx_rtmp_core_main_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_rtmp_kmp_api_get: no rtmp main conf");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size = ngx_rtmp_kmp_api_json_get_size();

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_rtmp_kmp_api_get: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    response->data = p;
    p = ngx_rtmp_kmp_api_json_write(p);
    response->len = p - response->data;

    if (response->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_rtmp_kmp_api_get: "
            "result length %uz greater than allocated length %uz",
            response->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_application_get_session(ngx_uint_t connection,
    ngx_rtmp_core_app_conf_t *app_conf)
{
    ngx_queue_t              *q;
    ngx_rtmp_kmp_ctx_t       *cur;
    ngx_rtmp_kmp_app_conf_t  *kacf;

    kacf = ngx_rtmp_get_module_app_conf(app_conf, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        return 0;
    }

    for (q = ngx_queue_head(&kacf->sessions);
        q != ngx_queue_sentinel(&kacf->sessions);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_rtmp_kmp_ctx_t, queue);

        if (cur->s->connection->number == connection) {
            return cur->s;
        }
    }

    return NULL;

}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_server_get_session(ngx_uint_t connection,
    ngx_rtmp_core_srv_conf_t *srv_conf)
{
    ngx_uint_t                  n;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_app_conf_t  **cacfp;

    cacfp = srv_conf->applications.elts;
    for (n = 0; n < srv_conf->applications.nelts; n++) {
        s = ngx_rtmp_kmp_api_application_get_session(connection, cacfp[n]);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_get_session(ngx_uint_t connection)
{
    ngx_uint_t                   n;
    ngx_rtmp_session_t          *s;
    ngx_rtmp_core_srv_conf_t   **cscfp;
    ngx_rtmp_core_main_conf_t   *cmcf = ngx_rtmp_core_main_conf;

    if (cmcf == NULL) {
        return NULL;
    }

    cscfp = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; n++) {
        s = ngx_rtmp_kmp_api_server_get_session(connection, cscfp[n]);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_rtmp_kmp_api_session_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t            connection;
    ngx_rtmp_session_t  *s;

    connection = ngx_atoi(params[0].data, params[0].len);
    if (connection == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_rtmp_kmp_api_session_delete: "
            "failed to parse connection num \"%V\"", &params[0]);
        return NGX_HTTP_BAD_REQUEST;
    }

    s = ngx_rtmp_kmp_api_get_session((ngx_uint_t) connection);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_rtmp_kmp_api_session_delete: connection %ui not found",
            connection);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_rtmp_kmp_api_session_delete: dropping connection %ui",
        connection);
    ngx_rtmp_finalize_session(s);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_kmp_api_handler(ngx_http_request_t *r)
{
    return ngx_http_api_handler(r, &ngx_rtmp_kmp_api_route);
}


static ngx_int_t
ngx_rtmp_kmp_api_ro_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_GET) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    return ngx_rtmp_kmp_api_handler(r);
}


static char *
ngx_rtmp_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                      *rv;
    ngx_http_api_options_t     options;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_memzero(&options, sizeof(options));
    rv = ngx_http_api_parse_options(cf, &options);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = options.write ? ngx_rtmp_kmp_api_handler :
        ngx_rtmp_kmp_api_ro_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_kmp_api_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_kmp_start_time = ngx_cached_time->sec;

    return NGX_OK;
}
