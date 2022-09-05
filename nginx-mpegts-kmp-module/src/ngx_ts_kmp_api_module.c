#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_api.h>

#include <ngx_live_kmp.h>
#include <ngx_kmp_out_track.h>
#include <ngx_kmp_out_upstream.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_stream_ts_kmp_module.h"
#include "ngx_ts_kmp_version.h"
#include "ngx_ts_kmp_track.h"


/* routes */
static ngx_int_t ngx_ts_kmp_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response);

static ngx_int_t ngx_ts_kmp_api_session_delete(ngx_http_request_t *r,
    ngx_str_t *params, ngx_str_t *response);

#include "ngx_ts_kmp_api_routes.h"


static ngx_str_t  ngx_ts_kmp_version = ngx_string(NGX_MPEGTS_KMP_VERSION);
static ngx_str_t  ngx_ts_kmp_nginx_version = ngx_string(NGINX_VERSION);
static ngx_str_t  ngx_ts_kmp_compiler = ngx_string(NGX_COMPILER);
static ngx_str_t  ngx_ts_kmp_built = ngx_string(__DATE__ " " __TIME__);
static time_t     ngx_ts_kmp_start_time = 0;


#include "ngx_ts_kmp_api_json.h"


/* module */
static ngx_int_t ngx_ts_kmp_api_postconfiguration(ngx_conf_t *cf);

static char *ngx_ts_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_ts_kmp_api_commands[] = {

    { ngx_string("ts_kmp_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_ts_kmp_api,
      0,
      0,
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_ts_kmp_api_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_ts_kmp_api_postconfiguration,   /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};


ngx_module_t ngx_ts_kmp_api_module = {
    NGX_MODULE_V1,
    &ngx_ts_kmp_api_module_ctx,         /* module context */
    ngx_ts_kmp_api_commands,            /* module directives */
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


static ngx_stream_core_main_conf_t *
ngx_ts_kmp_api_get_stream_core_main_conf(ngx_log_t *log)
{
    ngx_stream_conf_ctx_t        *stream_ctx;
    ngx_stream_core_main_conf_t  *cmcf;

    stream_ctx = (ngx_stream_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
        ngx_stream_module);
    if (stream_ctx == NULL) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
            "ngx_ts_kmp_api_get_stream_core_main_conf: no stream conf");
        return NULL;
    }

    cmcf = ngx_stream_get_module_main_conf(stream_ctx, ngx_stream_core_module);
    if (cmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_kmp_api_get_stream_core_main_conf: "
            "no stream core main conf");
        return NULL;
    }

    return cmcf;
}


static ngx_int_t
ngx_ts_kmp_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    u_char                       *p;
    size_t                        size;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_ts_kmp_api_get_stream_core_main_conf(r->connection->log);
    if (cmcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size = ngx_ts_kmp_api_json_get_size(cmcf);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_ts_kmp_api_get: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    response->data = p;
    p = ngx_ts_kmp_api_json_write(p, cmcf);
    response->len = p - response->data;

    if (response->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_ts_kmp_api_get: "
            "result length %uz greater than allocated length %uz",
            response->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_stream_session_t *
ngx_ts_kmp_api_server_get_session(ngx_uint_t connection,
    ngx_ts_kmp_conf_t *tscf)
{
    ngx_queue_t       *q;
    ngx_ts_kmp_ctx_t  *cur;

    for (q = ngx_queue_head(&tscf->sessions);
        q != ngx_queue_sentinel(&tscf->sessions);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_ts_kmp_ctx_t, queue);

        if (cur->connection->number == connection) {
            return cur->connection->data;
        }
    }

    return NULL;
}


static ngx_stream_session_t *
ngx_ts_kmp_api_get_session(ngx_uint_t connection, ngx_log_t *log)
{
    ngx_uint_t                     n;
    ngx_ts_kmp_conf_t             *tscf;
    ngx_stream_session_t          *s;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_core_main_conf_t   *cmcf;

    cmcf = ngx_ts_kmp_api_get_stream_core_main_conf(log);
    if (cmcf == NULL) {
        return NULL;
    }

    cscfp = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; n++) {
        tscf = ngx_stream_ts_get_ts_kmp_conf(cscfp[n]->ctx);
        s = ngx_ts_kmp_api_server_get_session(connection, tscf);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_ts_kmp_api_session_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t              connection;
    ngx_stream_session_t  *s;

    connection = ngx_atoi(params[0].data, params[0].len);
    if (connection == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_ts_kmp_api_session_delete: "
            "failed to parse connection num \"%V\"", &params[0]);
        return NGX_HTTP_BAD_REQUEST;
    }

    s = ngx_ts_kmp_api_get_session((ngx_uint_t) connection, r->connection->log);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_ts_kmp_api_session_delete: connection %ui not found",
            connection);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_ts_kmp_api_session_delete: dropping connection %ui", connection);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_api_handler(ngx_http_request_t *r)
{
    return ngx_http_api_handler(r, &ngx_ts_kmp_api_route);
}


static ngx_int_t
ngx_ts_kmp_api_ro_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_GET) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    return ngx_ts_kmp_api_handler(r);
}


static char *
ngx_ts_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
    clcf->handler = options.write ? ngx_ts_kmp_api_handler :
        ngx_ts_kmp_api_ro_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_ts_kmp_api_postconfiguration(ngx_conf_t *cf)
{
    ngx_ts_kmp_start_time = ngx_cached_time->sec;

    return NGX_OK;
}
