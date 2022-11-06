#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <ngx_http_api.h>
#include <ngx_json_str.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_version.h>

#include "ngx_rtmp_kmp_version.h"
#include "ngx_rtmp_kmp_api.h"


static ngx_int_t ngx_http_rtmp_kmp_api_postconfiguration(ngx_conf_t *cf);

static char *ngx_http_rtmp_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_json_str_t  ngx_http_rtmp_kmp_version =
    ngx_json_string(NGX_RTMP_KMP_VERSION);
static ngx_json_str_t  ngx_http_rtmp_kmp_nginx_version =
    ngx_json_string(NGINX_VERSION);
static ngx_json_str_t  ngx_http_rtmp_kmp_rtmp_version =
    ngx_json_string(NGINX_RTMP_VERSION);
static ngx_json_str_t  ngx_http_rtmp_kmp_compiler =
    ngx_json_string(NGX_COMPILER);
static ngx_json_str_t  ngx_http_rtmp_kmp_built =
    ngx_json_string(__DATE__ " " __TIME__);

static time_t     ngx_http_rtmp_kmp_start_time = 0;


#include "ngx_http_rtmp_kmp_api_json.h"


static ngx_command_t  ngx_http_rtmp_kmp_api_commands[] = {

    { ngx_string("rtmp_kmp_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_http_rtmp_kmp_api,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_rtmp_kmp_api_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_rtmp_kmp_api_postconfiguration,/* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t ngx_http_rtmp_kmp_api_module = {
    NGX_MODULE_V1,
    &ngx_http_rtmp_kmp_api_module_ctx,      /* module context */
    ngx_http_rtmp_kmp_api_commands,         /* module directives */
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


static ngx_int_t
ngx_http_rtmp_kmp_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        ngx_http_rtmp_kmp_api_json_get_size,
        ngx_http_rtmp_kmp_api_json_write,
    };

    return ngx_http_api_build_json(r, &writer, NULL, response);
}


static ngx_int_t
ngx_http_rtmp_kmp_api_session_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t  rc;
    ngx_int_t  connection;

    connection = ngx_atoi(params[0].data, params[0].len);
    if (connection == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_rtmp_kmp_api_session_delete: "
            "failed to parse connection num \"%V\"", &params[0]);
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_rtmp_kmp_api_finalize_session(connection, r->connection->log);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DECLINED:
        return NGX_HTTP_NOT_FOUND;

    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


#include "ngx_http_rtmp_kmp_api_routes.h"


static ngx_int_t
ngx_http_rtmp_kmp_api_handler(ngx_http_request_t *r)
{
    return ngx_http_api_handler(r, &ngx_http_rtmp_kmp_api_route);
}


static ngx_int_t
ngx_http_rtmp_kmp_api_ro_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_GET) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    return ngx_http_rtmp_kmp_api_handler(r);
}


static char *
ngx_http_rtmp_kmp_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
    clcf->handler = options.write ? ngx_http_rtmp_kmp_api_handler :
        ngx_http_rtmp_kmp_api_ro_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_rtmp_kmp_api_postconfiguration(ngx_conf_t *cf)
{
    ngx_json_str_set_escape(&ngx_http_rtmp_kmp_version);
    ngx_json_str_set_escape(&ngx_http_rtmp_kmp_nginx_version);
    ngx_json_str_set_escape(&ngx_http_rtmp_kmp_rtmp_version);
    ngx_json_str_set_escape(&ngx_http_rtmp_kmp_compiler);
    ngx_json_str_set_escape(&ngx_http_rtmp_kmp_built);

    ngx_http_rtmp_kmp_start_time = ngx_cached_time->sec;

    return NGX_OK;
}
