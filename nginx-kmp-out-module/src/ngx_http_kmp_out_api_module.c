#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <ngx_http_api.h>
#include <ngx_json_str.h>

#include "ngx_kmp_out_track.h"
#include "ngx_kmp_out_version.h"


static ngx_int_t ngx_http_kmp_out_api_postconfiguration(ngx_conf_t *cf);

static char *ngx_http_kmp_out_api(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_json_str_t  ngx_kmp_out_version =
    ngx_json_string(NGX_KMP_OUT_VERSION);
static ngx_json_str_t  ngx_kmp_out_nginx_version =
    ngx_json_string(NGINX_VERSION);
static ngx_json_str_t  ngx_kmp_out_compiler =
    ngx_json_string(NGX_COMPILER);
static ngx_json_str_t  ngx_kmp_out_built =
    ngx_json_string(__DATE__ " " __TIME__);

static time_t          ngx_kmp_out_start_time = 0;


#include "ngx_http_kmp_out_api_json.h"


static ngx_command_t  ngx_http_kmp_out_api_commands[] = {

    { ngx_string("kmp_out_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_http_kmp_out_api,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_kmp_out_api_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_kmp_out_api_postconfiguration, /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t ngx_http_kmp_out_api_module = {
    NGX_MODULE_V1,
    &ngx_http_kmp_out_api_module_ctx,       /* module context */
    ngx_http_kmp_out_api_commands,          /* module directives */
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
ngx_http_kmp_out_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        ngx_http_kmp_out_api_json_get_size,
        ngx_http_kmp_out_api_json_write,
    };

    return ngx_http_api_build_json(r, &writer, NULL, response);
}


static ngx_int_t
ngx_http_kmp_out_api_tracks_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        ngx_kmp_out_tracks_json_get_size,
        ngx_kmp_out_tracks_json_write,
    };

    return ngx_http_api_build_json(r, &writer, NULL, response);
}


static ngx_int_t
ngx_http_kmp_out_api_tracks_list(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        ngx_kmp_out_track_ids_json_get_size,
        ngx_kmp_out_track_ids_json_write,
    };

    return ngx_http_api_build_json(r, &writer, NULL, response);
}


static ngx_int_t
ngx_http_kmp_out_api_track_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        (ngx_http_api_json_writer_get_size_pt) ngx_kmp_out_track_json_get_size,
        (ngx_http_api_json_writer_write_pt) ngx_kmp_out_track_json_write,
    };

    ngx_str_t             id;
    ngx_kmp_out_track_t  *track;

    id = params[0];
    track = ngx_kmp_out_track_get(&id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_kmp_out_api_track_get: unknown track \"%V\"", &id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_api_build_json(r, &writer, track, response);
}


static ngx_int_t
ngx_http_kmp_out_api_upstreams_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        (ngx_http_api_json_writer_get_size_pt)
            ngx_kmp_out_track_upstreams_json_get_size,
        (ngx_http_api_json_writer_write_pt)
            ngx_kmp_out_track_upstreams_json_write,
    };

    ngx_str_t             id;
    ngx_kmp_out_track_t  *track;

    id = params[0];
    track = ngx_kmp_out_track_get(&id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_kmp_out_api_upstreams_get: unknown track \"%V\"", &id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_api_build_json(r, &writer, track, response);
}


static ngx_int_t
ngx_http_kmp_out_api_upstreams_list(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_http_api_json_writer_t  writer = {
        (ngx_http_api_json_writer_get_size_pt)
            ngx_kmp_out_track_upstream_ids_json_get_size,
        (ngx_http_api_json_writer_write_pt)
            ngx_kmp_out_track_upstream_ids_json_write,
    };

    ngx_str_t             id;
    ngx_kmp_out_track_t  *track;

    id = params[0];
    track = ngx_kmp_out_track_get(&id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_kmp_out_api_upstreams_list: unknown track \"%V\"", &id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_api_build_json(r, &writer, track, response);
}


static ngx_int_t
ngx_http_kmp_out_api_upstreams_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                              rc;
    ngx_str_t                              id;
    ngx_str_t                             *src_id;
    ngx_json_object_t                     *obj;
    ngx_kmp_out_track_t                   *track;
    ngx_http_kmp_out_api_upstream_json_t   json;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_kmp_out_api_upstreams_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    id = params[0];
    track = ngx_kmp_out_track_get(&id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_kmp_out_api_upstreams_post: unknown track \"%V\"", &id);
        return NGX_HTTP_NOT_FOUND;
    }

    obj = &body->v.obj;

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, obj, ngx_http_kmp_out_api_upstream_json,
        ngx_array_entries(ngx_http_kmp_out_api_upstream_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_kmp_out_api_upstreams_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    src_id = json.src_id.data != NGX_JSON_UNSET_PTR ? &json.src_id : NULL;

    rc = ngx_kmp_out_track_add_upstream(r->pool, track, src_id, obj);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DECLINED:
        return NGX_HTTP_NOT_FOUND;

    case NGX_ERROR:
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;

    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_kmp_out_api_upstream_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t             rc;
    ngx_str_t             id;
    ngx_str_t             upstream_id;
    ngx_log_t            *log;
    ngx_kmp_out_track_t  *track;

    log = r->connection->log;

    id = params[0];
    track = ngx_kmp_out_track_get(&id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_kmp_out_api_upstream_delete: unknown track \"%V\"", &id);
        return NGX_HTTP_NOT_FOUND;
    }

    upstream_id = params[1];

    rc = ngx_kmp_out_track_del_upstream(track, &upstream_id, log);
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


#include "ngx_http_kmp_out_api_routes.h"


static ngx_int_t
ngx_http_kmp_out_api_handler(ngx_http_request_t *r)
{
    return ngx_http_api_handler(r, &ngx_http_kmp_out_api_route);
}


static ngx_int_t
ngx_http_kmp_out_api_ro_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_GET) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    return ngx_http_kmp_out_api_handler(r);
}


static char *
ngx_http_kmp_out_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
    clcf->handler = options.write ? ngx_http_kmp_out_api_handler :
        ngx_http_kmp_out_api_ro_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_kmp_out_api_postconfiguration(ngx_conf_t *cf)
{
    ngx_json_str_set_escape(&ngx_kmp_out_version);
    ngx_json_str_set_escape(&ngx_kmp_out_nginx_version);
    ngx_json_str_set_escape(&ngx_kmp_out_compiler);
    ngx_json_str_set_escape(&ngx_kmp_out_built);

    ngx_kmp_out_start_time = ngx_cached_time->sec;

    return NGX_OK;
}
