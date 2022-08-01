#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_json_parser.h>
#include <ngx_mem_rstream.h>
#include "ngx_pckg_ksmp.h"
#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_data.h"

#include "ngx_http_pckg_data_json.h"


typedef struct {
    ngx_http_complex_value_t  *json;
} ngx_http_pckg_data_loc_conf_t;


static void *ngx_http_pckg_data_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_data_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_http_pckg_data_commands[] = {

    { ngx_string("pckg_session_data_json"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_zero_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_data_loc_conf_t, json),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_data_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_pckg_data_create_loc_conf,     /* create location configuration */
    ngx_http_pckg_data_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_data_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_data_module_ctx,         /* module context */
    ngx_http_pckg_data_commands,            /* module directives */
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
ngx_http_pckg_data_value_json_parse(ngx_http_request_t *r,
    ngx_pckg_data_value_t *dv, ngx_json_object_t *obj)
{
    ngx_flag_t                       has_uri;
    ngx_flag_t                       has_value;
    ngx_http_pckg_data_value_json_t  json;

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, obj, ngx_http_pckg_data_value_json,
            ngx_array_entries(ngx_http_pckg_data_value_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_data_value_json_parse: parse failed");
        return NGX_BAD_DATA;
    }

    if (json.id.data == NGX_JSON_UNSET_PTR || json.id.len <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_value_json_parse: missing id");
        return NGX_BAD_DATA;
    }

    has_value = json.value.data != NGX_JSON_UNSET_PTR && json.value.len > 0;
    has_uri = json.uri.data != NGX_JSON_UNSET_PTR && json.uri.len > 0;

    if (!has_value && !has_uri) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_value_json_parse: "
            "must contain either value or uri, id: \"%V\"", &json.id);
        return NGX_BAD_DATA;
    }

    if (has_value && has_uri) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_value_json_parse: "
            "must not contain both value and uri, id: \"%V\"", &json.id);
        return NGX_BAD_DATA;
    }

    dv->id = json.id;
    if (has_value) {
        dv->value = json.value;

    } else {
        dv->uri = json.uri;
    }

    if (json.lang.data != NGX_JSON_UNSET_PTR) {
        dv->lang = json.lang;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_data_json_parse(ngx_http_request_t *r, ngx_json_value_t *value,
    ngx_array_t *out)
{
    ngx_int_t               rc;
    ngx_array_t             dvs;
    ngx_json_array_t       *arr;
    ngx_array_part_t       *part;
    ngx_json_object_t      *cur;
    ngx_json_object_t      *last;
    ngx_pckg_data_value_t  *dv;

    if (value->type != NGX_JSON_ARRAY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_json_parse: "
            "invalid element type %d, expected array", value->type);
        return NGX_BAD_DATA;
    }

    arr = &value->v.arr;

    if (arr->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_json_parse: "
            "invalid array element type %d, expected object", arr->type);
        return NGX_BAD_DATA;
    }

    if (ngx_array_init(&dvs, r->pool, arr->count, sizeof(*dv)) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_data_json_parse: array init failed");
        return NGX_ERROR;
    }

    part = &arr->part;
    cur = part->first;
    last = part->last;

    for ( ;; ) {

        if (cur >= last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->first;
            last = part->last;
        }

        dv = ngx_array_push(&dvs);
        if (dv == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_data_json_parse: push failed");
            return NGX_ERROR;
        }

        ngx_memzero(dv, sizeof(*dv));

        rc = ngx_http_pckg_data_value_json_parse(r, dv, cur);
        if (rc != NGX_OK) {
            return rc;
        }

        cur++;
    }

    *out = dvs;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_data_init(ngx_http_request_t *r, ngx_array_t *dvs)
{
    ngx_int_t                       rc;
    ngx_str_t                       str;
    ngx_json_value_t                json;
    ngx_http_pckg_data_loc_conf_t  *clcf;
    u_char                          error[128];

    ngx_memzero(dvs, sizeof(*dvs));

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_data_module);
    if (clcf->json == NULL) {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, clcf->json, &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_data_init: complex value failed");
        return NGX_ERROR;
    }

    if (str.data[0] == '\0') {
        return NGX_OK;
    }

    rc =  ngx_json_parse(r->pool, str.data, &json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_data_init: ngx_json_parse failed %i, %s",
            rc, error);
        return rc == NGX_JSON_BAD_DATA ? NGX_BAD_DATA : NGX_ERROR;
    }

    rc = ngx_http_pckg_data_json_parse(r, &json, dvs);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static void *
ngx_http_pckg_data_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_data_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_data_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->json = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_pckg_data_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_data_loc_conf_t  *prev = parent;
    ngx_http_pckg_data_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->json, prev->json, NULL);

    return NGX_CONF_OK;
}
