#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_json_parser.h>
#include <ngx_mem_rstream.h>
#include "ngx_pckg_ksmp.h"
#include "ngx_http_pckg_utils.h"

#include "ngx_http_pckg_captions_json.h"


typedef struct {
    ngx_http_complex_value_t  *json;
} ngx_http_pckg_captions_loc_conf_t;


static void *ngx_http_pckg_captions_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_captions_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_pckg_captions_commands[] = {

    { ngx_string("pckg_captions_json"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_zero_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_captions_loc_conf_t, json),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_captions_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_pckg_captions_create_loc_conf, /* create location configuration */
    ngx_http_pckg_captions_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_captions_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_captions_module_ctx,     /* module context */
    ngx_http_pckg_captions_commands,        /* module directives */
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


static ngx_flag_t
ngx_http_pckg_captions_is_service_id_valid(ngx_str_t *id)
{
    u_char  *p;

    switch (id->len) {

    case 3:
        /* cc1 - cc4 */
        p = id->data;
        return p[0] == 'c' && p[1] == 'c' && p[2] >= '1' && p[2] <= '4';

    case 8:
    case 9:
        /* service1 - service63 */
        p = id->data;
        if (ngx_strncmp(p, "service", 7) != 0) {
            return 0;
        }

        p += 7;

        if (id->len == 8) {                     /* 1 - 9 */
            return p[0] >= '1' && p[0] <= '9';
        }

        if (p[0] >= '1' && p[0] <= '5') {       /* 10 - 59 */
            return p[1] >= '0' && p[1] <= '9';
        }

        if (p[0] == '6') {                      /* 60 - 63 */
            return p[1] >= '0' && p[1] <= '3';
        }

        break;
    }

    return 0;
}


static ngx_int_t
ngx_http_pckg_captions_service_json_parse(ngx_http_request_t *r,
    ngx_pckg_captions_service_t *cs, ngx_json_object_t *obj)
{
    ngx_http_pckg_captions_service_json_t  json;

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, obj,
            ngx_http_pckg_captions_service_json,
            ngx_array_entries(ngx_http_pckg_captions_service_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_captions_service_json_parse: parse failed");
        return NGX_BAD_DATA;
    }

    if (json.label.data == NGX_JSON_UNSET_PTR || json.label.len <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_captions_service_json_parse: missing label");
        return NGX_BAD_DATA;
    }

    cs->label = json.label;
    if (json.lang.data != NGX_JSON_UNSET_PTR) {
        cs->lang = json.lang;

    } else {
        ngx_str_null(&cs->lang);
    }

    cs->is_default = json.is_default != NGX_JSON_UNSET && json.is_default;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_captions_json_parse(ngx_http_request_t *r,
    ngx_json_value_t *value)
{
    ngx_int_t                     rc;
    ngx_array_t                   css;
    ngx_json_object_t            *obj;
    ngx_json_key_value_t         *cur;
    ngx_json_key_value_t         *last;
    ngx_http_pckg_core_ctx_t     *ctx;
    ngx_pckg_captions_service_t  *cs;

    if (value->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_captions_json_parse: "
            "invalid element type %d, expected object", value->type);
        return NGX_BAD_DATA;
    }

    if (ngx_array_init(&css, r->pool, value->v.obj.nelts, sizeof(*cs))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_captions_json_parse: array init failed");
        return NGX_ERROR;
    }

    obj = &value->v.obj;

    cur = obj->elts;
    last = cur + obj->nelts;
    for (; cur < last; cur++) {

        if (!ngx_http_pckg_captions_is_service_id_valid(&cur->key)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_captions_json_parse: "
                "invalid key \"%V\"", &cur->key);
            return NGX_BAD_DATA;
        }

        if (cur->value.type != NGX_JSON_OBJECT) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_captions_json_parse: "
                "invalid value type for key \"%V\"", &cur->key);
            return NGX_BAD_DATA;
        }

        cs = ngx_array_push(&css);
        if (cs == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_captions_json_parse: push failed");
            return NGX_ERROR;
        }

        cs->id = cur->key;

        rc = ngx_http_pckg_captions_service_json_parse(r, cs,
            &cur->value.v.obj);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    ctx->channel->css = css;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_captions_init(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_str_t                           str;
    ngx_json_value_t                    json;
    ngx_http_pckg_captions_loc_conf_t  *clcf;
    u_char                              error[128];

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_captions_module);
    if (clcf->json == NULL) {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, clcf->json, &str) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_captions_init: complex value failed");
        return NGX_ERROR;
    }

    if (str.data[0] == '\0') {
        return NGX_OK;
    }

    rc =  ngx_json_parse(r->pool, str.data, &json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_captions_init: ngx_json_parse failed %i, %s",
            rc, error);
        return rc == NGX_JSON_BAD_DATA ? NGX_BAD_DATA : NGX_ERROR;
    }

    rc = ngx_http_pckg_captions_json_parse(r, &json);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static void *
ngx_http_pckg_captions_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_captions_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_captions_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->json = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_pckg_captions_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_pckg_captions_loc_conf_t  *prev = parent;
    ngx_http_pckg_captions_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->json, prev->json, NULL);

    return NGX_CONF_OK;
}
