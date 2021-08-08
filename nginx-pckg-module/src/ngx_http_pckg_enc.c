#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "ngx_http_pckg_enc.h"
#include "ngx_http_pckg_utils.h"


static ngx_int_t ngx_http_pckg_enc_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_enc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_enc_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_conf_enum_t  ngx_http_pckg_enc_schemes[] = {
    { ngx_string("none"),    NGX_HTTP_PCKG_ENC_NONE },
    { ngx_string("aes-128"), NGX_HTTP_PCKG_ENC_AES_128 },
    { ngx_string("cbcs"),    NGX_HTTP_PCKG_ENC_CBCS },
    { ngx_string("cenc"),    NGX_HTTP_PCKG_ENC_CENC },

    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_enc_commands[] = {

    { ngx_string("pckg_enc_scheme"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, scheme),
      &ngx_http_pckg_enc_schemes },

    { ngx_string("pckg_enc_key_seed"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, key_seed),
      NULL },

    { ngx_string("pckg_enc_iv_seed"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, iv_seed),
      NULL },

    { ngx_string("pckg_enc_serve_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, serve_key),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_enc_module_ctx = {
    ngx_http_pckg_enc_preconfiguration,     /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_pckg_enc_create_loc_conf,      /* create location configuration */
    ngx_http_pckg_enc_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_enc_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_enc_module_ctx,         /* module context */
    ngx_http_pckg_enc_commands,            /* module directives */
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


static ngx_str_t  ngx_http_pckg_enc_key_content_type =
    ngx_string("application/octet-stream");

/* some random salt to prevent the iv from being equal to key
    in case enc_iv_seed is not set */
static ngx_str_t  ngx_http_pckg_enc_iv_salt =
    ngx_string("\xa7\xc6\x17\xab\x52\x2c\x40\x3c\xf6\x8a");


ngx_str_t  ngx_http_pckg_enc_key_prefix = ngx_string("enc");
ngx_str_t  ngx_http_pckg_enc_key_ext = ngx_string(".key");


static ngx_int_t
ngx_http_pckg_enc_generate_key(ngx_http_request_t *r,
    ngx_http_complex_value_t *seed, ngx_str_t *salt, u_char *result)
{
    ngx_md5_t                  md5;
    ngx_str_t                  seed_str;
    ngx_http_pckg_core_ctx_t  *ctx;

    if (seed != NULL) {
        if (ngx_http_complex_value(r, seed, &seed_str) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_enc_generate_key: complex value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

        seed_str = ctx->channel->id;
    }

    ngx_md5_init(&md5);
    if (salt != NULL) {
        ngx_md5_update(&md5, salt->data, salt->len);
    }
    ngx_md5_update(&md5, seed_str.data, seed_str.len);
    ngx_md5_final(result, &md5);

    return NGX_OK;
}

ngx_int_t
ngx_http_pckg_enc_get_key(ngx_http_request_t *r, u_char *result)
{
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    return ngx_http_pckg_enc_generate_key(r, elcf->key_seed, NULL, result);
}

ngx_int_t
ngx_http_pckg_enc_get_iv(ngx_http_request_t *r, u_char *result)
{
    ngx_http_complex_value_t      *seed;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (elcf->iv_seed != NULL) {
        seed = elcf->iv_seed;

    } else {
        seed = elcf->key_seed;
    }

    return ngx_http_pckg_enc_generate_key(r, seed, &ngx_http_pckg_enc_iv_salt,
        result);
}


static ngx_int_t
ngx_http_pckg_handle_enc_key(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_str_t  response;

    response.len = AES_BLOCK_SIZE;
    response.data = ngx_palloc(r->pool, response.len);
    if (response.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_handle_enc_key: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_pckg_enc_get_key(r, response.data);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_enc_key_content_type, -1, NGX_HTTP_PCKG_EXPIRES_STATIC);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_enc_key_handler = {
    ngx_http_pckg_handle_enc_key,
    NULL,
};


static ngx_int_t
ngx_http_pckg_parse_key_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t                       flags;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
            ngx_http_pckg_enc_key_prefix)
        && elcf->serve_key && elcf->scheme != NGX_HTTP_PCKG_ENC_NONE)
    {
        start_pos += ngx_http_pckg_enc_key_prefix.len;

        *handler = &ngx_http_pckg_enc_key_handler;
        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

    } else {
        return NGX_DECLINED;
    }

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_int_t
ngx_http_pckg_enc_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_enc_key_ext,
        ngx_http_pckg_parse_key_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_pckg_enc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_enc_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_enc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->scheme = NGX_CONF_UNSET_UINT;
    conf->serve_key = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_pckg_enc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_enc_loc_conf_t  *prev = parent;
    ngx_http_pckg_enc_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->scheme,
                              prev->scheme, NGX_HTTP_PCKG_ENC_NONE);

    ngx_conf_merge_value(conf->serve_key,
                         prev->serve_key, 1);

    if (conf->key_seed == NULL) {
        conf->key_seed = prev->key_seed;
    }

    if (conf->iv_seed == NULL) {
        conf->iv_seed = prev->iv_seed;
    }

    return NGX_CONF_OK;
}
