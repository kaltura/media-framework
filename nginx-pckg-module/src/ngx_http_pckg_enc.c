#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "ngx_http_pckg_enc.h"
#include "ngx_http_pckg_utils.h"

#include "ngx_http_pckg_enc_json.h"


static ngx_int_t ngx_http_pckg_enc_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_enc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_enc_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


enum {
    NGX_HTTP_PCKG_ENC_SCOPE_CHANNEL,
    NGX_HTTP_PCKG_ENC_SCOPE_MEDIA_TYPE,
    NGX_HTTP_PCKG_ENC_SCOPE_TRACK,
};


static ngx_conf_enum_t  ngx_http_pckg_enc_schemes[] = {
    { ngx_string("none"),    NGX_HTTP_PCKG_ENC_NONE },
    { ngx_string("aes-128"), NGX_HTTP_PCKG_ENC_AES_128 },
    { ngx_string("cbcs"),    NGX_HTTP_PCKG_ENC_CBCS },
    { ngx_string("cenc"),    NGX_HTTP_PCKG_ENC_CENC },

    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_pckg_enc_scopes[] = {
    { ngx_string("channel"),    NGX_HTTP_PCKG_ENC_SCOPE_CHANNEL },
    { ngx_string("media_type"), NGX_HTTP_PCKG_ENC_SCOPE_MEDIA_TYPE},
    { ngx_string("track"),      NGX_HTTP_PCKG_ENC_SCOPE_TRACK },

    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_enc_commands[] = {

    { ngx_string("pckg_enc_scheme"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, scheme),
      &ngx_http_pckg_enc_schemes },

    { ngx_string("pckg_enc_scope"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, scope),
      &ngx_http_pckg_enc_scopes },

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

    { ngx_string("pckg_enc_json"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_zero_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_enc_loc_conf_t, json),
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
            return NGX_ERROR;
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

static ngx_int_t
ngx_http_pckg_enc_get_key(ngx_http_request_t *r, u_char *result)
{
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    return ngx_http_pckg_enc_generate_key(r, elcf->key_seed, NULL, result);
}

static ngx_int_t
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
ngx_http_pckg_enc_json_parse_systems(ngx_http_request_t *r,
    ngx_json_object_t *systems, media_enc_t *enc)
{
    ngx_int_t              rc;
    ngx_uint_t             i, n;
    media_enc_sys_t       *sys;
    ngx_json_key_value_t  *elt, *elts;

    n = systems->nelts;
    if (ngx_array_init(&enc->systems, r->pool, n, sizeof(media_enc_sys_t))
        != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_enc_json_parse_systems: array init failed");
        return NGX_ERROR;
    }

    elts = systems->elts;
    for (i = 0; i < n; i++) {
        elt = &elts[i];
        if (elt->value.type != NGX_JSON_STRING) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse_systems: "
                "invalid element type %d, expected string", elt->value.type);
            return NGX_BAD_DATA;
        }

        sys = ngx_array_push(&enc->systems);
        if (sys == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse_systems: array push failed");
            return NGX_ERROR;
        }

        if (ngx_http_pckg_parse_guid(&elt->key, sys->id) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse_systems: "
                "failed to parse guid \"%V\"", &elt->key);
            return NGX_BAD_DATA;
        }

        if (elt->value.v.str.escape) {
            sys->base64_data.data = elt->value.v.str.s.data;
            sys->base64_data.len = 0;

            if (ngx_json_decode_string(&sys->base64_data, &elt->value.v.str.s)
                != NGX_JSON_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_pckg_enc_json_parse_systems: "
                    "failed to decode data \"%V\"",
                    &elt->value.v.str.s);
                return NGX_BAD_DATA;
            }

        } else {
            sys->base64_data = elt->value.v.str.s;
        }

        rc = ngx_http_pckg_parse_base64(r->pool, &sys->base64_data,
            &sys->data);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse_systems: "
                "failed to parse data \"%V\" %i", &sys->base64_data, rc);
            return rc;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_pckg_enc_json_parse(ngx_http_request_t *r, ngx_json_value_t *value,
    media_enc_t *enc)
{
    ngx_int_t            rc;
    ngx_pckg_enc_json_t  json;

    if (value->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_enc_json_parse: "
            "invalid element type %d, expected object", value->type);
        return NGX_BAD_DATA;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &value->v.obj, ngx_pckg_enc_json,
        ngx_array_entries(ngx_pckg_enc_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_enc_json_parse: failed to parse object");
        return NGX_BAD_DATA;
    }

    if (json.key.data == NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_enc_json_parse: missing mandatory params");
        return NGX_BAD_DATA;
    }

    if (ngx_http_pckg_parse_base64_fixed(&json.key,
        enc->key, sizeof(enc->key)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_enc_json_parse: invalid key \"%V\"", &json.key);
        return NGX_BAD_DATA;
    }

    if (json.key_id.data != NGX_JSON_UNSET_PTR) {
        if (ngx_http_pckg_parse_base64_fixed(&json.key_id,
            enc->key_id, sizeof(enc->key_id)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse: invalid key_id \"%V\"",
                &json.key_id);
            return NGX_BAD_DATA;
        }

        enc->has_key_id = 1;
    }

    if (json.iv.data != NGX_JSON_UNSET_PTR) {
        if (ngx_http_pckg_parse_base64_fixed(&json.iv,
            enc->iv, sizeof(enc->iv)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_enc_json_parse: invalid iv \"%V\"", &json.iv);
            return NGX_BAD_DATA;
        }

    } else {
        if (ngx_http_pckg_enc_get_iv(r, enc->iv) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (json.systems != NGX_JSON_UNSET_PTR) {
        rc = ngx_http_pckg_enc_json_parse_systems(r, json.systems, enc);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_enc_create(ngx_http_request_t *r, media_enc_t **result)
{
    ngx_int_t                      rc;
    media_enc_t                   *enc;
    ngx_json_value_t               value;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    enc = ngx_pcalloc(r->pool, sizeof(*enc));
    if (enc == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_enc_create: alloc failed");
        return NGX_ERROR;
    }

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (elcf->json) {
        if (ngx_http_pckg_complex_value_json(r, elcf->json, &value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        rc = ngx_http_pckg_enc_json_parse(r, &value, enc);
        if (rc != NGX_OK) {
            return rc;
        }

        *result = enc;
        return NGX_OK;
    }

    if (ngx_http_pckg_enc_get_key(r, enc->key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_pckg_enc_get_iv(r, enc->iv) != NGX_OK) {
        return NGX_ERROR;
    }

    *result = enc;
    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_enc_init_track_scope(ngx_http_request_t *r)
{
    uint32_t                   media_type;
    ngx_int_t                  rc;
    ngx_uint_t                 i, n;
    media_enc_t               *enc;
    ngx_pckg_track_t          *track;
    ngx_pckg_variant_t        *variant, *variants;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    variants = channel->variants.elts;
    n = channel->variants.nelts;
    for (i = 0; i < n; i++) {
        variant = &variants[i];

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            track = variant->tracks[media_type];

            if (track == NULL || track->enc != NULL) {
                continue;
            }

            ctx->variant = variant;
            ctx->media_type = media_type;

            rc = ngx_http_pckg_enc_create(r, &enc);
            if (rc != NGX_OK) {
                return rc;
            }

            track->enc = enc;
        }
    }

    ctx->variant = NULL;
    ctx->media_type = KMP_MEDIA_COUNT;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_enc_init_media_type_scope(ngx_http_request_t *r)
{
    uint32_t                   media_type;
    ngx_int_t                  rc;
    ngx_uint_t                 i, n;
    media_enc_t               *enc;
    media_enc_t               *encs[KMP_MEDIA_COUNT];
    ngx_pckg_track_t          *track, *tracks;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ngx_memzero(encs, sizeof(encs));

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;
    for (i = 0; i < n; i++) {
        track = &tracks[i];
        media_type = track->header->media_type;

        enc = encs[media_type];
        if (enc == NULL) {
            ctx->media_type = media_type;

            rc = ngx_http_pckg_enc_create(r, &enc);
            if (rc != NGX_OK) {
                return rc;
            }

            encs[media_type] = enc;
        }

        track->enc = enc;
    }

    ctx->media_type = KMP_MEDIA_COUNT;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_enc_init_channel_scope(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_uint_t                 i, n;
    media_enc_t               *enc;
    ngx_pckg_track_t          *track, *tracks;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_enc_create(r, &enc);
    if (rc != NGX_OK) {
        return rc;
    }

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;
    for (i = 0; i < n; i++) {
        track = &tracks[i];
        track->enc = enc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_enc_init(ngx_http_request_t *r)
{
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    static ngx_http_handler_pt     handlers[] = {
        ngx_http_pckg_enc_init_channel_scope,
        ngx_http_pckg_enc_init_media_type_scope,
        ngx_http_pckg_enc_init_track_scope,
    };

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (elcf->scheme == NGX_HTTP_PCKG_ENC_NONE) {
        return NGX_OK;
    }

    return handlers[elcf->scope](r);
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
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
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

    if (ngx_http_pckg_core_add_init_handler(cf, ngx_http_pckg_enc_init)
        != NGX_OK)
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
    conf->scope = NGX_CONF_UNSET_UINT;
    conf->serve_key = NGX_CONF_UNSET;
    conf->json = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_pckg_enc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_enc_loc_conf_t  *prev = parent;
    ngx_http_pckg_enc_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->scheme,
                              prev->scheme, NGX_HTTP_PCKG_ENC_NONE);

    ngx_conf_merge_uint_value(conf->scope,
                              prev->scope, NGX_HTTP_PCKG_ENC_SCOPE_CHANNEL);

    ngx_conf_merge_value(conf->serve_key,
                         prev->serve_key, 1);

    if (conf->key_seed == NULL) {
        conf->key_seed = prev->key_seed;
    }

    if (conf->iv_seed == NULL) {
        conf->iv_seed = prev->iv_seed;
    }

    ngx_conf_merge_ptr_value(conf->json, prev->json, NULL);

    return NGX_CONF_OK;
}
