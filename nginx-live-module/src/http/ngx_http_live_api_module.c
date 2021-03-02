#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_api.h>
#include "../ngx_live.h"
#include "../ngx_live_timeline.h"
#include <ngx_live_version.h>


static ngx_int_t ngx_http_live_api_postconfiguration(ngx_conf_t *cf);

static void *ngx_http_live_api_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_live_api_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_live_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_str_t  ngx_http_live_version = ngx_string(NGX_LIVE_VERSION);
static ngx_str_t  ngx_http_live_nginx_version = ngx_string(NGINX_VERSION);
static ngx_str_t  ngx_http_live_compiler = ngx_string(NGX_COMPILER);
static ngx_str_t  ngx_http_live_built = ngx_string(__DATE__ " " __TIME__);
static time_t     ngx_http_live_start_time = 0;


#include "ngx_http_live_api_json.h"


typedef struct {
    ngx_flag_t                upsert;
} ngx_http_live_api_loc_conf_t;


typedef struct {
    ngx_http_request_t       *r;
    ngx_live_channel_t       *channel;
    ngx_json_object_t         body;
    ngx_live_channel_json_t   json;
} ngx_http_live_api_channel_ctx_t;


static ngx_command_t  ngx_http_live_api_commands[] = {

    { ngx_string("live_api"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_http_live_api,
      0,
      0,
      NULL},

      ngx_null_command
};

static ngx_http_module_t  ngx_http_live_api_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_live_api_postconfiguration,    /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_live_api_create_loc_conf,      /* create location configuration */
    ngx_http_live_api_merge_loc_conf        /* merge location configuration */
};

ngx_module_t  ngx_http_live_api_module = {
    NGX_MODULE_V1,
    &ngx_http_live_api_module_ctx,          /* module context */
    ngx_http_live_api_commands,             /* module directives */
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
ngx_http_live_api_build_json(ngx_http_request_t *r,
    ngx_live_json_writer_t *writer, void *obj, ngx_str_t *response)
{
    u_char  *p;
    size_t   size;

    size = writer->get_size(obj);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_build_json: alloc failed, size: %uz", size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    response->data = p;

    p = writer->write(p, obj);

    response->len = p - response->data;

    if (response->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_api_build_json: "
            "result length %uz greater than allocated length %uz",
            response->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

/* route handlers */
static ngx_int_t
ngx_http_live_api_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        ngx_http_live_api_json_get_size,
        ngx_http_live_api_json_write,
    };

    return ngx_http_live_api_build_json(r, &writer, NULL, response);
}

static ngx_int_t
ngx_http_live_api_channels_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        ngx_live_channels_json_get_size,
        ngx_live_channels_json_write,
    };

    return ngx_http_live_api_build_json(r, &writer, NULL, response);
}

static ngx_int_t
ngx_http_live_api_channel_update(ngx_http_request_t *r,
    ngx_live_channel_t *channel, ngx_json_object_t *body,
    ngx_live_channel_json_t *json)
{
    int64_t     val;
    ngx_int_t   rc;

    if (json->opaque.data != NGX_JSON_UNSET_PTR) {
        rc = ngx_live_channel_block_str_set(channel, &channel->opaque,
            &json->opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_api_channel_update: failed to set opaque");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (json->initial_segment_index != NGX_JSON_UNSET) {
        val = json->initial_segment_index;
        if (val < 0 || val >= NGX_LIVE_INVALID_SEGMENT_INDEX) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_channel_update: "
                "invalid segment index %L", val);
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        ngx_live_channel_update(channel, val);
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_CHANNEL,
        channel, body, r->pool);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_channel_update: json commands failed %i", rc);
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static void
ngx_http_live_api_channel_read_handler(void *arg, ngx_int_t rc)
{
    ngx_log_t                        *log;
    ngx_str_t                         response;
    ngx_str_t                         channel_id;
    ngx_http_request_t               *r;
    ngx_live_channel_t               *channel;
    ngx_live_conf_ctx_t               conf_ctx;
    ngx_http_live_api_channel_ctx_t  *ctx = arg;

    r = ctx->r;
    channel = ctx->channel;
    log = r->connection->log;

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_http_live_api_channel_read_handler: called %i", rc);

    if (rc == NGX_DECLINED) {

        /* recreate the channel in order to cancel the read */

        conf_ctx.main_conf = channel->main_conf;
        conf_ctx.preset_conf = channel->preset_conf;

        ngx_live_channel_free(channel);

        channel_id = ctx->json.id;
        rc = ngx_live_channel_create(&channel_id, &conf_ctx, r->pool,
            &channel);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_channel_read_handler: "
                "create channel failed %i", rc);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        rc = ngx_live_json_commands_exec(channel,
            NGX_LIVE_JSON_CTX_PRE_CHANNEL, channel, &ctx->body, r->pool);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_channel_read_handler: "
                "json commands failed %i", rc);
            rc = NGX_HTTP_BAD_REQUEST;
            goto free;
        }

    } else if (rc != NGX_OK) {

        if (rc == NGX_BAD_DATA) {
            rc = NGX_HTTP_SERVICE_UNAVAILABLE;

        } else if (rc < 400 || rc > 599) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        goto free;
    }

    rc = ngx_http_live_api_channel_update(r, channel, &ctx->body, &ctx->json);
    if (rc == NGX_OK) {
        goto done;
    }

free:

    ngx_live_channel_free(channel);

done:

    response.len = 0;
    ngx_http_api_done(r, rc, &response);
}

static ngx_int_t
ngx_http_live_api_channels_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                         rc;
    ngx_json_object_t                *obj;
    ngx_live_channel_t               *channel;
    ngx_live_conf_ctx_t              *conf_ctx;
    ngx_live_channel_json_t           json;
    ngx_http_live_api_loc_conf_t     *llcf;
    ngx_http_live_api_channel_ctx_t  *ctx;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channels_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    obj = &body->v.obj;
    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, obj, ngx_live_channel_json,
        ngx_array_entries(ngx_live_channel_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_channels_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (json.id.data == NGX_JSON_UNSET_PTR ||
        json.preset.data == NGX_JSON_UNSET_PTR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channels_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    conf_ctx = ngx_live_core_get_preset_conf((ngx_cycle_t *) ngx_cycle,
        &json.preset);
    if (conf_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channels_post: "
            "unknown preset \"%V\"", &json.preset);
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_live_channel_create(&json.id, conf_ctx, r->pool, &channel);
    switch (rc) {

    case NGX_EXISTS:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_channels_post: "
                "channel \"%V\" already exists", &json.id);
            return NGX_HTTP_CONFLICT;
        }

        if (channel->blocked) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_channels_post: "
                "channel \"%V\" is blocked", &json.id);
            return NGX_HTTP_FORBIDDEN;
        }

        return ngx_http_live_api_channel_update(r, channel, obj, &json);

    case NGX_INVALID_ARG:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        break;      /* handled outside the switch */

    default:
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_channels_post: create channel failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_PRE_CHANNEL,
        channel, obj, r->pool);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_channels_post: json commands failed %i", rc);
        rc = NGX_HTTP_BAD_REQUEST;
        goto free;
    }

    if (json.read) {    /* unset or true */

        ctx = ngx_palloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_api_channels_post: alloc failed");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto free;
        }

        rc = ngx_live_persist_read(channel, r->pool,
            ngx_http_live_api_channel_read_handler, ctx);
        if (rc == NGX_DONE) {
            ctx->r = r;
            ctx->channel = channel;
            ctx->body = *obj;
            ctx->json = json;

            return NGX_DONE;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_api_channels_post: read failed %i", rc);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto free;
        }
    }

    rc = ngx_http_live_api_channel_update(r, channel, obj, &json);
    if (rc != NGX_OK) {
        goto free;
    }

    return NGX_HTTP_CREATED;

free:

    ngx_live_channel_free(channel);
    return rc;
}

static ngx_int_t
ngx_http_live_api_channel_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        (ngx_live_json_writer_get_size_pt) ngx_live_channel_json_get_size,
        (ngx_live_json_writer_write_pt) ngx_live_channel_json_write,
    };

    ngx_str_t            channel_id;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channel_get: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_live_api_build_json(r, &writer, channel, response);
}

static ngx_int_t
ngx_http_live_api_channel_get_unblocked(ngx_http_request_t *r, ngx_str_t *id,
    ngx_live_channel_t **result)
{
    ngx_live_channel_t  *channel;

    channel = ngx_live_channel_get(id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channel_get_unblocked: "
            "unknown channel \"%V\"", id);
        return NGX_HTTP_NOT_FOUND;
    }

    if (channel->blocked) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channel_get_unblocked: "
            "channel \"%V\" is blocked", id);
        return NGX_HTTP_FORBIDDEN;
    }

    *result = channel;

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_channel_put(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                 rc;
    ngx_str_t                 channel_id;
    ngx_live_channel_t       *channel;
    ngx_live_channel_json_t   json;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channel_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_channel_json,
        ngx_array_entries(ngx_live_channel_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_channel_put: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_live_api_channel_update(r, channel, &body->v.obj, &json);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_channel_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_str_t            channel_id;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_channel_delete: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_live_channel_free(channel);

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_api_variants_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        (ngx_live_json_writer_get_size_pt) ngx_live_variants_json_get_size,
        (ngx_live_json_writer_write_pt) ngx_live_variants_json_write,
    };

    ngx_str_t            channel_id;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_variants_get: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_live_api_build_json(r, &writer, channel, response);
}

static void
ngx_http_live_api_variant_init_conf(ngx_live_variant_json_t *json,
    ngx_live_variant_conf_t *conf, ngx_log_t *log)
{
    ngx_json_set_uint_value(conf->role, json->role);
    ngx_json_set_str_value(conf->label, json->label);
    ngx_json_set_str_value(conf->lang, json->lang);
    ngx_json_set_value(conf->is_default, json->is_default);
}

static ngx_int_t
ngx_http_live_api_variant_init_tracks(ngx_live_channel_t *channel,
    ngx_json_object_t *obj, ngx_live_track_t **result, ngx_log_t *log)
{
    ngx_str_t              media_type;
    ngx_live_track_t      *cur_track;
    ngx_json_key_value_t  *cur;
    ngx_json_key_value_t  *last;

    ngx_memzero(result, sizeof(*result) * KMP_MEDIA_COUNT);

    cur = obj->elts;
    last = cur + obj->nelts;
    for (; cur < last; cur++) {
        if (cur->value.type != NGX_JSON_STRING) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variant_init_tracks: invalid value type %d",
                cur->value.type);
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        cur_track = ngx_live_track_get(channel, &cur->value.v.str.s);
        if (cur_track == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variant_init_tracks: "
                "unknown track \"%V\" in channel \"%V\"",
                &cur->value.v.str.s, &channel->sn.str);
            return NGX_HTTP_NOT_FOUND;
        }

        media_type = ngx_live_track_media_type_names[cur_track->media_type];
        if (cur->key.len != media_type.len ||
            ngx_memcmp(cur->key.data, media_type.data, media_type.len) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variant_init_tracks: "
                "invalid key \"%V\" expected \"%V\"",
                &cur->key, &media_type);
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        if (result[cur_track->media_type] != NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variant_init_tracks: "
                "duplicate %V track", &media_type);
            return NGX_HTTP_BAD_REQUEST;
        }

        result[cur_track->media_type] = cur_track;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_variants_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                      rc;
    ngx_str_t                      channel_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_flag_t                     created;
    ngx_live_track_t              *tracks[KMP_MEDIA_COUNT];
    ngx_live_variant_t            *variant;
    ngx_live_channel_t            *channel;
    ngx_live_variant_conf_t        conf;
    ngx_live_variant_json_t        json;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variants_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_variant_json,
        ngx_array_entries(ngx_live_variant_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_variants_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    if (json.id.data == NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variants_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&conf, sizeof(conf));

    ngx_http_live_api_variant_init_conf(&json, &conf, log);

    if (json.track_ids != NGX_JSON_UNSET_PTR) {
        rc = ngx_http_live_api_variant_init_tracks(channel, json.track_ids,
            tracks, log);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    rc = ngx_live_variant_create(channel, &json.id, &conf, log, &variant);
    switch (rc) {

    case NGX_EXISTS:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variants_post: "
                "variant \"%V\" already exists in channel \"%V\"",
                &json.id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        conf = variant->conf;

        ngx_http_live_api_variant_init_conf(&json, &conf, log);

        if (ngx_live_variant_update(variant, &conf, log) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        created = 0;
        break;

    case NGX_INVALID_ARG:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        created = 1;
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_variants_post: create variant failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (json.track_ids != NGX_JSON_UNSET_PTR) {
        if (ngx_live_variant_set_tracks(variant, tracks, log) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (json.opaque.data != NGX_JSON_UNSET_PTR) {
        rc = ngx_live_channel_block_str_set(channel, &variant->opaque,
            &json.opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_variants_post: failed to set opaque");
            if (created) {
                ngx_live_variant_free(variant);
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return created ? NGX_HTTP_CREATED : NGX_OK;
}

static ngx_int_t
ngx_http_live_api_variant_put(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                 rc;
    ngx_str_t                 channel_id;
    ngx_str_t                 variant_id;
    ngx_log_t                *log = r->connection->log;
    ngx_live_track_t         *tracks[KMP_MEDIA_COUNT];
    ngx_live_channel_t       *channel;
    ngx_live_variant_t       *variant;
    ngx_live_variant_conf_t   conf;
    ngx_live_variant_json_t   json;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_variant_json,
        ngx_array_entries(ngx_live_variant_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_variant_put: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    variant_id = params[1];
    variant = ngx_live_variant_get(channel, &variant_id);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_put: "
            "unknown variant \"%V\" in channel \"%V\"",
            &variant_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    conf = variant->conf;

    ngx_http_live_api_variant_init_conf(&json, &conf, log);

    if (json.track_ids != NGX_JSON_UNSET_PTR) {
        rc = ngx_http_live_api_variant_init_tracks(channel, json.track_ids,
            tracks, log);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (ngx_live_variant_update(variant, &conf, log) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (json.track_ids != NGX_JSON_UNSET_PTR) {
        if (ngx_live_variant_set_tracks(variant, tracks, log) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (json.opaque.data != NGX_JSON_UNSET_PTR) {
        rc = ngx_live_channel_block_str_set(channel, &variant->opaque,
            &json.opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_variant_put: failed to set opaque");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_variant_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t            rc;
    ngx_str_t            channel_id;
    ngx_str_t            variant_id;
    ngx_live_channel_t  *channel;
    ngx_live_variant_t  *variant;

    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    variant_id = params[1];
    variant = ngx_live_variant_get(channel, &variant_id);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_variant_delete: "
            "unknown variant \"%V\" in channel \"%V\"",
            &variant_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_live_variant_free(variant);

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_api_tracks_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        (ngx_live_json_writer_get_size_pt) ngx_live_tracks_json_get_size,
        (ngx_live_json_writer_write_pt) ngx_live_tracks_json_write,
    };

    ngx_str_t            channel_id;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_tracks_get: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_live_api_build_json(r, &writer, channel, response);
}

static ngx_int_t
ngx_http_live_api_tracks_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                      rc;
    ngx_str_t                      channel_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_flag_t                     created;
    ngx_live_track_t              *track;
    ngx_live_channel_t            *channel;
    ngx_live_track_json_t          json;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_track_json,
        ngx_array_entries(ngx_live_track_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_tracks_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (json.id.data == NGX_JSON_UNSET_PTR ||
        json.media_type == NGX_JSON_UNSET_UINT)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_live_track_create(channel, &json.id, NGX_LIVE_INVALID_TRACK_ID,
        json.media_type, log, &track);
    switch (rc) {

    case NGX_EXISTS:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_tracks_post: "
                "track \"%V\" already exists in channel \"%V\"",
                &json.id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        created = 0;
        break;

    case NGX_INVALID_ARG:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        created = 1;
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_tracks_post: create track failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (json.opaque.data != NGX_JSON_UNSET_PTR) {
        rc = ngx_live_channel_block_str_set(channel, &track->opaque,
            &json.opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_tracks_post: failed to set opaque");
            if (created) {
                ngx_live_track_free(track);
            }
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_TRACK, track,
        &body->v.obj, r->pool);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_tracks_post: json commands failed %i", rc);
        if (created) {
            ngx_live_track_free(track);
        }
        return NGX_HTTP_BAD_REQUEST;
    }

    return created ? NGX_HTTP_CREATED : NGX_OK;
}

static ngx_int_t
ngx_http_live_api_track_put(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t               rc;
    ngx_str_t               track_id;
    ngx_str_t               channel_id;
    ngx_live_track_t       *track;
    ngx_live_channel_t     *channel;
    ngx_live_track_json_t   json;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_track_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_track_json,
        ngx_array_entries(ngx_live_track_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_track_put: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    track_id = params[1];
    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_track_put: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }


    if (json.opaque.data != NGX_JSON_UNSET_PTR) {
        rc = ngx_live_channel_block_str_set(channel, &track->opaque,
            &json.opaque);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_api_track_put: failed to set opaque");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_TRACK, track,
        &body->v.obj, r->pool);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_api_track_put: json commands failed %i", rc);
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_track_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t            rc;
    ngx_str_t            track_id;
    ngx_str_t            channel_id;
    ngx_live_track_t    *track;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    track_id = params[1];
    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_track_delete: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_live_track_free(track);

    return NGX_OK;

}


static ngx_int_t
ngx_http_live_api_variant_tracks_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                      rc;
    ngx_str_t                      variant_id;
    ngx_str_t                      channel_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_live_track_t              *track;
    ngx_live_channel_t            *channel;
    ngx_live_variant_t            *variant;
    ngx_live_track_json_t          json;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_track_json,
        ngx_array_entries(ngx_live_track_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_variant_tracks_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (json.id.data == NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    variant_id = params[1];
    variant = ngx_live_variant_get(channel, &variant_id);
    if (variant == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "unknown variant \"%V\" in channel \"%V\"",
            &variant_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    track = ngx_live_track_get(channel, &json.id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "unknown track \"%V\" in channel \"%V\"",
            &json.id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    if (variant->tracks[track->media_type] == track) {
        return NGX_OK;
    }

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);

    if (variant->tracks[track->media_type] != NULL && !llcf->upsert) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "variant \"%V\" in channel \"%V\" already has a track of type %uD",
            &variant_id, &channel_id, track->media_type);
        return NGX_HTTP_CONFLICT;
    }

    if (ngx_live_variant_set_track(variant, track, log) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_HTTP_CREATED;
}

static ngx_int_t
ngx_http_live_api_timelines_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        (ngx_live_json_writer_get_size_pt)
            ngx_live_timeline_channel_json_get_size,
        (ngx_live_json_writer_write_pt)
            ngx_live_timeline_channel_json_write,
    };

    ngx_str_t            channel_id;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_timelines_get: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_live_api_build_json(r, &writer, channel, response);
}

static void
ngx_http_live_api_timeline_init_conf(ngx_live_timeline_json_t *json,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf)
{
    ngx_json_set_value(conf->period_gap, json->period_gap);
    ngx_json_set_value(conf->max_segments, json->max_segments);
    ngx_json_set_value(conf->max_duration, json->max_duration);
    ngx_json_set_value(conf->start, json->start);
    ngx_json_set_value(conf->end, json->end);
    ngx_json_set_value(conf->active, json->active);
    ngx_json_set_value(conf->no_truncate, json->no_truncate);
    ngx_json_set_value(conf->end_list, json->end_list);

    ngx_json_set_value(manifest_conf->max_segments,
        json->manifest_max_segments);
    ngx_json_set_value(manifest_conf->max_duration,
        json->manifest_max_duration);
    ngx_json_set_value(manifest_conf->expiry_threshold,
        json->manifest_expiry_threshold);
    ngx_json_set_value(manifest_conf->target_duration_segments,
        json->manifest_target_duration_segments);
}

static ngx_int_t
ngx_http_live_api_timelines_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                           rc;
    ngx_str_t                           channel_id;
    ngx_log_t                          *log = r->connection->log;
    ngx_live_channel_t                 *channel;
    ngx_live_timeline_t                *source;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_json_t            json;
    ngx_live_timeline_conf_t            conf;
    ngx_http_live_api_loc_conf_t       *llcf;
    ngx_live_timeline_manifest_conf_t   manifest_conf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timelines_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_timeline_json,
        ngx_array_entries(ngx_live_timeline_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_timelines_post: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (json.id.data == NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timelines_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    if (json.source_id.data != NGX_JSON_UNSET_PTR) {
        source = ngx_live_timeline_get(channel, &json.source_id);
        if (source == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_timelines_post: "
                "unknown timeline \"%V\" in channel \"%V\"",
                &json.source_id, &channel_id);
            return NGX_HTTP_NOT_FOUND;
        }

    } else {
        source = NULL;
    }

    ngx_live_timeline_conf_default(&conf, &manifest_conf);

    ngx_http_live_api_timeline_init_conf(&json, &conf, &manifest_conf);

    rc = ngx_live_timeline_create(channel, &json.id, &conf,
        &manifest_conf, log, &timeline);
    switch (rc) {

    case NGX_EXISTS:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_timelines_post: "
                "timeline \"%V\" already exists in channel \"%V\"",
                &json.id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        conf = timeline->conf;
        manifest_conf = timeline->manifest.conf;

        ngx_http_live_api_timeline_init_conf(&json, &conf, &manifest_conf);

        if (ngx_live_timeline_update(timeline, &conf, &manifest_conf, log)
            != NGX_OK)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        return NGX_OK;

    case NGX_INVALID_ARG:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_timelines_post: create timeline failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (source != NULL) {
        if (ngx_live_timeline_copy(timeline, source) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_timelines_post: copy timeline failed");
            ngx_live_timeline_free(timeline);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_HTTP_CREATED;
}

static ngx_int_t
ngx_http_live_api_timeline_get(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    static ngx_live_json_writer_t  writer = {
        (ngx_live_json_writer_get_size_pt) ngx_live_timeline_json_get_size,
        (ngx_live_json_writer_write_pt) ngx_live_timeline_json_write,
    };

    ngx_int_t             rc;
    ngx_str_t             channel_id;
    ngx_str_t             timeline_id;
    ngx_live_channel_t   *channel;
    ngx_live_timeline_t  *timeline;

    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    timeline_id = params[1];
    timeline = ngx_live_timeline_get(channel, &timeline_id);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_timeline_get: "
            "unknown timeline \"%V\" in channel \"%V\"",
            &timeline_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    return ngx_http_live_api_build_json(r, &writer, timeline, response);

}

static ngx_int_t
ngx_http_live_api_timeline_put(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                           rc;
    ngx_str_t                           channel_id;
    ngx_str_t                           timeline_id;
    ngx_log_t                          *log = r->connection->log;
    ngx_live_channel_t                 *channel;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_json_t            json;
    ngx_live_timeline_conf_t            conf;
    ngx_live_timeline_manifest_conf_t   manifest_conf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timeline_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(r->pool, &body->v.obj, ngx_live_timeline_json,
        ngx_array_entries(ngx_live_timeline_json), &json) != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_timeline_put: failed to parse object");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    timeline_id = params[1];
    timeline = ngx_live_timeline_get(channel, &timeline_id);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timeline_put: "
            "unknown timeline \"%V\" in channel \"%V\"",
            &timeline_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    conf = timeline->conf;
    manifest_conf = timeline->manifest.conf;

    ngx_http_live_api_timeline_init_conf(&json, &conf, &manifest_conf);

    if (ngx_live_timeline_update(timeline, &conf, &manifest_conf, log)
        != NGX_OK)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_timeline_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_int_t             rc;
    ngx_str_t             channel_id;
    ngx_str_t             timeline_id;
    ngx_live_channel_t   *channel;
    ngx_live_timeline_t  *timeline;

    channel_id = params[0];
    rc = ngx_http_live_api_channel_get_unblocked(r, &channel_id, &channel);
    if (rc != NGX_OK) {
        return rc;
    }

    timeline_id = params[1];
    timeline = ngx_live_timeline_get(channel, &timeline_id);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_timeline_delete: "
            "unknown timeline \"%V\" in channel \"%V\"",
            &timeline_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_live_timeline_free(timeline);

    return NGX_OK;
}

#include "ngx_http_live_api_routes.h"


static ngx_int_t
ngx_http_live_api_handler(ngx_http_request_t *r)
{
    return ngx_http_api_handler(r, &ngx_http_live_api_route);
}

static ngx_int_t
ngx_http_live_api_ro_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_GET) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_ro_handler: "
            "method %ui not allowed", r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    return ngx_http_live_api_handler(r);
}

static char *
ngx_http_live_api(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                          *rv;
    ngx_http_api_options_t         options;
    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_live_api_loc_conf_t  *llcf;

    ngx_memzero(&options, sizeof(options));
    rv = ngx_http_api_parse_options(cf, &options);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = options.write ? ngx_http_live_api_handler :
        ngx_http_live_api_ro_handler;

    llcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_live_api_module);
    llcf->upsert = options.upsert;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_live_api_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_live_start_time = ngx_time();

    return NGX_OK;
}

static void *
ngx_http_live_api_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_live_api_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_api_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_live_api_create_loc_conf: ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    conf->upsert = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_live_api_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_api_loc_conf_t  *prev = parent;
    ngx_http_live_api_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->upsert, prev->upsert, 0);

    return NGX_CONF_OK;
}
