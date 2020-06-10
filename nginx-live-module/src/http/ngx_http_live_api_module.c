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
    ngx_flag_t           upsert;
} ngx_http_live_api_loc_conf_t;


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


/* channel */
enum {
    CHANNEL_PARAM_ID,
    CHANNEL_PARAM_PRESET,
    CHANNEL_PARAM_OPAQUE,
    CHANNEL_PARAM_READ,
    CHANNEL_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_live_channel_params[] = {
    { vod_string("id"),          NGX_JSON_STRING, CHANNEL_PARAM_ID },
    { vod_string("preset"),      NGX_JSON_STRING, CHANNEL_PARAM_PRESET },
    { vod_string("opaque"),      NGX_JSON_STRING, CHANNEL_PARAM_OPAQUE },
    { vod_string("read"),        NGX_JSON_BOOL,   CHANNEL_PARAM_READ },
    { vod_null_string, 0, 0 }
};

typedef struct {
    ngx_http_request_t  *r;
    ngx_live_channel_t  *channel;
    ngx_json_object_t    body;
    ngx_json_value_t    *values[CHANNEL_PARAM_COUNT];
} ngx_http_live_api_channel_ctx_t;


/* timeline */
enum {
    TIMELINE_PARAM_ID,
    TIMELINE_PARAM_SOURCE_ID,
    TIMELINE_PARAM_ACTIVE,
    TIMELINE_PARAM_NO_TRUNCATE,
    TIMELINE_PARAM_MAX_SEGMENTS,
    TIMELINE_PARAM_MAX_DURATION,
    TIMELINE_PARAM_START,
    TIMELINE_PARAM_END,
    TIMELINE_PARAM_MANIFEST_MAX_SEGMENTS,
    TIMELINE_PARAM_MANIFEST_MAX_DURATION,
    TIMELINE_PARAM_MANIFEST_EXPIRY_THRESHOLD,
    TIMELINE_PARAM_MANIFEST_TARGET_DURATION_SEGMENTS,

    TIMELINE_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_live_timeline_params[] = {
    { vod_string("id"),                                 NGX_JSON_STRING,
        TIMELINE_PARAM_ID },
    { vod_string("source_id"),                          NGX_JSON_STRING,
        TIMELINE_PARAM_SOURCE_ID },
    { vod_string("active"),                             NGX_JSON_BOOL,
        TIMELINE_PARAM_ACTIVE },
    { vod_string("no_truncate"),                        NGX_JSON_BOOL,
        TIMELINE_PARAM_NO_TRUNCATE },
    { vod_string("max_segments"),                       NGX_JSON_INT,
        TIMELINE_PARAM_MAX_SEGMENTS },
    { vod_string("max_duration"),                       NGX_JSON_INT,
        TIMELINE_PARAM_MAX_DURATION },
    { vod_string("start"),                              NGX_JSON_INT,
        TIMELINE_PARAM_START },
    { vod_string("end"),                                NGX_JSON_INT,
        TIMELINE_PARAM_END },
    { vod_string("manifest_max_segments"),              NGX_JSON_INT,
        TIMELINE_PARAM_MANIFEST_MAX_SEGMENTS },
    { vod_string("manifest_max_duration"),              NGX_JSON_INT,
        TIMELINE_PARAM_MANIFEST_MAX_DURATION },
    { vod_string("manifest_expiry_threshold"),          NGX_JSON_INT,
        TIMELINE_PARAM_MANIFEST_EXPIRY_THRESHOLD },
    { vod_string("manifest_target_duration_segments"),  NGX_JSON_INT,
        TIMELINE_PARAM_MANIFEST_TARGET_DURATION_SEGMENTS },
    { vod_null_string, 0, 0 }
};


/* variant */
enum {
    VARIANT_PARAM_ID,
    VARIANT_PARAM_OPAQUE,
    VARIANT_PARAM_LABEL,
    VARIANT_PARAM_LANG,
    VARIANT_PARAM_ROLE,
    VARIANT_PARAM_IS_DEFAULT,
    VARIANT_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_live_variant_params[] = {
    { vod_string("id"),          NGX_JSON_STRING, VARIANT_PARAM_ID },
    { vod_string("opaque"),      NGX_JSON_STRING, VARIANT_PARAM_OPAQUE },
    { vod_string("label"),       NGX_JSON_STRING, VARIANT_PARAM_LABEL },
    { vod_string("lang"),        NGX_JSON_STRING, VARIANT_PARAM_LANG },
    { vod_string("role"),        NGX_JSON_STRING, VARIANT_PARAM_ROLE },
    { vod_string("is_default"),  NGX_JSON_BOOL,   VARIANT_PARAM_IS_DEFAULT },
    { vod_null_string, 0, 0 }
};


/* track */
enum {
    TRACK_PARAM_ID,
    TRACK_PARAM_MEDIA_TYPE,
    TRACK_PARAM_OPAQUE,
    TRACK_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_live_track_params[] = {
    { vod_string("id"),          NGX_JSON_STRING, TRACK_PARAM_ID },
    { vod_string("media_type"),  NGX_JSON_STRING, TRACK_PARAM_MEDIA_TYPE },
    { vod_string("opaque"),      NGX_JSON_STRING, TRACK_PARAM_OPAQUE },
    { vod_null_string, 0, 0 }
};


static ngx_int_t
ngx_http_live_find_string(ngx_str_t *arr, ngx_str_t *str)
{
    ngx_int_t  index;

    for (index = 0; arr[index].len != 0; index++) {
        if (arr[index].len == str->len &&
            ngx_strncasecmp(arr[index].data, str->data, str->len) == 0)
        {
            return index;
        }
    }

    return -1;
}

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
    ngx_json_value_t **values)
{
    ngx_int_t   rc;
    ngx_log_t  *log = r->connection->log;

    if (values[CHANNEL_PARAM_OPAQUE] != NULL) {
        rc = ngx_live_channel_block_str_set(channel, &channel->opaque,
            &values[CHANNEL_PARAM_OPAQUE]->v.str);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_channel_update: failed to set opaque");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_CHANNEL,
        channel, body, log);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_channel_update: json commands failed %i", rc);
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static void
ngx_http_live_api_channel_read_handler(void *arg, ngx_int_t rc)
{
    ngx_str_t                         response;
    ngx_http_request_t               *r;
    ngx_live_channel_t               *channel;
    ngx_http_live_api_channel_ctx_t  *ctx = arg;

    r = ctx->r;
    channel = ctx->channel;

    if (rc != NGX_OK) {

        if (rc == NGX_ABORT) {
            rc = NGX_HTTP_SERVICE_UNAVAILABLE;

        } else if (rc < 500 || rc > 599) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_live_channel_free(channel);
        goto done;
    }

    rc = ngx_http_live_api_channel_update(r, channel, &ctx->body, ctx->values);
    if (rc != NGX_OK) {
        ngx_live_channel_free(channel);
        goto done;
    }

    response.len = 0;

    ngx_http_api_send_response(r, NGX_HTTP_OK, &response);

done:

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_live_api_channels_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                         rc;
    ngx_str_t                         channel_id;
    ngx_str_t                         preset_name;
    ngx_log_t                        *log = r->connection->log;
    ngx_json_value_t                 *values[CHANNEL_PARAM_COUNT];
    ngx_json_object_t                *obj;
    ngx_live_channel_t               *channel;
    ngx_live_conf_ctx_t              *conf_ctx;
    ngx_http_live_api_loc_conf_t     *llcf;
    ngx_http_live_api_channel_ctx_t  *ctx;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_channels_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    obj = &body->v.obj;
    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(obj, ngx_live_channel_params, values);

    if (values[CHANNEL_PARAM_ID] == NULL ||
        values[CHANNEL_PARAM_PRESET] == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_channels_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    preset_name = values[CHANNEL_PARAM_PRESET]->v.str;

    conf_ctx = ngx_live_core_get_preset_conf((ngx_cycle_t *) ngx_cycle,
        &preset_name);
    if (conf_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_channels_post: "
            "unknown preset \"%V\"", &preset_name);
        return NGX_HTTP_BAD_REQUEST;
    }

    channel_id = values[CHANNEL_PARAM_ID]->v.str;
    rc = ngx_live_channel_create(&channel_id, conf_ctx, r->pool, &channel);
    switch (rc) {

    case NGX_BUSY:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_channels_post: "
                "channel \"%V\" already exists", &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        return ngx_http_live_api_channel_update(r, channel, obj, values);

    case NGX_DECLINED:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        break;      /* handled outside the switch */

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_channels_post: create channel failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_PRE_CHANNEL,
        channel, obj, log);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_channels_post: json commands failed %i", rc);
        rc = NGX_HTTP_BAD_REQUEST;
        goto free;
    }

    if (values[CHANNEL_PARAM_READ] == NULL ||
        values[CHANNEL_PARAM_READ]->v.boolean)
    {
        ctx = ngx_palloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
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
            ngx_memcpy(ctx->values, values, sizeof(ctx->values));

            r->main->count++;
            return NGX_DONE;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_channels_post: read failed");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto free;
        }
    }

    rc = ngx_http_live_api_channel_update(r, channel, obj, values);
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
ngx_http_live_api_channel_put(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t            rc;
    ngx_str_t            channel_id;
    ngx_log_t           *log = r->connection->log;
    ngx_json_value_t    *values[CHANNEL_PARAM_COUNT];
    ngx_live_channel_t  *channel;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_channel_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_channel_params, values);


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_channel_put: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_http_live_api_channel_update(r, channel, &body->v.obj, values);
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

static ngx_int_t
ngx_http_live_api_variant_init_conf(ngx_json_value_t **values,
    ngx_live_variant_conf_t *conf, ngx_log_t *log)
{
    ngx_int_t  role;

    if (values[VARIANT_PARAM_ROLE] != NULL) {
        role = ngx_http_live_find_string(ngx_live_variant_role_names,
            &values[VARIANT_PARAM_ROLE]->v.str);
        if (role < 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_variant_init_conf: invalid role \"%V\"",
                &values[VARIANT_PARAM_ROLE]->v.str);
            return NGX_HTTP_BAD_REQUEST;
        }

        conf->role = role;
    }

    if (values[VARIANT_PARAM_LABEL] != NULL) {
        conf->label = values[VARIANT_PARAM_LABEL]->v.str;
    }

    if (values[VARIANT_PARAM_LANG] != NULL) {
        conf->lang = values[VARIANT_PARAM_LANG]->v.str;
    }

    if (values[VARIANT_PARAM_IS_DEFAULT] != NULL) {
        conf->is_default = values[VARIANT_PARAM_IS_DEFAULT]->v.boolean;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_variants_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                      rc;
    ngx_str_t                      channel_id;
    ngx_str_t                      variant_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_flag_t                     created;
    ngx_json_value_t              *values[VARIANT_PARAM_COUNT];
    ngx_live_variant_t            *variant;
    ngx_live_channel_t            *channel;
    ngx_live_variant_conf_t        conf;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variants_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_variant_params, values);

    if (values[VARIANT_PARAM_ID] == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variants_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variants_post: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_memzero(&conf, sizeof(conf));

    rc = ngx_http_live_api_variant_init_conf(values, &conf, log);
    if (rc != NGX_OK) {
        return rc;
    }

    variant_id = values[VARIANT_PARAM_ID]->v.str;
    rc = ngx_live_variant_create(channel, &variant_id, &conf, log, &variant);
    switch (rc) {

    case NGX_BUSY:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_variants_post: "
                "variant \"%V\" already exists in channel \"%V\"",
                &variant_id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        conf = variant->conf;

        (void) ngx_http_live_api_variant_init_conf(values, &conf, log);

        if (ngx_live_variant_update(variant, &conf, log) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        created = 0;
        break;

    case NGX_DECLINED:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        created = 1;
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_variants_post: create variant failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (values[VARIANT_PARAM_OPAQUE] != NULL) {
        rc = ngx_live_channel_block_str_set(channel, &variant->opaque,
            &values[VARIANT_PARAM_OPAQUE]->v.str);
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
    ngx_json_value_t         *values[VARIANT_PARAM_COUNT];
    ngx_live_channel_t       *channel;
    ngx_live_variant_t       *variant;
    ngx_live_variant_conf_t   conf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_variant_params, values);


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_put: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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

    rc = ngx_http_live_api_variant_init_conf(values, &conf, log);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_live_variant_update(variant, &conf, log) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (values[VARIANT_PARAM_OPAQUE] != NULL) {
        rc = ngx_live_channel_block_str_set(channel, &variant->opaque,
            &values[VARIANT_PARAM_OPAQUE]->v.str);
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
    ngx_str_t            channel_id;
    ngx_str_t            variant_id;
    ngx_live_channel_t  *channel;
    ngx_live_variant_t  *variant;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_variant_delete: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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
    int32_t                        media_type;
    ngx_int_t                      rc;
    ngx_str_t                      track_id;
    ngx_str_t                      channel_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_flag_t                     created;
    ngx_live_track_t              *track;
    ngx_json_value_t              *values[TRACK_PARAM_COUNT];
    ngx_live_channel_t            *channel;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_track_params, values);

    if (values[TRACK_PARAM_ID] == NULL ||
        values[TRACK_PARAM_MEDIA_TYPE] == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    media_type = ngx_http_live_find_string(ngx_live_track_media_type_names,
        &values[TRACK_PARAM_MEDIA_TYPE]->v.str);
    if (media_type < 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: invalid media type \"%V\"",
            &values[TRACK_PARAM_MEDIA_TYPE]->v.str);
        return NGX_HTTP_BAD_REQUEST;
    }


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    track_id = values[TRACK_PARAM_ID]->v.str;
    rc = ngx_live_track_create(channel, &track_id, NGX_LIVE_INVALID_TRACK_ID,
        media_type, log, &track);
    switch (rc) {

    case NGX_BUSY:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_api_tracks_post: "
                "track \"%V\" already exists in channel \"%V\"",
                &track_id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        created = 0;
        break;

    case NGX_DECLINED:
        return NGX_HTTP_BAD_REQUEST;

    case NGX_OK:
        created = 1;
        break;

    default:
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_tracks_post: create track failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (values[TRACK_PARAM_OPAQUE] != NULL) {
        rc = ngx_live_channel_block_str_set(channel, &track->opaque,
            &values[TRACK_PARAM_OPAQUE]->v.str);
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
        &body->v.obj, log);
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
    ngx_int_t            rc;
    ngx_str_t            track_id;
    ngx_str_t            channel_id;
    ngx_log_t           *log = r->connection->log;
    ngx_live_track_t    *track;
    ngx_json_value_t    *values[TRACK_PARAM_COUNT];
    ngx_live_channel_t  *channel;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_tracks_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_track_params, values);

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_track_put: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    track_id = params[1];
    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_track_put: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }


    if (values[TRACK_PARAM_OPAQUE] != NULL) {
        rc = ngx_live_channel_block_str_set(channel, &track->opaque,
            &values[TRACK_PARAM_OPAQUE]->v.str);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_live_api_tracks_post: failed to set opaque");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = ngx_live_json_commands_exec(channel, NGX_LIVE_JSON_CTX_TRACK, track,
        &body->v.obj, log);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_http_live_api_track_put: json commands failed %i", rc);
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_api_track_delete(ngx_http_request_t *r, ngx_str_t *params,
    ngx_str_t *response)
{
    ngx_str_t            track_id;
    ngx_str_t            channel_id;
    ngx_live_track_t    *track;
    ngx_live_channel_t  *channel;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_track_delete: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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
    ngx_str_t                      track_id;
    ngx_str_t                      variant_id;
    ngx_str_t                      channel_id;
    ngx_log_t                     *log = r->connection->log;
    ngx_live_track_t              *track;
    ngx_json_value_t              *values[TRACK_PARAM_COUNT];
    ngx_live_channel_t            *channel;
    ngx_live_variant_t            *variant;
    ngx_http_live_api_loc_conf_t  *llcf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_track_params, values);

    if (values[TRACK_PARAM_ID] == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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

    track_id = values[TRACK_PARAM_ID]->v.str;
    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_variant_tracks_post: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
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
ngx_http_live_api_timeline_init_conf(ngx_json_value_t **values,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf)
{
    if (values[TIMELINE_PARAM_MAX_SEGMENTS] != NULL) {
        conf->max_segments = values[TIMELINE_PARAM_MAX_SEGMENTS]->v.num.num;
    }

    if (values[TIMELINE_PARAM_MAX_DURATION] != NULL) {
        conf->max_duration = values[TIMELINE_PARAM_MAX_DURATION]->v.num.num;
    }

    if (values[TIMELINE_PARAM_START] != NULL) {
        conf->start = values[TIMELINE_PARAM_START]->v.num.num;
    }

    if (values[TIMELINE_PARAM_END] != NULL) {
        conf->end = values[TIMELINE_PARAM_END]->v.num.num;
    }

    if (values[TIMELINE_PARAM_ACTIVE] != NULL) {
        conf->active = values[TIMELINE_PARAM_ACTIVE]->v.boolean;
    }

    if (values[TIMELINE_PARAM_NO_TRUNCATE] != NULL) {
        conf->no_truncate = values[TIMELINE_PARAM_NO_TRUNCATE]->v.boolean;
    }


    if (values[TIMELINE_PARAM_MANIFEST_MAX_SEGMENTS] != NULL) {
        manifest_conf->max_segments =
            values[TIMELINE_PARAM_MANIFEST_MAX_SEGMENTS]->v.num.num;
    }

    if (values[TIMELINE_PARAM_MANIFEST_MAX_DURATION] != NULL) {
        manifest_conf->max_duration =
            values[TIMELINE_PARAM_MANIFEST_MAX_DURATION]->v.num.num;
    }

    if (values[TIMELINE_PARAM_MANIFEST_EXPIRY_THRESHOLD] != NULL) {
        manifest_conf->expiry_threshold =
            values[TIMELINE_PARAM_MANIFEST_EXPIRY_THRESHOLD]->v.num.num;
    }

    if (values[TIMELINE_PARAM_MANIFEST_TARGET_DURATION_SEGMENTS] != NULL) {
        manifest_conf->target_duration_segments =
            values[TIMELINE_PARAM_MANIFEST_TARGET_DURATION_SEGMENTS]->v.num.num;
    }
}

static ngx_int_t
ngx_http_live_api_timelines_post(ngx_http_request_t *r, ngx_str_t *params,
    ngx_json_value_t *body)
{
    ngx_int_t                           rc;
    ngx_str_t                           channel_id;
    ngx_str_t                           timeline_id;
    ngx_log_t                          *log = r->connection->log;
    ngx_json_value_t                   *values[TIMELINE_PARAM_COUNT];
    ngx_live_channel_t                 *channel;
    ngx_live_timeline_t                *source;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_conf_t            conf;
    ngx_http_live_api_loc_conf_t       *llcf;
    ngx_live_timeline_manifest_conf_t   manifest_conf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timelines_post: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_timeline_params, values);

    if (values[TIMELINE_PARAM_ID] == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timelines_post: missing mandatory params");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timelines_post: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
    }

    if (values[TIMELINE_PARAM_SOURCE_ID] != NULL) {
        timeline_id = values[TIMELINE_PARAM_SOURCE_ID]->v.str;
        source = ngx_live_timeline_get(channel, &timeline_id);
        if (source == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_timelines_post: "
                "unknown timeline \"%V\" in channel \"%V\"",
                &timeline_id, &channel_id);
            return NGX_HTTP_NOT_FOUND;
        }

    } else {
        source = NULL;
    }

    timeline_id = values[TIMELINE_PARAM_ID]->v.str;

    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&manifest_conf, sizeof(manifest_conf));

    conf.active = 1;    /* active by default */
    manifest_conf.target_duration_segments = 3;

    ngx_http_live_api_timeline_init_conf(values, &conf, &manifest_conf);

    rc = ngx_live_timeline_create(channel, &timeline_id, &conf,
        &manifest_conf, log, &timeline);
    switch (rc) {

    case NGX_BUSY:
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_api_module);
        if (!llcf->upsert) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_http_live_api_timelines_post: "
                "timeline \"%V\" already exists in channel \"%V\"",
                &timeline_id, &channel_id);
            return NGX_HTTP_CONFLICT;
        }

        conf = timeline->conf;
        manifest_conf = timeline->manifest.conf;

        ngx_http_live_api_timeline_init_conf(values, &conf, &manifest_conf);

        if (ngx_live_timeline_update(timeline, &conf, &manifest_conf, log)
            != NGX_OK)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        return NGX_OK;

    case NGX_DECLINED:
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

    ngx_str_t             channel_id;
    ngx_str_t             timeline_id;
    ngx_live_channel_t   *channel;
    ngx_live_timeline_t  *timeline;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_timeline_get: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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
    ngx_str_t                           channel_id;
    ngx_str_t                           timeline_id;
    ngx_log_t                          *log = r->connection->log;
    ngx_json_value_t                   *values[TIMELINE_PARAM_COUNT];
    ngx_live_channel_t                 *channel;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_conf_t            conf;
    ngx_live_timeline_manifest_conf_t   manifest_conf;

    if (body->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timeline_put: "
            "invalid element type %d, expected object", body->type);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&body->v.obj, ngx_live_timeline_params, values);


    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_http_live_api_timeline_put: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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

    ngx_http_live_api_timeline_init_conf(values, &conf, &manifest_conf);

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
    ngx_str_t             channel_id;
    ngx_str_t             timeline_id;
    ngx_live_channel_t   *channel;
    ngx_live_timeline_t  *timeline;

    channel_id = params[0];
    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_api_timeline_delete: unknown channel \"%V\"",
            &channel_id);
        return NGX_HTTP_NOT_FOUND;
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
    ngx_http_live_start_time = ngx_cached_time->sec;

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
