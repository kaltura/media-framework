#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "ngx_http_live_core_module.h"
#include "../ngx_live_segment_cache.h"
#include "../ngx_live_media_info.h"
#include "../media/buffer_pool.h"


#define NGX_HTTP_LIVE_DEFAULT_LAST_MODIFIED  (1262304000)   /* 1/1/2010 */


static ngx_int_t ngx_http_live_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_live_ctx_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_live_segment_dts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_live_source_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_live_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_live_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_live_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_live_buffer_pool_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_int_t  ngx_http_live_error_map[VOD_ERROR_LAST - VOD_ERROR_FIRST] = {
    NGX_HTTP_NOT_FOUND,                 /* VOD_BAD_DATA             */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_ALLOC_FAILED         */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_UNEXPECTED           */
    NGX_HTTP_BAD_REQUEST,               /* VOD_BAD_REQUEST          */
    NGX_HTTP_SERVICE_UNAVAILABLE,       /* VOD_BAD_MAPPING          */
    NGX_HTTP_NOT_FOUND,                 /* VOD_EXPIRED              */
    NGX_HTTP_NOT_FOUND,                 /* VOD_NO_STREAMS           */
    NGX_HTTP_NOT_FOUND,                 /* VOD_EMPTY_MAPPING        */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_NOT_FOUND (internal) */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_REDIRECT (internal)  */
};


static ngx_command_t  ngx_http_live_core_commands[] = {

    { ngx_string("live_channel_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, channel_id),
      NULL},

    { ngx_string("live_timeline_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, timeline_id),
      NULL},

    { ngx_string("live_expires_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t,
        expires[NGX_HTTP_LIVE_EXPIRES_STATIC]),
      NULL },

    { ngx_string("live_expires_index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t,
        expires[NGX_HTTP_LIVE_EXPIRES_INDEX]),
      NULL },

    { ngx_string("live_expires_master"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t,
        expires[NGX_HTTP_LIVE_EXPIRES_MASTER]),
      NULL },

    { ngx_string("live_last_modified_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_live_set_time_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, last_modified_static),
      NULL },

    { ngx_string("live_encryption_key_seed"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, encryption_key_seed),
      NULL },

    { ngx_string("live_encryption_iv_seed"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, encryption_iv_seed),
      NULL },

    { ngx_string("live_output_buffer_pool"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_live_buffer_pool_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, output_buffer_pool),
      NULL },

    { ngx_string("live_segment_metadata"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, segment_metadata),
      NULL },

    { ngx_string("live_empty_segments"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_core_loc_conf_t, empty_segments),
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_live_core_module_ctx = {
    ngx_http_live_add_variables,            /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_live_create_loc_conf,          /* create location configuration */
    ngx_http_live_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_live_core_module = {
    NGX_MODULE_V1,
    &ngx_http_live_core_module_ctx,         /* module context */
    ngx_http_live_core_commands,            /* module directives */
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

static ngx_http_variable_t  ngx_http_live_vars[] = {

    { ngx_string("live_channel_id"), NULL, ngx_http_live_ctx_variable,
      offsetof(ngx_http_live_core_ctx_t, params.channel_id), 0, 0 },

    { ngx_string("live_timeline_id"), NULL, ngx_http_live_ctx_variable,
      offsetof(ngx_http_live_core_ctx_t, params.timeline_id), 0, 0 },

    { ngx_string("live_variant_id"), NULL, ngx_http_live_ctx_variable,
      offsetof(ngx_http_live_core_ctx_t, params.variant_id), 0, 0 },

    { ngx_string("live_source"), NULL, ngx_http_live_source_variable,
      0, 0, 0 },

    { ngx_string("live_segment_dts"), NULL, ngx_http_live_segment_dts_variable,
      0, 0, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_live_options_content_type =
    ngx_string("text/plain");

static ngx_str_t  ngx_http_live_default_timeline_id = ngx_string("main");

static time_t  ngx_http_live_default_expires[NGX_HTTP_LIVE_EXPIRES_COUNT] = {
    8640000,        /* static - 100 days */
    3,              /* index - 3 sec */
    30,             /* master - 30 sec */
};

u_char  ngx_http_live_media_type_code[KMP_MEDIA_COUNT] = {
    'v',
    'a',
};


static u_char *
ngx_http_live_core_parse_uint32(u_char *start_pos, u_char *end_pos,
    uint32_t *result)
{
    uint32_t  value = 0;

    for (;
        start_pos < end_pos && *start_pos >= '0' && *start_pos <= '9';
        start_pos++)
    {
        value = value * 10 + *start_pos - '0';
    }
    *result = value;
    return start_pos;
}

static u_char *
ngx_http_live_core_extract_string(u_char *start_pos, u_char *end_pos,
    ngx_str_t *result)
{
    result->data = start_pos;
    start_pos = ngx_strlchr(start_pos, end_pos, '-');
    if (start_pos == NULL) {
        start_pos = end_pos;
    }

    result->len = start_pos - result->data;
    return start_pos;
}


#define expect_char(start_pos, end_pos, ch)                 \
    if (start_pos >= end_pos || *start_pos != ch) {         \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,   \
            "ngx_http_live_core_parse_uri_file_name: "      \
            "expected \"%c\"", ch);                         \
        return NGX_HTTP_BAD_REQUEST;                        \
    }                                                       \
    start_pos++;

#define skip_dash(start_pos, end_pos)                       \
    if (start_pos >= end_pos) {                             \
        return NGX_OK;                                      \
    }                                                       \
    if (*start_pos != '-' || end_pos - start_pos < 2) {     \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,   \
            "ngx_http_live_core_parse_uri_file_name: "      \
            "expected \"-\" followed by a specifier");      \
        return NGX_HTTP_BAD_REQUEST;                        \
    }                                                       \
    start_pos++;

ngx_int_t
ngx_http_live_core_parse_uri_file_name(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, uint32_t flags,
    ngx_http_live_request_params_t *result)
{
    uint32_t  media_type;

    result->media_type_mask = (1 << KMP_MEDIA_COUNT) - 1;

    /* required params */
    if ((flags & NGX_HTTP_LIVE_PARSE_REQUIRE_INDEX) != 0) {
        expect_char(start_pos, end_pos, '-');

        start_pos = ngx_http_live_core_parse_uint32(start_pos, end_pos,
            &result->index);
        if (result->index <= 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_parse_uri_file_name: "
                "failed to parse segment index");
            return NGX_HTTP_BAD_REQUEST;
        }
        result->index--;
    }

    if ((flags & NGX_HTTP_LIVE_PARSE_REQUIRE_SINGLE_VARIANT) != 0) {
        expect_char(start_pos, end_pos, '-');
        expect_char(start_pos, end_pos, 's');

        start_pos = ngx_http_live_core_extract_string(start_pos, end_pos,
            &result->variant_id);
    }

    /* optional params */
    skip_dash(start_pos, end_pos);

    if (*start_pos == 's' &&
        (flags & NGX_HTTP_LIVE_PARSE_OPTIONAL_VARIANTS) != 0)
    {
        do {

            start_pos++;    /* skip the s */

            if (result->variant_ids_count >= NGX_HTTP_LIVE_MAX_VARIANT_IDS) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_live_core_parse_uri_file_name: "
                    "number of variant ids exceeds the limit");
                return NGX_HTTP_BAD_REQUEST;
            }

            start_pos = ngx_http_live_core_extract_string(start_pos, end_pos,
                &result->variant_ids[result->variant_ids_count]);
            result->variant_ids_count++;

            skip_dash(start_pos, end_pos);

        } while (*start_pos == 's');
    }

    if ((*start_pos == 'v' || *start_pos == 'a') &&
        (flags & NGX_HTTP_LIVE_PARSE_OPTIONAL_MEDIA_TYPE) != 0)
    {
        result->media_type_mask = 0;

        while (*start_pos != '-') {

            switch (*start_pos) {

            case 'v':
                media_type = KMP_MEDIA_VIDEO;
                break;

            case 'a':
                media_type = KMP_MEDIA_AUDIO;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_live_core_parse_uri_file_name: "
                    "invalid media type");
                return NGX_HTTP_BAD_REQUEST;
            }

            if (result->media_type_mask & (1 << media_type)) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_live_core_parse_uri_file_name: "
                    "media type repeats more than once");
                return NGX_HTTP_BAD_REQUEST;
            }

            result->media_type_mask |= (1 << media_type);

            start_pos++;

            if (start_pos >= end_pos) {
                return NGX_OK;
            }
        }

        start_pos++;
        if (start_pos >= end_pos) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_parse_uri_file_name: "
                "trailing dash in file name");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_live_core_parse_uri_file_name: "
        "did not consume the whole name");
    return NGX_HTTP_BAD_REQUEST;
}

u_char *
ngx_http_live_write_media_type_mask(u_char *p, uint32_t media_type_mask)
{
    uint32_t  i;

    if (media_type_mask == (1 << KMP_MEDIA_COUNT) - 1) {
        return p;
    }

    *p++ = '-';
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        if (media_type_mask & (1 << i)) {
            *p++ = ngx_http_live_media_type_code[i];
        }
    }

    return p;
}

static ngx_int_t
ngx_http_live_find_string(ngx_str_t *arr, ngx_int_t count, ngx_str_t *str)
{
    ngx_int_t  index;

    for (index = 0; index < count; index++) {

        if (arr[index].len == str->len &&
            ngx_memcmp(arr[index].data, str->data, str->len) == 0) {
            return index;
        }
    }

    return -1;
}

ngx_flag_t
ngx_http_live_output_variant(ngx_http_live_core_ctx_t *ctx,
    ngx_live_variant_t *variant)
{
    ngx_uint_t  media_type;

    /* included in the request variant ids list */
    if (ctx->params.variant_ids_count > 0 &&
        ngx_http_live_find_string(ctx->params.variant_ids,
            ctx->params.variant_ids_count, &variant->sn.str) < 0)
    {
        return 0;
    }

    /* has tracks in the request media type list */
    if (ctx->params.media_type_mask != (1 << KMP_MEDIA_COUNT) - 1) {

        for (media_type = 0; ; media_type++) {

            if (media_type >= KMP_MEDIA_COUNT) {
                return 0;
            }

            if ((ctx->params.media_type_mask & (1 << media_type)) != 0
                && variant->tracks[media_type] != NULL)
            {
                break;
            }
        }
    }

    /* main track has the last segment */
    return ngx_live_variant_is_main_track_active(variant,
        ctx->params.media_type_mask);
}

ngx_int_t
ngx_http_live_generate_key(ngx_http_request_t *r, ngx_flag_t iv,
    ngx_str_t *salt, u_char *result)
{
    ngx_md5_t                       md5;
    ngx_str_t                       seed;
    ngx_http_complex_value_t       *value;
    ngx_http_live_core_ctx_t       *ctx;
    ngx_http_live_core_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

    value = NULL;

    if (iv && conf->encryption_iv_seed != NULL) {
        value = conf->encryption_iv_seed;

    }
    else if (conf->encryption_key_seed != NULL) {
        value = conf->encryption_key_seed;

    } else {
        ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

        seed = ctx->params.channel_id;
    }

    if (value != NULL) {
        if (ngx_http_complex_value(r, value, &seed) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_hls_get_seed: ngx_http_complex_value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_md5_init(&md5);
    if (salt != NULL) {
        ngx_md5_update(&md5, salt->data, salt->len);
    }
    ngx_md5_update(&md5, seed.data, seed.len);
    ngx_md5_final(result, &md5);

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_core_init_ctx(ngx_http_request_t *r,
    ngx_http_live_request_params_t *params,
    ngx_http_live_request_objects_t *objects)
{
    uint32_t                        media_type;
    ngx_http_live_core_ctx_t       *ctx;
    ngx_http_live_core_loc_conf_t  *conf;

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

    /* get the channel */
    if (conf->channel_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: live_channel_id not set in conf");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, conf->channel_id, &params->channel_id)
        != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: channel complex value failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(objects, sizeof(*objects));

    objects->channel = ngx_live_channel_get(&params->channel_id);
    if (objects->channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: unknown channel \"%V\"",
            &params->channel_id);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* get the timeline */
    if (conf->timeline_id != NULL) {

        if (ngx_http_complex_value(r, conf->timeline_id, &params->timeline_id)
            != NGX_OK)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_core_init_ctx: timeline complex value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        params->timeline_id = ngx_http_live_default_timeline_id;
    }

    objects->timeline = ngx_live_timeline_get(objects->channel,
        &params->timeline_id);
    if (objects->timeline == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: unknown timeline \"%V\"",
            &params->timeline_id);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (objects->timeline->manifest.segment_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: no segments in timeline \"%V\"",
            &params->timeline_id);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (params->request_flags & NGX_HTTP_LIVE_REQUEST_EXPIRING &&
        ngx_live_timeline_is_expired(objects->timeline))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_init_ctx: timeline \"%V\" is expired",
            &params->timeline_id);
        return NGX_HTTP_GONE;
    }

    /* get the variant
        Note: not using len, since it is possible to have empty variant id */
    if (params->variant_id.data != NULL) {

        objects->variant = ngx_live_variant_get(objects->channel,
            &params->variant_id);
        if (objects->variant == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_init_ctx: unknown variant \"%V\"",
                &params->variant_id);
            return NGX_HTTP_BAD_REQUEST;
        }

        /* get the tracks */
        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

            if ((params->media_type_mask & (1 << media_type)) == 0) {
                continue;
            }

            if (objects->variant->tracks[media_type] == NULL) {
                continue;
            }

            objects->tracks[media_type] = objects->variant->tracks[media_type];
            objects->track_count++;
        }

        if (objects->track_count <= 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_init_ctx: no tracks found");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    ctx->r = r;
    ctx->params = *params;
    ctx->request_context.log = r->connection->log;
    ctx->request_context.pool = r->pool;
    ctx->request_context.output_buffer_pool = conf->output_buffer_pool;

    ngx_http_set_ctx(r, ctx, ngx_http_live_core_module);

    return NGX_OK;
}

static char *
ngx_http_live_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t           *sp;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    sp = (time_t *)(p + cmd->offset);
    if (*sp != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = ngx_http_parse_time(value[1].data, value[1].len);
    if (*sp == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_live_buffer_pool_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ssize_t          buffer_size;
    ngx_int_t        count;
    ngx_str_t       *value;
    buffer_pool_t  **buffer_pool;

    buffer_pool = (buffer_pool_t **)(p + cmd->offset);
    if (*buffer_pool != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    buffer_size = ngx_parse_size(&value[1]);
    if (buffer_size == NGX_ERROR) {
        return "invalid size";
    }

    count = ngx_atoi(value[2].data, value[2].len);
    if (count == NGX_ERROR) {
        return "invalid count";
    }

    *buffer_pool = buffer_pool_create(cf->pool, cf->log, buffer_size, count);
    if (*buffer_pool == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Implemented according to nginx's ngx_http_range_parse,
    dropped multi range support */
static ngx_int_t
ngx_http_live_range_parse(ngx_str_t *range, off_t content_length,
    off_t *out_start, off_t *out_end)
{
    u_char            *p;
    off_t              start, end, cutoff, cutlim;
    ngx_uint_t         suffix;

    if (range->len < 7 ||
        ngx_strncasecmp(range->data,
        (u_char *) "bytes=", 6) != 0) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    p = range->data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    suffix = 0;

    while (*p == ' ') { p++; }

    if (*p != '-') {
        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            start = start * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p++ != '-') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p == ' ') { p++; }

        if (*p == '\0') {
            end = content_length;
            goto found;
        }

    } else {
        suffix = 1;
        p++;
    }

    if (*p < '0' || *p > '9') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        end = end * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (suffix) {
        start = content_length - end;
        end = content_length - 1;
    }

    if (end >= content_length) {
        end = content_length;

    } else {
        end++;
    }

found:

    if (start >= end) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    *out_start = start;
    *out_end = end;

    return NGX_OK;
}

/* A run down version of ngx_http_set_expires */
static ngx_int_t
ngx_http_live_set_expires(ngx_http_request_t *r, time_t expires_time)
{
    size_t               len;
    time_t               now, max_age;
    ngx_uint_t           i;
    ngx_table_elt_t     *e, *cc, **ccp;

    e = r->headers_out.expires;

    if (e == NULL) {

        e = ngx_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        ngx_str_set(&e->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    e->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
            1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    e->value.data = ngx_pnalloc(r->pool, len);
    if (e->value.data == NULL) {
        return NGX_ERROR;
    }

    if (expires_time == 0) {
        ngx_memcpy(e->value.data, ngx_cached_http_time.data,
            ngx_cached_http_time.len + 1);
        ngx_str_set(&cc->value, "max-age=0");
        return NGX_OK;
    }

    now = ngx_time();

    max_age = expires_time;
    expires_time += now;

    ngx_http_time(e->value.data, expires_time);

    if (max_age < 0) {
        ngx_str_set(&cc->value, "no-cache");
        return NGX_OK;
    }

    cc->value.data = ngx_pnalloc(r->pool,
        sizeof("max-age=") + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", max_age)
        - cc->value.data;

    return NGX_OK;
}

ngx_int_t
ngx_http_live_send_header(ngx_http_request_t *r, off_t content_length_n,
    ngx_str_t *content_type, time_t last_modified_time,
    ngx_uint_t expires_type)
{
    time_t                          expires_time;
    ngx_int_t                       rc;
    ngx_http_live_core_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

    if (content_type != NULL) {
        r->headers_out.content_type = *content_type;
        r->headers_out.content_type_len = content_type->len;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_length_n;

    /* last modified */
    if (last_modified_time >= 0) {
        r->headers_out.last_modified_time = last_modified_time;

    } else if (conf->last_modified_static >= 0) {
        r->headers_out.last_modified_time = conf->last_modified_static;
    }

    /* expires */
    expires_time = conf->expires[expires_type];
    if (expires_time >= 0) {
        rc = ngx_http_live_set_expires(r, expires_time);
        if (rc != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_send_header: failed to set expires %i", rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* set the etag */
    rc = ngx_http_set_etag(r);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_send_header: ngx_http_set_etag failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* send the response headers */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_send_header: ngx_http_send_header failed %i", rc);
        return rc;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_live_send_response(ngx_http_request_t *r, ngx_str_t *response)
{
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t   out;

    if (r->header_only || r->method == NGX_HTTP_HEAD) {
        return NGX_OK;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_send_response: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = response->data;
    b->last = response->data + response->len;
    if (response->len > 0) {
        b->temporary = 1;
    }
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_send_response: output filter failed %i", rc);
        return rc;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_live_status_to_ngx_error(ngx_http_request_t *r, vod_status_t rc)
{
    if (rc < VOD_ERROR_FIRST || rc >= VOD_ERROR_LAST) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_live_error_map[rc - VOD_ERROR_FIRST];
}

ngx_int_t
ngx_http_live_core_handler(ngx_http_request_t *r,
    ngx_http_live_submodule_t *module)
{
    u_char                           *end_pos;
    u_char                           *start_pos;
    ngx_int_t                         rc;
    ngx_str_t                         response;
    ngx_http_live_request_params_t    params;
    ngx_http_live_request_objects_t   objects;

    /* handle options */
    if (r->method == NGX_HTTP_OPTIONS) {

        rc = ngx_http_live_send_header(r, 0,
            &ngx_http_live_options_content_type, -1, 0);
        if (rc != NGX_OK) {
            return rc;
        }

        response.data = NULL;
        response.len = 0;

        return ngx_http_live_send_response(r, &response);
    }

    /* we respond to 'GET' and 'HEAD' requests only */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_handler: unsupported method %ui", r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* discard request body, don't need it here */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_handler: discard body failed %i", rc);
        return rc;
    }

    /* parse the file name */
    start_pos = memrchr(r->uri.data, '/', r->uri.len);
    if (start_pos == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_handler: no \"/\" found in uri");
        return NGX_HTTP_BAD_REQUEST;
    }

    start_pos++;        /* skip the / */
    end_pos = r->uri.data + r->uri.len;

    ngx_memzero(&params, sizeof(params));

    rc = module->parse_uri_file_name(r, start_pos, end_pos, &params);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_handler: parse file name failed %i", rc);
        return rc;
    }

    /* initialize the context */
    rc = ngx_http_live_core_init_ctx(r, &params, &objects);
    if (rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_handler: init ctx failed");
        return rc;
    }

    r->allow_ranges = 1;

    /* run the handler */
    return params.handler->handler(r, &objects);
}

static vod_status_t
ngx_http_live_write_segment_buffer(void *arg, u_char *buffer, uint32_t size)
{
    ngx_buf_t                           *b;
    ngx_int_t                            rc;
    ngx_chain_t                          out;
    ngx_chain_t                         *chain;
    ngx_http_request_t                  *r;
    ngx_http_live_segment_writer_ctx_t  *ctx;

    if (size <= 0) {
        return VOD_OK;
    }

    ctx = arg;
    r = ctx->r;

    /* create a wrapping ngx_buf_t */
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_write_segment_buffer: alloc buf failed");
        return VOD_ALLOC_FAILED;
    }

    b->pos = buffer;
    b->last = buffer + size;
    b->temporary = 1;

    if (r->header_sent) {

        /* headers already sent, output the chunk */
        out.buf = b;
        out.next = NULL;

        rc = ngx_http_output_filter(r, &out);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            /* either the connection dropped, or some allocation failed
               in case the connection dropped, the error code doesn't matter */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_write_segment_buffer: "
                "ngx_http_output_filter failed %i", rc);
            return VOD_ALLOC_FAILED;
        }

    } else {

        /* headers not sent yet, add the buffer to the chain */
        if (ctx->last->buf != NULL) {

            chain = ngx_alloc_chain_link(r->pool);
            if (chain == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_live_write_segment_buffer: alloc chain failed");
                return VOD_ALLOC_FAILED;
            }

            ctx->last->next = chain;
            ctx->last = chain;
        }
        ctx->last->buf = b;
    }

    ctx->total_size += size;

    return VOD_OK;
}

static vod_status_t
ngx_http_live_write_segment_head_buffer(void *arg, u_char *buffer,
    uint32_t size)
{
    ngx_buf_t                           *b;
    ngx_chain_t                         *chain;
    ngx_http_request_t                  *r;
    ngx_http_live_segment_writer_ctx_t  *ctx = arg;

    r = ctx->r;

    if (r->header_sent) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_write_segment_head_buffer: "
            "called after the headers were already sent");
        return VOD_UNEXPECTED;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_write_segment_head_buffer: alloc buf failed");
        return VOD_ALLOC_FAILED;
    }

    b->pos = buffer;
    b->last = buffer + size;
    b->temporary = 1;

    chain = ngx_alloc_chain_link(r->pool);
    if (chain == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_write_segment_head_buffer: alloc chain failed");
        return VOD_ALLOC_FAILED;
    }

    *chain = ctx->out;
    if (ctx->last == &ctx->out) {
        ctx->last = chain;
    }

    ctx->out.buf = b;
    ctx->out.next = chain;

    ctx->total_size += size;

    return VOD_OK;
}

static ngx_int_t
ngx_http_live_finalize_segment_response(ngx_http_live_core_ctx_t *ctx)
{
    ngx_int_t            rc;
    ngx_http_request_t  *r = ctx->r;

    rc = ctx->segment_writer.write_tail(ctx->segment_writer.context, NULL, 0);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_finalize_segment_response: write_tail failed %i",
            rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* if we everything was already sent, just signal completion and return */
    if (r->header_sent) {

        if (ctx->segment_writer_ctx.total_size != ctx->content_length &&
            (ctx->size_limit == 0 ||
            ctx->segment_writer_ctx.total_size < ctx->size_limit)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "ngx_http_live_finalize_segment_response: "
                "actual content length %uz different than reported length %uz",
                ctx->segment_writer_ctx.total_size, ctx->content_length);
        }

        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_finalize_segment_response: "
                "ngx_http_send_special failed %i", rc);
            return rc;
        }

        return NGX_OK;
    }

    /* mark the current buffer as last */
    if (ctx->segment_writer_ctx.last->buf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_finalize_segment_response: "
            "no buffers were written");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->segment_writer_ctx.last->next = NULL;
    ctx->segment_writer_ctx.last->buf->last_buf = 1;

    /* send the response header */
    rc = ngx_http_live_send_header(r, ctx->segment_writer_ctx.total_size,
        NULL, -1, 0);
    if (rc != NGX_OK) {
        return rc;
    }

    if (r->header_only || r->method == NGX_HTTP_HEAD) {
        return NGX_OK;
    }

    /* send the response buffer chain */
    rc = ngx_http_output_filter(r, &ctx->segment_writer_ctx.out);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_finalize_segment_response: "
            "ngx_http_output_filter failed %i", rc);
        return rc;
    }

    return NGX_OK;
}

static void
ngx_http_live_core_init_writer(ngx_http_live_core_ctx_t *ctx)
{
    ctx->segment_writer_ctx.r = ctx->r;
    ctx->segment_writer_ctx.last = &ctx->segment_writer_ctx.out;

    ctx->segment_writer.write_tail = ngx_http_live_write_segment_buffer;
    ctx->segment_writer.write_head = ngx_http_live_write_segment_head_buffer;
    ctx->segment_writer.context = &ctx->segment_writer_ctx;
}


static ngx_int_t
ngx_http_live_core_write_segment(ngx_http_request_t *r)
{
    void                              *processor_state;
    off_t                              range_start;
    off_t                              range_end;
    ngx_str_t                          output_buffer = ngx_null_string;
    ngx_str_t                          content_type;
    vod_status_t                       rc;
    ngx_http_live_core_ctx_t          *ctx;
    ngx_http_live_core_loc_conf_t     *conf;
    ngx_http_live_frame_processor_pt   processor;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

    if (conf->segment_metadata != NULL) {
        if (ngx_http_complex_value(r, conf->segment_metadata,
            &ctx->segment->metadata) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_core_write_segment: "
                "ngx_http_complex_value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_http_live_core_init_writer(ctx);

    rc = ctx->params.handler->init_frame_processor(r, ctx->segment, &processor,
        &processor_state, &output_buffer, &ctx->content_length, &content_type);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_write_segment: init processor failed %i", rc);
        return rc;
    }

    r->headers_out.content_type = content_type;
    r->headers_out.content_type_len = content_type.len;

    if (ctx->content_length != 0) {

        /* send the response header */
        rc = ngx_http_live_send_header(r, ctx->content_length, NULL, -1, 0);
        if (rc != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_core_write_segment: send header failed %i", rc);
            return rc;
        }

        if (r->header_only || r->method == NGX_HTTP_HEAD) {
            return NGX_OK;
        }

        /* in case of range request, get the end offset */
        if (r->headers_in.range != NULL &&
            ngx_http_live_range_parse(&r->headers_in.range->value,
                ctx->content_length, &range_start, &range_end) == NGX_OK)
        {
            ctx->size_limit = range_end;
        }
    }

    if (output_buffer.len != 0) {

        rc = ctx->segment_writer.write_tail(
            ctx->segment_writer.context,
            output_buffer.data,
            output_buffer.len);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_core_write_segment: write_tail failed %i", rc);
            return ngx_http_live_status_to_ngx_error(r, rc);
        }

        /* if the request range is fully contained in the output buffer
            (e.g. 0-0), we're done */
        if (ctx->size_limit != 0 &&
            output_buffer.len >= ctx->size_limit && r->header_sent)
        {
            return NGX_OK;
        }
    }

    if (processor_state != NULL) {
        rc = processor(processor_state);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_live_core_write_segment: processor failed %i", rc);
            return ngx_http_live_status_to_ngx_error(r, rc);
        }
    }

    rc = ngx_http_live_finalize_segment_response(ctx);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_write_segment: finalize failed %i", rc);
        return ngx_http_live_status_to_ngx_error(r, rc);
    }

    return NGX_OK;
}

static void
ngx_http_live_core_write_segment_async(void *arg, ngx_int_t rc)
{
    ngx_connection_t               *c;
    ngx_http_request_t             *r = arg;
    ngx_http_live_core_loc_conf_t  *conf;

    switch (rc) {

    case NGX_ABORT:
        conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

        if (!conf->empty_segments) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_write_segment_async: segment not found");
            rc = NGX_HTTP_NOT_FOUND;
            break;
        }
        /* fall through */

    case NGX_OK:
        rc = ngx_http_live_core_write_segment(r);
        break;
    }

    c = r->connection;

    ngx_http_finalize_request(r, rc);

    ngx_http_run_posted_requests(c);
}

static ngx_live_track_ref_t *
ngx_http_live_core_get_track_refs(ngx_http_request_t *r,
    ngx_http_live_request_objects_t *objects, uint32_t segment_index,
    media_segment_t *segment)
{
    uint32_t                i;
    ngx_live_track_t       *cur_track;
    ngx_live_track_ref_t   *result;
    ngx_live_track_ref_t   *cur;
    media_segment_track_t  *seg_track;

    result = ngx_palloc(r->pool, sizeof(result[0]) * objects->track_count);
    if (result == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_get_track_refs: alloc failed");
        return NULL;
    }

    seg_track = segment->tracks;
    cur = result;

    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        cur_track = objects->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        seg_track->media_info = ngx_live_media_info_queue_get(
            cur_track, segment_index, &cur->id);
        if (seg_track->media_info == NULL) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "ngx_http_live_core_get_track_refs: "
                "media info not found, track: %V, index: %uD",
                &cur_track->sn.str, segment_index);
            continue;
        }

        seg_track++;
        segment->track_count++;

        if (cur->id == cur_track->in.key) {
            cur->track = cur_track;

        } else {
            cur->track = ngx_live_track_get_by_int(objects->channel, cur->id);
        }
        cur++;
    }

    segment->tracks_end = seg_track;

    return result;
}

ngx_int_t
ngx_http_live_core_segment_handler(ngx_http_request_t *r,
    ngx_http_live_request_objects_t *objects)
{
    ngx_int_t                       rc;
    media_segment_t                *segment;
    ngx_http_live_core_ctx_t       *ctx;
    ngx_live_segment_read_req_t     req;
    ngx_http_live_core_loc_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    if (!ngx_live_timeline_contains_segment(objects->timeline,
        ctx->params.index))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_segment_handler: "
            "segment %uD does not exist in timeline \"%V\"",
            ctx->params.index, &objects->timeline->sn.str);
        return NGX_HTTP_BAD_REQUEST;
    }

    segment = ngx_pcalloc(r->pool, sizeof(*segment) +
        sizeof(segment->tracks[0]) * objects->track_count);
    if (segment == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_segment_handler: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    segment->tracks = (void*)(segment + 1);
    segment->segment_index = ctx->params.index;

    req.tracks = ngx_http_live_core_get_track_refs(r, objects,
        ctx->params.index, segment);
    if (req.tracks == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_segment_handler: failed to get track refs");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (segment->track_count <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_core_segment_handler: "
            "no media info found, index: %uD", ctx->params.index);
        return NGX_HTTP_BAD_REQUEST;
    }

    ctx->segment = segment;

    req.pool = r->pool;
    req.channel = objects->channel;
    req.flags = ctx->params.read_flags;
    req.segment = segment;
    req.callback = ngx_http_live_core_write_segment_async;
    req.arg = r;

    rc = ngx_live_read_segment(&req);
    switch (rc) {

    case NGX_DONE:
        r->main->count++;
        return NGX_DONE;

    case NGX_ABORT:
        conf = ngx_http_get_module_loc_conf(r, ngx_http_live_core_module);

        if (!conf->empty_segments) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_core_segment_handler: "
                "segment %uD not found", ctx->params.index);
            return NGX_HTTP_NOT_FOUND;
        }
        /* fall through */

    case NGX_OK:
        return ngx_http_live_core_write_segment(r);

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_core_segment_handler: read failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

ngx_int_t
ngx_http_live_core_get_init_segment(ngx_http_request_t *r,
    ngx_http_live_request_objects_t *objects,
    media_init_segment_t *result)
{
    uint32_t                     i;
    uint32_t                     ignore;
    media_info_t                *media_info;
    ngx_live_track_t            *cur_track;
    ngx_http_live_core_ctx_t    *ctx;
    media_init_segment_track_t  *cur;

    cur = ngx_pcalloc(r->pool, sizeof(*cur) * objects->track_count);
    if (cur == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_core_get_init_segment: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->first = cur;
    result->count = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        cur_track = objects->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        media_info = ngx_live_media_info_queue_get(cur_track,
            ctx->params.index, &ignore);
        if (media_info == NULL) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "ngx_http_live_core_get_init_segment: "
                "media info not found, track: %V, index: %uD",
                &cur_track->sn.str, ctx->params.index);
            continue;
        }

        cur->media_info = media_info;

        cur++;
        result->count++;
    }

    if (result->count <= 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_http_live_core_get_init_segment: "
            "no media info found, index: %uD", ctx->params.index);
        return NGX_HTTP_BAD_REQUEST;
    }

    result->last = cur;

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_live_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_ctx_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                 *s;
    ngx_http_live_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    s = (ngx_str_t *)((char *) ctx + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_source_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_live_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);
    if (ctx == NULL || ctx->segment == NULL || ctx->segment->source.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->segment->source.data;
    v->len = ctx->segment->source.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_live_segment_dts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    int64_t                    dts;
    media_segment_track_t     *track;
    ngx_http_live_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);
    if (ctx == NULL || ctx->segment == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_palloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    track = &ctx->segment->tracks[0];
    dts = (track->start_dts * 1000) / track->media_info->timescale;

    v->len = ngx_sprintf(v->data, "%L", dts) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static void *
ngx_http_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_uint_t                      type;
    ngx_http_live_core_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_core_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_live_create_loc_conf: ngx_pcalloc failed");
        return NULL;
    }

    for (type = 0; type < NGX_HTTP_LIVE_EXPIRES_COUNT; type++) {
        conf->expires[type] = NGX_CONF_UNSET;
    }
    conf->last_modified_static = NGX_CONF_UNSET;

    conf->empty_segments = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t                      type;
    ngx_http_live_core_loc_conf_t  *prev = parent;
    ngx_http_live_core_loc_conf_t  *conf = child;

    if (conf->channel_id == NULL) {
        conf->channel_id = prev->channel_id;
    }

    if (conf->timeline_id == NULL) {
        conf->timeline_id = prev->timeline_id;
    }

    for (type = 0; type < NGX_HTTP_LIVE_EXPIRES_COUNT; type++) {
        ngx_conf_merge_value(conf->expires[type],
                             prev->expires[type],
                             ngx_http_live_default_expires[type]);
    }

    ngx_conf_merge_value(conf->last_modified_static,
                         prev->last_modified_static,
                         NGX_HTTP_LIVE_DEFAULT_LAST_MODIFIED);

    if (conf->encryption_key_seed == NULL) {
        conf->encryption_key_seed = prev->encryption_key_seed;
    }

    if (conf->encryption_iv_seed == NULL) {
        conf->encryption_iv_seed = prev->encryption_iv_seed;
    }

    ngx_conf_merge_value(conf->empty_segments,
                         prev->empty_segments, 0);

    return NGX_CONF_OK;
}
