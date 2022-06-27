#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_utils.h"

#include "media/thumb/thumb_grabber.h"


static ngx_int_t ngx_http_pckg_capture_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_pckg_capture_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_capture_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_capture_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    ngx_flag_t              enable;
    ngx_flag_t              redirect;
    ngx_uint_t              granularity;
} ngx_http_pckg_capture_loc_conf_t;


typedef struct {
    ngx_str_t               uri_suffix;
    thumb_grabber_params_t  params;
} ngx_http_pckg_capture_ctx_t;


static ngx_conf_enum_t  ngx_http_pckg_capture_granularity[] = {
    { ngx_string("frame"),  NGX_KSMP_FLAG_MEDIA_MIN_GOP },
    { ngx_string("key"),    NGX_KSMP_FLAG_MEDIA_CLOSEST_KEY },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_capture_commands[] = {

    { ngx_string("pckg_capture"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_capture_loc_conf_t, enable),
      NULL },

    { ngx_string("pckg_capture_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_capture_loc_conf_t, redirect),
      NULL },

    { ngx_string("pckg_capture_granularity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_capture_loc_conf_t, granularity),
      &ngx_http_pckg_capture_granularity },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_capture_module_ctx = {
    ngx_http_pckg_capture_preconfiguration, /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_pckg_capture_create_loc_conf,  /* create location configuration */
    ngx_http_pckg_capture_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_capture_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_capture_module_ctx,      /* module context */
    ngx_http_pckg_capture_commands,         /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_http_pckg_capture_init_process,     /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_pckg_capture_content_type =
    ngx_string("image/jpeg");

static ngx_str_t  ngx_http_pckg_capture_ext = ngx_string(".jpg");


static ngx_int_t
ngx_http_pckg_capture_init_process(ngx_cycle_t *cycle)
{
    thumb_grabber_process_init(cycle->log);

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_capture_init_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment, ngx_http_pckg_frame_processor_t *processor)
{
    vod_status_t                  rc;
    segment_writer_t             *writer;
    ngx_http_pckg_core_ctx_t     *ctx;
    ngx_http_pckg_capture_ctx_t  *cctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    cctx = ngx_http_get_module_ctx(r, ngx_http_pckg_capture_module);

    writer = &ctx->segment_writer;
    cctx->params.time = ctx->channel->segment_index->time;

    rc = thumb_grabber_init_state(&ctx->request_context, segment->tracks,
        &cctx->params, writer->write_tail, writer->context, &processor->ctx);
    if (rc != VOD_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_capture_init_frame_processor: init failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    processor->process = thumb_grabber_process;
    processor->content_type = ngx_http_pckg_capture_content_type;

    return NGX_OK;
}


#if (NGX_HAVE_LIB_SW_SCALE)

#define skip_dash(cur, end)                                                 \
    if (cur >= end) {                                                       \
        return cur;                                                         \
    }                                                                       \
                                                                            \
    if (*cur != '-' || end - cur < 2) {                                     \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,                   \
            "ngx_http_pckg_capture_parse_dims: "                            \
            "expected \"-\" followed by a specifier");                      \
        return NULL;                                                        \
    }                                                                       \
                                                                            \
    cur++;    /* skip the - */


static u_char *
ngx_http_pckg_capture_parse_dims(ngx_http_request_t *r, u_char *cur,
    u_char *end)
{
    ngx_http_pckg_capture_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_pckg_capture_module);

    /* width */

    if (*cur == 'w') {
        cur++;    /* skip the w */

        cur = ngx_http_pckg_parse_uint32(cur, end, &cctx->params.width);
        if (cctx->params.width <= 0) {
            return NULL;
        }

        skip_dash(cur, end);
    }

    /* height */

    if (*cur == 'h') {
        cur++;    /* skip the h */

        cur = ngx_http_pckg_parse_uint32(cur, end, &cctx->params.height);
        if (cctx->params.height <= 0) {
            return NULL;
        }

        skip_dash(cur, end);
    }

    return cur;
}
#endif

static ngx_int_t
ngx_http_pckg_capture_parse_uri(ngx_http_request_t *r,
    u_char *cur, u_char *end, ngx_pckg_ksmp_req_t *result)
{
    ngx_http_pckg_capture_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_pckg_capture_module);

    /*  required params */

    if (cur >= end || *cur != '-') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: expected \"-\"");
        return NGX_HTTP_BAD_REQUEST;
    }

    cur++;        /* skip the - */

    if (cur < end) {
        switch (*cur) {

        case '-':
            cur++;        /* skip the - */
            result->flags |= NGX_KSMP_FLAG_TIME_END_RELATIVE;
            break;

        case '+':
            cur++;        /* skip the + */
            result->flags |= NGX_KSMP_FLAG_TIME_START_RELATIVE;
            break;
        }
    }

    if (cur >= end || *cur < '0' || *cur > '9') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: time expected");
        return NGX_HTTP_BAD_REQUEST;
    }

    result->time = 0;
    do
    {
        result->time = result->time * 10 + *cur++ - '0';
    } while (cur < end && *cur >= '0' && *cur <= '9');

    if (result->time == NGX_KSMP_INVALID_TIMESTAMP) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: invalid time");
        return NGX_HTTP_BAD_REQUEST;
    }


    cctx->uri_suffix.data = cur;
    cctx->uri_suffix.len = end - cur;

    if (cur + 1 >= end || cur[0] != '-' || cur[1] != 's') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: expected \"-s\"");
        return NGX_HTTP_BAD_REQUEST;
    }

    cur += 2;   /* skip the -s */

    cur = ngx_http_pckg_extract_string(cur, end, &result->variant_ids);
    if (ngx_strlchr(result->variant_ids.data, cur, ',') != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: invalid variant id \"%V\"",
            &result->variant_ids);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* optional params */

    if (cur >= end) {
        return NGX_OK;
    }

    cur++;      /* skip the - */

#if (NGX_HAVE_LIB_SW_SCALE)
    cur = ngx_http_pckg_capture_parse_dims(r, cur, end);
    if (cur == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_uri: failed to parse width/height");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (cur >= end) {
        return NGX_OK;
    }
#endif

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_pckg_capture_parse_uri: "
        "did not consume the whole name");
    return NGX_HTTP_BAD_REQUEST;
}


static ngx_int_t
ngx_http_pckg_capture_redirect(ngx_http_request_t *r)
{
    u_char                       *p;
    size_t                        size;
    int64_t                       time;
    ngx_table_elt_t              *location;
    ngx_http_pckg_core_ctx_t     *ctx;
    ngx_http_pckg_capture_ctx_t  *cctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_pckg_capture_module);

    size = sizeof("-") - 1 + ngx_http_pckg_prefix_frame.len + NGX_INT64_LEN
        + cctx->uri_suffix.len + ngx_http_pckg_capture_ext.len;

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_capture_redirect: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_clear_location(r);

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_capture_redirect: push failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    time = rescale_time(ctx->channel->segment_index->time,
        ctx->channel->header->timescale, 1000);

    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;

    location->hash = 1;
#if (nginx_version >= 1023000)
    location->next = NULL;
#endif
    ngx_str_set(&location->key, "Location");

    location->value.data = p;
    p = ngx_sprintf(p, "%V-%L%V%V", &ngx_http_pckg_prefix_frame, time,
        &cctx->uri_suffix, &ngx_http_pckg_capture_ext);
    location->value.len = p - location->value.data;

    r->headers_out.location = location;

    return r->headers_out.status;
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_redirect_handler = {
    ngx_http_pckg_capture_redirect,
    NULL,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_capture_handler = {
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_capture_init_frame_processor,
};


static ngx_int_t
ngx_http_pckg_capture_parse_request(ngx_http_request_t *r, u_char *cur,
    u_char *end, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    ngx_int_t                          rc;
    ngx_http_pckg_capture_ctx_t       *cctx;
    ngx_http_pckg_capture_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_capture_module);

    if (!clcf->enable || !ngx_http_pckg_match_prefix(cur, end,
        ngx_http_pckg_prefix_frame))
    {
        return NGX_DECLINED;
    }

    cur += ngx_http_pckg_prefix_frame.len;


    cctx = ngx_pcalloc(r->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_capture_parse_request: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, cctx, ngx_http_pckg_capture_module);


    result->flags = 0;
    result->media_type_mask = 1 << KMP_MEDIA_VIDEO;
    result->media_type_count = 1;

    rc = ngx_http_pckg_capture_parse_uri(r, cur, end, result);
    if (rc != NGX_OK) {
        return rc;
    }

    if (clcf->redirect && (result->flags & NGX_KSMP_FLAG_TIME_RELATIVE)) {
        *handler = &ngx_http_pckg_redirect_handler;
        return NGX_OK;
    }

    *handler = &ngx_http_pckg_capture_handler;

    result->padding = VOD_BUFFER_PADDING_SIZE;
    result->flags |= NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_MEDIA
        | clcf->granularity;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_capture_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_capture_ext,
        ngx_http_pckg_capture_parse_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_pckg_capture_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_capture_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_capture_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_pckg_capture_create_loc_conf: ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->redirect = NGX_CONF_UNSET;
    conf->granularity = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_pckg_capture_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_capture_loc_conf_t  *prev = parent;
    ngx_http_pckg_capture_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    ngx_conf_merge_uint_value(conf->granularity,
                              prev->granularity,
                              NGX_KSMP_FLAG_MEDIA_MIN_GOP);

    return NGX_CONF_OK;
}
