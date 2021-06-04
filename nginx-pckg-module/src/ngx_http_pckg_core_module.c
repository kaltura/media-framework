#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_pckg_core_module.h"
#include "ngx_http_pckg_utils.h"
#include "media/buffer_pool.h"


#define NGX_HTTP_PCKG_DEFAULT_LAST_MODIFIED  (1262304000)   /* 1/1/2010 */


static ngx_int_t ngx_http_pckg_core_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_pckg_core_postconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_core_create_main_conf(ngx_conf_t *cf);

static void *ngx_http_pckg_core_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_core_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


static char *ngx_http_pckg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_pckg_core_set_time_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_pckg_core_buffer_pool_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_int_t ngx_http_pckg_core_ctx_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_pckg_core_segment_dts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_pckg_core_unknown_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


enum {
    NGX_HTTP_PCKG_MTS_REQUEST,
    NGX_HTTP_PCKG_MTS_ACTUAL,
};


typedef struct {
    ngx_persist_conf_t      *persist;
    ngx_hash_t               handlers_hash;
    ngx_hash_keys_arrays_t  *handlers_keys;
} ngx_http_pckg_core_main_conf_t;


typedef struct {
    ngx_log_t               *log;
    u_char                  *pos;
    size_t                   left;
    size_t                   frame_size;
} ngx_http_pckg_read_source_t;


static ngx_conf_enum_t  ngx_http_pckg_media_type_selector[] = {
    { ngx_string("request"), NGX_HTTP_PCKG_MTS_REQUEST },
    { ngx_string("actual"),  NGX_HTTP_PCKG_MTS_ACTUAL },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_core_commands[] = {

    { ngx_string("pckg"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_pckg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pckg_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, uri),
      NULL },

    { ngx_string("pckg_channel_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, channel_id),
      NULL },

    { ngx_string("pckg_timeline_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, timeline_id),
      NULL },

    { ngx_string("pckg_ksmp_max_uncomp_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, max_uncomp_size),
      NULL },

    { ngx_string("pckg_expires_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t,
        expires[NGX_HTTP_PCKG_EXPIRES_STATIC]),
      NULL },

    { ngx_string("pckg_expires_index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t,
        expires[NGX_HTTP_PCKG_EXPIRES_INDEX]),
      NULL },

    { ngx_string("pckg_expires_index_gone"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t,
        expires[NGX_HTTP_PCKG_EXPIRES_INDEX_GONE]),
      NULL },

    { ngx_string("pckg_expires_master"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t,
        expires[NGX_HTTP_PCKG_EXPIRES_MASTER]),
      NULL },

    { ngx_string("pckg_last_modified_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_pckg_core_set_time_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, last_modified_static),
      NULL },

    { ngx_string("pckg_output_buffer_pool"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_pckg_core_buffer_pool_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, output_buffer_pool),
      NULL },

    { ngx_string("pckg_segment_metadata"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, segment_metadata),
      NULL },

    { ngx_string("pckg_empty_segments"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, empty_segments),
      NULL },

    { ngx_string("pckg_media_type_selector"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_core_loc_conf_t, media_type_selector),
      &ngx_http_pckg_media_type_selector },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_core_module_ctx = {
    ngx_http_pckg_core_add_variables,       /* preconfiguration */
    ngx_http_pckg_core_postconfiguration,   /* postconfiguration */

    ngx_http_pckg_core_create_main_conf,    /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_pckg_core_create_loc_conf,     /* create location configuration */
    ngx_http_pckg_core_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_core_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_core_module_ctx,         /* module context */
    ngx_http_pckg_core_commands,            /* module directives */
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


static ngx_http_variable_t  ngx_http_pckg_core_vars[] = {

    { ngx_string("pckg_channel_id"), NULL, ngx_http_pckg_core_ctx_variable,
      offsetof(ngx_http_pckg_core_ctx_t, params.channel_id), 0, 0 },

    { ngx_string("pckg_timeline_id"), NULL, ngx_http_pckg_core_ctx_variable,
      offsetof(ngx_http_pckg_core_ctx_t, params.timeline_id), 0, 0 },

    { ngx_string("pckg_variant_ids"), NULL, ngx_http_pckg_core_ctx_variable,
      offsetof(ngx_http_pckg_core_ctx_t, params.variant_ids), 0, 0 },

    { ngx_string("pckg_segment_dts"), NULL,
      ngx_http_pckg_core_segment_dts_variable, 0, 0, 0 },

    { ngx_string("pckg_var_"), NULL, ngx_http_pckg_core_unknown_variable,
      0, NGX_HTTP_VAR_PREFIX, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_pckg_content_type_options =
    ngx_string("text/plain");

static ngx_str_t  ngx_http_pckg_default_timeline_id = ngx_string("main");

static time_t  ngx_http_pckg_default_expires[NGX_HTTP_PCKG_EXPIRES_COUNT] = {
    8640000,        /* static - 100 days */
    3,              /* index - 3 sec */
    5,              /* index gone - 5 sec */
    30,             /* master - 30 sec */
};


ngx_str_t  ngx_http_pckg_prefix_manifest = ngx_string("manifest");
ngx_str_t  ngx_http_pckg_prefix_master = ngx_string("master");
ngx_str_t  ngx_http_pckg_prefix_index = ngx_string("index");
ngx_str_t  ngx_http_pckg_prefix_init_seg = ngx_string("init");
ngx_str_t  ngx_http_pckg_prefix_seg = ngx_string("seg");


static ngx_int_t
ngx_http_pckg_core_post_handler(ngx_http_request_t *sr, void *data,
    ngx_int_t rc)
{
    ngx_str_t                        input;
    ngx_http_request_t              *r;
    ngx_pckg_channel_t              *channel;
    ngx_http_upstream_t             *u;
    ngx_http_pckg_core_ctx_t        *ctx;
    ngx_http_pckg_core_loc_conf_t   *plcf;
    ngx_http_pckg_core_main_conf_t  *pmcf;

    r = sr->parent;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: subrequest failed %i", rc);
        rc = NGX_HTTP_BAD_GATEWAY;
        goto done;
    }

    u = sr->upstream;
    if (u == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: no upstream");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    if (u->headers_in.status_n != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: bad subrequest status %ui",
            u->headers_in.status_n);
        rc = NGX_HTTP_BAD_GATEWAY;
        goto done;
    }

    if (!sr->out || !sr->out->buf) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: no subrequest buffer");
        rc = NGX_HTTP_BAD_GATEWAY;
        goto done;
    }

    input.data = sr->out->buf->pos;
    input.len = sr->out->buf->last - input.data;

    if (u->headers_in.content_length_n > 0 &&
        (size_t) u->headers_in.content_length_n != input.len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: "
            "upstream connection was closed with %O bytes left to read",
            u->headers_in.content_length_n - (off_t) input.len);
        rc = NGX_HTTP_BAD_GATEWAY;
        goto done;
    }

    channel = ngx_pcalloc(r->pool, sizeof(*channel));
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: alloc failed");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_pckg_core_module);
    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    channel->log = r->connection->log;
    channel->pool = r->pool;
    channel->persist = pmcf->persist;
    channel->flags = ctx->params.flags;

    ngx_rbtree_init(&channel->vars.rbtree, &channel->vars.sentinel,
        ngx_str_rbtree_insert_value);

    rc = ngx_pckg_ksmp_parse(channel, &input, plcf->max_uncomp_size);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: parse failed %i", rc);
        rc = rc == NGX_BAD_DATA ? NGX_HTTP_BAD_GATEWAY :
            NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    ctx->channel = channel;

    if (channel->err_code) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_post_handler: "
            "ksmp error, code: %uD, msg: \"%V\"",
            channel->err_code, &channel->err_message);

        switch (channel->err_code) {

        case NGX_KSMP_ERR_CHANNEL_NOT_FOUND:
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_KSMP_ERR_TIMELINE_EMPTIED:
        case NGX_KSMP_ERR_TIMELINE_EXPIRED:
        case NGX_KSMP_ERR_VARIANT_INACTIVE:
            rc = ngx_http_pckg_gone(r);
            break;

        default:
            rc = NGX_HTTP_BAD_REQUEST;
            break;
        }

    } else {
        if (plcf->media_type_selector == NGX_HTTP_PCKG_MTS_ACTUAL) {
            channel->media_types = channel->header->res_media_types;

        } else {
            channel->media_types = channel->header->req_media_types;
        }

        rc = ctx->handler->handler(r);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_post_handler: handler failed %i", rc);
        }
    }

done:

    ngx_http_finalize_request(r, rc);

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_core_subrequest(ngx_http_request_t *r,
    ngx_pckg_ksmp_req_t *params)
{
    ngx_int_t                       rc;
    ngx_str_t                       uri;
    ngx_str_t                       args;
    ngx_http_request_t             *sr;
    ngx_http_post_subrequest_t     *psr;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    if (plcf->uri == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: \"pckg_uri\" not set in conf");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_complex_value(r, plcf->uri, &uri);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: complex value failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (uri.len == 0) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: empty subrequest uri");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_pckg_ksmp_create_request(r->pool, params, &args) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: create request failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_pckg_core_post_handler;
    psr->data = NULL;

    rc = ngx_http_subrequest(r, &uri, &args, &sr, psr,
        NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_subrequest: subrequest failed %i", rc);
        return rc;
    }

    r->main->count++;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_pckg_core_init_ctx(ngx_http_request_t *r, ngx_pckg_ksmp_req_t *params,
    ngx_http_pckg_request_handler_t *handler)
{
    ngx_int_t                       rc;
    ngx_http_pckg_core_ctx_t       *ctx;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_core_init_ctx: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    /* get the channel id */
    if (plcf->channel_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_init_ctx: pckg_channel_id not set in conf");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_complex_value(r, plcf->channel_id, &params->channel_id);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_init_ctx: complex value failed (1) %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* get the timeline id */
    if (plcf->timeline_id != NULL) {
        rc = ngx_http_complex_value(r, plcf->timeline_id,
            &params->timeline_id);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_init_ctx: complex value failed (2) %i",
                rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        params->timeline_id = ngx_http_pckg_default_timeline_id;
    }

    ctx->params = *params;
    ctx->handler = handler;
    ctx->request_context.log = r->connection->log;
    ctx->request_context.pool = r->pool;
    ctx->request_context.output_buffer_pool = plcf->output_buffer_pool;

    ngx_http_set_ctx(r, ctx, ngx_http_pckg_core_module);

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_core_parse(ngx_http_request_t *r, ngx_pckg_ksmp_req_t *params,
    ngx_http_pckg_request_handler_t **handler)
{
    u_char                          *end_pos;
    u_char                          *start_pos;
    ngx_int_t                        rc;
    ngx_str_t                        base;
    ngx_uint_t                       key;
    ngx_array_t                     *parsers;
    ngx_http_pckg_parse_uri_pt      *cur, *last;
    ngx_http_pckg_core_main_conf_t  *pmcf;

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_pckg_core_module);

    key = ngx_hash_key(r->exten.data, r->exten.len);

    parsers = ngx_hash_find(&pmcf->handlers_hash, key,
                            r->exten.data, r->exten.len);
    if (parsers == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_parse: unknown extension \"%V\"", &r->exten);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* get the base file name of the uri */
    start_pos = memrchr(r->uri.data, '/', r->uri.len);
    if (start_pos == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_parse: no \"/\" found in uri");
        return NGX_HTTP_BAD_REQUEST;
    }

    start_pos++;        /* skip the / */

    end_pos = r->uri.data + r->uri.len;
    if (r->exten.len > 0) {
        end_pos -= r->exten.len + 1;
    }

    ngx_memzero(params, sizeof(*params));
    params->media_type_mask = KMP_MEDIA_TYPE_MASK;
    params->segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;

    cur = parsers->elts;
    for (last = cur + parsers->nelts; cur < last; cur++) {

        rc = (*cur)(r, start_pos, end_pos, params, handler);
        if (rc == NGX_OK) {
            return NGX_OK;
        }

        if (rc != NGX_DECLINED) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_core_parse: parser failed %i", rc);
            return rc;
        }
    }

    base.data = start_pos;
    base.len = end_pos - start_pos;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_pckg_core_parse: unknown request \"%V\"", &base);
    return NGX_HTTP_BAD_REQUEST;
}


static ngx_int_t
ngx_http_pckg_core_handler(ngx_http_request_t *r)
{
    ngx_int_t                         rc;
    ngx_str_t                         response;
    ngx_pckg_ksmp_req_t               params;
    ngx_http_pckg_request_handler_t  *handler;

    if (r->method == NGX_HTTP_OPTIONS) {
        rc = ngx_http_pckg_send_header(r, 0,
            &ngx_http_pckg_content_type_options, -1, 0);
        if (rc != NGX_OK) {
            return rc;
        }

        response.data = NULL;
        response.len = 0;

        return ngx_http_pckg_send_response(r, &response);
    }

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_core_handler: unsupported method %ui", r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_core_handler: discard body failed %i", rc);
        return rc;
    }

    rc = ngx_http_pckg_core_parse(r, &params, &handler);
    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_core_handler: parse failed %i", rc);
        return rc;
    }

    rc = ngx_http_pckg_core_init_ctx(r, &params, handler);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_handler: init ctx failed %i", rc);
        return rc;
    }

    r->allow_ranges = 1;

    return ngx_http_pckg_core_subrequest(r, &params);
}


/* frame source */

static void *
ngx_http_pckg_source_init(ngx_pool_t *pool, ngx_str_t *buffer)
{
    ngx_http_pckg_read_source_t  *state;

    state = ngx_palloc(pool, sizeof(*state));
    if (state == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_http_pckg_source_init: ngx_palloc failed");
        return NULL;
    }

    state->log = pool->log;
    state->pos = buffer->data;
    state->left = buffer->len;

    return state;
}

static vod_status_t
ngx_http_pckg_source_start_frame(void *ctx, input_frame_t *frame)
{
    ngx_http_pckg_read_source_t  *state = ctx;

    state->frame_size = frame->size;

    return VOD_OK;
}

static vod_status_t
ngx_http_pckg_source_read(void *ctx, u_char **buffer, uint32_t *size,
    bool_t *frame_done)
{
    ngx_http_pckg_read_source_t  *state = ctx;

    if (state->left < state->frame_size) {
        ngx_log_error(NGX_LOG_ERR, state->log, 0,
            "ngx_http_pckg_source_read: "
            "frame size %uz overflows input buffer", state->frame_size);
        return VOD_BAD_DATA;
    }

    *buffer = state->pos;
    *size = state->frame_size;
    *frame_done = TRUE;

    state->pos += state->frame_size;
    state->left -= state->frame_size;

    return VOD_OK;
}

static frames_source_t  ngx_http_pckg_source = {
    ngx_http_pckg_source_start_frame,
    ngx_http_pckg_source_read,
};


/* segment writer */

static vod_status_t
ngx_http_pckg_writer_tail(void *arg, u_char *buffer, uint32_t size)
{
    ngx_buf_t                   *b;
    ngx_int_t                    rc;
    ngx_chain_t                  out;
    ngx_chain_t                 *chain;
    ngx_http_request_t          *r;
    ngx_http_pckg_writer_ctx_t  *ctx;

    if (size <= 0) {
        return VOD_OK;
    }

    ctx = arg;
    r = ctx->r;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_writer_tail: alloc buf failed");
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
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_writer_tail: output filter failed %i", rc);
            return VOD_ALLOC_FAILED;
        }

    } else {

        /* headers not sent yet, add the buffer to the chain */
        if (ctx->last->buf != NULL) {

            chain = ngx_alloc_chain_link(r->pool);
            if (chain == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_pckg_writer_tail: alloc chain failed");
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
ngx_http_pckg_writer_head(void *arg, u_char *buffer, uint32_t size)
{
    ngx_buf_t                   *b;
    ngx_chain_t                 *chain;
    ngx_http_request_t          *r;
    ngx_http_pckg_writer_ctx_t  *ctx = arg;

    r = ctx->r;

    if (r->header_sent) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_writer_head: "
            "called after the headers were already sent");
        return VOD_UNEXPECTED;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_writer_head: alloc buf failed");
        return VOD_ALLOC_FAILED;
    }

    b->pos = buffer;
    b->last = buffer + size;
    b->temporary = 1;

    chain = ngx_alloc_chain_link(r->pool);
    if (chain == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_writer_head: alloc chain failed");
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


static void
ngx_http_pckg_writer_init(ngx_http_request_t *r)
{
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    ctx->segment_writer_ctx.r = r;
    ctx->segment_writer_ctx.last = &ctx->segment_writer_ctx.out;

    ctx->segment_writer.write_tail = ngx_http_pckg_writer_tail;
    ctx->segment_writer.write_head = ngx_http_pckg_writer_head;
    ctx->segment_writer.context = &ctx->segment_writer_ctx;
}


static ngx_int_t
ngx_http_pckg_writer_close(ngx_http_request_t *r)
{
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_chain_t               *last;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    /* Note: if the writer is aes-cbc, need to write an empty buffer
            to flush it */

    rc = ctx->segment_writer.write_tail(ctx->segment_writer.context, NULL, 0);
    if (rc != VOD_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_writer_close: write tail failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->header_sent) {

        /* everything already sent, just signal completion and return */

        if (ctx->segment_writer_ctx.total_size != ctx->content_length &&
            (ctx->size_limit == 0 ||
            ctx->segment_writer_ctx.total_size < ctx->size_limit))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "ngx_http_pckg_writer_close: "
                "actual content length %uz different than reported length %uz",
                ctx->segment_writer_ctx.total_size, ctx->content_length);
        }

        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_writer_close: send special failed %i", rc);
            return rc;
        }

        return NGX_OK;
    }

    last = ctx->segment_writer_ctx.last;
    b = last->buf;
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_writer_close: no buffers were written");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    last->next = NULL;

    rc = ngx_http_pckg_send_header(r, ctx->segment_writer_ctx.total_size,
        NULL, -1, 0);
    if (rc != NGX_OK) {
        return rc;
    }

    if (r->header_only || r->method == NGX_HTTP_HEAD) {
        return NGX_OK;
    }

    rc = ngx_http_output_filter(r, &ctx->segment_writer_ctx.out);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_writer_close: output filter failed %i", rc);
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_media_segment(ngx_http_request_t *r, media_segment_t **segment)
{
    ngx_uint_t                      i, n;
    ngx_flag_t                      found;
    media_segment_t                *dst;
    ngx_pckg_track_t               *tracks;
    ngx_pckg_segment_t             *src;
    ngx_pckg_channel_t             *channel;
    media_segment_track_t          *dst_track;
    ngx_http_pckg_core_ctx_t       *ctx;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    dst = ngx_pcalloc(r->pool, sizeof(*dst) +
        sizeof(dst->tracks[0]) * channel->tracks.nelts);
    if (dst == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_media_segment: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dst_track = (void *)(dst + 1);

    dst->tracks = dst_track;
    dst->segment_index = channel->segment_index->segment_index;

    found = 0;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;
    for (i = 0; i < n; i++, dst_track++) {

        dst_track->media_info = &tracks[i].last_media_info->media_info;

        src = tracks[i].segment;
        if (src == NULL) {
            continue;
        }

        dst_track->frame_count = src->header->frame_count;
        dst_track->start_dts = src->header->start_dts +
            channel->segment_index->correction;

        dst_track->frames.part.nelts = src->header->frame_count;
        dst_track->frames.part.elts = src->frames;

        dst_track->frames_source_context = ngx_http_pckg_source_init(
            r->pool, &src->media);
        if (dst_track->frames_source_context == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_media_segment: source init failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        dst_track->frames_source = &ngx_http_pckg_source;

        found = 1;
    }

    if (!found) {
        plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

        if (!plcf->empty_segments) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_media_segment: "
                "segment %uD not found", dst->segment_index);
            return NGX_HTTP_NOT_FOUND;
        }
    }

    dst->tracks_end = dst_track;
    dst->track_count = dst_track - dst->tracks;

    *segment = dst;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_media_init_segment(ngx_http_request_t *r,
    media_init_segment_t *dst)
{
    ngx_uint_t                   i, n;
    ngx_pckg_track_t            *tracks;
    ngx_pckg_channel_t          *channel;
    ngx_http_pckg_core_ctx_t    *ctx;
    media_init_segment_track_t  *dst_track;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    dst_track = ngx_pcalloc(r->pool,
        sizeof(*dst_track) * channel->tracks.nelts);
    if (dst_track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_media_init_segment: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dst->first = dst_track;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;
    for (i = 0; i < n; i++) {

        dst_track->media_info = &tracks[i].last_media_info->media_info;

        dst_track++;
    }

    dst->last = dst_track;
    dst->count = dst->last - dst->first;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_core_write_segment(ngx_http_request_t *r)
{
    off_t                             range_start;
    off_t                             range_end;
    vod_status_t                      rc;
    media_segment_t                  *segment;
    ngx_http_pckg_core_ctx_t         *ctx;
    ngx_http_pckg_core_loc_conf_t    *plcf;
    ngx_http_pckg_frame_processor_t   processor;

    rc = ngx_http_pckg_media_segment(r, &segment);
    if (rc != NGX_OK) {
        return rc;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    if (plcf->segment_metadata != NULL) {
        rc = ngx_http_complex_value(r, plcf->segment_metadata,
            &segment->metadata);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_write_segment: complex value failed %i",
                rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_http_pckg_writer_init(r);

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    ngx_memzero(&processor, sizeof(processor));

    rc = ctx->handler->init_frame_processor(r, segment, &processor);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_write_segment: init processor failed %i", rc);
        return rc;
    }

    r->headers_out.content_type = processor.content_type;
    r->headers_out.content_type_len = processor.content_type.len;

    if (processor.response_size != 0) {

        ctx->content_length = processor.response_size;

        /* send the response header */
        rc = ngx_http_pckg_send_header(r, ctx->content_length, NULL, -1, 0);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_write_segment: send header failed %i", rc);
            return rc;
        }

        if (r->header_only || r->method == NGX_HTTP_HEAD) {
            return NGX_OK;
        }

        /* in case of range request, get the end offset */
        if (r->headers_in.range != NULL &&
            ngx_http_pckg_range_parse(&r->headers_in.range->value,
                ctx->content_length, &range_start, &range_end) == NGX_OK)
        {
            ctx->size_limit = range_end;
        }
    }

    if (processor.output.len != 0) {

        rc = ctx->segment_writer.write_tail(ctx->segment_writer.context,
            processor.output.data, processor.output.len);
        if (rc != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_write_segment: write tail failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        /* if the request range is fully contained in the output buffer
            (e.g. 0-0), we're done */
        if (ctx->size_limit != 0 &&
            processor.output.len >= ctx->size_limit && r->header_sent)
        {
            return NGX_OK;
        }
    }

    if (processor.ctx != NULL) {
        rc = processor.process(processor.ctx);
        if (rc != VOD_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_core_write_segment: processor failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
    }

    rc = ngx_http_pckg_writer_close(r);
    if (rc != VOD_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_core_write_segment: close failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    return NGX_OK;
}


static char *
ngx_http_pckg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_pckg_core_handler;

    return NGX_OK;
}


static char *
ngx_http_pckg_core_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    time_t           *sp;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    sp = (time_t *) (p + cmd->offset);
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
ngx_http_pckg_core_buffer_pool_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ssize_t          buffer_size;
    ngx_int_t        count;
    ngx_str_t       *value;
    buffer_pool_t  **buffer_pool;

    buffer_pool = (buffer_pool_t **) (p + cmd->offset);
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


static ngx_int_t
ngx_http_pckg_core_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_pckg_core_vars; v->name.len; v++) {
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
ngx_http_pckg_core_ctx_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                 *s;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    s = (ngx_str_t *) ((char *) ctx + data);

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
ngx_http_pckg_core_segment_dts_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    int64_t                    dts;
    uint32_t                   timescale;
    ngx_uint_t                 i, n;
    ngx_pckg_track_t          *tracks, *track;
    ngx_pckg_segment_t        *segment;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    if (ctx == NULL || ctx->channel == NULL) {
        goto not_found;
    }

    tracks = ctx->channel->tracks.elts;
    n = ctx->channel->tracks.nelts;
    for (i = 0; ; i++) {

        if (i >= n) {
            goto not_found;
        }

        track = &tracks[i];
        segment = track->segment;
        if (segment == NULL) {
            continue;
        }

        timescale = track->last_media_info->media_info.timescale;
        dts = (segment->header->start_dts * 1000) / timescale;
        break;
    }

    v->data = ngx_palloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%L", dts) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_core_unknown_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    uint32_t                   hash;
    ngx_str_t                 *name;
    ngx_str_t                  search;
    ngx_rbtree_t              *rbtree;
    ngx_pckg_dynamic_var_t    *var;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    if (ctx == NULL || ctx->channel == NULL) {
        goto not_found;
    }

    name = (void *) data;

    search.data = name->data + sizeof("pckg_var_") - 1;
    search.len = name->len - (sizeof("pckg_var_") - 1);

    rbtree = &ctx->channel->vars.rbtree;
    hash = ngx_crc32_short(search.data, search.len);
    var = (ngx_pckg_dynamic_var_t *)
                ngx_str_rbtree_lookup(rbtree, &search, hash);

    if (var == NULL) {
        goto not_found;
    }

    v->data = var->value.data;
    v->len = var->value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_core_add_handler(ngx_conf_t *cf, ngx_str_t *ext,
    ngx_http_pckg_parse_uri_pt parse)
{
    ngx_str_t                        key;
    ngx_uint_t                       i, n;
    ngx_array_t                     *arr;
    ngx_hash_key_t                  *hk;
    ngx_hash_key_t                  *keys;
    ngx_http_pckg_parse_uri_pt      *parsep;
    ngx_http_pckg_core_main_conf_t  *pmcf;

    key = *ext;
    if (key.len > 0 && key.data[0] == '.') {
        key.data++;
        key.len--;
    }

    arr = NULL;

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_pckg_core_module);

    keys = pmcf->handlers_keys->keys.elts;
    n = pmcf->handlers_keys->keys.nelts;

    for (i = 0; i < n; i++) {
        hk = &keys[i];

        if (hk->key.len == key.len &&
            ngx_strncmp(hk->key.data, key.data, key.len) == 0)
        {
            arr = hk->value;
            break;
        }
    }

    if (arr == NULL) {
        arr = ngx_array_create(cf->pool, 1, sizeof(parse));
        if (arr == NULL) {
            return NGX_ERROR;
        }

        if (ngx_hash_add_key(pmcf->handlers_keys, &key, arr,
                             NGX_HASH_READONLY_KEY) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    parsep = ngx_array_push(arr);
    if (parsep == NULL) {
        return NGX_ERROR;
    }

    *parsep = parse;

    return NGX_OK;
}


static void *
ngx_http_pckg_core_create_loc_conf(ngx_conf_t *cf)
{
    ngx_uint_t                      type;
    ngx_http_pckg_core_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_core_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_uncomp_size = NGX_CONF_UNSET_SIZE;

    for (type = 0; type < NGX_HTTP_PCKG_EXPIRES_COUNT; type++) {
        conf->expires[type] = NGX_CONF_UNSET;
    }
    conf->last_modified_static = NGX_CONF_UNSET;

    conf->empty_segments = NGX_CONF_UNSET;

    conf->media_type_selector = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_pckg_core_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_uint_t                      type;
    ngx_http_pckg_core_loc_conf_t  *prev = parent;
    ngx_http_pckg_core_loc_conf_t  *conf = child;

    if (conf->uri == NULL) {
        conf->uri = prev->uri;
    }

    ngx_conf_merge_size_value(conf->max_uncomp_size,
                              prev->max_uncomp_size, 5 * 1024 * 1024);

    if (conf->channel_id == NULL) {
        conf->channel_id = prev->channel_id;
    }

    if (conf->timeline_id == NULL) {
        conf->timeline_id = prev->timeline_id;
    }

    for (type = 0; type < NGX_HTTP_PCKG_EXPIRES_COUNT; type++) {
        ngx_conf_merge_value(conf->expires[type],
                             prev->expires[type],
                             ngx_http_pckg_default_expires[type]);
    }

    ngx_conf_merge_value(conf->last_modified_static,
                         prev->last_modified_static,
                         NGX_HTTP_PCKG_DEFAULT_LAST_MODIFIED);

    if (conf->segment_metadata == NULL) {
        conf->segment_metadata = prev->segment_metadata;
    }

    if (conf->output_buffer_pool == NULL) {
        conf->output_buffer_pool = prev->output_buffer_pool;
    }

    ngx_conf_merge_value(conf->empty_segments,
                         prev->empty_segments, 0);

    ngx_conf_merge_uint_value(conf->media_type_selector,
                              prev->media_type_selector,
                              NGX_HTTP_PCKG_MTS_REQUEST);

    return NGX_CONF_OK;
}


static void *
ngx_http_pckg_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_core_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_core_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->persist = ngx_pckg_ksmp_conf_create(cf);
    if (conf->persist == NULL) {
        return NULL;
    }

    conf->handlers_keys = ngx_pcalloc(cf->temp_pool,
                                      sizeof(ngx_hash_keys_arrays_t));
    if (conf->handlers_keys == NULL) {
        return NULL;
    }

    conf->handlers_keys->pool = cf->pool;
    conf->handlers_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(conf->handlers_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NULL;
    }

    return conf;
}


static ngx_int_t
ngx_http_pckg_core_postconfiguration(ngx_conf_t *cf)
{
    ngx_hash_init_t                  hash;
    ngx_http_pckg_core_main_conf_t  *pmcf;

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_pckg_core_module);

    if (ngx_persist_conf_init(cf, pmcf->persist) != NGX_OK) {
        return NGX_ERROR;
    }

    hash.hash = &pmcf->handlers_hash;
    hash.key = ngx_hash_key;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "handlers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, pmcf->handlers_keys->keys.elts,
                      pmcf->handlers_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pmcf->handlers_keys = NULL;

    return NGX_OK;
}
