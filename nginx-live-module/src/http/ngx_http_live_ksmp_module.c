#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_api.h>
#include "../ngx_live.h"
#include "../ngx_live_media_info.h"
#include "../ngx_live_segment_cache.h"
#include "../ngx_live_timeline.h"
#include "../ngx_live_filler.h"
#include "../ngx_live_notif_segment.h"


#define ngx_all_set(mask, f)  (((mask) & (f)) == (f))


static ngx_int_t ngx_http_live_ksmp_wait_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_live_ksmp_init_scope(ngx_http_request_t *r,
    ngx_live_persist_serve_scope_t *scope);
static ngx_int_t ngx_http_live_ksmp_write(ngx_http_request_t *r,
    ngx_live_persist_serve_scope_t *scope);

static ngx_int_t ngx_http_live_ksmp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_live_ksmp_uint32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_live_ksmp_msec_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_live_ksmp_add_variables(ngx_conf_t *cf);

static void *ngx_http_live_ksmp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_live_ksmp_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_live_ksmp(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


typedef struct {
    ngx_int_t                      comp_level;
} ngx_http_live_ksmp_loc_conf_t;


typedef struct {
    ngx_http_request_t            *r;

    ngx_str_t                      channel_id;
    ngx_str_t                      timeline_id;
    ngx_str_t                      variant_ids;
    uint32_t                       media_type_mask;
    int64_t                        time;
    uint32_t                       segment_index;
    uint32_t                       max_segment_index;
    uint32_t                       part_index;
    uint32_t                       skip_boundary_percent;
    size_t                         padding;
    uint32_t                       flags;

    uint32_t                       wait_sequence;
    uint32_t                       wait_part;

    uint32_t                       err_code;
    ngx_str_t                      err_msg;
    u_char                        *err_buf;
} ngx_http_live_ksmp_params_t;


typedef struct {
    ngx_live_channel_t            *channel;
    ngx_live_timeline_t           *timeline;
    ngx_live_track_t              *track;        /* only if single track */
} ngx_http_live_ksmp_objs_t;


typedef struct {
    ngx_http_live_ksmp_params_t    params;
    ngx_http_live_ksmp_objs_t      objs;

    ngx_chain_t                   *out;
    ngx_chain_t                  **last;
    size_t                         size;
    ngx_str_t                      source;
    ngx_str_t                      err_msg;
    uint32_t                       err_code;
    ngx_msec_int_t                 block_duration;
} ngx_http_live_ksmp_ctx_t;


static ngx_conf_num_bounds_t  ngx_http_live_ksmp_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 9
};


static ngx_command_t  ngx_http_live_ksmp_commands[] = {

    { ngx_string("live_ksmp"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_live_ksmp,
      0,
      0,
      NULL },

    { ngx_string("live_ksmp_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_live_ksmp_loc_conf_t, comp_level),
      &ngx_http_live_ksmp_comp_level_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_live_ksmp_module_ctx = {
    ngx_http_live_ksmp_add_variables,       /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_live_ksmp_create_loc_conf,     /* create location configuration */
    ngx_http_live_ksmp_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_live_ksmp_module = {
    NGX_MODULE_V1,
    &ngx_http_live_ksmp_module_ctx,         /* module context */
    ngx_http_live_ksmp_commands,            /* module directives */
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


static ngx_http_variable_t  ngx_http_live_ksmp_vars[] = {

    { ngx_string("live_ksmp_source"), NULL, ngx_http_live_ksmp_variable,
      offsetof(ngx_http_live_ksmp_ctx_t, source), 0, 0 },

    { ngx_string("live_ksmp_err_msg"), NULL, ngx_http_live_ksmp_variable,
      offsetof(ngx_http_live_ksmp_ctx_t, err_msg), 0, 0 },

    { ngx_string("live_ksmp_err_code"), NULL,
      ngx_http_live_ksmp_uint32_variable,
      offsetof(ngx_http_live_ksmp_ctx_t, err_code), 0, 0 },

    { ngx_string("live_ksmp_block_duration"), NULL,
      ngx_http_live_ksmp_msec_variable,
      offsetof(ngx_http_live_ksmp_ctx_t, block_duration), 0, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_live_ksmp_type =
    ngx_string("application/octet-stream");

static ngx_str_t  ngx_http_live_ksmp_filler_source = ngx_string("filler");


static ngx_int_t
ngx_http_live_ksmp_args_handler(ngx_http_request_t *r, void *data,
    ngx_str_t *key, ngx_str_t *value)
{
    ngx_int_t                     int_val;
    ngx_http_live_ksmp_params_t  *params = data;

    if (key->len == sizeof("channel_id") - 1 &&
        ngx_memcmp(key->data, "channel_id", sizeof("channel_id") - 1) == 0)
    {
        params->channel_id = *value;

    } else if (key->len == sizeof("timeline_id") - 1 &&
        ngx_memcmp(key->data, "timeline_id", sizeof("timeline_id") - 1) == 0)
    {
        params->timeline_id = *value;

    } else if (key->len == sizeof("variant_ids") - 1 &&
        ngx_memcmp(key->data, "variant_ids", sizeof("variant_ids") - 1) == 0)
    {
        params->variant_ids = *value;

    } else if (key->len == sizeof("media_type_mask") - 1 &&
        ngx_memcmp(key->data, "media_type_mask", sizeof("media_type_mask") - 1)
        == 0)
    {
        int_val = ngx_hextoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid media_type_mask \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->media_type_mask &= int_val;
        if (!params->media_type_mask) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "empty media_type_mask \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

    } else if (key->len == sizeof("time") - 1 &&
        ngx_memcmp(key->data, "time", sizeof("time") - 1)
        == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid time \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (int_val >= NGX_KSMP_INVALID_TIMESTAMP) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "time \"%V\" too large", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->time = int_val;


    } else if (key->len == sizeof("segment_index") - 1 &&
        ngx_memcmp(key->data, "segment_index", sizeof("segment_index") - 1)
        == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid segment_index \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (int_val >= NGX_KSMP_INVALID_SEGMENT_INDEX) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "segment_index \"%V\" too large", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->segment_index = int_val;

    } else if (key->len == sizeof("max_segment_index") - 1 &&
        ngx_memcmp(key->data, "max_segment_index",
            sizeof("max_segment_index") - 1) == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid max_segment_index \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->max_segment_index = int_val;

    } else if (key->len == sizeof("part_index") - 1 &&
        ngx_memcmp(key->data, "part_index", sizeof("part_index") - 1) == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid part_index \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (int_val >= NGX_KSMP_INVALID_PART_INDEX) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "part_index \"%V\" too large", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->part_index = int_val;

    } else if (key->len == sizeof("skip_boundary_percent") - 1 &&
        ngx_memcmp(key->data, "skip_boundary_percent",
            sizeof("skip_boundary_percent") - 1) == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid skip_boundary_percent \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->skip_boundary_percent = int_val;

    } else if (key->len == sizeof("padding") - 1 &&
        ngx_memcmp(key->data, "padding", sizeof("padding") - 1) == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid padding \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (!int_val) {
            return NGX_OK;
        }

        if (int_val < (ngx_int_t) NGX_KSMP_MIN_PADDING
            || int_val > NGX_KSMP_MAX_PADDING)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid padding %i", int_val);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->padding = int_val;

    } else if (key->len == sizeof("flags") - 1 &&
        ngx_memcmp(key->data, "flags", sizeof("flags") - 1) == 0)
    {
        int_val = ngx_hextoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_args_handler: "
                "invalid flags \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->flags = int_val;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_parse(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_live_ksmp_ctx_t     *ctx;
    ngx_http_live_ksmp_params_t  *params;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    params = &ctx->params;
    params->r = r;
    params->media_type_mask = KMP_MEDIA_TYPE_MASK;
    params->segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
    params->max_segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
    params->part_index = NGX_KSMP_INVALID_PART_INDEX;
    params->time = NGX_KSMP_INVALID_TIMESTAMP;

    rc = ngx_http_api_parse_args(r, ngx_http_live_ksmp_args_handler, params);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!params->flags) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_ksmp_parse: missing \"flags\" arg");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (!params->channel_id.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_ksmp_parse: missing \"channel_id\" arg");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (!params->timeline_id.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_ksmp_parse: missing \"timeline_id\" arg");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (params->segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX) {

        if (params->time != NGX_KSMP_INVALID_TIMESTAMP) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_parse: "
                "request includes both \"segment_index\" and \"time\"");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (params->flags & NGX_KSMP_FLAG_MEDIA_CLIP) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_parse: "
                "clip request without \"time\" arg");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (params->flags & NGX_KSMP_FLAG_WAIT) {
            params->wait_sequence = params->segment_index;
            params->wait_part = params->part_index;

            params->segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
            params->part_index = NGX_KSMP_INVALID_PART_INDEX;
        }

    } else {

        if (params->part_index != NGX_KSMP_INVALID_PART_INDEX) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_parse: "
                "request includes \"part_index\" but not \"segment_index\"");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (params->time == NGX_KSMP_INVALID_TIMESTAMP &&
            (params->flags & (NGX_KSMP_FLAG_MEDIA
                | NGX_KSMP_FLAG_SEGMENT_TIME)))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_parse: "
                "missing \"segment_index\" arg when requesting media/time");
            return NGX_HTTP_BAD_REQUEST;
        }

        if (params->flags & NGX_KSMP_FLAG_WAIT) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_parse: "
                "wait request without \"segment_index\" arg");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (ngx_all_set(params->flags,
        NGX_KSMP_FLAG_TIME_START_RELATIVE | NGX_KSMP_FLAG_TIME_END_RELATIVE))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_ksmp_parse: "
            "request includes both start-relative and end-relative flags");
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_write_padding(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    ngx_http_live_ksmp_ctx_t    *ctx;
    ngx_persist_block_header_t  *header;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    if (!ctx->params.padding) {
        return NGX_OK;
    }

    b = ngx_create_temp_buf(r->pool, ctx->params.padding);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write_padding: alloc buf failed");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write_padding: alloc chain failed");
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    header = (void *) b->pos;
    header->id = NGX_KSMP_BLOCK_PADDING;
    header->size = b->end - b->pos;
    header->header_size = sizeof(*header);
    b->last = (void *) (header + 1);

    ngx_memzero(b->last, b->end - b->last);
    b->last = b->end;

    rc = ngx_http_output_filter(r, cl);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write_padding: output filter failed %i", rc);
        return rc;
    }

    return rc;
}


static ngx_int_t
ngx_http_live_ksmp_output(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_int_t                  rc;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    r->headers_out.content_type = ngx_http_live_ksmp_type;
    r->headers_out.content_length_n = ctx->size + ctx->params.padding;
    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output: send header failed %i", rc);
        return rc;
    }

    if (r->header_only) {
        return NGX_HTTP_OK;     /* != NGX_OK to stop execution */
    }

    rc = ngx_http_output_filter(r, ctx->out);
    ctx->out = NULL;

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output: output filter failed %i", rc);
        return rc;
    }

    if (!flags) {
        return NGX_OK;
    }

    rc = ngx_http_live_ksmp_write_padding(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_special(r, flags);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output: send special failed %i", rc);
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_segment_set_size(void *arg, size_t size)
{
    ngx_int_t                  rc;
    ngx_http_request_t        *r = arg;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    ctx->size += size;

    rc = ngx_http_live_ksmp_output(r, 0);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_segment_set_size: output failed %i", rc);
        return rc;
    }

    ngx_http_run_posted_requests(r->connection);

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_segment_write(void *arg, ngx_chain_t *cl)
{
    ngx_int_t            rc;
    ngx_http_request_t  *r = arg;

    rc = ngx_http_output_filter(r, cl);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_segment_write: output filter failed %i", rc);
        return rc;
    }

    ngx_http_run_posted_requests(r->connection);

    return NGX_OK;
}


static void
ngx_http_live_ksmp_segment_close(void *arg, ngx_int_t rc)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r = arg;

    c = r->connection;

    if (rc != NGX_OK) {
        if (r->header_sent) {
            rc = NGX_ERROR;
            goto done;
        }

        switch (rc) {

        case NGX_DECLINED:
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_BAD_DATA:
            rc = NGX_HTTP_BAD_GATEWAY;
            break;

        default:
            if (rc < 400 || rc > 599) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        goto done;
    }

    rc = ngx_http_live_ksmp_write_padding(r);
    if (rc != NGX_OK) {
        rc = NGX_ERROR;
        goto done;
    }

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_http_live_ksmp_segment_close: send special failed %i",
            rc);
    }

done:

    ngx_http_finalize_request(r, rc);

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_live_ksmp_cleanup(void *data)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r = data;

    c = r->connection;

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
        "ngx_http_live_ksmp_cleanup: request cleaned up");

    ngx_http_finalize_request(r, NGX_ERROR);

    ngx_http_run_posted_requests(c);
}


static void
ngx_http_live_ksmp_set_error(ngx_http_live_ksmp_params_t *params,
    uint32_t code, const char *fmt, ...)
{
    u_char     *p, *last;
    va_list     args;
    ngx_str_t   err_msg;
    u_char      err_buf[NGX_MAX_ERROR_STR];

    /* in case of multiple errors, keep the one with higher prio */
    if (!params->err_code || code < params->err_code) {
        if (params->err_buf == NULL) {
            params->err_buf = ngx_pnalloc(params->r->pool, NGX_MAX_ERROR_STR);
            if (params->err_buf == NULL) {
                return;
            }
        }

        err_msg.data = params->err_buf;
        last = params->err_buf + NGX_MAX_ERROR_STR;

    } else {
        err_msg.data = err_buf;
        last = err_buf + sizeof(err_buf);
    }

    va_start(args, fmt);
    p = ngx_vslprintf(err_msg.data, last, fmt, args);
    va_end(args);

    err_msg.len = p - err_msg.data;

    ngx_log_error(NGX_LOG_INFO, params->r->connection->log, 0,
        "ngx_http_live_ksmp_set_error: %V", &err_msg);

    if (err_msg.data == params->err_buf) {
        params->err_msg = err_msg;
        params->err_code = code;
    }
}


static ngx_int_t
ngx_http_live_ksmp_output_error_str(ngx_http_request_t *r, uint32_t code,
    ngx_str_t *message)
{
    ngx_wstream_t             *ws;
    ngx_persist_write_ctx_t   *write_ctx;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_live_ksmp_output_error_str: %V, code: %uD", message, code);

    ctx->err_msg.data = ngx_pnalloc(r->pool, message->len);
    if (ctx->err_msg.data != NULL) {
        ngx_memcpy(ctx->err_msg.data, message->data, message->len);
        ctx->err_msg.len = message->len;
    }

    ctx->err_code = code;

    write_ctx = ngx_persist_write_init(r->pool, NGX_KSMP_PERSIST_TYPE, 0);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output_error_str: write init failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_ERROR) != NGX_OK ||
        ngx_persist_write(write_ctx, &code, sizeof(code)) != NGX_OK ||
        ngx_wstream_str(ws, message) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output_error_str: write failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);      /* error */

    ctx->out = ngx_persist_write_close(write_ctx, &ctx->size, NULL);
    if (ctx->out == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_output_error_str: close failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_live_ksmp_output(r, NGX_HTTP_LAST);
}


static ngx_int_t
ngx_http_live_ksmp_output_error(ngx_http_request_t *r, uint32_t code,
    const char *fmt, ...)
{
    u_char     *p;
    va_list     args;
    ngx_str_t   message;
    u_char      buf[NGX_MAX_ERROR_STR];

    va_start(args, fmt);
    p = ngx_vslprintf(buf, buf + sizeof(buf), fmt, args);
    va_end(args);

    message.data = buf;
    message.len = p - buf;

    return ngx_http_live_ksmp_output_error_str(r, code, &message);
}


static void
ngx_http_live_ksmp_wait_notif_handler(void *arg, ngx_int_t rc)
{
    ngx_http_request_t  *r = arg;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_notif_handler: wait failed %i", rc);
        ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
        return;
    }

    ngx_post_event(r->connection->write, &ngx_posted_events);
}


static void
ngx_http_live_ksmp_wait_write_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_time_t                      *tp;
    ngx_event_t                     *wev;
    ngx_msec_int_t                   ms;
    ngx_connection_t                *c;
    ngx_live_timeline_t             *timeline;
    ngx_http_live_ksmp_ctx_t        *ctx;
    ngx_live_persist_serve_scope_t   scope;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    tp = ngx_timeofday();
    ms = (ngx_msec_int_t)
        ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

    if (ms > 0) {
        ctx->block_duration = ms;
    }

    c = r->connection;
    wev = c->write;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
            "ngx_http_live_ksmp_wait_write_handler: wait request timed out");

        rc = ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_WAIT_TIMED_OUT,
            "wait timed out");
        goto finalize;
    }


    timeline = ctx->objs.timeline;
    if (timeline->manifest.segment_count <= 0) {
        rc = ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_TIMELINE_EMPTIED,
            "timeline \"%V\" no longer has segments, channel: %V",
            &timeline->sn.str, &timeline->channel->sn.str);
        goto finalize;
    }

    if (ctx->params.flags & NGX_KSMP_FLAG_WAIT) {
        rc = ngx_http_live_ksmp_wait_request(r);
        if (rc != NGX_OK || r->header_sent) {
            goto finalize;
        }
    }


    rc = ngx_http_live_ksmp_init_scope(r, &scope);
    if (rc != NGX_OK || r->header_sent) {
        goto finalize;
    }

    rc = ngx_http_live_ksmp_write(r, &scope);

finalize:

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_live_ksmp_wait_segment(ngx_http_request_t *r,
    uint32_t segment_index, uint32_t part_index)
{
    uint32_t                       target_duration;
    ngx_time_t                    *tp;
    ngx_msec_t                     timer;
    ngx_msec_int_t                 elapsed;
    ngx_live_channel_t            *channel;
    ngx_live_timeline_t           *timeline;
    ngx_http_live_ksmp_ctx_t      *ctx;
    ngx_http_live_ksmp_objs_t     *objs;
    ngx_live_notif_segment_sub_t  *sub;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    objs = &ctx->objs;

    timeline = objs->timeline;

    sub = ngx_live_notif_segment_subscribe(r->pool, objs->track,
        timeline, segment_index, part_index);
    if (sub == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_segment: subscribe failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sub->handler = ngx_http_live_ksmp_wait_notif_handler;
    sub->data = r;

    channel = objs->channel;

    target_duration = timeline->manifest.target_duration;
    if (target_duration > 0) {
        timer = 3 * ngx_live_rescale_time(target_duration, channel->timescale,
            1000);

    } else {
        timer = 3 * channel->conf.segment_duration;
    }

    tp = ngx_timeofday();
    elapsed = (ngx_msec_int_t)
        ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));

    if (elapsed > 0) {
        if (timer > (ngx_msec_t) elapsed) {
            timer -= elapsed;

        } else {
            timer = 0;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_LIVE, r->connection->log, 0,
        "ngx_http_live_ksmp_wait_segment: "
        "timer: %M, elapsed: %M", timer, elapsed);

    r->write_event_handler = ngx_http_live_ksmp_wait_write_handler;

    ngx_add_timer(r->connection->write, timer);

    r->main->count++;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_live_ksmp_wait_request(ngx_http_request_t *r)
{
    uint32_t                      wait_part;
    uint32_t                      segment_index;
    uint32_t                      wait_sequence;
    uint32_t                      next_sequence;
    uint32_t                      next_segment_index;
    uint32_t                      advance_part_limit;
    ngx_flag_t                    exists;
    ngx_live_track_t             *track;
    ngx_live_channel_t           *channel;
    ngx_live_timeline_t          *timeline;
    ngx_http_live_ksmp_ctx_t     *ctx;
    ngx_http_live_ksmp_objs_t    *objs;
    ngx_http_live_ksmp_params_t  *params;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    params = &ctx->params;
    objs = &ctx->objs;

    track = objs->track;
    timeline = objs->timeline;

    if (ngx_live_timeline_serve_end_list(timeline, track,
        params->max_segment_index))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_LIVE, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_request: timeline end list");
        return NGX_OK;
    }

    channel = objs->channel;

    next_segment_index = channel->next_segment_index + track->pending_index;
    next_sequence = ngx_live_timeline_index_to_sequence(timeline,
        next_segment_index, &exists);

    wait_sequence = params->wait_sequence;
    if (wait_sequence < next_sequence) {
        ngx_log_debug2(NGX_LOG_DEBUG_LIVE, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_request: "
            "past sequence %uD, next_sequence: %uD",
            wait_sequence, next_sequence);
        return NGX_OK;
    }

    wait_part = params->wait_part;
    if (wait_sequence == next_sequence && exists
        && wait_part < track->next_part_index)
    {
        ngx_log_debug3(NGX_LOG_DEBUG_LIVE, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_request: "
            "past part %uD, npi: %uD, sequence: %uD",
            wait_part, track->next_part_index, wait_sequence);
        return NGX_OK;
    }

    if (wait_sequence >= next_sequence + 2) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_WAIT_SEQUENCE_EXCEEDS_LIMIT,
            "wait sequence %uD exceeds limit, "
            "next_sequene: %uD, timeline: %V, channel: %V",
            wait_sequence, next_sequence, &timeline->sn.str, &channel->sn.str);
    }

    if (wait_part != NGX_LIVE_INVALID_PART_INDEX) {

        if (channel->part_duration <= 0) {
            return ngx_http_live_ksmp_output_error(r,
                NGX_KSMP_ERR_WAIT_NO_PARTS,
                "part wait request on a channel without parts, channel: %V",
                &channel->sn.str);
        }

        if (channel->part_duration < channel->timescale) {
            advance_part_limit = 3 * channel->timescale
                / channel->part_duration;

        } else {
            advance_part_limit = 3;
        }

        if (wait_part >= track->next_part_index + advance_part_limit) {
            return ngx_http_live_ksmp_output_error(r,
                NGX_KSMP_ERR_WAIT_PART_EXCEEDS_LIMIT,
                "wait part %uD exceeds limit, "
                "npi: %uD, apl: %uD, timeline: %V, channel: %V",
                wait_part, track->next_part_index, advance_part_limit,
                &timeline->sn.str, &channel->sn.str);
        }
    }

    segment_index = ngx_live_timeline_sequence_to_index(timeline,
        wait_sequence);

    if (segment_index < next_segment_index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_request: "
            "segment index %uD before next index %uD",
            segment_index, next_segment_index);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (segment_index == next_segment_index
        && wait_part < track->next_part_index)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_ksmp_wait_request: "
            "wait part %uD before next part %uD, index: %uD",
            wait_part, track->next_part_index, segment_index);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_live_ksmp_wait_segment(r, segment_index, wait_part);
}


static ngx_int_t
ngx_http_live_ksmp_init_track(ngx_http_request_t *r)
{
    ngx_uint_t                    i;
    ngx_live_track_t             *track, *cur_track;
    ngx_live_variant_t           *variant;
    ngx_live_channel_t           *channel;
    ngx_http_live_ksmp_ctx_t     *ctx;
    ngx_http_live_ksmp_objs_t    *objs;
    ngx_http_live_ksmp_params_t  *params;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    params = &ctx->params;
    if (params->variant_ids.data == NULL
        || memchr(params->variant_ids.data, NGX_KSMP_VARIANT_IDS_DELIM,
            params->variant_ids.len))
    {
        /* no variant ids / multiple variant ids */
        return NGX_OK;
    }

    objs = &ctx->objs;
    channel = objs->channel;

    variant = ngx_live_variant_get(channel, &params->variant_ids);
    if (variant == NULL) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_VARIANT_NOT_FOUND,
            "unknown variant \"%V\", channel: %V",
            &params->variant_ids, &channel->sn.str);
    }

    track = NULL;
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        cur_track = variant->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        if (!(params->media_type_mask & (1 << i))) {
            continue;
        }

        if (track != NULL) {
            /* multiple tracks */
            return NGX_OK;
        }

        track = cur_track;
    }

    if (track == NULL) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_TRACK_NOT_FOUND,
            "no tracks found, mask: 0x%uxD, variant: %V, channel: %V",
            params->media_type_mask, &variant->sn.str, &channel->sn.str);
    }

    objs->track = track;
    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_wait_media(ngx_http_request_t *r)
{
    uint32_t                   part_index;
    uint32_t                   segment_index;
    ngx_live_track_t          *track;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);

    track = ctx->objs.track;
    if (track == NULL) {
        return NGX_OK;
    }

    segment_index = ctx->params.segment_index;
    part_index = ctx->params.part_index;

    if (!ngx_live_segment_cache_is_pending_part(track, segment_index,
        part_index))
    {
        return NGX_OK;
    }

    return ngx_http_live_ksmp_wait_segment(r, segment_index, part_index);
}


static ngx_int_t
ngx_http_live_ksmp_init_objs(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_live_channel_t           *channel;
    ngx_live_timeline_t          *timeline;
    ngx_http_live_ksmp_ctx_t     *ctx;
    ngx_http_live_ksmp_params_t  *params;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    params = &ctx->params;

    /* channel */

    channel = ngx_live_channel_get(&params->channel_id);
    if (channel == NULL) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_CHANNEL_NOT_FOUND,
            "unknown channel \"%V\"", &params->channel_id);
    }

    channel->last_accessed = ngx_time();

    if (channel->blocked) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_CHANNEL_BLOCKED,
            "channel \"%V\" is blocked", &channel->sn.str);
    }

    ctx->objs.channel = channel;

    /* timeline */

    timeline = ngx_live_timeline_get(channel, &params->timeline_id);
    if (timeline == NULL) {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_TIMELINE_NOT_FOUND,
            "unknown timeline \"%V\", channel: %V",
            &params->timeline_id, &channel->sn.str);
    }

    timeline->last_accessed = ngx_time();

    if (timeline->manifest.segment_count <= 0) {
        if (timeline->manifest.target_duration_segments) {
            return ngx_http_live_ksmp_output_error(r,
                NGX_KSMP_ERR_TIMELINE_EMPTIED,
                "timeline \"%V\" no longer has segments, channel: %V",
                &timeline->sn.str, &channel->sn.str);
        }

        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_TIMELINE_EMPTY,
            "no segments in timeline \"%V\", channel: %V",
            &timeline->sn.str, &channel->sn.str);
    }

    if ((params->flags & NGX_KSMP_FLAG_CHECK_EXPIRY) &&
        ngx_live_timeline_is_expired(timeline))
    {
        return ngx_http_live_ksmp_output_error(r,
            NGX_KSMP_ERR_TIMELINE_EXPIRED,
            "timeline \"%V\" is expired, channel: %V",
            &timeline->sn.str, &channel->sn.str);
    }

    ctx->objs.timeline = timeline;

    /* track */

    rc = ngx_http_live_ksmp_init_track(r);
    if (rc != NGX_OK || r->header_sent) {
        return rc;
    }

    /* wait */

    if (params->flags & NGX_KSMP_FLAG_WAIT) {

        if (ctx->objs.track == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_ksmp_init_objs: "
                "wait request on multiple tracks, "
                "variant_ids: %V, media_type_mask: 0x%uxD",
                &params->variant_ids, params->media_type_mask);
            return NGX_HTTP_BAD_REQUEST;
        }

        rc = ngx_http_live_ksmp_wait_request(r);
        if (rc != NGX_OK || r->header_sent) {
            return rc;
        }

    } else if (params->flags & NGX_KSMP_FLAG_MEDIA) {
        rc = ngx_http_live_ksmp_wait_media(r);
        if (rc != NGX_OK || r->header_sent) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_add_track_ref(ngx_live_persist_serve_scope_t *scope,
    uint32_t track_id, ngx_live_track_t *track)
{
    ngx_uint_t             i, n;
    ngx_array_t           *refs = scope->track_refs;
    ngx_live_track_ref_t  *ref;

    ref = refs->elts;
    n = refs->nelts;
    for (i = 0; i < n; i++) {
        if (ref[i].id == track_id) {
            return NGX_OK;
        }
    }

    ref = ngx_array_push(refs);
    if (ref == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, refs->pool->log, 0,
            "ngx_http_live_ksmp_add_track_ref: push failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ref->id = track_id;
    if (track_id == track->in.key) {
        ref->track = track;

    } else {
        ref->track = ngx_live_track_get_by_int(scope->channel, track_id);
    }

    return NGX_OK;
}


/*
 * NGX_OK - output the variant
 * NGX_ABORT - don't output the variant
 * other - error
 */
static ngx_int_t
ngx_http_live_ksmp_output_variant(ngx_http_live_ksmp_params_t *params,
    ngx_live_variant_t *variant, ngx_live_persist_serve_scope_t *scope)
{
    uint32_t           track_id;
    uint32_t           req_media_types;
    ngx_int_t          rc;
    ngx_uint_t         i;
    ngx_live_track_t  *cur_track;

    req_media_types = params->media_type_mask;

    if ((params->flags & NGX_KSMP_FLAG_ACTIVE_LAST) &&
        !ngx_live_variant_is_active_last(variant, scope->timeline))
    {
        ngx_http_live_ksmp_set_error(params,
            NGX_KSMP_ERR_VARIANT_INACTIVE,
            "variant inactive (last), mask: 0x%uxD, variant: %V, channel: %V",
            params->media_type_mask, &variant->sn.str,
            &variant->channel->sn.str);
        return NGX_ABORT;
    }

    if (params->flags & NGX_KSMP_FLAG_ACTIVE_ANY) {
        req_media_types = ngx_live_variant_is_active_any(variant,
            scope->timeline, req_media_types);
        if (!req_media_types) {
            ngx_http_live_ksmp_set_error(params,
                NGX_KSMP_ERR_VARIANT_INACTIVE,
                "variant inactive (any), mask: 0x%uxD, variant: %V, "
                "channel: %V",
                params->media_type_mask, &variant->sn.str,
                &variant->channel->sn.str);
            return NGX_ABORT;
        }
    }

    variant->output_media_types = 0;
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        cur_track = variant->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        if (!(req_media_types & (1 << i))) {
            continue;
        }

        if (!(params->flags & NGX_KSMP_FLAG_BACK_FILL) &&
            cur_track->initial_segment_index > scope->max_index &&
            cur_track->initial_segment_index > variant->initial_segment_index)
        {
            continue;
        }

        cur_track->media_info_node = ngx_live_media_info_queue_get_node(
            cur_track, scope->max_index, &track_id);
        if (cur_track->media_info_node == NULL) {
            ngx_http_live_ksmp_set_error(params,
                NGX_KSMP_ERR_MEDIA_INFO_NOT_FOUND,
                "no media info, index: %uD, track: %V, variant: %V, "
                "channel: %V",
                scope->max_index, &cur_track->sn.str, &variant->sn.str,
                &variant->channel->sn.str);
            continue;
        }

        if (scope->track_refs) {
            rc = ngx_http_live_ksmp_add_track_ref(scope, track_id, cur_track);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        variant->output_media_types |= 1 << cur_track->media_type;
    }

    if (!variant->output_media_types) {
        ngx_http_live_ksmp_set_error(params,
            NGX_KSMP_ERR_TRACK_NOT_FOUND,
            "no tracks found, mask: 0x%uxD, variant: %V, channel: %V",
            params->media_type_mask, &variant->sn.str,
            &variant->channel->sn.str);
        return NGX_ABORT;
    }

    scope->header.res_media_types |= variant->output_media_types;

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_add_variants(ngx_http_request_t *r,
    ngx_http_live_ksmp_params_t *params, ngx_live_persist_serve_scope_t *scope)
{
    ngx_int_t             rc;
    ngx_queue_t          *q;
    ngx_live_channel_t   *channel = scope->channel;
    ngx_live_variant_t   *cur_variant;
    ngx_live_variant_t  **dst;

    dst = ngx_palloc(r->pool, sizeof(dst[0]) * channel->variants.count);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_add_variants: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    scope->variants = dst;

    for (q = ngx_queue_head(&channel->variants.queue);
        q != ngx_queue_sentinel(&channel->variants.queue);
        q = ngx_queue_next(q))
    {
        cur_variant = ngx_queue_data(q, ngx_live_variant_t, queue);

        rc = ngx_http_live_ksmp_output_variant(params, cur_variant, scope);
        if (rc == NGX_OK) {
            *dst++ = cur_variant;

        } else if (rc != NGX_ABORT) {
            return rc;
        }
    }

    scope->header.variant_count = dst - scope->variants;

    return NGX_OK;
}


static ngx_uint_t
ngx_http_live_ksmp_variant_ids_count(ngx_str_t *value)
{
    u_char      *p, *last;
    ngx_uint_t   n;

    p = value->data;
    last = p + value->len;

    for (n = 1; p < last; p++) {
        if (*p == NGX_KSMP_VARIANT_IDS_DELIM) {
            n++;
        }
    }

    return n;
}


static ngx_int_t
ngx_http_live_ksmp_parse_variant_ids(ngx_http_request_t *r,
    ngx_http_live_ksmp_params_t *params, ngx_live_persist_serve_scope_t *scope)
{
    u_char               *p, *last, *next;
    ngx_int_t             rc;
    ngx_str_t             cur;
    ngx_uint_t            variant_count;
    ngx_live_channel_t   *channel;
    ngx_live_variant_t   *variant;
    ngx_live_variant_t  **dst;

    variant_count = ngx_http_live_ksmp_variant_ids_count(&params->variant_ids);

    dst = ngx_palloc(r->pool, sizeof(dst[0]) * variant_count);
    if (dst == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_parse_variant_ids: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    scope->variants = dst;
    channel = scope->channel;

    p = params->variant_ids.data;
    last = p + params->variant_ids.len;

    for ( ;; ) {
        next = ngx_strlchr(p, last, NGX_KSMP_VARIANT_IDS_DELIM);

        cur.data = p;
        cur.len = next != NULL ? next - p : last - p;

        variant = ngx_live_variant_get(channel, &cur);
        if (variant != NULL) {
            rc = ngx_http_live_ksmp_output_variant(params, variant, scope);
            if (rc == NGX_OK) {
                *dst++ = variant;

            } else if (rc != NGX_ABORT) {
                return rc;
            }

        } else {
            ngx_http_live_ksmp_set_error(params,
                NGX_KSMP_ERR_VARIANT_NOT_FOUND,
                "unknown variant \"%V\", channel: %V", &cur, &channel->sn.str);
        }

        if (next == NULL) {
            break;
        }

        p = next + 1;
    }

    scope->header.variant_count = dst - scope->variants;

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_init_scope(ngx_http_request_t *r,
    ngx_live_persist_serve_scope_t *scope)
{
    int64_t                       time;
    uint32_t                      code;
    uint32_t                      flags;
    uint32_t                      segment_index;
    uint32_t                      next_segment_index;
    ngx_int_t                     rc;
    ngx_queue_t                  *q;
    ngx_live_track_t             *track;
    ngx_live_period_t            *period;
    ngx_live_channel_t           *channel;
    ngx_live_timeline_t          *timeline;
    ngx_live_segment_iter_t       iter;
    ngx_http_live_ksmp_ctx_t     *ctx;
    ngx_http_live_ksmp_params_t  *params;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    params = &ctx->params;

    flags = params->flags;
    channel = ctx->objs.channel;
    timeline = ctx->objs.timeline;

    scope->channel = channel;
    scope->timeline = timeline;
    scope->track = ctx->objs.track;

    if (channel->part_duration <= 0) {
        flags &= ~(NGX_KSMP_FLAG_RENDITION_REPORTS
            | NGX_KSMP_FLAG_SEGMENT_PARTS);
    }

    /* time param */

    if (params->time != NGX_KSMP_INVALID_TIMESTAMP) {

        time = ngx_live_rescale_time(params->time, 1000, channel->timescale);

        if (ngx_live_timeline_get_time(timeline, flags, r->connection->log,
            &time))
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_live_timelines_get_segment_index(channel, time,
            &params->segment_index) != NGX_OK)
        {
            return ngx_http_live_ksmp_output_error(r,
                NGX_KSMP_ERR_SEGMENT_TIME_NOT_FOUND,
                "time %L not found in any segment, timeline: %V, channel: %V",
                time, &timeline->sn.str, &channel->sn.str);
        }

    } else {
        time = NGX_KSMP_INVALID_TIMESTAMP;
    }

    /* segment timestamp correction */

    segment_index = params->segment_index;

    if (flags & NGX_KSMP_FLAG_MEDIA) {
        code = ngx_live_timeline_get_segment_info(timeline, segment_index,
            flags, &scope->si.correction);
        if (code != NGX_KSMP_ERR_SUCCESS) {
            return ngx_http_live_ksmp_output_error(r, code,
                "segment %uD does not exist, timeline: %V, channel: %V",
                segment_index, &timeline->sn.str, &channel->sn.str);
        }

    } else {
        scope->si.correction = 0;
    }

    if (flags & NGX_KSMP_FLAG_SEGMENT_TIME) {
        if (ngx_live_timelines_get_segment_iter(channel,
            &iter, segment_index, &scope->si.start))
        {
            return ngx_http_live_ksmp_output_error(r, code,
                "segment %uD does not exist, channel: %V",
                segment_index, &channel->sn.str);
        }

        scope->si.duration = ngx_live_segment_iter_get_one(&iter);

    } else {
        scope->si.start = 0;
        scope->si.duration = 0;
    }

    scope->si.index = segment_index;
    scope->si.time = time;

    if (segment_index != NGX_KSMP_INVALID_SEGMENT_INDEX) {
        scope->min_index = scope->max_index = segment_index;

    } else {

        /* timeline min/max index */

        q = ngx_queue_last(&timeline->periods);
        period = ngx_queue_data(q, ngx_live_period_t, queue);
        scope->max_index = period->node.key + period->segment_count - 1;

        q = ngx_queue_head(&timeline->periods);
        period = ngx_queue_data(q, ngx_live_period_t, queue);
        scope->min_index = period->node.key;

        /* exclude pending segments */

        track = scope->track;
        if (track != NULL || !(flags & NGX_KSMP_FLAG_MAX_PENDING)) {
            next_segment_index = channel->next_segment_index;

            if (timeline->manifest.conf.end_list != ngx_live_end_list_forced
                && track != NULL)
            {
                next_segment_index += track->pending_index
                    + track->has_pending_segment;
            }

            if (next_segment_index <= scope->min_index) {
                return ngx_http_live_ksmp_output_error(r,
                    NGX_KSMP_ERR_TIMELINE_EMPTY,
                    "no ready segments in range, "
                    "min: %uD, next: %uD, timeline: %V, channel: %V",
                    scope->min_index, next_segment_index,
                    &timeline->sn.str, &channel->sn.str);
            }

            if (scope->max_index >= next_segment_index) {
                scope->max_index = next_segment_index - 1;
            }
        }

        /* max_segment_index param */

        if (params->max_segment_index < scope->max_index) {
            if (params->max_segment_index < scope->min_index) {
                return ngx_http_live_ksmp_output_error(r,
                    NGX_KSMP_ERR_TIMELINE_EMPTY,
                    "no segments in range, "
                    "min: %uD, max: %uD, timeline: %V, channel: %V",
                    scope->min_index, params->max_segment_index,
                    &timeline->sn.str, &channel->sn.str);
            }

            scope->max_index = params->max_segment_index;
        }

        if (flags & NGX_KSMP_FLAG_LAST_SEGMENT_ONLY) {
            scope->min_index = scope->max_index;
        }
    }

    /* track refs */

    if (flags & NGX_KSMP_FLAG_MEDIA) {
        scope->track_refs = ngx_array_create(r->pool, KMP_MEDIA_COUNT,
            sizeof(ngx_live_track_ref_t));
        if (scope->track_refs == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_ksmp_init_scope: create array failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        scope->track_refs = NULL;
    }

    scope->flags = flags;
    scope->skip_boundary_percent = params->skip_boundary_percent;

    /* variants */

    ngx_memzero(&scope->header, sizeof(scope->header));

    if (params->variant_ids.data != NULL) {
        rc = ngx_http_live_ksmp_parse_variant_ids(r, params, scope);
        if (rc != NGX_OK) {
            return rc;
        }

    } else {
        rc = ngx_http_live_ksmp_add_variants(r, params, scope);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (scope->header.variant_count <= 0) {
        if (params->err_code) {
            return ngx_http_live_ksmp_output_error(r,
                params->err_code, "%V", &params->err_msg);

        } else {
            return ngx_http_live_ksmp_output_error(r,
                NGX_KSMP_ERR_VARIANT_NO_MATCH,
                "no variant matches the request, channel: %V",
                &channel->sn.str);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_write(ngx_http_request_t *r,
    ngx_live_persist_serve_scope_t *scope)
{
    ngx_int_t                       rc;
    ngx_wstream_t                  *ws;
    ngx_live_channel_t             *channel;
    ngx_persist_write_ctx_t        *write_ctx;
    ngx_http_live_ksmp_ctx_t       *ctx;
    ngx_persist_write_marker_t      marker;
    ngx_http_live_ksmp_params_t    *params;
    ngx_live_segment_serve_req_t    req;
    ngx_http_live_ksmp_loc_conf_t  *klcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    params = &ctx->params;

    klcf = ngx_http_get_module_loc_conf(r, ngx_http_live_ksmp_module);

    write_ctx = ngx_persist_write_init(r->pool, NGX_KSMP_PERSIST_TYPE,
        klcf->comp_level);
    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write: write init failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_persist_write_ctx(write_ctx) = scope;

    ws = ngx_persist_write_stream(write_ctx);

    channel = scope->channel;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_CHANNEL) != NGX_OK ||
        ngx_wstream_str(ws, &channel->sn.str) != NGX_OK ||
        ngx_persist_write_reserve(write_ctx, sizeof(scope->header), &marker)
            != NGX_OK ||
        ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write: write failed (1)");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    scope->header.timescale = channel->timescale;
    scope->header.req_media_types = params->media_type_mask;
    scope->header.part_duration = channel->part_duration;
    scope->header.last_modified = channel->last_modified;
    scope->header.now = ngx_time();
    ngx_persist_write_marker_write(&marker, &scope->header,
        sizeof(scope->header));

    ngx_persist_write_block_close(write_ctx);      /* channel */

    ctx->out = ngx_persist_write_close(write_ctx, &ctx->size, &ctx->last);
    if (ctx->out == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write: close failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(params->flags & NGX_KSMP_FLAG_MEDIA)) {
        return ngx_http_live_ksmp_output(r, NGX_HTTP_LAST);
    }

    if (params->part_index == NGX_KSMP_INVALID_PART_INDEX) {

        rc = ngx_live_filler_serve_segments(r->pool, scope->track_refs,
            scope->si.index, &ctx->last, &ctx->size);
        switch (rc) {

        case NGX_OK:
            req.source = ngx_http_live_ksmp_filler_source;
            break;

        case NGX_DONE:
            req.source.len = 0;
            break;

        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_ksmp_write: serve filler failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        req.source.len = 0;
    }

    req.size = 0;
    req.chain = NULL;

    if (scope->track_refs->nelts > 0) {
        req.pool = r->pool;
        req.channel = channel;
        req.tracks = scope->track_refs->elts;
        req.track_count = scope->track_refs->nelts;
        req.flags = params->flags;
        req.segment_index = params->segment_index;
        req.part_index = params->part_index;
        req.time = scope->si.time;

        req.writer.set_size = ngx_http_live_ksmp_segment_set_size;
        req.writer.write = ngx_http_live_ksmp_segment_write;
        req.writer.close = ngx_http_live_ksmp_segment_close;
        req.writer.cleanup = ngx_http_live_ksmp_cleanup;
        req.writer.arg = r;

        rc = ngx_live_serve_segment(&req);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            ctx->source = req.source;

            /* channel objects must not be used beyond this point */
            ngx_memzero(&ctx->objs, sizeof(ctx->objs));

            r->main->count++;
            return NGX_DONE;

        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_ksmp_write: read failed %i", rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ctx->source = req.source;
    ctx->size += req.size;

    rc = ngx_http_live_ksmp_output(r, 0);
    if (rc != NGX_OK) {
        return rc;
    }

    if (req.chain != NULL) {
        rc = ngx_http_output_filter(r, req.chain);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_ksmp_write: output filter failed %i", rc);
            return rc;
        }
    }

    rc = ngx_http_live_ksmp_write_padding(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_write: send special failed %i", rc);
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_http_live_ksmp_ctx_t        *ctx;
    ngx_live_persist_serve_scope_t   scope;

    if (r->method != NGX_HTTP_GET) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_ksmp_handler: unsupported method %ui", r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_handler: discard request body failed %i", rc);
        return rc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_ksmp_handler: alloc ctx failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_live_ksmp_module);

    rc = ngx_http_live_ksmp_parse(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_live_ksmp_init_objs(r);
    if (rc != NGX_OK || r->header_sent) {
        return rc;
    }


    rc = ngx_http_live_ksmp_init_scope(r, &scope);
    if (rc != NGX_OK || r->header_sent) {
        return rc;
    }

    return ngx_http_live_ksmp_write(r, &scope);
}


static ngx_int_t
ngx_http_live_ksmp_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                 *s;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    s = (ngx_str_t *) ((char *) ctx + data);

    if (s->len) {
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
ngx_http_live_ksmp_uint32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    uint32_t                   n;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    n = *(uint32_t *) ((char *) ctx + data);
    v->len = ngx_sprintf(v->data, "%uD", n) - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_msec_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_msec_int_t             ms;
    ngx_http_live_ksmp_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_ksmp_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ms = *(ngx_msec_int_t *) ((char *) ctx + data);
    v->len = ngx_sprintf(v->data, "%T.%03M", (time_t) ms / 1000, ms % 1000)
        - v->data;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_live_ksmp_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_live_ksmp_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_live_ksmp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_live_ksmp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_ksmp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->comp_level = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_live_ksmp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_ksmp_loc_conf_t  *prev = parent;
    ngx_http_live_ksmp_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->comp_level, prev->comp_level, 6);

    return NGX_CONF_OK;
}


static char *
ngx_http_live_ksmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_live_ksmp_handler;

    return NGX_CONF_OK;
}
