
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_ts_module.h"

#include "ngx_ts_stream.h"


typedef struct {
    ngx_array_t               *handlers;  /* ngx_ts_init_handler_t */
    ngx_http_complex_value_t  *stream_id;

    size_t                     mem_limit;
    ngx_str_t                  dump_folder;
} ngx_http_ts_loc_conf_t;


typedef struct {
    ngx_ts_stream_t           *ts;
} ngx_http_ts_ctx_t;


static ngx_int_t ngx_http_ts_handler(ngx_http_request_t *r);
static void ngx_http_ts_init(ngx_http_request_t *r);
static void ngx_http_ts_read_event_handler(ngx_http_request_t *r);

static char *ngx_http_ts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_ts_create_conf(ngx_conf_t *cf);
static char *ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_http_ts_commands[] = {

    { ngx_string("ts"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_ts,
      0,
      0,
      NULL },

    { ngx_string("ts_stream_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_loc_conf_t, stream_id),
      NULL },

    { ngx_string("ts_mem_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_loc_conf_t, mem_limit),
      NULL },

    { ngx_string("ts_dump_folder"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ts_loc_conf_t, dump_folder),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ts_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_ts_create_conf,       /* create location configuration */
    ngx_http_ts_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_ts_module = {
    NGX_MODULE_V1,
    &ngx_http_ts_module_ctx,       /* module context */
    ngx_http_ts_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_ts_add_init_handler(ngx_conf_t *cf,
    ngx_ts_init_handler_pt handler, void *data)
{
    ngx_http_ts_loc_conf_t  *tlcf;

    tlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_ts_module);

    return ngx_ts_add_init_handler(cf, &tlcf->handlers, handler, data);
}


static ngx_int_t
ngx_http_ts_handler(ngx_http_request_t *r)
{
    ngx_int_t                rc;
    ngx_ts_stream_t         *ts;
    ngx_http_ts_ctx_t       *ctx;
    ngx_ts_stream_conf_t     conf;
    ngx_http_ts_loc_conf_t  *tlcf;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ts_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_ts_module);

    if (tlcf->stream_id) {
        if (ngx_http_complex_value(r, tlcf->stream_id, &conf.stream_id)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        conf.stream_id.len = 0;
    }

    conf.mem_limit = tlcf->mem_limit;
    conf.dump_folder = tlcf->dump_folder;

    ts = ngx_ts_stream_create(r->connection, r->pool, &conf);
    if (ts == NULL) {
        return NGX_ERROR;
    }

    ctx->ts = ts;

    ngx_http_set_ctx(r, ctx, ngx_http_ts_module);

    if (ngx_ts_init_handlers(tlcf->handlers, ts) != NGX_OK) {
        return NGX_ERROR;
    }

    r->request_body_no_buffering = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_ts_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_ts_init(ngx_http_request_t *r)
{
    ngx_http_ts_ctx_t        *ctx;
    ngx_http_request_body_t  *rb;

    rb = r->request_body;

    if (rb == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    if (ngx_ts_read(ctx->ts, rb->bufs) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->reading_body) {
        r->read_event_handler = ngx_http_ts_read_event_handler;
    }
}


static void
ngx_http_ts_read_event_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_ts_ctx_t        *ctx;
    ngx_http_request_body_t  *rb;

    if (ngx_exiting || ngx_terminate) {
        ngx_http_finalize_request(r, NGX_HTTP_CLOSE);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ts_module);

    rb = r->request_body;

    for ( ;; ) {
        rc = ngx_http_read_unbuffered_request_body(r);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_finalize_request(r, rc);
            return;
        }

        if (rb->bufs == NULL) {
            return;
        }

        if (ngx_ts_read(ctx->ts, rb->bufs) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        if (rc == NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_NO_CONTENT);
            return;
        }

        rb->bufs = NULL;
    }
}


static char *
ngx_http_ts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ts_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_ts_create_conf(ngx_conf_t *cf)
{
    ngx_http_ts_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ts_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->handlers = NGX_CONF_UNSET_PTR;

    conf->mem_limit = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_ts_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ts_loc_conf_t  *prev = parent;
    ngx_http_ts_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->handlers, prev->handlers, NULL);

    if (conf->stream_id == NULL) {
        conf->stream_id = prev->stream_id;
    }

    ngx_conf_merge_size_value(conf->mem_limit, prev->mem_limit,
        5 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->dump_folder, prev->dump_folder, "");

    return NGX_CONF_OK;
}
