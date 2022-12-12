#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_call.h>
#include <ngx_json_parser.h>
#include <ngx_kmp_out_utils.h>
#include <ngx_kmp_out_connect.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_ts_kmp_track.h"


typedef struct {
    ngx_ts_kmp_ctx_t  *ctx;
    ngx_str_t          stream_id;
    ngx_uint_t         retries_left;
} ngx_ts_kmp_connect_call_ctx_t;


typedef struct {
    ngx_json_str_t     stream_id;
} ngx_ts_kmp_connect_t;


static ngx_int_t ngx_ts_kmp_init_process(ngx_cycle_t *cycle);


static ngx_core_module_t  ngx_ts_kmp_module_ctx = {
    ngx_string("ts_kmp"),
    NULL,
    NULL
};


ngx_module_t  ngx_ts_kmp_module = {
    NGX_MODULE_V1,
    &ngx_ts_kmp_module_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_ts_kmp_init_process,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_queue_t  ngx_ts_kmp_sessions;


#include "ngx_ts_kmp_module_json.h"


static ngx_int_t
ngx_ts_kmp_init_process(ngx_cycle_t *cycle)
{
    ngx_queue_init(&ngx_ts_kmp_sessions);

    return NGX_OK;
}


static ngx_chain_t *
ngx_ts_kmp_connect_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    size_t                          size;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_ts_kmp_ctx_t               *ctx;
    ngx_ts_kmp_conf_t              *conf;
    ngx_ts_kmp_connect_t            connect;
    ngx_ts_kmp_connect_call_ctx_t  *cctx = arg;

    ctx = cctx->ctx;
    conf = ctx->conf;

    connect.stream_id.s = cctx->stream_id;
    ngx_json_str_set_escape(&connect.stream_id);

    size = ngx_ts_kmp_connect_json_get_size(&connect, ctx->connection);
    cl = ngx_http_call_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_ts_kmp_connect_create: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;
    b->last = ngx_ts_kmp_connect_json_write(b->last, &connect,
        ctx->connection);

    if ((size_t) (b->last - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_ts_kmp_connect_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (b->last - b->pos), size);
        return NULL;
    }

    return ngx_http_call_format_json_post(pool,
        &conf->ctrl_connect_url->host, &conf->ctrl_connect_url->uri,
        conf->t.ctrl_headers, cl);
}


static ngx_int_t
ngx_ts_kmp_connect_handle(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_int_t                       rc;
    ngx_log_t                      *log;
    ngx_str_t                       desc;
    ngx_ts_kmp_ctx_t               *ctx;
    ngx_ts_kmp_connect_call_ctx_t  *cctx = arg;

    ctx = cctx->ctx;
    log = ctx->connection->log;

    rc = ngx_kmp_out_connect_parse(temp_pool, log, code, content_type,
        body, &desc);
    switch (rc) {

    case NGX_OK:
        if (ctx->state == ngx_ts_kmp_state_initial) {
            ctx->state = ngx_ts_kmp_state_connect_done;
        }

        break;

    case NGX_DECLINED:
        goto error;

    default:    /* NGX_ERROR */
        if (cctx->retries_left > 0) {
            cctx->retries_left--;
            return NGX_AGAIN;
        }

        desc.data = (u_char *) "Internal server error";
        goto error;
    }

    return NGX_OK;

error:

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "ngx_ts_kmp_connect_handle: connect error \"%V\"", &desc);
    ctx->state = ngx_ts_kmp_state_error;

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_connect(ngx_ts_handler_data_t *hd)
{
    ngx_url_t                      *url;
    ngx_ts_stream_t                *ts = hd->ts;
    ngx_ts_kmp_ctx_t               *ctx = hd->data;
    ngx_ts_kmp_conf_t              *conf = ctx->conf;
    ngx_http_call_init_t            ci;
    ngx_ts_kmp_connect_call_ctx_t   create_ctx;

    url = ctx->conf->ctrl_connect_url;
    if (url == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_KMP, ts->log, 0,
            "ngx_ts_kmp_connect: no connect url set in conf");
        ctx->state = ngx_ts_kmp_state_connect_done;
        return NGX_OK;
    }

    ctx->stream_id.s = ts->stream_id;
    ngx_json_str_set_escape(&ctx->stream_id);

    create_ctx.ctx = ctx;
    create_ctx.stream_id = ts->stream_id;
    create_ctx.retries_left = conf->t.ctrl_retries;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_ts_kmp_connect_create;
    ci.handle = ngx_ts_kmp_connect_handle;
    ci.handler_pool = ts->pool;
    ci.arg = &create_ctx;
    ci.argsize = sizeof(create_ctx);
    ci.timeout = conf->t.ctrl_timeout;
    ci.read_timeout = conf->t.ctrl_read_timeout;
    ci.buffer_size = conf->t.ctrl_buffer_size;
    ci.retry_interval = conf->t.ctrl_retry_interval;

    ngx_log_error(NGX_LOG_INFO, ts->log, 0,
        "ngx_ts_kmp_connect: sending connect request to \"%V\"", &url->url);

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ts->log, 0,
            "ngx_ts_kmp_connect: http call to \"%V\" failed",
            &url->url);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_kmp_pes_handler(ngx_ts_handler_data_t *hd)
{
    ngx_ts_es_t         *es = hd->es;
    ngx_ts_kmp_ctx_t    *ctx;
    ngx_ts_kmp_track_t  *ts_track;

    ctx = hd->data;

    ts_track = ngx_ts_kmp_track_get(ctx, es->pid);
    if (ts_track == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_KMP, hd->ts->log, 0,
            "ngx_ts_kmp_pes_handler: no track for pid %uD",
            (uint32_t) es->pid);
        return NGX_OK;
    }

    return ngx_ts_kmp_track_pes_handler(ts_track, hd);
}


static ngx_int_t
ngx_ts_kmp_handler(ngx_ts_handler_data_t *hd)
{
    ngx_ts_kmp_ctx_t  *ctx = hd->data;

    if (ctx->state == ngx_ts_kmp_state_error) {
        return NGX_ERROR;
    }

    switch (hd->event) {

    case NGX_TS_PAT:
        return ngx_ts_kmp_connect(hd);

    case NGX_TS_PMT:
        return ngx_ts_kmp_track_create(hd);

    case NGX_TS_PES:
        return ngx_ts_kmp_pes_handler(hd);

    default:
        return NGX_OK;
    }
}


static void
ngx_ts_kmp_detach_tracks(ngx_ts_kmp_ctx_t *ctx, char *reason)
{
    ngx_queue_t         *q;
    ngx_ts_kmp_track_t  *ts_track;

    for (q = ngx_queue_head(&ctx->tracks);
        q != ngx_queue_sentinel(&ctx->tracks);
        )
    {
        ts_track = ngx_queue_data(q, ngx_ts_kmp_track_t, queue);
        q = ngx_queue_next(q);      /* the track may be freed */

        ngx_kmp_out_track_detach(ts_track->track, reason);
    }
}


static void
ngx_ts_kmp_cleanup(void *data)
{
    ngx_ts_kmp_ctx_t  *ctx;

    ctx = data;
    ngx_queue_remove(&ctx->queue);

    ngx_ts_kmp_detach_tracks(ctx, "");
}


ngx_int_t
ngx_ts_kmp_init_handler(ngx_ts_stream_t *ts, void *data)
{
    ngx_ts_kmp_ctx_t    *ctx;
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    ctx = ngx_pcalloc(ts->pool, sizeof(ngx_ts_kmp_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(ts->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ts->log, 0,
            "ngx_ts_kmp_init_handler: cleanup add failed");
        return NGX_ERROR;
    }

    c = ts->connection;

    ctx->connection = c;
    ctx->conf = data;
    ctx->start_msec = ngx_current_msec;

    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->tracks);

    ngx_queue_insert_tail(&ngx_ts_kmp_sessions, &ctx->queue);

    ctx->remote_addr.s.data = ctx->remote_addr_buf;

#if (nginx_version >= 1017006)
    u_char                *p;
    ngx_proxy_protocol_t  *pp;

    pp = c->proxy_protocol;
    if (pp && pp->src_addr.len < NGX_SOCKADDR_STRLEN - (sizeof(":65535") - 1)) {
        p = ngx_copy(ctx->remote_addr_buf, pp->src_addr.data, pp->src_addr.len);
        p = ngx_sprintf(p, ":%uD", (uint32_t) pp->src_port);
        ctx->remote_addr.s.len = p - ctx->remote_addr_buf;

    } else {
#endif
        ctx->remote_addr.s.len = ngx_sock_ntop(c->sockaddr, c->socklen,
        ctx->remote_addr_buf, NGX_SOCKADDR_STRLEN, 1);
        if (ctx->remote_addr.s.len == 0) {
            ctx->remote_addr.s = c->addr_text;
        }
#if (nginx_version >= 1017006)
    }
#endif

    ngx_json_str_set_escape(&ctx->remote_addr);

    ctx->local_addr.s.len = NGX_SOCKADDR_STRLEN;
    ctx->local_addr.s.data = ctx->local_addr_buf;

    if (ngx_connection_local_sockaddr(c, &ctx->local_addr.s, 1) != NGX_OK) {
        ctx->local_addr.s.len = 0;
    }

    ngx_json_str_set_escape(&ctx->local_addr);

    cln->handler = ngx_ts_kmp_cleanup;
    cln->data = ctx;

    return ngx_ts_add_handler(ts, ngx_ts_kmp_handler, ctx);
}


static ngx_ts_kmp_ctx_t *
ngx_ts_kmp_get_session(ngx_uint_t connection)
{
    ngx_queue_t       *q;
    ngx_ts_kmp_ctx_t  *cur;

    for (q = ngx_queue_head(&ngx_ts_kmp_sessions);
        q != ngx_queue_sentinel(&ngx_ts_kmp_sessions);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_ts_kmp_ctx_t, queue);

        if (cur->connection->number == connection) {
            return cur;
        }
    }

    return NULL;
}


ngx_int_t
ngx_ts_kmp_finalize_session(ngx_uint_t connection, ngx_log_t *log)
{
    ngx_ts_kmp_ctx_t  *ctx;

    ctx = ngx_ts_kmp_get_session(connection);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_kmp_finalize_session: "
            "connection %ui not found", connection);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_ts_kmp_finalize_session: "
        "dropping connection %ui", connection);
    ctx->conf->finalize(ctx->connection);

    return NGX_OK;
}
