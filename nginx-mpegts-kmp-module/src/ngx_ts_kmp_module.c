#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_http_call.h>
#include <ngx_json_parser.h>
#include <ngx_kmp_push_utils.h>
#include <ngx_kmp_push_connect.h>

#include "ngx_ts_kmp_module.h"
#include "ngx_ts_kmp_track.h"


typedef struct {
    ngx_ts_kmp_ctx_t  *ctx;
    ngx_str_t          stream_id;
    ngx_uint_t         retries_left;
} ngx_ts_kmp_connect_call_ctx_t;

typedef struct {
    ngx_str_t          stream_id;
} ngx_ts_kmp_connect_t;


#include "ngx_ts_kmp_json.h"


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

    connect.stream_id = cctx->stream_id;
    size = ngx_ts_kmp_connect_json_get_size(&connect, ctx->connection);
    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
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

    return ngx_kmp_push_format_json_http_request(pool,
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
    ngx_ts_kmp_connect_call_ctx_t  *cctx = arg;

    log = cctx->ctx->connection->log;

    rc = ngx_kmp_push_connect_parse(temp_pool, log, code, content_type,
        body, &desc);
    switch (rc) {

    case NGX_OK:
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
    cctx->ctx->error = 1;

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
        return NGX_ERROR;
    }

    ctx->header = ts->header;
    create_ctx.ctx = ctx;
    create_ctx.stream_id = ts->header;
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

    if (ctx->error) {
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

        ngx_kmp_push_track_detach(ts_track->track, reason);
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
    u_char                *p;
    ngx_ts_kmp_ctx_t      *ctx;
    ngx_connection_t      *c;
    ngx_pool_cleanup_t    *cln;
    ngx_proxy_protocol_t  *pp;

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
    ngx_queue_insert_tail(&ctx->conf->sessions, &ctx->queue);
    ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->tracks);

    ctx->remote_addr.data = ctx->remote_addr_buf;
    pp = c->proxy_protocol;
    if (pp && pp->src_addr.len < NGX_SOCKADDR_STRLEN - (sizeof(":65535") - 1)) {
        p = ngx_copy(ctx->remote_addr_buf, pp->src_addr.data, pp->src_addr.len);
#if (nginx_version >= 1017006)
        p = ngx_sprintf(p, ":%uD", (uint32_t) pp->src_port);
#endif
        ctx->remote_addr.len = p - ctx->remote_addr_buf;

    } else {
        ctx->remote_addr.len = ngx_sock_ntop(c->sockaddr, c->socklen,
        ctx->remote_addr_buf, NGX_SOCKADDR_STRLEN, 1);
        if (ctx->remote_addr.len == 0) {
            ctx->remote_addr = c->addr_text;
        }
    }

    cln->handler = ngx_ts_kmp_cleanup;
    cln->data = ctx;

    return ngx_ts_add_handler(ts, ngx_ts_kmp_handler, ctx);
}
