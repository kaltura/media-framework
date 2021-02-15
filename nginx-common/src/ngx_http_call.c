#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include "ngx_http_call.h"


#define NGX_HTTP_CONTINUE                  100


struct ngx_http_call_ctx_s {
    ngx_pool_cleanup_t          *cln;
    ngx_pool_t                  *pool;

    void                        *arg;
    ngx_http_call_handle_pt      handle;
    ngx_msec_t                   timeout;
    ngx_msec_t                   read_timeout;
    ngx_msec_t                   retry_interval;
    size_t                       buffer_size;
    size_t                       max_response_size;
    ngx_pool_t                  *handler_pool;

    ngx_event_t                  retry;
    ngx_url_t                   *url;

    void                       (*handler)(ngx_http_call_ctx_t *ctx);

    ngx_chain_t                 *request;
    ngx_chain_t                 *request_body;
    ngx_chain_t                 *orig_request;
    ngx_chain_t                 *orig_request_body;
    ngx_buf_t                   *response;
    ngx_peer_connection_t        peer;

    ngx_int_t                  (*process)(ngx_http_call_ctx_t *ctx);

    ngx_uint_t                   state;

    ngx_uint_t                   code;
    ngx_uint_t                   count;

    ngx_uint_t                   done;

    u_char                      *header_name_start;
    u_char                      *header_name_end;
    u_char                      *header_start;
    u_char                      *header_end;

    ngx_log_t                   *log;
    u_char                       addr_text_buf[NGX_SOCKADDR_STRLEN];
    ngx_str_t                    request_line;

    ngx_str_t                    content_type;
    off_t                        content_length_n;

    unsigned                     destroy_pool:1;
};


static void ngx_http_call_free(ngx_http_call_ctx_t *ctx);
static void ngx_http_call_done(ngx_http_call_ctx_t *ctx);
static ngx_int_t ngx_http_call_connect(ngx_http_call_ctx_t *ctx);
static void ngx_http_call_write_handler(ngx_event_t *wev);
static void ngx_http_call_read_handler(ngx_event_t *rev);
static void ngx_http_call_dummy_handler(ngx_event_t *ev);

static ngx_int_t ngx_http_call_create_request(ngx_http_call_ctx_t *ctx,
    ngx_http_call_init_t *ci);
static ngx_int_t ngx_http_call_process_status_line(ngx_http_call_ctx_t *ctx);
static ngx_int_t ngx_http_call_parse_status_line(ngx_http_call_ctx_t *ctx);
static ngx_int_t ngx_http_call_process_headers(ngx_http_call_ctx_t *ctx);
static ngx_int_t ngx_http_call_parse_header_line(ngx_http_call_ctx_t *ctx);
static ngx_int_t ngx_http_call_process_body(ngx_http_call_ctx_t *ctx);

static u_char *ngx_http_call_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

ngx_http_call_ctx_t *
ngx_http_call_create(ngx_http_call_init_t *ci)
{
    ngx_int_t             rc;
    ngx_log_t            *log = ngx_cycle->log;
    ngx_flag_t            destroy_pool;
    ngx_pool_t           *pool;
    ngx_http_call_ctx_t  *ctx;

    destroy_pool = 0;

    if (ci->pool == NULL) {
        pool = ngx_create_pool(2048, log);
        if (pool == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_http_call_create: create pool failed");
            goto error;
        }
        destroy_pool = 1;

    } else {
        pool = ci->pool;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_http_call_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_http_call_create: alloc ctx failed");
        goto error;
    }

    if (ci->argsize) {
        ctx->arg = ngx_pcalloc(pool, ci->argsize);
        if (ctx->arg == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_http_call_create: alloc arg failed, size: %uz",
                ci->argsize);
            goto error;
        }
        ngx_memcpy(ctx->arg, ci->arg, ci->argsize);
        ci->arg = ctx->arg;

    } else {
        ctx->arg = ci->arg;
    }

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_http_call_create: alloc log failed");
        goto error;
    }

    ctx->pool = pool;
    ctx->destroy_pool = destroy_pool;

    *log = *pool->log;

    pool->log = log;
    ctx->log = log;

    log->handler = ngx_http_call_log_error;
    log->data = ctx;

    if (ngx_http_call_create_request(ctx, ci) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_http_call_create: create request failed");
        goto error;
    }

    ctx->timeout = ci->timeout;
    ctx->read_timeout = ci->read_timeout;
    ctx->retry_interval = ci->retry_interval;
    ctx->buffer_size = ci->buffer_size;
    ctx->max_response_size = ci->max_response_size;
    ctx->response = ci->response;
    ctx->handler = ngx_http_call_done;
    ctx->url = ci->url;

    if (ci->handler_pool && ci->handle) {
        ctx->handle = ci->handle;

        ctx->cln = ngx_pool_cleanup_add(ci->handler_pool, 0);
        if (ctx->cln == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_http_call_create: cleanup add failed");
            goto error;
        }

        ctx->cln->data = ctx;
        ctx->cln->handler = (ngx_pool_cleanup_pt) ngx_http_call_free;

        ctx->handler_pool = ci->handler_pool;
    }

    rc = ngx_http_call_connect(ctx);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_http_call_create: connect failed");
        if (ctx->handler_pool) {
            ctx->cln->handler = NULL;
        }
        goto error;
    }

    return ctx;

error:
    if (destroy_pool) {
        ngx_destroy_pool(pool);
    }

    return NULL;
}


static void
ngx_http_call_free(ngx_http_call_ctx_t *ctx)
{
    if (ctx->retry.timer_set) {
        ngx_del_timer(&ctx->retry);
    }

    if (ctx->handler_pool) {
        ctx->cln->handler = NULL;
    }

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
    }

    if (ctx->destroy_pool) {
        ngx_destroy_pool(ctx->pool);
    }
}


static void
ngx_http_call_reset(ngx_http_call_ctx_t *ctx)
{
    ctx->state = 0;
    ctx->code = 0;
    ctx->count = 0;
    ctx->done = 0;
    ctx->content_type.len = 0;
    ctx->content_length_n = 0;
}


static void
ngx_http_call_retry(ngx_event_t *ev)
{
    ngx_int_t             rc;
    ngx_chain_t          *cl;
    ngx_http_call_ctx_t  *ctx = ev->data;

    ngx_http_call_reset(ctx);

    ctx->request = ctx->orig_request;
    ctx->request_body = ctx->orig_request_body;

    /* Note: assuming that pos was equal to start when the request was sent */
    for (cl = ctx->request; cl != NULL; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
    }

    for (cl = ctx->request_body; cl != NULL; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
    }

    if (ctx->response) {
        ctx->response->last = ctx->response->pos;
    }

    rc = ngx_http_call_connect(ctx);
    if (rc == NGX_ERROR) {
        ngx_http_call_done(ctx);
    }
}


static void
ngx_http_call_done(ngx_http_call_ctx_t *ctx)
{
    ngx_pool_t  *pool;
    ngx_pool_t  *handler_pool;
    ngx_flag_t   destroy_pool;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "http call done, code:%ui, content_type:%V, body_size:%uz",
            ctx->code, &ctx->content_type, ctx->response ?
            (size_t)(ctx->response->last - ctx->response->pos) : 0);

    handler_pool = ctx->handler_pool;
    if (!handler_pool) {
        ngx_http_call_free(ctx);
        return;
    }

    /* remove from handler pool, handler may destroy the pool */
    ctx->cln->handler = NULL;
    ctx->handler_pool = NULL;

    /* clean up everything except pool - must not access ctx if handler
        returns != NGX_AGAIN */
    if (ctx->retry.timer_set) {
        ngx_del_timer(&ctx->retry);
    }

    ctx->log->connection = 0;
    ngx_close_connection(ctx->peer.connection);
    ctx->peer.connection = NULL;

    pool = ctx->pool;
    destroy_pool = ctx->destroy_pool;

    if (ctx->handle(pool, ctx->arg, ctx->code, &ctx->content_type,
        ctx->response) != NGX_AGAIN)
    {
        if (destroy_pool) {
            ngx_destroy_pool(pool);
        }
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "http call retry");

    /* add back to handler pool */
    ctx->cln->handler = (ngx_pool_cleanup_pt) ngx_http_call_free;
    ctx->handler_pool = handler_pool;

    ctx->retry.handler = ngx_http_call_retry;
    ctx->retry.data = ctx;
    ctx->retry.log = ctx->log;

    ngx_add_timer(&ctx->retry, ctx->retry_interval);
}


void
ngx_http_call_cancel(ngx_http_call_ctx_t *ctx)
{
    ngx_http_call_free(ctx);
}


static void
ngx_http_call_error(ngx_http_call_ctx_t *ctx, ngx_uint_t code)
{
    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
        "http call error");

    ctx->code = code;
    ctx->handler(ctx);
}


#if (NGX_DEBUG)
static void
ngx_http_call_log_request(ngx_http_call_ctx_t *ctx)
{
    ngx_str_t     cur;
    ngx_chain_t  *cl;

    for (cl = ctx->request; cl != NULL; cl = cl->next) {
        cur.data = cl->buf->pos;
        cur.len = cl->buf->last - cl->buf->pos;
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "http call request: %V", &cur);
    }
}
#endif


static ngx_int_t
ngx_http_call_connect(ngx_http_call_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_str_t          addr_text;
    ngx_connection_t  *cc;

    ctx->peer.sockaddr = (struct sockaddr *)&ctx->url->sockaddr;
    ctx->peer.socklen = ctx->url->socklen;

    addr_text.data = ctx->addr_text_buf;
    addr_text.len = ngx_sock_ntop(ctx->peer.sockaddr, ctx->peer.socklen,
        ctx->addr_text_buf, sizeof(ctx->addr_text_buf), 1);

    ctx->peer.name = &ctx->url->host;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_http_call_connect: connect peer failed %i, addr: %V",
            rc, &addr_text);
        return NGX_ERROR;
    }

    cc = ctx->peer.connection;
    cc->data = ctx;
    cc->pool = ctx->pool;

    cc->read->handler = ngx_http_call_read_handler;
    cc->write->handler = ngx_http_call_write_handler;

    ctx->process = ngx_http_call_process_status_line;

    ctx->log->connection = cc->number;
    cc->addr_text = addr_text;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "ngx_http_call_connect: connecting to %V, ctx: %p", &addr_text, ctx);

#if (NGX_DEBUG)
    ngx_http_call_log_request(ctx);
#endif

    ctx->log->action = "connecting to upstream";

    if (rc == NGX_AGAIN) {
        ngx_add_timer(cc->write, ctx->timeout);
        return rc;
    }

    ngx_http_call_write_handler(ctx->peer.connection->write);
    return NGX_OK;
}


static void
ngx_http_call_write_handler(ngx_event_t *wev)
{
    ngx_chain_t          *cl;
    ngx_connection_t     *c;
    ngx_http_call_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, wev->log, 0,
        "ngx_http_call_write_handler: called");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
            "ngx_http_call_write_handler: timed out");
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_TIME_OUT);
        return;
    }

    ctx->log->action = "sending request to upstream";

    cl = c->send_chain(c, ctx->request, 0);

    if (cl == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_http_call_write_handler: send_chain failed");
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_BAD_GATEWAY);
        return;
    }

    ctx->request = cl;

    if (cl == NULL) {
        wev->handler = ngx_http_call_dummy_handler;
        ctx->log->action = "reading upstream";

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        ngx_add_timer(c->read, ctx->read_timeout);

        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_http_call_write_handler: ngx_handle_write_event failed");
            ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_INTERNAL);
        }

        return;
    }

    if (!wev->timer_set) {
        ngx_add_timer(wev, ctx->timeout);
    }
}


static ngx_int_t
ngx_http_call_write_request_body(ngx_http_call_ctx_t *ctx)
{
    ngx_chain_t          *cl;
    ngx_event_t          *wev;
    ngx_connection_t     *c;

    c = ctx->peer.connection;

    cl = c->send_chain(c, ctx->request_body, 0);

    if (cl == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_http_call_write_request_body: send_chain failed");
        return NGX_ERROR;
    }

    ctx->request_body = cl;

    wev = c->write;

    if (cl == NULL) {
        wev->handler = ngx_http_call_dummy_handler;
        ctx->log->action = "reading upstream";

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        ngx_add_timer(c->read, ctx->read_timeout);

        return NGX_OK;
    }

    if (!wev->timer_set) {
        ngx_add_timer(wev, ctx->timeout);
    }

    return NGX_AGAIN;
}

static void
ngx_http_call_body_write_handler(ngx_event_t *wev)
{
    ngx_connection_t     *c;
    ngx_http_call_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, wev->log, 0,
        "ngx_http_call_body_write_handler: called");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
            "ngx_http_call_body_write_handler: timed out");
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_TIME_OUT);
        return;
    }

    if (ngx_http_call_write_request_body(ctx) == NGX_ERROR) {
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_BAD_GATEWAY);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_http_call_body_write_handler: "
            "ngx_handle_write_event failed");
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_INTERNAL);
        return;
    }
}


static void
ngx_http_call_read_handler(ngx_event_t *rev)
{
    ssize_t               n, size;
    ngx_int_t             rc;
    ngx_connection_t     *c;
    ngx_http_call_ctx_t  *ctx;

    c = rev->data;
    ctx = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0,
        "ngx_http_call_read_handler: called");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
            "ngx_http_call_read_handler: timed out");
        ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_TIME_OUT);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, ctx->buffer_size);
        if (ctx->response == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_http_call_read_handler: create buf failed");
            ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_INTERNAL);
            return;
        }
    }

    for ( ;; ) {

        size = ctx->response->end - ctx->response->last;

        if (size <= 0) {

            if (ctx->content_length_n &&
                ctx->response->last - ctx->response->pos >=
                ctx->content_length_n)
            {
                /* already read everything */
                break;
            }

            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                "response buffer size too small");
            ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_BAD_GATEWAY);
            return;
        }

        n = ngx_recv(c, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;

            rc = ctx->process(ctx);

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_http_call_read_handler: process failed");
                ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_BAD_GATEWAY);
                return;
            }

            continue;
        }

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_http_call_read_handler: "
                    "ngx_handle_read_event failed");
                ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_INTERNAL);
            }

            return;
        }

        break;
    }

    ctx->done = 1;

    rc = ctx->process(ctx);

    if (rc == NGX_DONE) {
        /* ctx->handler() was called */
        return;
    }

    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
        "ngx_http_call_read_handler: prematurely closed connection");
    ngx_http_call_error(ctx, NGX_HTTP_CALL_ERROR_BAD_GATEWAY);
}


static void
ngx_http_call_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
        "ngx_http_call_dummy_handler: called");
}


static ngx_int_t
ngx_http_call_create_request(ngx_http_call_ctx_t *ctx, ngx_http_call_init_t *ci)
{
    u_char       *end;
#if (NGX_DEBUG)
    ngx_chain_t  *cl;
#endif

    ctx->request = ci->create(ci->arg, ctx->pool, &ctx->request_body);
    if (ctx->request == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_http_call_create_request: create failed");
        return NGX_ERROR;
    }

#if (NGX_DEBUG)
    for (cl = ctx->request; cl; cl = cl->next) {
        if (cl->buf->pos != cl->buf->start) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_http_call_create_request: "
                "request buffer pos is different from buffer start");
            ngx_debug_point();
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_http_call_create_request: zero size request buf "
                "t:%d %p %p-%p", cl->buf->temporary, cl->buf->start,
                cl->buf->pos, cl->buf->last);
            ngx_debug_point();
            return NGX_ERROR;
        }
    }

    for (cl = ctx->request_body; cl; cl = cl->next) {
        if (cl->buf->pos != cl->buf->start) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_http_call_create_request: "
                "request body buffer pos is different from buffer start");
            ngx_debug_point();
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_http_call_create_request: zero size request body buf "
                "t:%d %p %p-%p", cl->buf->temporary, cl->buf->start,
                cl->buf->pos, cl->buf->last);
            ngx_debug_point();
            return NGX_ERROR;
        }
    }
#endif

    ctx->orig_request = ctx->request;
    ctx->orig_request_body = ctx->request_body;

    ctx->request_line.data = ctx->request->buf->pos;
    end = ngx_strlchr(ctx->request_line.data, ctx->request->buf->last, '\r');
    if (end != NULL) {
        ctx->request_line.len = end - ctx->request_line.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_call_process_status_line(ngx_http_call_ctx_t *ctx)
{
    ngx_int_t  rc;

    rc = ngx_http_call_parse_status_line(ctx);

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "http call status %ui \"%*s\"",
            ctx->code,
            ctx->header_end - ctx->header_start,
            ctx->header_start);

        ctx->process = ngx_http_call_process_headers;
        return ctx->process(ctx);
    }

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* rc == NGX_ERROR */

    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
        "ngx_http_call_process_status_line: got invalid response");
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_call_parse_status_line(ngx_http_call_ctx_t *ctx)
{
    u_char      ch;
    u_char     *p;
    ngx_buf_t  *b;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
        "ngx_http_call_parse_status_line: called");

    state = ctx->state;
    b = ctx->response;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

            /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

            /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

            /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

            /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

            /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

            /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            ctx->code = ctx->code * 10 + (ch - '0');

            if (++ctx->count == 3) {
                state = sw_space_after_status;
                ctx->header_start = p - 2;
            }

            break;

            /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

            /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

            /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                ctx->header_end = p - 1;
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_call_process_headers(ngx_http_call_ctx_t *ctx)
{
    ngx_int_t   rc;
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_buf_t  *b;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
        "ngx_http_call_process_headers: called");

    for ( ;; ) {
        rc = ngx_http_call_parse_header_line(ctx);

        if (rc == NGX_OK) {

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;

            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                "http call header \"%V: %V\"", &key, &value);

            if (key.len == sizeof("Content-Type") - 1
                && ngx_strncasecmp(key.data,
                (u_char *) "Content-Type",
                    sizeof("Content-Type") - 1)
                == 0)
            {
                ctx->content_type = value;
                continue;
            }

            if (key.len == sizeof("Content-Length") - 1
                && ngx_strncasecmp(key.data,
                (u_char *) "Content-Length",
                    sizeof("Content-Length") - 1)
                == 0)
            {
                ctx->content_length_n = ngx_atoof(value.data, value.len);
                if (ctx->content_length_n < 0) {
                    ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                        "ngx_http_call_process_headers: "
                        "invalid content-length \"%V\"", &value);
                    return NGX_ERROR;
                }
            }

            continue;
        }

        if (rc == NGX_DONE) {
            break;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_ERROR */

        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_http_call_process_headers: invalid response");
        return NGX_ERROR;
    }

    if (ctx->content_length_n > ctx->response->end - ctx->response->pos) {

        if (ctx->max_response_size &&
            (size_t) ctx->content_length_n > ctx->max_response_size)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "ngx_http_call_process_headers: content length %O too big",
                ctx->content_length_n);
            return NGX_ERROR;
        }

        b = ngx_create_temp_buf(ctx->pool, ctx->content_length_n);
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_http_call_process_headers: create buf failed");
            return NGX_ERROR;
        }

        b->last = ngx_copy(b->last, ctx->response->pos,
            ctx->response->last - ctx->response->pos);

        ctx->response = b;
    }

    ctx->process = ngx_http_call_process_body;
    return ctx->process(ctx);
}


static ngx_int_t
ngx_http_call_parse_header_line(ngx_http_call_ctx_t *ctx)
{
    u_char  c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
            "s:%d in:'%02Xd:%c'", state, ch, ch);
#endif

        switch (state) {

            /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char)(ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NGX_ERROR;
            }
            break;

            /* header name */
        case sw_name:
            c = (u_char)(ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NGX_ERROR;

            /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

            /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

            /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

            /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }

            /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_call_process_body(ngx_http_call_ctx_t *ctx)
{
    ngx_connection_t  *cc = ctx->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
        "ngx_http_call_process_body: called");

    if (ctx->code == NGX_HTTP_CONTINUE && ctx->request_body &&
        cc->write->handler == ngx_http_call_dummy_handler)
    {
        ngx_http_call_reset(ctx);

        ctx->process = ngx_http_call_process_status_line;

        if (cc->read->timer_set) {
            ngx_del_timer(cc->read);
        }

        ctx->log->action = "sending request body to upstream";

        cc->write->handler = ngx_http_call_body_write_handler;
        if (ngx_http_call_write_request_body(ctx) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (ctx->done) {
        ctx->handler(ctx);
        return NGX_DONE;
    }

    return NGX_AGAIN;
}


static u_char *
ngx_http_call_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char               *p;
    ngx_http_call_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    if (ctx != NULL) {
        if (ctx->peer.connection && ctx->peer.connection->addr_text.len) {
            p = ngx_snprintf(buf, len, ", addr: %V",
                &ctx->peer.connection->addr_text);
            len -= p - buf;
            buf = p;
        }

        if (ctx->peer.name) {
            p = ngx_snprintf(buf, len, ", peer: %V", ctx->peer.name);
            len -= p - buf;
            buf = p;
        }

        if (ctx->request_line.len) {
            p = ngx_snprintf(buf, len, ", request: \"%V\"",
                &ctx->request_line);
            len -= p - buf;
            buf = p;
        }
    }

    return p;
}
