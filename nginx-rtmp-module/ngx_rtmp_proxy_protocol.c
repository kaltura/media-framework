
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include "ngx_rtmp_proxy_protocol.h"


static void ngx_rtmp_proxy_protocol_recv(ngx_event_t *rev);


void
ngx_rtmp_proxy_protocol(ngx_rtmp_session_t *s)
{
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = s->connection;
    rev = c->read;
    rev->handler =  ngx_rtmp_proxy_protocol_recv;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "proxy_protocol: start");

    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    ngx_add_timer(rev, s->timeout);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }
}


static void
ngx_rtmp_proxy_protocol_recv(ngx_event_t *rev)
{
    u_char              *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
    size_t               size;
    ssize_t              n;
    ngx_err_t            err;
    ngx_connection_t    *c;
    ngx_rtmp_session_t  *s;

    c = rev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                      "proxy_protocol: recv: client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0, "recv(): %d", n);

    if (n == -1) {

        if (err == NGX_EAGAIN) {
            ngx_add_timer(rev, s->timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }

            return;
        }

        ngx_rtmp_finalize_session(s);

        return;
    }

    p = ngx_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_rtmp_handshake(s);
}
