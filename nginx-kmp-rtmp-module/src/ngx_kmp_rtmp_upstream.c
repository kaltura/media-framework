#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_json_parser.h>
#include <ngx_http_call.h>

#include "ngx_kmp_rtmp_track.h"
#include "ngx_kmp_rtmp_stream.h"
#include "ngx_kmp_rtmp_encoder.h"
#include "ngx_kmp_rtmp_upstream.h"
#include "ngx_kmp_rtmp_version.h"


#define NGX_KMP_RTMP_FLASH_VER         "FMLE/3.0 (compatible; KalturaLive/%V)"

#define NGX_KMP_RTMP_ISO8601_DATE_LEN  (sizeof("yyyy-mm-dd") - 1)


typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_kmp_rtmp_upstreams_t;


static ngx_kmp_rtmp_upstreams_t  ngx_kmp_rtmp_upstreams;

static ngx_str_t  ngx_kmp_rtmp_url_prefix = ngx_string("rtmp://");

ngx_json_str_t  ngx_kmp_rtmp_version = ngx_json_string(NGX_KMP_RTMP_VERSION);


#include "ngx_kmp_rtmp_upstream_json.h"


ngx_int_t
ngx_kmp_rtmp_init_process(ngx_cycle_t *cycle)
{
    ngx_json_str_set_escape(&ngx_kmp_rtmp_version);

    ngx_rbtree_init(&ngx_kmp_rtmp_upstreams.rbtree,
        &ngx_kmp_rtmp_upstreams.sentinel, ngx_str_rbtree_insert_value);
    ngx_queue_init(&ngx_kmp_rtmp_upstreams.queue);

    return NGX_OK;
}


ngx_buf_chain_t *
ngx_kmp_rtmp_upstream_alloc_chain(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_buf_chain_t  *chain;

    chain = u->free_chains;
    if (chain) {
        u->free_chains = chain->next;
        return chain;
    }

    if (u->mem_left < sizeof(*chain)) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_rtmp_upstream_alloc_chain: memory limit exceeded");
        goto failed;
    }

    u->mem_left -= sizeof(*chain);

    chain = ngx_palloc(u->pool, sizeof(*chain));
    if (chain == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_alloc_chain: alloc failed");
        goto failed;
    }

    return chain;

failed:

    ngx_kmp_rtmp_upstream_finalize(u, "alloc_chain_failed");
    return NULL;
}


void
ngx_kmp_rtmp_upstream_free_chain_list(ngx_kmp_rtmp_upstream_t *u,
    ngx_buf_chain_t *head, ngx_buf_chain_t *tail)
{
    if (tail == NULL) {
        for (tail = head; tail->next != NULL; tail = tail->next);
    }

    tail->next = u->free_chains;
    u->free_chains = head;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_send(ngx_kmp_rtmp_upstream_t *u)
{
    off_t              sent;
    u_char            *limit;
    ngx_chain_t       *chain;
    ngx_chain_t       *next;
    ngx_chain_t       *cl;
    ngx_connection_t  *c = u->peer.connection;

#if (NGX_DEBUG)
    size_t             buffered;
#endif

    if (c->error) {
        return NGX_ERROR;
    }

    if (u->hs != NULL || !u->busy) {
        return NGX_OK;
    }

    sent = c->sent;

    chain = c->send_chain(c, u->busy, 0);
    if (chain == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_rtmp_upstream_send: send_chain failed");
        c->error = 1;
        return NGX_ERROR;
    }

    /* move sent buffers to free */
    for (cl = u->busy; cl && cl != chain; cl = next) {
        next = cl->next;

        cl->next = u->free;
        u->free = cl;
    }

    u->busy = chain;

    /* Note: u->free contains the last chain that was sent */
    limit = chain ? chain->buf->pos : u->free->buf->last - 1;

    ngx_buf_queue_free(&u->buf_queue, limit);

#if (NGX_DEBUG)
    buffered = 0;
    for (cl = u->busy; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
        "ngx_kmp_rtmp_upstream_send: sent %O bytes, %uz in buffer",
        c->sent - sent, buffered);
#endif

    if (u->busy == NULL) {

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        u->last = &u->busy;

        if (ngx_queue_empty(&u->streams.queue)
            && u->active_buf.last <= u->active_buf.pos)
        {
            ngx_kmp_rtmp_upstream_finalize(u, "done");
        }

        return NGX_OK;

    } else if (c->sent != sent) {
        ngx_add_timer(c->write, u->conf.timeout);
    }

    return NGX_AGAIN;
}


static ngx_chain_t *
ngx_kmp_rtmp_alloc_chain_buf(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (u->mem_left < sizeof(*cl) + sizeof(*b)) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_rtmp_alloc_chain_buf: memory limit exceeded");
        return NULL;
    }

    u->mem_left -= sizeof(*cl) + sizeof(*b);

    cl = ngx_alloc_chain_link(u->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_alloc_chain_buf: alloc chain failed");
        return NULL;
    }

    b = ngx_calloc_buf(u->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_alloc_chain_buf: alloc buf failed");
        return NULL;
    }

    b->temporary = 1;

    cl->buf = b;

    return cl;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_append(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (u->active_buf.last <= u->active_buf.pos) {
        return NGX_OK;
    }

    cl = u->free;
    if (cl != NULL) {
        u->free = cl->next;

    } else {
        cl = ngx_kmp_rtmp_alloc_chain_buf(u);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_rtmp_upstream_append: alloc chain buf failed");
            return NGX_ERROR;
        }
    }

    b = cl->buf;

    b->start = b->pos = u->active_buf.pos;
    b->end = b->last = u->active_buf.last;

    *u->last = cl;
    u->last = &cl->next;

    cl->next = NULL;

    u->active_buf.pos = u->active_buf.last;

    return NGX_OK;
}


ngx_int_t
ngx_kmp_rtmp_upstream_write(void *data, void *buf, size_t size)
{
    u_char                   *p;
    size_t                    left;
    ngx_int_t                 rc;
    ngx_buf_t                *b;
    ngx_flag_t                appended;
    ngx_connection_t         *c;
    ngx_kmp_rtmp_upstream_t  *u;

    u = data;
    if (u->write_error) {
        return NGX_ERROR;
    }

    b = &u->active_buf;

    p = buf;
    appended = 0;

    while (size > 0) {

        left = b->end - b->last;
        if (left > size) {
            b->last = ngx_copy(b->last, p, size);
            u->written_bytes += size;
            break;
        }

        ngx_memcpy(b->last, p, left);
        b->last = b->end;
        u->written_bytes += left;

        if (ngx_kmp_rtmp_upstream_append(u) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_rtmp_upstream_write: append failed");
            goto error;
        }

        b->start = ngx_buf_queue_get(&u->buf_queue);
        if (b->start == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_rtmp_upstream_write: get buf failed");
            goto error;
        }

        b->end = b->start + u->buf_queue.used_size;
        b->pos = b->last = b->start;

        appended = 1;

        p += left;
        size -= left;
    }

    if (appended || !u->flush.timer_set) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_write: resetting flush timer");

        ngx_add_timer(&u->flush, u->conf.flush_timeout);
    }

    c = u->peer.connection;
    if (appended && c && c->write->ready) {
        rc = ngx_kmp_rtmp_upstream_send(u);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_rtmp_upstream_write: send failed");
            goto error;
        }
    }

    return NGX_OK;

error:

    u->write_error = 1;
    return NGX_ERROR;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_flush(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    if (ngx_kmp_rtmp_upstream_append(u) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_flush: append failed");
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (!c || !c->write->ready) {
        return NGX_OK;
    }

    rc = ngx_kmp_rtmp_upstream_send(u);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_flush: send failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


u_char *
ngx_kmp_rtmp_upstream_get_buf(ngx_kmp_rtmp_upstream_t *u, size_t size)
{
    u_char     *p;
    ngx_buf_t  *b;

    if (u->write_error) {
        return NULL;
    }

    b = &u->active_buf;
    p = b->last;

    if (size < (size_t) (b->end - p)) {
        if (!u->flush.timer_set) {
            ngx_add_timer(&u->flush, u->conf.flush_timeout);
        }

        goto done;
    }

    if (size > u->buf_queue.used_size) {
        ngx_log_error(NGX_LOG_CRIT, &u->log, 0,
            "ngx_kmp_rtmp_upstream_get_buf: not enough space in buf");
        goto error;
    }

    if (ngx_kmp_rtmp_upstream_flush(u) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_get_buf: flush failed");
        goto error;
    }

    p = ngx_buf_queue_get(&u->buf_queue);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_get_buf: get buf failed");
        goto error;
    }

    b->pos = b->start = p;
    b->end = p + u->buf_queue.used_size;

    ngx_add_timer(&u->flush, u->conf.flush_timeout);

done:

    b->last = p + size;
    u->written_bytes += size;

    return p;

error:

    u->write_error = 1;
    return NULL;
}


static void
ngx_kmp_rtmp_upstream_flush_handler(ngx_event_t *ev)
{
    ngx_kmp_rtmp_upstream_t  *u;

    u = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &u->log, 0,
        "ngx_kmp_rtmp_upstream_flush_handler: called");

    if (ngx_kmp_rtmp_upstream_flush(u) != NGX_OK) {
        ngx_kmp_rtmp_upstream_free(u, "flush_failed");
    }
}


static ngx_int_t
ngx_kmp_rtmp_upstream_process_expired(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_int_t           rc;
    ngx_rbtree_node_t  *root, *sentinel, *node;

    sentinel = u->tracks.added_rbtree.sentinel;

    for ( ;; ) {

        root = u->tracks.added_rbtree.root;
        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);

        rc = ngx_kmp_rtmp_track_process_expired(node);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            return NGX_OK;

        default:
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_process(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_int_t              rc;
    ngx_msec_t             timer;
    ngx_rbtree_node_t     *root, *sentinel, *node;

    sentinel = u->tracks.dts_rbtree.sentinel;

    for ( ;; ) {

        root = u->tracks.dts_rbtree.root;
        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);

        rc = ngx_kmp_rtmp_track_process_frame(node, &timer);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_DONE:
            rc = ngx_kmp_rtmp_upstream_process_expired(u);
            if (rc != NGX_OK) {
                return rc;
            }

            ngx_add_timer(&u->process, timer);
            return NGX_OK;

        default:
            return rc;
        }
    }

    return NGX_OK;
}


static void
ngx_kmp_rtmp_upstream_process_handler(ngx_event_t *ev)
{
    ngx_kmp_rtmp_upstream_t  *u;

    u = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, &u->log, 0,
        "ngx_kmp_rtmp_upstream_process_handler: called");

    if (ngx_kmp_rtmp_upstream_process(u) != NGX_OK) {
        ngx_kmp_rtmp_upstream_free(u, "process_frame_failed");
    }
}


void
ngx_kmp_rtmp_upstream_stream_removed(ngx_kmp_rtmp_upstream_t *u)
{
    if (ngx_queue_empty(&u->streams.queue) && !u->busy
        && u->active_buf.last <= u->active_buf.pos)
    {
        ngx_kmp_rtmp_upstream_finalize(u, "done");
    }
}


static void
ngx_kmp_rtmp_upstream_read_handler(ngx_event_t *rev)
{
    ssize_t                   n;
    ngx_connection_t         *c;
    ngx_kmp_rtmp_upstream_t  *u;

    c = rev->data;
    u = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0,
        "ngx_kmp_rtmp_upstream_read_handler: called");

    for ( ;; ) {

        n = ngx_recv(c, u->recv_buf, sizeof(u->recv_buf));

        if (n > 0) {

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, rev->log, 0,
                "ngx_kmp_rtmp_upstream_read_handler: read %z bytes", n);

            u->received_bytes += n;

            if (u->dump_fd != NGX_INVALID_FILE) {
                if (ngx_write_fd(u->dump_fd, u->recv_buf, n) == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, &u->log, ngx_errno,
                        "ngx_kmp_rtmp_upstream_read_handler: "
                        "failed to write to dump file");
                    ngx_close_file(u->dump_fd);
                    u->dump_fd = NGX_INVALID_FILE;
                }
            }

            continue;
        }

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }

            return;
        }

        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
        "ngx_kmp_rtmp_upstream_read_handler: upstream closed connection");
    ngx_kmp_rtmp_upstream_free(u, "recv_failed");
}


static void
ngx_kmp_rtmp_upstream_write_handler(ngx_event_t *wev)
{
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_kmp_rtmp_upstream_t  *u;

    c = wev->data;
    u = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, wev->log, 0,
        "ngx_kmp_rtmp_upstream_write_handler: called");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
            "ngx_kmp_rtmp_upstream_write_handler: write timed out");
        goto failed;
    }

    rc = ngx_kmp_rtmp_upstream_send(u);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_write_handler: send failed");
        goto failed;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_write_handler: "
            "ngx_handle_write_event failed");
        goto failed;
    }

    return;

failed:

    ngx_kmp_rtmp_upstream_free(u, "send_failed");
}


static void
ngx_kmp_rtmp_upstream_handshake_handler(ngx_kmp_rtmp_handshake_t *hs,
    ngx_int_t rc)
{
    ngx_connection_t         *c;
    ngx_kmp_rtmp_upstream_t  *u;

    u = hs->data;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_handshake_handler: handshake failed");
        ngx_kmp_rtmp_upstream_finalize(u, "handshake_failed");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_handshake_handler: handshake done");

    u->dump_fd = hs->dump_fd;
    hs->dump_fd = NGX_INVALID_FILE;

    u->received_bytes = hs->received_bytes;
    u->written_bytes = hs->written_bytes;

    ngx_kmp_rtmp_handshake_free(hs);
    u->hs = NULL;

    c = u->peer.connection;

    u->local_addr.s.len = NGX_SOCKADDR_STRLEN;
    u->local_addr.s.data = u->local_addr_buf;

    if (ngx_connection_local_sockaddr(c, &u->local_addr.s, 1) != NGX_OK) {
        u->local_addr.s.len = 0;
    }

    ngx_json_str_set_escape(&u->local_addr);

    c->data = u;

    c->read->handler =  ngx_kmp_rtmp_upstream_read_handler;
    c->write->handler = ngx_kmp_rtmp_upstream_write_handler;

    rc = ngx_kmp_rtmp_upstream_send(u);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_kmp_rtmp_upstream_finalize(u, "send_failed");
        return;
    }

    ngx_kmp_rtmp_upstream_read_handler(c->read);
}


static u_char *
ngx_kmp_rtmp_upstream_get_dump_path(ngx_kmp_rtmp_upstream_t *u)
{
    u_char     *p;
    size_t      size;
    ngx_str_t   folder;

    folder = u->conf.dump_folder;
    if (folder.len == 0) {
        return NULL;
    }

    size = folder.len + sizeof("/ngx_kmp_rtmp_dump___.dat")
        + NGX_KMP_RTMP_ISO8601_DATE_LEN + u->sn.str.len + NGX_ATOMIC_T_LEN;

    p = ngx_pnalloc(u->pool, size);
    if (p == NULL) {
        return NULL;
    }

    ngx_sprintf(p, "%V/ngx_kmp_rtmp_dump_%*s_%V_%uA.dat%Z",
        &folder, NGX_KMP_RTMP_ISO8601_DATE_LEN,
        ngx_cached_http_log_iso8601.data, &u->sn.str,
        u->peer.connection->number);

    return p;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_connect(ngx_kmp_rtmp_upstream_t *u, ngx_addr_t *addr)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_kmp_rtmp_handshake_t  *hs;

    if (addr->socklen > sizeof(u->sockaddr_buf)) {
        ngx_log_error(NGX_LOG_ALERT, &u->log, 0,
            "ngx_kmp_rtmp_upstream_connect: address length %d too big",
            (int) addr->socklen);
        return NGX_ERROR;
    }

    u->peer.socklen = addr->socklen;
    u->peer.sockaddr = (void *) u->sockaddr_buf;
    ngx_memcpy(u->peer.sockaddr, addr->sockaddr, u->peer.socklen);

    ngx_inet_set_port(u->peer.sockaddr, u->port);

    u->remote_addr.s.data = u->remote_addr_buf;
    u->remote_addr.s.len = ngx_sock_ntop(u->peer.sockaddr, u->peer.socklen,
        u->remote_addr_buf, sizeof(u->remote_addr_buf), 1);
    ngx_json_str_set_escape(&u->remote_addr);

    u->peer.name = &u->remote_addr.s;
    u->peer.get = ngx_event_get_peer;
    u->peer.log = &u->log;
    u->peer.log_error = NGX_ERROR_ERR;

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_connect: connecting to %V", &u->remote_addr.s);

    rc = ngx_event_connect_peer(&u->peer);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_connect: "
            "connect failed %i, addr: %V", rc, &u->remote_addr.s);
        return NGX_ERROR;
    }

    c = u->peer.connection;

    c->pool = u->pool;
    c->addr_text = u->remote_addr.s;
    c->log->connection = c->number;

    hs = ngx_kmp_rtmp_handshake_create(c);
    if (hs == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_connect: create handshake failed");
        return NGX_ERROR;
    }

    u->hs = hs;

    c->data = hs;

    hs->handler = ngx_kmp_rtmp_upstream_handshake_handler;
    hs->data = u;

    hs->timeout = u->conf.timeout;
    hs->header = u->header.s;
    hs->dump_path = ngx_kmp_rtmp_upstream_get_dump_path(u);

    if (ngx_kmp_rtmp_handshake_client(hs, rc == NGX_AGAIN) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_connect: start handshake failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_rtmp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    char                     *reason;
    ngx_addr_t                addr;
    ngx_kmp_rtmp_upstream_t  *u;

    u = ctx->data;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, &u->log, 0,
        "ngx_kmp_rtmp_upstream_resolve_handler: called");

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_rtmp_upstream_resolve_handler: "
            "%V could not be resolved (%i: %s)",
            &ctx->name, ctx->state,
            ngx_resolver_strerror(ctx->state));
        reason = "resolve_failed";
        goto failed;
    }

#if (NGX_DEBUG)
    {
        u_char      text[NGX_SOCKADDR_STRLEN];
        ngx_str_t   saddr;
        ngx_uint_t  i;

        saddr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            saddr.len = ngx_sock_ntop(ctx->addrs[i].sockaddr,
                ctx->addrs[i].socklen, text, NGX_SOCKADDR_STRLEN, 0);

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, &u->log, 0,
                "ngx_kmp_rtmp_upstream_resolve_handler: "
                "name was resolved to %V", &saddr);
        }
    }
#endif

    addr.sockaddr = ctx->addrs[0].sockaddr;
    addr.socklen = ctx->addrs[0].socklen;

    ngx_memzero(&addr.name, sizeof(addr.name));

    if (ngx_kmp_rtmp_upstream_connect(u, &addr) != NGX_OK) {
        reason = "start_connect_failed";
        goto failed;
    }

    ngx_resolve_name_done(ctx);
    u->resolve_ctx = NULL;

    return;

failed:

    ngx_kmp_rtmp_upstream_finalize(u, reason);
}


static ngx_int_t
ngx_kmp_rtmp_upstream_resolve(ngx_kmp_rtmp_upstream_t *u, ngx_str_t *name)
{
    ngx_str_t            host;
    ngx_resolver_ctx_t  *ctx;

    host.len = name->len;
    host.data = ngx_pstrdup(u->pool, name);
    if (host.data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_resolve: strdup failed");
        return NGX_ERROR;
    }

    ctx = ngx_resolve_start(u->conf.resolver, NULL);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_resolve: start failed");
        return NGX_ERROR;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_rtmp_upstream_resolve: "
            "no resolver defined to resolve %V", &host);
        return NGX_ERROR;
    }

    ctx->name = host;
    ctx->handler = ngx_kmp_rtmp_upstream_resolve_handler;
    ctx->data = u;
    ctx->timeout = u->conf.resolver_timeout;

    u->resolve_ctx = ctx;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_resolve: resolve failed");
        u->resolve_ctx = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_kmp_rtmp_upstream_t *
ngx_kmp_rtmp_upstream_get(ngx_str_t *id)
{
    uint32_t  hash;

    hash = ngx_crc32_short(id->data, id->len);

    return (ngx_kmp_rtmp_upstream_t *) ngx_str_rbtree_lookup(
        &ngx_kmp_rtmp_upstreams.rbtree, id, hash);
}


static u_char *
ngx_kmp_rtmp_upstream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                   *p;
    ngx_kmp_rtmp_upstream_t  *u;

    u = log->data;

    p = ngx_snprintf(buf, len, ", upstream: %V", &u->sn.str);
    buf = p;

    return buf;
}


static ngx_kmp_rtmp_upstream_t *
ngx_kmp_rtmp_upstream_create(ngx_kmp_rtmp_upstream_conf_t *conf,
    ngx_str_t *id)
{
    uint32_t                  hash;
    ngx_log_t                *log = ngx_cycle->log;
    ngx_pool_t               *pool;
    ngx_kmp_rtmp_upstream_t  *u;

    pool = ngx_create_pool(2048, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_rtmp_upstream_create: create pool failed");
        return NULL;
    }

    u = ngx_pcalloc(pool, sizeof(*u) + id->len);
    if (u == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_rtmp_upstream_create: alloc failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    u->log = *log;

    u->log.handler = ngx_kmp_rtmp_upstream_log_error;
    u->log.data = u;
    u->log.action = NULL;

    pool->log = &u->log;

    u->mem_left = u->mem_limit = conf->mem_limit;

    if (ngx_buf_queue_init(&u->buf_queue, &u->log, conf->lba,
        conf->max_free_buffers, &u->mem_left) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_rtmp_upstream_create: ngx_buf_queue_init failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    u->conf = *conf;
    u->pool = pool;

    u->sn.str.data = (void *) (u + 1);
    u->sn.str.len = id->len;
    ngx_memcpy(u->sn.str.data, id->data, id->len);

    hash = ngx_crc32_short(id->data, id->len);
    u->sn.node.key = hash;

    u->id_escape = ngx_json_str_get_escape(id);

    u->last = &u->busy;

    ngx_rbtree_init(&u->streams.rbtree, &u->streams.sentinel,
        ngx_str_rbtree_insert_value);
    ngx_queue_init(&u->streams.queue);

    ngx_rbtree_init(&u->tracks.dts_rbtree, &u->tracks.dts_sentinel,
        ngx_rbtree_insert_value);
    ngx_rbtree_init(&u->tracks.added_rbtree, &u->tracks.added_sentinel,
        ngx_rbtree_insert_value);

    u->flush.handler = ngx_kmp_rtmp_upstream_flush_handler;
    u->flush.data = u;
    u->flush.log = &u->log;

    u->process.handler = ngx_kmp_rtmp_upstream_process_handler;
    u->process.data = u;
    u->process.log = &u->log;

    u->dump_fd = NGX_INVALID_FILE;

    ngx_rbtree_insert(&ngx_kmp_rtmp_upstreams.rbtree, &u->sn.node);
    ngx_queue_insert_tail(&ngx_kmp_rtmp_upstreams.queue, &u->queue);

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_create: created %p", u);

    return u;
}


static void
ngx_kmp_rtmp_upstream_free_set_reason(ngx_kmp_rtmp_upstream_t *u, char *reason)
{
    if (u->free_reason.s.data != NULL || reason == NULL) {
        return;
    }

    u->free_reason.s.data = (u_char *) reason;
    u->free_reason.s.len = ngx_strlen(u->free_reason.s.data);
    ngx_json_str_set_escape(&u->free_reason);
}


static ngx_chain_t *
ngx_kmp_rtmp_upstream_free_notify_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    size_t                    size;
    u_char                   *p;
    ngx_buf_t                *b;
    ngx_chain_t              *pl;
    ngx_kmp_rtmp_upstream_t  *u;

    u = arg;

    size = ngx_kmp_rtmp_upstream_free_json_get_size(u);

    pl = ngx_http_call_alloc_chain_temp_buf(pool, size);
    if (pl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_rtmp_upstream_free_notify_create: "
            "alloc chain buf failed");
        return NULL;
    }

    b = pl->buf;
    p = b->last;

    p = ngx_kmp_rtmp_upstream_free_json_write(p, u);

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_rtmp_upstream_free_notify_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NULL;
    }

    b->last = p;

    return ngx_http_call_format_json_post(pool, &u->conf.notif_url->host,
        &u->conf.notif_url->uri, u->conf.notif_headers, pl);
}


static void
ngx_kmp_rtmp_upstream_free_notify(ngx_kmp_rtmp_upstream_t *u)
{
    ngx_url_t             *url;
    ngx_http_call_init_t   ci;

    url = u->conf.notif_url;
    if (url == NULL) {
        return;
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_rtmp_upstream_free_notify_create;
    ci.arg = u;

    ci.timeout = u->conf.notif_timeout;
    ci.read_timeout = u->conf.notif_read_timeout;
    ci.buffer_size = u->conf.notif_buffer_size;

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_free_notify: sending request to \"%V\"",
        &url->url);

    if (ngx_http_call_create(&ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_free_notify: http call create failed");
    }
}


void
ngx_kmp_rtmp_upstream_free(ngx_kmp_rtmp_upstream_t *u, char *reason)
{
    ngx_queue_t            *q;
    ngx_connection_t       *c;
    ngx_kmp_rtmp_stream_t  *stream;

    if (u->freed) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_free: freeing %p", u);

    u->freed = 1;

    ngx_kmp_rtmp_upstream_free_set_reason(u, reason);

    ngx_kmp_rtmp_upstream_free_notify(u);

    for (q = ngx_queue_head(&u->streams.queue);
        q != ngx_queue_sentinel(&u->streams.queue); )
    {
        stream = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);
        q = ngx_queue_next(q);      /* stream may be removed from queue */

        ngx_kmp_rtmp_stream_free(stream);
    }

    if (u->close.posted) {
        ngx_delete_posted_event(&u->close);
    }

    if (u->flush.timer_set) {
        ngx_del_timer(&u->flush);
    }

    if (u->process.timer_set) {
        ngx_del_timer(&u->process);
    }

    c = u->peer.connection;
    if (c) {
        ngx_close_connection(c);
    }

    if (u->hs) {
        ngx_kmp_rtmp_handshake_free(u->hs);
    }

    if (u->resolve_ctx) {
        ngx_resolve_name_done(u->resolve_ctx);
    }

    if (u->dump_fd != NGX_INVALID_FILE) {
        ngx_close_file(u->dump_fd);
    }

    ngx_queue_remove(&u->queue);
    ngx_rbtree_delete(&ngx_kmp_rtmp_upstreams.rbtree, &u->sn.node);

    ngx_buf_queue_delete(&u->buf_queue);

    ngx_destroy_pool(u->pool);
}


static void
ngx_kmp_rtmp_upstream_close_handler(ngx_event_t *ev)
{
    ngx_kmp_rtmp_upstream_t  *u;

    u = ev->data;

    ngx_kmp_rtmp_upstream_free(u, NULL);
}


void
ngx_kmp_rtmp_upstream_finalize(ngx_kmp_rtmp_upstream_t *u, char *reason)
{
    ngx_event_t  *e;

    ngx_kmp_rtmp_upstream_free_set_reason(u, reason);

    e = &u->close;

    e->handler = ngx_kmp_rtmp_upstream_close_handler;
    e->data = u;
    e->log = &u->log;

    ngx_post_event(e, &ngx_posted_events);
}


static ngx_int_t
ngx_kmp_rtmp_upstream_write_connect(ngx_kmp_rtmp_upstream_t *u,
    ngx_kmp_rtmp_connect_t *connect)
{
    size_t   size;
    size_t   written;
    u_char  *p;
    u_char  *start;

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_rtmp_upstream_write_connect: "
        "writing connect message, tc_url: %V, app: %V",
        &connect->tc_url, &connect->app);

    size = ngx_kmp_rtmp_encoder_connect_get_size(connect);

    start = ngx_kmp_rtmp_upstream_get_buf(u, size);
    if (start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_rtmp_upstream_write_connect: failed to get buf");
        return NGX_ERROR;
    }

    p = ngx_kmp_rtmp_encoder_connect_write(start, connect, u->conf.chunk_size);

    written = p - start;
    if (written != size) {
        ngx_log_error(NGX_LOG_ALERT, &u->log, 0,
            "ngx_kmp_rtmp_upstream_write_connect: "
            "size written %uz does not match allocated size %uz",
            written, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_kmp_rtmp_upstream_t *
ngx_kmp_rtmp_upstream_from_json(ngx_kmp_rtmp_upstream_conf_t *conf,
    ngx_kmp_rtmp_connect_data_json_t *json, ngx_kmp_rtmp_connect_t *connect,
    ngx_url_t *url)
{
    char                     *reason;
    u_char                   *p;
    ngx_kmp_rtmp_upstream_t  *u;

    u = ngx_kmp_rtmp_upstream_create(conf, &json->upstream_id);
    if (u == NULL) {
        return NULL;
    }

    u->url.s.len = json->url.len;
    u->header.s.len = json->header.data != NGX_JSON_UNSET_PTR
        ? json->header.len : 0;
    u->opaque.len = json->opaque.data != NGX_JSON_UNSET_PTR
        ? json->opaque.len : 0;

    p = ngx_pnalloc(u->pool, u->url.s.len + u->header.s.len + u->opaque.len);
    if (p == NULL) {
        reason = "alloc_failed";
        goto failed;
    }

    u->url.s.data = p;
    p = ngx_copy(p, json->url.data, u->url.s.len);
    ngx_json_str_set_escape(&u->url);

    u->header.s.data = p;
    p = ngx_copy(p, json->header.data, u->header.s.len);
    ngx_json_str_set_escape(&u->header);

    u->opaque.data = p;
    p = ngx_copy(p, json->opaque.data, u->opaque.len);


    if (json->app.data != NGX_JSON_UNSET_PTR) {
        connect->app = json->app;
    }

    if (json->flash_ver.data != NGX_JSON_UNSET_PTR) {
        connect->flash_ver = json->flash_ver;

    } else {
        connect->flash_ver = u->conf.flash_ver;
    }

    if (json->swf_url.data != NGX_JSON_UNSET_PTR) {
        connect->swf_url = json->swf_url;
    }

    if (json->tc_url.data != NGX_JSON_UNSET_PTR) {
        connect->tc_url = json->tc_url;

    } else {
        connect->tc_url = json->url;
        if (connect->app.len > 0) {
            connect->tc_url.len = connect->app.data + connect->app.len
                - json->url.data;
        }
    }

    if (json->page_url.data != NGX_JSON_UNSET_PTR) {
        connect->page_url = json->page_url;
    }

    connect->base.tx_id = ++u->tx_id;

    if (ngx_kmp_rtmp_upstream_write_connect(u, connect) != NGX_OK) {
        reason = "write_connect_failed";
        goto failed;
    }


    u->port = url->port;

    if (url->naddrs > 0) {
        if (ngx_kmp_rtmp_upstream_connect(u, &url->addrs[0]) != NGX_OK) {
            reason = "start_connect_failed";
            goto failed;
        }

    } else {
        if (ngx_kmp_rtmp_upstream_resolve(u, &url->host) != NGX_OK) {
            reason = "start_resolve_failed";
            goto failed;
        }
    }

    return u;

failed:

    ngx_kmp_rtmp_upstream_free(u, reason);
    return NULL;
}


static void
ngx_kmp_rtmp_upstream_parse_uri(ngx_str_t *uri, ngx_str_t *app,
    ngx_str_t *name)
{
    u_char  *p, *last;

    app->len = 0;
    name->len = 0;

    if (uri->len <= 0) {
        return;
    }

    p = uri->data;
    last = p + uri->len;

    if (*p == '/') {
        p++;
    }

    /* app name */

    app->data = p;

    p = ngx_strlchr(p, last, '/');
    if (p == NULL) {
        p = last;
    }

    app->len = p - app->data;

    if (p >= last) {
        return;
    }

    p++;    /* skip the / */

    /* stream name */

    name->data = p;

    p = ngx_strlchr(p, last, '/');
    if (p == NULL) {
        p = last;
    }

    name->len = p - name->data;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_parse_url(ngx_pool_t *pool, ngx_str_t *url_str,
    ngx_url_t *url)
{
    size_t  add;

    if (url_str->len > ngx_kmp_rtmp_url_prefix.len
        && ngx_strncasecmp(url_str->data, ngx_kmp_rtmp_url_prefix.data,
            ngx_kmp_rtmp_url_prefix.len) == 0)
    {
        add = ngx_kmp_rtmp_url_prefix.len;

    } else {
        add = 0;
    }

    ngx_memzero(url, sizeof(*url));

    url->url.data = url_str->data + add;
    url->url.len = url_str->len - add;
    url->default_port = 1935;
    url->uri_part = 1;
    url->no_resolve = 1;

    if (ngx_parse_url(pool, url) != NGX_OK) {
        if (url->err) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_kmp_rtmp_upstream_parse_url: %s in \"%V\"",
                url->err, &url->url);
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_rtmp_upstream_get_or_create(ngx_pool_t *temp_pool,
    ngx_kmp_rtmp_upstream_conf_t *conf, ngx_json_value_t *value,
    ngx_kmp_rtmp_upstream_t **upstream, ngx_str_t *stream_name)
{
    ngx_url_t                          url;
    ngx_json_object_t                 *obj;
    ngx_kmp_rtmp_connect_t             connect;
    ngx_kmp_rtmp_upstream_t           *u;
    ngx_kmp_rtmp_connect_data_json_t   json;

    if (value->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
            "ngx_kmp_rtmp_upstream_get_or_create: "
            "invalid json type %d, expected object", value->type);
        return NGX_ERROR;
    }

    obj = &value->v.obj;

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(temp_pool, obj, ngx_kmp_rtmp_connect_data_json,
            ngx_array_entries(ngx_kmp_rtmp_connect_data_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_upstream_get_or_create: failed to parse object");
        return NGX_ERROR;
    }

    if (json.upstream_id.data == NGX_JSON_UNSET_PTR
        || json.url.data == NGX_JSON_UNSET_PTR)
    {
        ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
            "ngx_kmp_rtmp_upstream_get_or_create: missing mandatory params");
        return NGX_ERROR;
    }

    if (ngx_kmp_rtmp_upstream_parse_url(temp_pool, &json.url, &url)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_upstream_get_or_create: failed to parse url");
        return NGX_ERROR;
    }

    ngx_memzero(&connect, sizeof(connect));

    ngx_kmp_rtmp_upstream_parse_uri(&url.uri, &connect.app, stream_name);

    if (json.name.data != NGX_JSON_UNSET_PTR) {
        *stream_name = json.name;
    }

    u = ngx_kmp_rtmp_upstream_get(&json.upstream_id);
    if (u != NULL) {
        *upstream = u;
        return NGX_OK;
    }

    u = ngx_kmp_rtmp_upstream_from_json(conf, &json, &connect, &url);
    if (u == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_rtmp_upstream_get_or_create: failed to create upstream");
        return NGX_ABORT;
    }

    *upstream = u;
    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_upstream_init_flash_ver(ngx_conf_t *cf, ngx_str_t *flash_ver)
{
    u_char  *p;

    p = ngx_pnalloc(cf->pool, sizeof(NGX_KMP_RTMP_FLASH_VER) - 1
        + ngx_kmp_rtmp_version.s.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    flash_ver->data = p;

    p = ngx_sprintf(p, NGX_KMP_RTMP_FLASH_VER,
        &ngx_kmp_rtmp_version.s);

    flash_ver->len = p - flash_ver->data;

    return NGX_OK;
}


void
ngx_kmp_rtmp_upstream_conf_init(ngx_kmp_rtmp_upstream_conf_t *conf)
{
    conf->notif_url = NGX_CONF_UNSET_PTR;
    conf->notif_timeout = NGX_CONF_UNSET_MSEC;
    conf->notif_read_timeout = NGX_CONF_UNSET_MSEC;
    conf->notif_buffer_size = NGX_CONF_UNSET_SIZE;

    conf->mem_limit = NGX_CONF_UNSET_SIZE;
    conf->max_free_buffers = NGX_CONF_UNSET_UINT;

    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->flush_timeout = NGX_CONF_UNSET_MSEC;

    conf->chunk_size = NGX_CONF_UNSET_SIZE;
    conf->write_meta_timeout = NGX_CONF_UNSET_MSEC;
    conf->min_process_delay = NGX_CONF_UNSET_MSEC;
    conf->max_process_delay = NGX_CONF_UNSET_MSEC;
    conf->onfi_period = NGX_CONF_UNSET_MSEC;
}


ngx_int_t
ngx_kmp_rtmp_upstream_conf_merge(ngx_conf_t *cf,
    ngx_kmp_rtmp_upstream_conf_t *prev, ngx_kmp_rtmp_upstream_conf_t *conf)
{
    ngx_conf_merge_ptr_value(conf->notif_url,
                             prev->notif_url, NULL);

    ngx_conf_merge_msec_value(conf->notif_timeout,
                              prev->notif_timeout, 2000);

    ngx_conf_merge_msec_value(conf->notif_read_timeout,
                              prev->notif_read_timeout, 20000);

    ngx_conf_merge_size_value(conf->notif_buffer_size,
                              prev->notif_buffer_size, 4 * 1024);

    if (conf->notif_headers == NULL) {
        conf->notif_headers = prev->notif_headers;
    }

    ngx_conf_merge_size_value(conf->mem_limit,
                              prev->mem_limit, 16 * 1024 * 1024);

    ngx_conf_merge_uint_value(conf->max_free_buffers,
                              prev->max_free_buffers, 4);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10000);

    ngx_conf_merge_msec_value(conf->flush_timeout,
                              prev->flush_timeout, 500);

    ngx_conf_merge_str_value(conf->flash_ver,
                             prev->flash_ver, "");

    ngx_conf_merge_size_value(conf->chunk_size,
                              prev->chunk_size, 64 * 1024);

    ngx_conf_merge_msec_value(conf->write_meta_timeout,
                              prev->write_meta_timeout, 3000);

    ngx_conf_merge_msec_value(conf->min_process_delay,
                              prev->min_process_delay, 500);

    ngx_conf_merge_msec_value(conf->max_process_delay,
                              prev->max_process_delay, 1000);

    ngx_conf_merge_msec_value(conf->onfi_period,
                              prev->onfi_period, 5000);

    ngx_conf_merge_str_value(conf->dump_folder,
                             prev->dump_folder, "");

    if (conf->flash_ver.len == 0) {
        if (ngx_kmp_rtmp_upstream_init_flash_ver(cf, &conf->flash_ver)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
