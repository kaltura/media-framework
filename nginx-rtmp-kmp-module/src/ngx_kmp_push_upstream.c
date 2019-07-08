#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>

#include <ngx_json_parser.h>
#include <ngx_live_kmp.h>
#include <ngx_http_call.h>
#include <ngx_buf_queue_reader.h>

#include "ngx_kmp_push_utils.h"
#include "ngx_kmp_push_track_internal.h"
#include "ngx_kmp_push_upstream.h"

#include "ngx_kmp_push_upstream_json.h"


static void ngx_kmp_push_upstream_read_handler(ngx_event_t *rev);
static void ngx_kmp_push_upstream_write_handler(ngx_event_t *wev);


typedef struct {
    ngx_kmp_push_upstream_t  *u;
    ngx_str_t                 host;
    ngx_str_t                 uri;
    ngx_uint_t                retries_left;
} ngx_kmp_push_republish_call_ctx_t;

enum {
    NGX_KMP_UPSTREAM_URL,
    NGX_KMP_UPSTREAM_ID,
    NGX_KMP_UPSTREAM_AUTO_ACK,
    NGX_KMP_UPSTREAM_PARAM_COUNT
};

static json_object_key_def_t  ngx_kmp_upstream_json_params[] = {
    { ngx_string("url"),       NGX_JSON_STRING,  NGX_KMP_UPSTREAM_URL },
    { ngx_string("id"),        NGX_JSON_STRING,  NGX_KMP_UPSTREAM_ID },
    { ngx_string("auto_ack"),  NGX_JSON_BOOL,    NGX_KMP_UPSTREAM_AUTO_ACK },
    { ngx_null_string, 0, 0 }
};

static ngx_str_t  kmp_url_prefix = ngx_string("kmp://");


static u_char *
ngx_kmp_push_upstream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                   *p;
    ngx_kmp_push_upstream_t  *u;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    u = log->data;
    if (u == NULL) {
        return p;
    }

    p = u->track->log.handler(&u->track->log, buf, len);
    len -= p - buf;
    buf = p;

    if (u->peer.name) {
        p = ngx_snprintf(buf, len, ", peer: %V", u->peer.name);
        len -= p - buf;
        buf = p;
    }

    return p;
}

static ngx_kmp_push_upstream_t *
ngx_kmp_push_upstream_create(ngx_kmp_push_track_t *track, ngx_str_t *id)
{
    ngx_kmp_push_upstream_t  *u;
    ngx_pool_t               *pool;
    ngx_log_t                *log = &track->log;

    pool = ngx_create_pool(2048, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_push_upstream_create: ngx_create_pool failed");
        return NULL;
    }

    u = ngx_palloc(pool, sizeof(ngx_kmp_push_upstream_t) + id->len);
    if (u == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_push_upstream_create: ngx_pcalloc failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    u->id.data = (void*)(u + 1);

    ngx_memzero(u, sizeof(*u));

    u->pool = pool;
    u->log = *log;
    u->log.handler = ngx_kmp_push_upstream_log_error;
    u->log.data = u;
    u->log.action = NULL;

    u->id.len = id->len;
    ngx_memcpy(u->id.data, id->data, id->len);

    u->track = track;
    u->timeout = track->conf->timeout;

    ngx_buf_queue_reader_init(&u->acked_reader, &track->buf_queue);
    u->acked_frame_id = track->connect.initial_frame_id;

    ngx_queue_insert_tail(&track->upstreams, &u->queue);

    return u;
}

static ngx_int_t
ngx_kmp_push_upstream_connect(ngx_kmp_push_upstream_t *u, ngx_addr_t *addr)
{
    ngx_connection_t  *c;
    ngx_int_t          rc;

    if (addr->socklen > sizeof(u->sockaddr_buf)) {
        ngx_log_error(NGX_LOG_ALERT, &u->log, 0,
            "ngx_kmp_push_upstream_connect: address length %d too big",
            (int)addr->socklen);
        return NGX_ERROR;
    }

    u->addr_text.data = u->addr_text_buf;
    u->addr_text.len = ngx_sock_ntop(addr->sockaddr, addr->socklen,
        u->addr_text_buf, sizeof(u->addr_text_buf), 1);

    u->peer.socklen = addr->socklen;
    u->peer.sockaddr = (void*)u->sockaddr_buf;
    ngx_memcpy(u->peer.sockaddr, addr->sockaddr, u->peer.socklen);

    u->peer.name = &u->addr_text;
    u->peer.get = ngx_event_get_peer;
    u->peer.log = &u->log;
    u->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&u->peer);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_connect: connect failed %i, addr=%V",
            rc, &u->addr_text);
        return NGX_ERROR;
    }

    c = u->peer.connection;
    c->data = u;
    c->pool = u->pool;

    c->addr_text = u->addr_text;

    c->log->connection = c->number;

    c->read->handler = ngx_kmp_push_upstream_read_handler;
    c->write->handler = ngx_kmp_push_upstream_write_handler;

    ngx_add_timer(c->write, u->timeout);

    u->last = &u->busy;
    u->recv_pos = (void*)&u->ack_frames;

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_push_upstream_connect: connecting to %V", &u->addr_text);

    if (rc == NGX_OK) {
        ngx_kmp_push_upstream_write_handler(c->write);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_upstream_parse_url(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_url_t *url)
{
    ngx_str_t  url_str;

    if (value == NULL) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_push_upstream_parse_url: no upstream url in json");
        return NGX_ERROR;
    }

    url_str = value->v.str;
    if (url_str.len > kmp_url_prefix.len &&
        ngx_strncasecmp(url_str.data,
            kmp_url_prefix.data,
            kmp_url_prefix.len) == 0) {
        url_str.data += kmp_url_prefix.len;
        url_str.len -= kmp_url_prefix.len;
    }

    ngx_memzero(url, sizeof(*url));
    url->url = url_str;
    url->no_resolve = 1;    // accept only ips

    if (ngx_parse_url(pool, url) != NGX_OK) {
        if (url->err) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_kmp_push_upstream_parse_url: %s in \"%V\"",
                url->err, &url_str);
        }
        return NGX_ERROR;
    }

    if (url->naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_kmp_push_upstream_parse_url: no addresses in \"%V\"",
            &url_str);
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_kmp_push_upstream_free(ngx_kmp_push_upstream_t *u)
{
    ngx_pool_t  *pool = u->pool;

    if (u->peer.connection) {
        ngx_close_connection(u->peer.connection);
    }

    ngx_queue_remove(&u->queue);

    ngx_destroy_pool(pool);
}

static void
ngx_kmp_push_upstream_free_notify(ngx_kmp_push_upstream_t *u)
{
    ngx_kmp_push_track_t  *track = u->track;

    ngx_kmp_push_upstream_free(u);

    ngx_kmp_push_track_error(track);
}

ngx_int_t
ngx_kmp_push_upstream_from_json(ngx_pool_t *temp_pool,
    ngx_kmp_push_track_t *track, ngx_json_object_t *json)
{
    ngx_kmp_push_upstream_t  *u;
    ngx_json_value_t         *values[NGX_KMP_UPSTREAM_PARAM_COUNT];
    ngx_url_t                 url;
    ngx_str_t                 id;

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(json, ngx_kmp_upstream_json_params, values);

    if (ngx_kmp_push_upstream_parse_url(temp_pool,
        values[NGX_KMP_UPSTREAM_URL], &url) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_push_upstream_from_json: parse url failed");
        return NGX_ERROR;
    }

    if (values[NGX_KMP_UPSTREAM_ID] != NULL) {
        id = values[NGX_KMP_UPSTREAM_ID]->v.str;
    } else {
        id.len = 0;
    }

    u = ngx_kmp_push_upstream_create(track, &id);
    if (u == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_push_upstream_from_json: create failed");
        return NGX_ERROR;
    }

    if (ngx_kmp_push_upstream_connect(u, &url.addrs[0]) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_from_json: connect failed");
        ngx_kmp_push_upstream_free(u);
        return NGX_ERROR;
    }

    if (values[NGX_KMP_UPSTREAM_AUTO_ACK] != NULL &&
        values[NGX_KMP_UPSTREAM_AUTO_ACK]->v.boolean) {
        u->auto_ack = 1;
    }

    return NGX_OK;
}

static ngx_chain_t *
ngx_kmp_push_upstream_republish_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    ngx_kmp_push_republish_call_ctx_t  *ctx = arg;
    ngx_kmp_push_upstream_t            *u = ctx->u;
    ngx_chain_t                        *cl;
    ngx_buf_t                          *b;
    size_t                              size;

    size = ngx_kmp_push_upstream_republish_json_get_size(u);

    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_upstream_republish_create: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;

    b->last = ngx_kmp_push_upstream_republish_json_write(b->last, u);

    if ((size_t)(b->last - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_push_upstream_republish_create: "
            "result length %uz greater than allocated length %uz",
            (size_t)(b->last - b->pos), size);
        return NULL;
    }

    return ngx_kmp_push_format_json_http_request(pool, &ctx->host,
        &ctx->uri, cl);
}

static ngx_int_t
ngx_kmp_push_upstream_republish_handle(ngx_pool_t *temp_pool, void *arg,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_kmp_push_republish_call_ctx_t  *ctx = arg;
    ngx_kmp_push_upstream_t            *u = ctx->u;
    ngx_json_value_t                   *values[NGX_KMP_UPSTREAM_PARAM_COUNT];
    ngx_json_value_t                    json;
    ngx_url_t                           url;

    if (ngx_kmp_push_parse_json_response(temp_pool, code, content_type,
            body, &json) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_push_upstream_republish_handle: parse response failed");
        goto retry;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&json.v.obj, ngx_kmp_upstream_json_params,
        values);

    if (ngx_kmp_push_upstream_parse_url(temp_pool,
        values[NGX_KMP_UPSTREAM_URL], &url) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_push_upstream_republish_handle: parse url failed");
        goto retry;
    }

    if (ngx_kmp_push_upstream_connect(u, &url.addrs[0]) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, temp_pool->log, 0,
            "ngx_kmp_push_upstream_republish_handle: connect failed");
        ngx_kmp_push_upstream_free_notify(u);
        return NGX_OK;
    }

    return NGX_OK;

retry:

    if (ctx->retries_left > 0) {
        ctx->retries_left--;
        return NGX_AGAIN;
    }

    ngx_kmp_push_upstream_free_notify(u);
    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_upstream_republish(ngx_kmp_push_upstream_t *u)
{
    ngx_url_t                          *url;
    ngx_chain_t                        *cl;
    ngx_http_call_init_t                ci;
    ngx_kmp_push_track_t               *track = u->track;
    ngx_kmp_push_republish_call_ctx_t   ctx;

    if (track->state != NGX_KMP_TRACK_ACTIVE ||
        track->conf->ctrl_republish_url == NULL ||
        u->no_republish) {
        return NGX_DECLINED;
    }

   // close the connection
    u->log.connection = 0;
    ngx_close_connection(u->peer.connection);
    u->peer.connection = NULL;
    u->addr_text.len = 0;

    for (cl = u->busy; cl; cl = cl->next) {
        cl->next = u->free;
        u->free = cl;
    }

    u->busy = NULL;
    u->sent_buffered = 0;

    // send the request
    url = u->track->conf->ctrl_republish_url;

    ctx.u = u;
    ctx.host = url->host;
    ctx.uri = url->uri;
    ctx.retries_left = u->track->conf->ctrl_retries;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_push_upstream_republish_create;
    ci.handle = ngx_kmp_push_upstream_republish_handle;
    ci.handler_pool = u->pool;
    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_push_upstream_connect: sending republish request to \"%V\"",
        &url->url);

    if (ngx_kmp_push_track_http_call_create(u->track, &ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_republish: failed to create http call");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_kmp_push_upstream_error(ngx_kmp_push_upstream_t *u)
{
    ngx_uint_t  level;

    level = u->sent_end ? NGX_LOG_INFO : NGX_LOG_NOTICE;

    ngx_log_error(level, &u->log, 0,
        "ngx_kmp_push_upstream_error: called");

    if (ngx_kmp_push_upstream_republish(u) == NGX_OK) {
        return;
    }

    ngx_kmp_push_upstream_free_notify(u);
}

static ngx_int_t
ngx_kmp_push_upstream_ack_packet(ngx_kmp_push_upstream_t *u,
    kmp_packet_header_t *kmp_header)
{
    u_char  *p;
    size_t   size;

    size = kmp_header->header_size + kmp_header->data_size;

    switch (kmp_header->packet_type) {

    case KMP_PACKET_MEDIA_INFO:
        if ((size_t)(u->acked_media_info.end - u->acked_media_info.start) <
            size) {
            u->acked_media_info.start = ngx_palloc(u->pool, size);
            if (u->acked_media_info.start == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                    "ngx_kmp_push_upstream_ack_packet: alloc failed");
                return NGX_ERROR;
            }
            u->acked_media_info.end = u->acked_media_info.start + size;
        }

        p = u->acked_media_info.start;
        u->acked_media_info.pos = p;
        u->acked_media_info.last = p + size;

        p = ngx_copy(p, kmp_header, sizeof(*kmp_header));
        if (ngx_buf_queue_reader_copy(&u->acked_reader, p,
            size - sizeof(*kmp_header)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, &u->log, 0,
                "ngx_kmp_push_upstream_ack_packet: "
                "failed to read packet, size=%uz", size);
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_INFO, &u->log, 0,
            "ngx_kmp_push_upstream_ack_packet: saved media info, size=%uz",
            size);
        break;

    case KMP_PACKET_FRAME:
        if (ngx_buf_queue_reader_skip(&u->acked_reader,
                size - sizeof(*kmp_header)) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, &u->log, 0,
                "ngx_kmp_push_upstream_ack_packet: "
                "failed to skip packet, size=%uz", size);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_KMP, &u->log, 0,
            "ngx_kmp_push_upstream_ack_packet: acked frame %uL",
            u->acked_frame_id);

        u->acked_frame_id++;
        break;

    case KMP_PACKET_END_OF_STREAM:      // can happen in case of auto push
        return NGX_DONE;

    default:
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_push_upstream_ack_packet: "
            "invalid packet type 0x%uxD", kmp_header->packet_type);
        return NGX_ERROR;
    }

    u->acked_bytes += size;
    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_upstream_auto_ack(ngx_kmp_push_upstream_t *u)
{
    size_t                   size;
    ngx_int_t                rc;
    kmp_packet_header_t      kmp_header_buf;
    kmp_packet_header_t     *kmp_header;
    ngx_buf_queue_reader_t   reader;

    for (;;) {

        reader = u->acked_reader;
        kmp_header = ngx_buf_queue_reader_read(&u->acked_reader,
            &kmp_header_buf, sizeof(kmp_header_buf));
        if (kmp_header == NULL) {
            u->acked_reader = reader;
            break;
        }

        size = kmp_header->header_size + kmp_header->data_size;
        if (u->acked_bytes + (off_t)size >
            u->sent_base + u->peer.connection->sent) {
            u->acked_reader = reader;
            break;
        }

        rc = ngx_kmp_push_upstream_ack_packet(u, kmp_header);
        if (rc != NGX_OK) {
            if (rc == NGX_DONE) {
                break;
            }

            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_auto_ack: ack packet failed");
            u->no_republish = 1;
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_upstream_ack_frames(ngx_kmp_push_upstream_t *u)
{
    uint64_t              frame_id = u->ack_frames.frame_id;
    ngx_int_t             rc;
    kmp_packet_header_t   kmp_header_buf;
    kmp_packet_header_t  *kmp_header;

    while (u->acked_frame_id < frame_id) {
        kmp_header = ngx_buf_queue_reader_read(&u->acked_reader,
            &kmp_header_buf, sizeof(kmp_header_buf));
        if (kmp_header == NULL) {
            ngx_log_error(NGX_LOG_ERR, &u->log, 0,
                "ngx_kmp_push_upstream_ack_frames: read packet header failed");
            goto failed;
        }

        rc = ngx_kmp_push_upstream_ack_packet(u, kmp_header);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_ack_frames: ack packet failed %i", rc);
            goto failed;
        }
    }

    if (u->acked_bytes > u->sent_base + u->peer.connection->sent) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_push_upstream_ack_frames: acked bytes exceed sent");
        goto failed;
    }

    u->acked_offset = u->ack_frames.offset;

    return NGX_OK;

failed:

    u->no_republish = 1;
    return NGX_ERROR;
}

static ngx_int_t
ngx_kmp_push_upstream_parse_ack_packet(ngx_kmp_push_upstream_t *u)
{
    kmp_packet_header_t  *header = &u->ack_frames.header;

    if (header->packet_type != KMP_PACKET_ACK_FRAMES) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_push_upstream_parse_ack_packet: "
            "invalid packet type 0x%uxD", header->packet_type);
        return NGX_ERROR;
    }

    if (header->header_size != sizeof(u->ack_frames)) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_push_upstream_parse_ack_packet: "
            "invalid ack header size %uD", header->header_size);
        return NGX_ERROR;
    }

    if (header->data_size != 0) {
        ngx_log_error(NGX_LOG_ERR, &u->log, 0,
            "ngx_kmp_push_upstream_parse_ack_packet: "
            "invalid ack data size %uD", header->data_size);
        return NGX_ERROR;
    }

    if (u->auto_ack) {
        ngx_log_error(NGX_LOG_WARN, &u->log, 0,
            "ngx_kmp_push_upstream_parse_ack_packet: "
            "ack packet received in auto mode, ignoring");
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, &u->log, 0,
        "ngx_kmp_push_upstream_parse_ack_packet: "
        "got ack packet for frame %uL",
        u->ack_frames.frame_id);

    if (ngx_kmp_push_upstream_ack_frames(u) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_parse_ack_packet: ack frames failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_kmp_push_upstream_read_handler(ngx_event_t *rev)
{
    u_char                   *recv_end;
    ssize_t                   n;
    ngx_uint_t                level;
    ngx_connection_t         *c;
    ngx_kmp_push_upstream_t  *u;

    c = rev->data;
    u = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_KMP, rev->log, 0,
        "ngx_kmp_push_upstream_read_handler: called");

    recv_end = (u_char*)&u->ack_frames + sizeof(u->ack_frames);

    for (;; ) {

        n = ngx_recv(c, u->recv_pos, recv_end - u->recv_pos);

        if (n > 0) {
            u->recv_pos += n;
            if (u->recv_pos < recv_end) {
                continue;
            }

            if (ngx_kmp_push_upstream_parse_ack_packet(u) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                    "ngx_kmp_push_upstream_read_handler: ack packet failed");
                break;
            }

            u->recv_pos = (u_char*)&u->ack_frames;
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

    level = u->sent_end ? NGX_LOG_INFO : NGX_LOG_ERR;
    ngx_log_error(level, &u->log, 0,
        "ngx_kmp_push_upstream_read_handler: upstream closed connection");
    ngx_kmp_push_upstream_error(u);
}

static ngx_int_t
ngx_kmp_push_upstream_send_chain(ngx_kmp_push_upstream_t *u)
{
    ngx_connection_t  *c = u->peer.connection;
    ngx_chain_t       *chain;
    ngx_chain_t       *next;
    ngx_chain_t       *cl;
    off_t              sent;
#if (NGX_DEBUG)
    size_t             buffered;
#endif

    if (!u->sent_buffered) {
        return NGX_OK;
    }

    if (c->error) {
        return NGX_ERROR;
    }

    sent = c->sent;

    chain = c->send_chain(c, u->busy, 0);
    if (chain == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_push_upstream_send_chain: send_chain failed");
        c->error = 1;
        return NGX_ERROR;
    }

    // move sent buffers to free
    for (cl = u->busy; cl && cl != chain; cl = next) {
        next = cl->next;

        cl->next = u->free;
        u->free = cl;
    }

    if (u->auto_ack) {
        if (ngx_kmp_push_upstream_auto_ack(u) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_send_chain: auto ack failed");
            return NGX_ERROR;
        }
    }

    u->busy = chain;

#if (NGX_DEBUG)
    buffered = 0;
    for (cl = u->busy; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_KMP, c->log, 0,
        "ngx_kmp_push_upstream_send_chain: sent %O bytes, %uz in buffer",
        c->sent - sent,
        buffered);
#endif

    if (u->busy == NULL) {

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        u->last = &u->busy;

        if (!c->buffered) {
            return NGX_OK;
        }
    } else if (c->sent != sent) {
        ngx_add_timer(c->write, u->timeout);
    }

    return NGX_AGAIN;
}

ngx_int_t
ngx_kmp_push_upstream_send(ngx_kmp_push_upstream_t *u)
{
    ngx_int_t  rc;

    rc = ngx_kmp_push_upstream_send_chain(u);
    if (rc != NGX_ERROR) {
        return rc;
    }

    if (ngx_kmp_push_upstream_republish(u) == NGX_OK) {
        return NGX_AGAIN;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_kmp_push_upstream_send_buffered(ngx_kmp_push_upstream_t *u)
{
    ngx_buf_queue_node_t  *cur;
    ngx_chain_t           *cl;
    ngx_pool_t            *pool = u->pool;
    u_char                *start;
    u_char                *end;

    u->sent_base = u->acked_bytes - u->peer.connection->sent;

    // connect header
    u->connect = u->track->connect;
    u->connect.initial_frame_id = u->acked_frame_id;
    u->connect.initial_offset = u->acked_offset;
    cl = ngx_kmp_push_alloc_chain_buf(pool, &u->connect, &u->connect + 1);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_send_buffered: alloc chain buf failed");
        return NGX_ERROR;
    }

    *u->last = cl;
    u->last = &cl->next;

    u->sent_base -= sizeof(u->connect);

    // initial media info
    if (u->acked_media_info.last > u->acked_media_info.pos) {
        cl = ngx_kmp_push_alloc_chain_buf(pool, u->acked_media_info.pos,
            u->acked_media_info.last);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_send_buffered: alloc chain buf failed");
            return NGX_ERROR;
        }

        *u->last = cl;
        u->last = &cl->next;

        u->sent_base -= (u->acked_media_info.last - u->acked_media_info.pos);
    }

    // media info / frames
    for (cur = u->acked_reader.node; ; cur = ngx_buf_queue_next(cur)) {

        start = ngx_buf_queue_start(cur);
        if (start == u->track->active_buf.start) {
            break;
        }

        if (cur == u->acked_reader.node) {
            start = u->acked_reader.start;
        }

        end = ngx_buf_queue_end(&u->track->buf_queue, cur);
        if (start >= end) {
            continue;
        }

        cl = ngx_kmp_push_alloc_chain_buf(pool, start, end);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_send_buffered: alloc chain buf failed");
            return NGX_ERROR;
        }

        *u->last = cl;
        u->last = &cl->next;
    }

    *u->last = NULL;

    return NGX_OK;
}

static void
ngx_kmp_push_upstream_write_handler(ngx_event_t *wev)
{
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_kmp_push_upstream_t  *u;

    c = wev->data;
    u = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_KMP, wev->log, 0,
        "ngx_kmp_push_upstream_write_handler: called");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
            "ngx_kmp_push_upstream_write_handler: write timed out");
        goto failed;
    }

    if (!u->sent_buffered) {
        u->sent_buffered = 1;
        if (ngx_kmp_push_upstream_send_buffered(u) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_write_handler: send buffered failed");
            goto failed;
        }
    }

    rc = ngx_kmp_push_upstream_send_chain(u);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_write_handler: send chain failed");
        goto failed;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_push_upstream_write_handler: "
            "ngx_handle_write_event failed");
        goto failed;
    }

    return;

failed:

    ngx_kmp_push_upstream_error(u);
}

ngx_int_t
ngx_kmp_push_upstream_append_buffer(ngx_kmp_push_upstream_t *u,
    ngx_buf_t *active_buf)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    cl = u->free;
    if (cl != NULL) {
        u->free = cl->next;
        b = cl->buf;

        b->start = b->pos = active_buf->pos;
        b->end = b->last = active_buf->last;

    } else {
        cl = ngx_kmp_push_alloc_chain_buf(u->pool, active_buf->pos,
            active_buf->last);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_push_upstream_append_buffer: alloc chain buf failed");
            return NGX_ERROR;
        }
    }

    cl->next = NULL;
    *u->last = cl;
    u->last = &cl->next;

    return NGX_OK;
}
