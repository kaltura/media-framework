
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <openssl/hmac.h>

#include "ngx_kmp_rtmp_handshake.h"


#define NGX_RTMP_HANDSHAKE_BUFSIZE                  1537


#define NGX_RTMP_HANDSHAKE_SERVER_RECV_CHALLENGE    1
#define NGX_RTMP_HANDSHAKE_SERVER_SEND_CHALLENGE    2
#define NGX_RTMP_HANDSHAKE_SERVER_SEND_RESPONSE     3
#define NGX_RTMP_HANDSHAKE_SERVER_RECV_RESPONSE     4
#define NGX_RTMP_HANDSHAKE_SERVER_DONE              5


#define NGX_RTMP_HANDSHAKE_CLIENT_SEND_HEADER       6
#define NGX_RTMP_HANDSHAKE_CLIENT_SEND_CHALLENGE    7
#define NGX_RTMP_HANDSHAKE_CLIENT_RECV_CHALLENGE    8
#define NGX_RTMP_HANDSHAKE_CLIENT_RECV_RESPONSE     9
#define NGX_RTMP_HANDSHAKE_CLIENT_SEND_RESPONSE     10
#define NGX_RTMP_HANDSHAKE_CLIENT_DONE              11


#define ngx_kmp_rtmp_rcpymem(dst, src, n)                                    \
    (((u_char *) ngx_kmp_rtmp_rmemcpy(dst, src, n)) + (n))


static void ngx_kmp_rtmp_handshake_send(ngx_event_t *wev);


/* RTMP handshake :
 *
 *          =peer1=                      =peer2=
 * challenge ----> (.....[digest1]......) ----> 1537 bytes
 * response  <---- (...........[digest2]) <---- 1536 bytes
 *
 *
 * - both packets contain random bytes except for digests
 * - digest1 position is calculated on random packet bytes
 * - digest2 is always at the end of the packet
 *
 * digest1: HMAC_SHA256(packet, peer1_partial_key)
 * digest2: HMAC_SHA256(packet, HMAC_SHA256(digest1, peer2_full_key))
 */


/* Handshake keys */

static u_char  ngx_kmp_rtmp_server_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
    'S', 'e', 'r', 'v', 'e', 'r', ' ',
    '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
    0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};


static u_char  ngx_kmp_rtmp_client_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ',
    '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
    0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};


static u_char  ngx_kmp_rtmp_server_version[4] = {
    0x0D, 0x0E, 0x0A, 0x0D
};


static u_char  ngx_kmp_rtmp_client_version[4] = {
    0x0C, 0x00, 0x0D, 0x0E
};


static ngx_str_t  ngx_kmp_rtmp_server_full_key =
    { sizeof(ngx_kmp_rtmp_server_key), ngx_kmp_rtmp_server_key };
static ngx_str_t  ngx_kmp_rtmp_server_partial_key =
    { 36, ngx_kmp_rtmp_server_key };

static ngx_str_t  ngx_kmp_rtmp_client_full_key =
    { sizeof(ngx_kmp_rtmp_client_key), ngx_kmp_rtmp_client_key };
static ngx_str_t  ngx_kmp_rtmp_client_partial_key =
    { 30, ngx_kmp_rtmp_client_key };


static void *
ngx_kmp_rtmp_rmemcpy(void *dst, const void *src, size_t n)
{
    u_char  *d, *s;

    d = dst;
    s = (u_char *) src + n - 1;

    while (s >= (u_char *) src) {
        *d++ = *s--;
    }

    return dst;
}


static ngx_int_t
ngx_kmp_rtmp_handshake_make_digest(ngx_str_t *key, ngx_buf_t *src,
    u_char *skip, u_char *dst, ngx_log_t *log)
{
    static HMAC_CTX      *hmac;
    unsigned int          len;

    if (hmac == NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        static HMAC_CTX   shmac;

        hmac = &shmac;
        HMAC_CTX_init(hmac);
#else
        hmac = HMAC_CTX_new();
        if (hmac == NULL) {
            return NGX_ERROR;
        }
#endif
    }

    HMAC_Init_ex(hmac, key->data, key->len, EVP_sha256(), NULL);

    if (skip && skip >= src->pos && skip <= src->last) {
        if (skip > src->pos) {
            HMAC_Update(hmac, src->pos, skip - src->pos);
        }

        skip += NGX_RTMP_HANDSHAKE_KEYLEN;

        if (src->last > skip) {
            HMAC_Update(hmac, skip, src->last - skip);
        }

    } else {
        HMAC_Update(hmac, src->pos, src->last - src->pos);
    }

    HMAC_Final(hmac, dst, &len);

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_handshake_find_digest(ngx_buf_t *b, ngx_str_t *key, size_t base,
    ngx_log_t *log)
{
    size_t   n, offs;
    u_char   digest[NGX_RTMP_HANDSHAKE_KEYLEN];
    u_char  *p;

    offs = 0;
    for (n = 0; n < 4; n++) {
        offs += b->pos[base + n];
    }

    offs = (offs % 728) + base + 4;
    p = b->pos + offs;

    if (ngx_kmp_rtmp_handshake_make_digest(key, b, p, digest, log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_memcmp(digest, p, NGX_RTMP_HANDSHAKE_KEYLEN) == 0) {
        return offs;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_kmp_rtmp_handshake_write_digest(ngx_buf_t *b, ngx_str_t *key, size_t base,
    ngx_log_t *log)
{
    size_t   n, offs;
    u_char  *p;

    offs = 0;
    for (n = 8; n < 12; n++) {
        offs += b->pos[base + n];
    }

    offs = (offs % 728) + base + 12;
    p = b->pos + offs;

    if (ngx_kmp_rtmp_handshake_make_digest(key, b, p, p, log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_rtmp_handshake_fill_random_buffer(ngx_buf_t *b)
{
    for (; b->last < b->end; b->last++) {
        *b->last = (u_char) rand();
    }
}


static ngx_int_t
ngx_kmp_rtmp_handshake_create_challenge(ngx_kmp_rtmp_handshake_t *hs,
    const u_char version[4], ngx_str_t *key)
{
    ngx_buf_t  *b;

    b = &hs->buf;

    b->last = b->pos = b->start;
    *b->last++ = '\x03';
    b->last = ngx_kmp_rtmp_rcpymem(b->last, &hs->epoch, 4);
    b->last = ngx_cpymem(b->last, version, 4);
    ngx_kmp_rtmp_handshake_fill_random_buffer(b);

    b->pos++;

    if (ngx_kmp_rtmp_handshake_write_digest(b, key, 0, hs->connection->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    b->pos--;

    hs->written_bytes += b->last - b->pos;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_handshake_parse_challenge(ngx_kmp_rtmp_handshake_t *hs,
    ngx_str_t *peer_key, ngx_str_t *key)
{
    u_char      *p;
    uint32_t     version;
    ngx_buf_t   *b;
    ngx_int_t    offs;
    ngx_msec_t   peer_epoch;

    b = &hs->buf;
    if (*b->pos != '\x03') {
        ngx_log_error(NGX_LOG_ERR, hs->connection->log, 0,
                      "handshake: unexpected RTMP version: %i",
                      (ngx_int_t) *b->pos);
        return NGX_ERROR;
    }

    b->pos++;
    peer_epoch = 0;
    ngx_kmp_rtmp_rmemcpy(&peer_epoch, b->pos, 4);

    p = b->pos + 4;
    ngx_log_debug5(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: peer version=%i.%i.%i.%i epoch=%uD",
            (ngx_int_t) p[3], (ngx_int_t) p[2],
            (ngx_int_t) p[1], (ngx_int_t) p[0],
            (uint32_t) peer_epoch);

    ngx_memcpy(&version, p, sizeof(version));
    if (version == 0) {
        hs->old = 1;
        return NGX_OK;
    }

    offs = ngx_kmp_rtmp_handshake_find_digest(b, peer_key, 772,
        hs->connection->log);
    if (offs == NGX_ERROR) {
        offs = ngx_kmp_rtmp_handshake_find_digest(b, peer_key, 8,
            hs->connection->log);
    }

    if (offs == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, hs->connection->log, 0,
                      "handshake: digest not found");
        hs->old = 1;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: digest found at pos=%i", offs);

    b->pos += offs;
    b->last = b->pos + NGX_RTMP_HANDSHAKE_KEYLEN;

    if (ngx_kmp_rtmp_handshake_make_digest(key, b, NULL, hs->digest,
        hs->connection->log) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_rtmp_handshake_create_response(ngx_kmp_rtmp_handshake_t *hs)
{
    u_char     *p;
    ngx_buf_t  *b;
    ngx_str_t   key;

    b = &hs->buf;

    b->pos = b->last = b->start + 1;
    ngx_kmp_rtmp_handshake_fill_random_buffer(b);

    if (!hs->old) {
        p = b->last - NGX_RTMP_HANDSHAKE_KEYLEN;
        key.data = hs->digest;
        key.len = sizeof(hs->digest);
        if (ngx_kmp_rtmp_handshake_make_digest(&key, b, p, p,
            hs->connection->log) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    hs->written_bytes += b->last - b->pos;

    return NGX_OK;
}


static void
ngx_kmp_rtmp_handshake_done(ngx_kmp_rtmp_handshake_t *hs)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: done");

    hs->handler(hs, NGX_OK);
}


static void
ngx_kmp_rtmp_handshake_dump(ngx_kmp_rtmp_handshake_t *hs, void *buf,
    size_t size)
{
    u_char  *dump_path;

    if (hs->dump_fd == NGX_INVALID_FILE) {
        dump_path = hs->dump_path;

        /* try to open only once */

        if (dump_path == NGX_CONF_UNSET_PTR) {
            return;
        }

        hs->dump_path = NGX_CONF_UNSET_PTR;

        hs->dump_fd = ngx_open_file((char *) dump_path,
            NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
        if (hs->dump_fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_ERR, hs->connection->log, ngx_errno,
                "ngx_kmp_rtmp_handshake_dump: "
                ngx_open_file_n " \"%s\" failed", dump_path);
            return;
        }
    }

    if (ngx_write_fd(hs->dump_fd, buf, size) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, hs->connection->log, ngx_errno,
            "ngx_kmp_rtmp_handshake_dump: write failed");
        ngx_close_file(hs->dump_fd);
        hs->dump_fd = NGX_INVALID_FILE;
    }
}


static void
ngx_kmp_rtmp_handshake_recv(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_kmp_rtmp_handshake_t  *hs;

    c = rev->data;
    hs = c->data;

    if (c->destroyed) {
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                      "handshake: recv: client timed out");
        c->timedout = 1;
        hs->handler(hs, NGX_ERROR);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = &hs->buf;

    while (b->last < b->end) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            hs->handler(hs, NGX_ERROR);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, hs->timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                hs->handler(hs, NGX_ERROR);
            }

            return;
        }

        if (hs->dump_path) {
            ngx_kmp_rtmp_handshake_dump(hs, b->last, n);
        }

        hs->received_bytes += n;

        b->last += n;
    }

    if (rev->active) {
        ngx_del_event(rev, NGX_READ_EVENT, 0);
    }

    hs->stage++;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: stage %ui", hs->stage);

    switch (hs->stage) {

    case NGX_RTMP_HANDSHAKE_SERVER_SEND_CHALLENGE:
        if (ngx_kmp_rtmp_handshake_parse_challenge(hs,
                &ngx_kmp_rtmp_client_partial_key,
                &ngx_kmp_rtmp_server_full_key) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "handshake: error parsing challenge");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        if (hs->old) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
                    "handshake: old-style challenge");
            b->pos = b->start;
            b->last = b->end;

            hs->written_bytes += b->last - b->pos;

        } else if (ngx_kmp_rtmp_handshake_create_challenge(hs,
                   ngx_kmp_rtmp_server_version,
                   &ngx_kmp_rtmp_server_partial_key) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "handshake: error creating challenge");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        ngx_kmp_rtmp_handshake_send(c->write);
        break;

    case NGX_RTMP_HANDSHAKE_SERVER_DONE:
        ngx_kmp_rtmp_handshake_done(hs);
        break;

    case NGX_RTMP_HANDSHAKE_CLIENT_RECV_RESPONSE:
        if (ngx_kmp_rtmp_handshake_parse_challenge(hs,
                &ngx_kmp_rtmp_server_partial_key,
                &ngx_kmp_rtmp_client_full_key) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "handshake: error parsing challenge");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        b->pos = b->last = b->start + 1;
        ngx_kmp_rtmp_handshake_recv(c->read);
        break;

    case NGX_RTMP_HANDSHAKE_CLIENT_SEND_RESPONSE:
        if (ngx_kmp_rtmp_handshake_create_response(hs) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "handshake: response error");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        ngx_kmp_rtmp_handshake_send(c->write);
        break;
    }
}


static void
ngx_kmp_rtmp_handshake_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_kmp_rtmp_handshake_t  *hs;

    c = wev->data;
    hs = c->data;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                      "handshake: send: client timed out");
        c->timedout = 1;
        hs->handler(hs, NGX_ERROR);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    b = &hs->buf;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_ERROR) {
            hs->handler(hs, NGX_ERROR);
            return;
        }

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, hs->timeout);

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                hs->handler(hs, NGX_ERROR);
            }

            return;
        }

        b->pos += n;
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    hs->stage++;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: stage %ui", hs->stage);

    switch (hs->stage) {

    case NGX_RTMP_HANDSHAKE_SERVER_SEND_RESPONSE:
        if (hs->old) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
                           "handshake: old-style response");
            b->pos = b->start + 1;
            b->last = b->end;

            hs->written_bytes += b->last - b->pos;

        } else if (ngx_kmp_rtmp_handshake_create_response(hs) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                          "handshake: response error");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        ngx_kmp_rtmp_handshake_send(wev);
        break;

    case NGX_RTMP_HANDSHAKE_SERVER_RECV_RESPONSE:
        b->pos = b->last = b->start + 1;
        ngx_kmp_rtmp_handshake_recv(c->read);
        break;

    case NGX_RTMP_HANDSHAKE_CLIENT_SEND_CHALLENGE:
        if (ngx_kmp_rtmp_handshake_create_challenge(hs,
            ngx_kmp_rtmp_client_version, &ngx_kmp_rtmp_client_partial_key)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "handshake: challenge error");
            hs->handler(hs, NGX_ERROR);
            return;
        }

        ngx_kmp_rtmp_handshake_send(wev);
        break;

    case NGX_RTMP_HANDSHAKE_CLIENT_RECV_CHALLENGE:
        b->pos = b->last = b->start;
        ngx_kmp_rtmp_handshake_recv(c->read);
        break;

    case NGX_RTMP_HANDSHAKE_CLIENT_DONE:
        ngx_kmp_rtmp_handshake_done(hs);
        break;
    }
}


ngx_kmp_rtmp_handshake_t *
ngx_kmp_rtmp_handshake_create(ngx_connection_t *c)
{
    ngx_buf_t                 *b;
    ngx_kmp_rtmp_handshake_t  *hs;

    hs = ngx_alloc(sizeof(*hs) + NGX_RTMP_HANDSHAKE_BUFSIZE, c->log);
    if (hs == NULL) {
        return NULL;
    }

    ngx_memzero(hs, sizeof(*hs));

    hs->connection = c;
    hs->epoch = ngx_current_msec;
    hs->dump_fd = NGX_INVALID_FILE;

    b = &hs->buf;

    b->start = (void *) (hs + 1);
    b->end = b->start + NGX_RTMP_HANDSHAKE_BUFSIZE;

    b->memory = 1;
    b->pos = b->last = b->start;

    return hs;
}


void
ngx_kmp_rtmp_handshake_free(ngx_kmp_rtmp_handshake_t *hs)
{
    if (hs->dump_fd != NGX_INVALID_FILE) {
        ngx_close_file(hs->dump_fd);
    }

    ngx_free(hs);
}


#if 0
void
ngx_kmp_rtmp_handshake(ngx_kmp_rtmp_handshake_t *hs)
{
    ngx_connection_t  *c;

    c = hs->connection;

    c->read->handler =  ngx_kmp_rtmp_handshake_recv;
    c->write->handler = ngx_kmp_rtmp_handshake_send;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, hs->connection->log, 0,
            "handshake: start server handshake");

    hs->stage = NGX_RTMP_HANDSHAKE_SERVER_RECV_CHALLENGE;

    ngx_kmp_rtmp_handshake_recv(c->read);

    return NGX_OK;
}
#endif


ngx_int_t
ngx_kmp_rtmp_handshake_client(ngx_kmp_rtmp_handshake_t *hs, unsigned async)
{
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = hs->connection;

    c->read->handler =  ngx_kmp_rtmp_handshake_recv;
    c->write->handler = ngx_kmp_rtmp_handshake_send;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
            "handshake: start client handshake");

    if (hs->header.len > 0) {
        hs->stage = NGX_RTMP_HANDSHAKE_CLIENT_SEND_HEADER;

        b = &hs->buf;
        b->pos = hs->header.data;
        b->last = b->pos + hs->header.len;

    } else {
        hs->stage = NGX_RTMP_HANDSHAKE_CLIENT_SEND_CHALLENGE;

        if (ngx_kmp_rtmp_handshake_create_challenge(hs,
            ngx_kmp_rtmp_client_version, &ngx_kmp_rtmp_client_partial_key)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (async) {
        ngx_add_timer(c->write, hs->timeout);

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    ngx_kmp_rtmp_handshake_send(c->write);

    return NGX_OK;
}
