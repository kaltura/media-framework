#ifndef _NGX_KMP_RTMP_HANDSHAKE_H_INCLUDED_
#define _NGX_KMP_RTMP_HANDSHAKE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/sha.h>


#define NGX_RTMP_HANDSHAKE_KEYLEN  SHA256_DIGEST_LENGTH


typedef struct ngx_kmp_rtmp_handshake_s  ngx_kmp_rtmp_handshake_t;

typedef void (*ngx_kmp_rtmp_handshake_handler_pt)(
    ngx_kmp_rtmp_handshake_t *hs, ngx_int_t rc);

struct ngx_kmp_rtmp_handshake_s {
    ngx_connection_t                   *connection;
    ngx_msec_t                          epoch;
    ngx_msec_t                          timeout;
    ngx_str_t                           header;

    ngx_kmp_rtmp_handshake_handler_pt   handler;
    void                               *data;

    size_t                              written_bytes;
    size_t                              received_bytes;

    u_char                             *dump_path;
    ngx_fd_t                            dump_fd;

    ngx_buf_t                           buf;
    u_char                              digest[NGX_RTMP_HANDSHAKE_KEYLEN];
    ngx_uint_t                          stage;
    unsigned                            old:1;
};


ngx_kmp_rtmp_handshake_t *ngx_kmp_rtmp_handshake_create(ngx_connection_t *c);

void ngx_kmp_rtmp_handshake_free(ngx_kmp_rtmp_handshake_t *hs);


ngx_int_t ngx_kmp_rtmp_handshake_client(ngx_kmp_rtmp_handshake_t *hs,
    unsigned async);

#endif /* _NGX_KMP_RTMP_HANDSHAKE_H_INCLUDED_ */
