#ifndef _NGX_RTMP_CHAIN_READER_H_INCLUDED_
#define _NGX_RTMP_CHAIN_READER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_chain_t              *cl;
    ngx_buf_t                *buf;
    u_char                   *pos;
} ngx_rtmp_chain_reader_t;


void ngx_rtmp_chain_reader_init(ngx_rtmp_chain_reader_t *reader,
    ngx_chain_t *in);

ngx_int_t ngx_rtmp_chain_reader_read(ngx_rtmp_chain_reader_t *reader,
    void *dst, size_t size);

ngx_int_t ngx_rtmp_chain_reader_skip(ngx_rtmp_chain_reader_t *reader,
    size_t size);


/* ep = emulation prevention, removes avc emulation prevention bytes */

typedef struct {
    ngx_rtmp_chain_reader_t   base;
    uint32_t                  last_three;
    size_t                    left;
} ngx_rtmp_chain_reader_ep_t;


void ngx_rtmp_chain_reader_ep_init(ngx_rtmp_chain_reader_ep_t *reader,
    ngx_rtmp_chain_reader_t *src);

ngx_int_t ngx_rtmp_chain_reader_ep_read(ngx_rtmp_chain_reader_ep_t *reader,
    u_char *dst, size_t size);

ngx_int_t ngx_rtmp_chain_reader_ep_skip(ngx_rtmp_chain_reader_ep_t *reader,
    size_t size);

#endif /* _NGX_RTMP_CHAIN_READER_H_INCLUDED_ */
