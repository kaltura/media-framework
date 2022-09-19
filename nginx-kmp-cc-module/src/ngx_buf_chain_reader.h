#ifndef _NGX_BUF_CHAIN_READER_H_INCLUDED_
#define _NGX_BUF_CHAIN_READER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_buf_chain.h>


typedef struct {
    ngx_buf_chain_t  base;
    uint32_t         last_three;
    size_t           left;
} ngx_buf_chain_reader_ep_t;


ngx_int_t ngx_buf_chain_reader_read(ngx_buf_chain_t *reader, void *dst,
    size_t size);

ngx_int_t ngx_buf_chain_reader_skip(ngx_buf_chain_t *reader, size_t size);


/* emulation prevention reader */

void ngx_buf_chain_reader_ep_init(ngx_buf_chain_reader_ep_t *reader,
    ngx_buf_chain_t *src);

ngx_int_t ngx_buf_chain_reader_ep_read(ngx_buf_chain_reader_ep_t *reader,
    u_char *dst, size_t size);

ngx_int_t ngx_buf_chain_reader_ep_skip(ngx_buf_chain_reader_ep_t *reader,
    size_t size);

#endif /* _NGX_BUF_CHAIN_READER_H_INCLUDED_ */
