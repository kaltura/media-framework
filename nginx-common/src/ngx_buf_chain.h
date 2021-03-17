#ifndef _NGX_BUF_CHAIN_H_INCLUDED_
#define _NGX_BUF_CHAIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_buf_chain_s  ngx_buf_chain_t;

struct ngx_buf_chain_s {
    ngx_buf_chain_t  *next;
    u_char           *data;
    size_t            size;
};


ngx_int_t ngx_buf_chain_skip(ngx_buf_chain_t **head_ptr, size_t size);

void *ngx_buf_chain_copy(ngx_buf_chain_t **head_ptr, void *buf, size_t size);

void *ngx_buf_chain_read(ngx_buf_chain_t **head_ptr, void *buf, size_t size);

ngx_int_t ngx_buf_chain_compare(ngx_buf_chain_t *head, void *buf, size_t size);

#endif /* _NGX_BUF_CHAIN_H_INCLUDED_ */
