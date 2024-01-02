#ifndef _NGX_TS_CHAIN_READER_H_INCLUDED_
#define _NGX_TS_CHAIN_READER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_chain_t  *cl;
    ngx_buf_t    *buf;
    u_char       *pos;
} ngx_ts_chain_reader_t;


void ngx_ts_chain_reader_init(ngx_ts_chain_reader_t *reader, ngx_chain_t *in);

ngx_int_t ngx_ts_chain_reader_read(ngx_ts_chain_reader_t *reader,
    void *dst, size_t size);

ngx_int_t ngx_ts_chain_reader_skip(ngx_ts_chain_reader_t *reader, size_t size);

#endif /* _NGX_TS_CHAIN_READER_H_INCLUDED_ */
