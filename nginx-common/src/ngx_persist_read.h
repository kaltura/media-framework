#ifndef _NGX_PERSIST_READ_H_INCLUDED_
#define _NGX_PERSIST_READ_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_persist_format.h"
#include "ngx_mem_rstream.h"


ngx_persist_file_header_t *ngx_persist_read_file_header(ngx_str_t *buf,
    uint32_t type, ngx_log_t *log, void *scope, ngx_mem_rstream_t *rs);

ngx_int_t ngx_persist_read_inflate(ngx_persist_file_header_t *header,
    size_t max_size, ngx_mem_rstream_t *rs, void **ptr);

ngx_persist_block_header_t *ngx_persist_read_block(ngx_mem_rstream_t *rs,
    ngx_mem_rstream_t *block_rs);

ngx_int_t ngx_persist_read_skip_block_header(ngx_mem_rstream_t *rs,
    ngx_persist_block_header_t *header);

#endif /* _NGX_PERSIST_READ_H_INCLUDED_ */
