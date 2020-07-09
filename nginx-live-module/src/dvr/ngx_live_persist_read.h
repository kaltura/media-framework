#ifndef _NGX_LIVE_PERSIST_READ_H_INCLUDED_
#define _NGX_LIVE_PERSIST_READ_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_format.h"
#include "../ngx_mem_rstream.h"


ngx_int_t ngx_live_persist_read_file_header(ngx_str_t *buf, uint32_t type,
    ngx_log_t *log, void *scope, ngx_mem_rstream_t *rs);

ngx_live_persist_block_header_t *ngx_live_persist_read_block(
    ngx_mem_rstream_t *rs, ngx_mem_rstream_t *block_rs);

ngx_int_t ngx_live_persist_read_skip_block_header(ngx_mem_rstream_t *rs,
    ngx_live_persist_block_header_t *header);

#endif /* _NGX_LIVE_PERSIST_READ_H_INCLUDED_ */
