#ifndef _NGX_PERSIST_READ_H_INCLUDED_
#define _NGX_PERSIST_READ_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_persist_format.h"
#include "ngx_mem_rstream.h"


/*
 * NGX_DECLINED - file has old version
 * NGX_BAD_DATA - file is corrupt/wrong type etc.
 */
ngx_int_t ngx_persist_read_file_header(ngx_str_t *buf, uint32_t type,
    ngx_log_t *log, void *scope, ngx_mem_rstream_t *rs);

ngx_int_t ngx_persist_read_inflate(ngx_str_t *buf, size_t max_size,
    ngx_mem_rstream_t *rs, ngx_pool_t *pool, void **ptr);

ngx_persist_block_hdr_t *ngx_persist_read_block(ngx_mem_rstream_t *rs,
    ngx_mem_rstream_t *block_rs);

ngx_int_t ngx_persist_read_skip_block_header(ngx_mem_rstream_t *rs,
    ngx_persist_block_hdr_t *header);

#endif /* _NGX_PERSIST_READ_H_INCLUDED_ */
