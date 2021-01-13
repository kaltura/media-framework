#ifndef _NGX_LBA_H_INCLUDED_
#define _NGX_LBA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_lba_s  ngx_lba_t;


ngx_lba_t *ngx_lba_create(ngx_pool_t *pool, size_t buf_size,
    ngx_uint_t bin_count);

ngx_flag_t ngx_lba_match(ngx_lba_t *lba, size_t buf_size,
    ngx_uint_t bin_count);

size_t ngx_lba_buf_size(ngx_lba_t *lba);

void *ngx_lba_alloc(ngx_lba_t *lba);

void ngx_lba_free(ngx_lba_t *lba, void *buf);

#endif /* _NGX_LBA_H_INCLUDED_ */
