#ifndef _NGX_BLOCK_STR_H_INCLUDED_
#define _NGX_BLOCK_STR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_block_pool.h"
#include "ngx_mem_rstream.h"
#include "ngx_wstream.h"


#define ngx_block_str_free(str, pool, index)    \
    ngx_block_str_free_data((str)->data, pool, index);


typedef struct ngx_block_str_node_s  ngx_block_str_node_t;

typedef struct {
    ngx_block_str_node_t  *data;
    size_t                 len;
    size_t                 block_len;
} ngx_block_str_t;


ngx_int_t ngx_block_str_set(ngx_block_str_t *dest, ngx_block_pool_t *pool,
    ngx_uint_t index, ngx_str_t *src);

void ngx_block_str_free_data(ngx_block_str_node_t *data,
    ngx_block_pool_t *pool, ngx_uint_t index);

u_char *ngx_block_str_copy(u_char *p, ngx_block_str_t *str);

ngx_int_t ngx_block_str_write(ngx_wstream_t *ws, ngx_block_str_t *str);

ngx_int_t ngx_block_str_read(ngx_mem_rstream_t *rs, ngx_block_str_t *str,
    ngx_block_pool_t *pool, ngx_uint_t index);

#endif /* _NGX_BLOCK_STR_H_INCLUDED_ */
