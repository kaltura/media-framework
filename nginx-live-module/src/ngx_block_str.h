#ifndef _NGX_BLOCK_STR_H_INCLUDED_
#define _NGX_BLOCK_STR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_block_pool.h"


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

u_char *ngx_block_str_write(u_char *p, ngx_block_str_t *str);


#endif /* _NGX_BLOCK_STR_H_INCLUDED_ */
