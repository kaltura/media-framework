#ifndef _NGX_BLOCK_POOL_H_INCLUDED_
#define _NGX_BLOCK_POOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* Note: NGX_BLOCK_POOL_SKIP makes the block pool use ngx_palloc/ngx_pfree
    directly. It is intended for testing with valgrind along with:
    https://github.com/openresty/no-pool-nginx */

#define ngx_block_pool_auto(size) (size + sizeof(ngx_block_pool_auto_header_t))


typedef struct {
    size_t                  size;
    size_t                  used;
    ngx_uint_t              nalloc;
#if !(NGX_BLOCK_POOL_SKIP)
    size_t                  alloc;
    void                   *free_head;
    void                   *free_tail;
    u_char                 *pos;
    u_char                 *end;
#endif
} ngx_block_pool_slot_t;

typedef struct {
    ngx_pool_t             *pool;
    size_t                 *mem_limit;
    ngx_uint_t              count;
    ngx_block_pool_slot_t   slots[1];
} ngx_block_pool_t;


typedef struct {
    uint32_t                slot;
} ngx_block_pool_auto_header_t;


ngx_block_pool_t *ngx_block_pool_create(ngx_pool_t *pool, size_t *sizes,
    ngx_uint_t count, size_t *mem_limit);

void *ngx_block_pool_alloc(ngx_block_pool_t *block_pool, ngx_uint_t index);

void *ngx_block_pool_calloc(ngx_block_pool_t *block_pool, ngx_uint_t index);

void ngx_block_pool_free(ngx_block_pool_t *block_pool, ngx_uint_t index,
    void *ptr);

void ngx_block_pool_free_list(ngx_block_pool_t *block_pool, ngx_uint_t index,
    void *head, void *tail);

size_t ngx_block_pool_get_size(ngx_block_pool_t *block_pool, ngx_uint_t index);


void *ngx_block_pool_auto_alloc(ngx_block_pool_t *block_pool, size_t size);

void ngx_block_pool_auto_free(ngx_block_pool_t *block_pool, void *ptr);

size_t ngx_block_pool_json_get_size(ngx_block_pool_t *block_pool);

u_char *ngx_block_pool_json_write(u_char *p, ngx_block_pool_t *block_pool);

#endif /* _NGX_BLOCK_POOL_H_INCLUDED_ */
