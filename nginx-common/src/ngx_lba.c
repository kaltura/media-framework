#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_lba.h"


/* Large Buffer Allocator - manages the allocation of large fixed-size buffers.
    Memory is allocated using mmap in large blocks, each block is ~512k,
    and contains multiple buffers. The blocks are grouped into bins, according
    to the number of used buffers. When allocating, blocks that have more used
    buffers are preferred, in order to reduce fragmentation between blocks,
    and allow blocks to be deallocated. */


#define ngx_queue_insert_before   ngx_queue_insert_tail

#define ngx_lba_free_next(buf)    (*(void **) (buf))

#define NGX_LBA_BLOCK_SIZE        (512 * 1024)


typedef struct {
    ngx_queue_t              queue;
    ngx_uint_t               bin_index;
    void                    *free;
    uint32_t                 inited;
    uint32_t                 used;
} ngx_lba_block_header_t;


typedef struct {
    ngx_lba_block_header_t  *block;
} ngx_lba_buf_header_t;


typedef struct {
    ngx_queue_t              queue;
    ngx_queue_t              blocks;
} ngx_lba_block_bin_t;


struct ngx_lba_s {
    ngx_uint_t               bin_count;
    ngx_uint_t               initial_bin;
    ngx_uint_t               block_bufs;
    size_t                   buf_size;
    ngx_queue_t             *active;        /* ordered by used count asc */
    ngx_lba_block_bin_t      bins[1];
};


/* Note: NGX_LBA_SKIP makes the module proxy to ngx_alloc/ngx_free. */

#if !(NGX_LBA_SKIP)

static void *
ngx_lba_mem_alloc(size_t size, ngx_log_t *log)
{
    void  *p;

    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
        -1, 0);
    if (p == MAP_FAILED) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
            "ngx_lba_mem_alloc: mmap(%uz) failed", size);
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
        "ngx_lba_mem_alloc: mmap: %p:%uz", p, size);

    return p;
}


static void
ngx_lba_mem_free(void *p, size_t size, ngx_log_t *log)
{
    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0,
        "ngx_lba_mem_free: munmap: %p:%uz", p, size);

    if (munmap(p, size) != 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_lba_mem_free: munmap(%p) failed", p);
    }
}


static void *
ngx_lba_block_alloc(ngx_lba_t *lba)
{
    void                    *buf;
    ngx_uint_t               bin_index;
    ngx_lba_block_bin_t     *bin;
    ngx_lba_buf_header_t    *header;
    ngx_lba_block_header_t  *block;

    block = ngx_lba_mem_alloc(NGX_LBA_BLOCK_SIZE, ngx_cycle->log);
    if (block == NULL) {
        return NULL;
    }

    bin_index = lba->initial_bin;

    block->bin_index = bin_index;
    block->free = NULL;
    block->inited = 1;
    block->used = 1;

    bin = &lba->bins[bin_index];

    ngx_queue_insert_tail(&bin->blocks, &block->queue);

    if (bin->queue.next == NULL) {
        /* this function is called only when there are no free blocks,
            so there can't be any block before this one */
        ngx_queue_insert_head(lba->active, &bin->queue);
    }

    header = (void *) (block + 1);
    header->block = block;
    buf = header + 1;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "ngx_lba_block_alloc: %p", buf);

    return buf;
}


static void
ngx_lba_block_free(ngx_lba_t *lba, ngx_lba_block_header_t *block)
{
    ngx_lba_block_bin_t  *bin;

    bin = &lba->bins[block->bin_index];

    ngx_queue_remove(&block->queue);

    ngx_lba_mem_free(block, NGX_LBA_BLOCK_SIZE, ngx_cycle->log);

    if (ngx_queue_empty(&bin->blocks)) {
        ngx_queue_remove(&bin->queue);
    }
}


static void *
ngx_lba_block_alloc_buf(ngx_lba_t *lba, ngx_lba_block_header_t *block)
{
    void                  *buf;
    ngx_uint_t             old_index;
    ngx_uint_t             new_index;
    ngx_lba_block_bin_t   *old_bin;
    ngx_lba_block_bin_t   *new_bin;
    ngx_lba_buf_header_t  *header;

    if (block->free) {
        buf = block->free;
        block->free = ngx_lba_free_next(buf);

    } else if (block->inited < lba->block_bufs) {
        header = (void *) ((u_char *) (block + 1) +
            lba->buf_size * block->inited);
        block->inited++;

        header->block = block;
        buf = header + 1;

    } else {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
            "ngx_lba_block_alloc_buf: no free buffers in active block");
        ngx_debug_point();
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "ngx_lba_block_alloc_buf: %p", buf);

    block->used++;

    old_index = block->bin_index;
    new_index = block->used * lba->bin_count / lba->block_bufs;
    if (new_index == old_index) {
        return buf;
    }

    old_bin = &lba->bins[old_index];
    new_bin = &lba->bins[new_index];

    ngx_queue_remove(&block->queue);
    ngx_queue_insert_tail(&new_bin->blocks, &block->queue);
    block->bin_index = new_index;

    if (new_bin->queue.next == NULL) {
        ngx_queue_insert_after(&old_bin->queue, &new_bin->queue);
    }

    if (ngx_queue_empty(&old_bin->blocks)) {
        ngx_queue_remove(&old_bin->queue);
    }

    return buf;
}


static void
ngx_lba_block_free_buf(ngx_lba_t *lba, ngx_lba_block_header_t *block,
    void *buf)
{
    ngx_uint_t            old_index;
    ngx_uint_t            new_index;
    ngx_lba_block_bin_t  *old_bin;
    ngx_lba_block_bin_t  *new_bin;

    block->used--;

    /* free the block only if there is already some other free block */
    if (block->used == 0 && !ngx_queue_empty(&lba->bins[0].blocks) &&
        (ngx_queue_head(&lba->bins[0].blocks) != &block->queue ||
         ngx_queue_last(&lba->bins[0].blocks) != &block->queue))
    {
        ngx_lba_block_free(lba, block);
        return;
    }

    ngx_lba_free_next(buf) = block->free;
    block->free = buf;

    old_index = block->bin_index;
    new_index = block->used * lba->bin_count / lba->block_bufs;
    if (new_index == old_index) {
        return;
    }

    old_bin = &lba->bins[old_index];
    new_bin = &lba->bins[new_index];

    ngx_queue_remove(&block->queue);
    ngx_queue_insert_tail(&new_bin->blocks, &block->queue);
    block->bin_index = new_index;

    if (new_bin->queue.next == NULL) {
        ngx_queue_insert_before(&old_bin->queue, &new_bin->queue);
    }

    if (ngx_queue_empty(&old_bin->blocks) && &old_bin->queue != lba->active) {
        ngx_queue_remove(&old_bin->queue);
    }
}


void *
ngx_lba_alloc(ngx_lba_t *lba)
{
    ngx_queue_t             *q;
    ngx_lba_block_bin_t     *bin;
    ngx_lba_block_header_t  *block;

    q = ngx_queue_last(lba->active);
    if (q == ngx_queue_sentinel(lba->active)) {
        return ngx_lba_block_alloc(lba);
    }

    bin = ngx_queue_data(q, ngx_lba_block_bin_t, queue);

    if (ngx_queue_empty(&bin->blocks)) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
            "ngx_lba_alloc: no blocks in active bin");
        ngx_debug_point();
        return NULL;
    }

    q = ngx_queue_last(&bin->blocks);
    block = ngx_queue_data(q, ngx_lba_block_header_t, queue);

    return ngx_lba_block_alloc_buf(lba, block);
}


void
ngx_lba_free(ngx_lba_t *lba, void *buf)
{
    ngx_lba_buf_header_t    *header;
    ngx_lba_block_header_t  *block;

    header = (ngx_lba_buf_header_t *) buf - 1;
    block = header->block;

    ngx_lba_block_free_buf(lba, block, buf);
}

#else

void *
ngx_lba_alloc(ngx_lba_t *lba)
{
    return ngx_alloc(lba->buf_size, ngx_cycle->log);
}


void
ngx_lba_free(ngx_lba_t *lba, void *buf)
{
    ngx_free(buf);
}

#endif


ngx_lba_t *
ngx_lba_create(ngx_pool_t *pool, size_t buf_size, ngx_uint_t bin_count)
{
    ngx_lba_t   *lba;
    ngx_uint_t   i;
    ngx_uint_t   block_bufs;

    if (buf_size < sizeof(void *)) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_lba_create: buf size %uz too small", buf_size);
        return NULL;
    }

    buf_size += sizeof(ngx_lba_buf_header_t);
    block_bufs = (NGX_LBA_BLOCK_SIZE - sizeof(ngx_lba_block_header_t)) /
        buf_size;

    if (block_bufs <= 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_lba_create: buf size %uz too large", buf_size);
        return NULL;
    }

    if (bin_count > block_bufs) {
        bin_count = block_bufs;
    }

    lba = ngx_palloc(pool, sizeof(*lba) + sizeof(ngx_lba_block_bin_t) *
        bin_count);
    if (lba == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_lba_create: alloc failed");
        return NULL;
    }

    lba->bin_count = bin_count;
    lba->initial_bin = bin_count / block_bufs;    /* for used = 1 */
    lba->block_bufs = block_bufs;
    lba->buf_size = buf_size;

    for (i = 0; i < bin_count; i++) {
        lba->bins[i].queue.prev = NULL;
        lba->bins[i].queue.next = NULL;
        ngx_queue_init(&lba->bins[i].blocks);
    }

    ngx_queue_init(&lba->bins[bin_count].queue);
    ngx_queue_init(&lba->bins[bin_count].blocks);

    /* the last bin holds the blocks that are completely full, therefore,
        it is never active, and used as the sentinel of the active queue */
    lba->active = &lba->bins[bin_count].queue;

    return lba;
}


ngx_flag_t
ngx_lba_match(ngx_lba_t *lba, size_t buf_size, ngx_uint_t bin_count)
{
    buf_size += sizeof(ngx_lba_buf_header_t);
    if (lba->buf_size != buf_size) {
        return 0;
    }

    if (bin_count > lba->block_bufs) {
        bin_count = lba->block_bufs;
    }

    return bin_count == lba->bin_count;
}


size_t
ngx_lba_buf_size(ngx_lba_t *lba)
{
    return lba->buf_size - sizeof(ngx_lba_buf_header_t);
}
