#include "ngx_block_pool.h"


#define NGX_BLOCK_POOL_MIN_ALLOC_COUNT  (4)

#define ngx_block_pool_free_next(ptr)  (*(void **) ptr)
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)


#if !(NGX_BLOCK_POOL_SKIP)

#if (NGX_DEBUG)
static void
ngx_block_pool_validate(ngx_block_pool_t *block_pool)
{
    void                   *item;
    ngx_block_pool_slot_t  *cur;
    ngx_block_pool_slot_t  *next;
    ngx_block_pool_slot_t  *last;

    last = block_pool->slots + block_pool->count;
    for (cur = block_pool->slots; cur < last; cur++) {

        if (cur->free_head == NULL) {
            continue;
        }

        /* validate free_head / free_tail are aligned */
        for (item = cur->free_head; ; item = next) {
            next = ngx_block_pool_free_next(item);
            if (next == NULL) {
                break;
            }
        }

        if (item != cur->free_tail) {
            ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
                "ngx_block_pool_validate: free tail mismatch");
            ngx_debug_point();
        }
    }
}
#else
#define ngx_block_pool_validate(block_pool)
#endif

static void
ngx_block_pool_init_slot(ngx_block_pool_slot_t *slot)
{
    if (slot->size < sizeof(void *)) {
        /* must be large enough to hold the free list ptr */
        slot->size = sizeof(void *);
    }

    slot->alloc = (slot->size * NGX_BLOCK_POOL_MIN_ALLOC_COUNT
        + ngx_pagesize - 1) & ~(ngx_pagesize - 1);

    slot->free_head = NULL;
    slot->pos = NULL;
    slot->end = NULL;
}

static void *
ngx_block_pool_alloc_internal(ngx_block_pool_t *block_pool,
    ngx_block_pool_slot_t *slot)
{
    u_char  *ptr;

    if (slot->free_head) {
        ptr = slot->free_head;
        slot->free_head = ngx_block_pool_free_next(ptr);
        slot->nalloc++;
        return ptr;
    }

    ptr = slot->pos;
    if ((size_t)(slot->end - ptr) < slot->size) {

        if (*block_pool->mem_limit < slot->alloc) {
            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_alloc: memory limit exceeded");
            return NULL;
        }

        ptr = ngx_palloc(block_pool->pool, slot->alloc);
        if (ptr == NULL) {
            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_alloc: alloc failed");
            return NULL;
        }

        slot->end = ptr + slot->alloc;
        *block_pool->mem_limit -= slot->alloc;
    }

    slot->pos = ptr + slot->size;
    slot->nalloc++;
    return ptr;
}

static void
ngx_block_pool_free_list_internal(ngx_block_pool_t *block_pool,
    ngx_block_pool_slot_t *slot, void *head, void *tail)
{
    if (slot->free_head == NULL) {
        slot->free_head = head;

    } else {
        ngx_block_pool_free_next(slot->free_tail) = head;
    }

    slot->free_tail = tail;

    ngx_block_pool_validate(block_pool);
}

#else

static void
ngx_block_pool_init_slot(ngx_block_pool_slot_t *slot)
{
}

static void *
ngx_block_pool_alloc_internal(ngx_block_pool_t *block_pool,
    ngx_block_pool_slot_t *slot)
{
    void  **ptr;

    ptr = ngx_palloc(block_pool->pool, sizeof(void *) + slot->size);
    if (ptr == NULL) {
        return NULL;
    }

    slot->nalloc++;
    *ptr = slot;
    return ptr + 1;
}

static void
ngx_block_pool_free_list_internal(ngx_block_pool_t *block_pool,
    ngx_block_pool_slot_t *slot, void *head, void *tail)
{
    void  **ptr;
    void  **cur = head;

    while (cur != NULL) {

        ptr = cur - 1;
        cur = ngx_block_pool_free_next(cur);

        if (*ptr != slot) {
            ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
                "ngx_block_pool_free_list: non-matching slot");
            ngx_debug_point();
        }

        ngx_pfree(block_pool->pool, ptr);
    }
}

#endif


ngx_block_pool_t *
ngx_block_pool_create(ngx_pool_t *pool, size_t *sizes, ngx_uint_t count,
    size_t *mem_limit)
{
    size_t                 *sizes_end;
    ngx_block_pool_t       *block_pool;
    ngx_block_pool_slot_t  *cur_slot;

    block_pool = ngx_palloc(pool, sizeof(*block_pool) +
        sizeof(block_pool->slots[0]) * (count - 1));
    if (block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_block_pool_create: alloc failed");
        return NULL;
    }

    block_pool->pool = pool;
    block_pool->count = count;
    block_pool->mem_limit = mem_limit;

    cur_slot = block_pool->slots;
    sizes_end = sizes + count;
    for (; sizes < sizes_end; sizes++, cur_slot++) {

        cur_slot->size = *sizes;
        cur_slot->nalloc = 0;
        cur_slot->used = 0;

        ngx_block_pool_init_slot(cur_slot);
    }

    return block_pool;
}

void *
ngx_block_pool_alloc(ngx_block_pool_t *block_pool, ngx_uint_t index)
{
    ngx_block_pool_slot_t  *slot;

    if (index >= block_pool->count) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_alloc: invalid index %ui", index);
        return NULL;
    }

    slot = &block_pool->slots[index];
    return ngx_block_pool_alloc_internal(block_pool, slot);
}

void *
ngx_block_pool_calloc(ngx_block_pool_t *block_pool, ngx_uint_t index)
{
    void  *ptr;

    ptr = ngx_block_pool_alloc(block_pool, index);
    if (ptr == NULL) {
        return NULL;
    }

    ngx_memzero(ptr, block_pool->slots[index].size);
    return ptr;
}

void
ngx_block_pool_free(ngx_block_pool_t *block_pool, ngx_uint_t index, void *ptr)
{
    ngx_block_pool_free_next(ptr) = NULL;

    ngx_block_pool_free_list(block_pool, index, ptr, ptr);
}

void
ngx_block_pool_free_list(ngx_block_pool_t *block_pool, ngx_uint_t index,
    void *head, void *tail)
{
#if (NGX_DEBUG)
    u_char                 *cur;
#endif
    ngx_block_pool_slot_t  *slot;

    if (index >= block_pool->count) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_free_list: invalid index %ui", index);
        return;
    }

    slot = &block_pool->slots[index];

#if (NGX_DEBUG)
    for (cur = head; cur != NULL; cur = ngx_block_pool_free_next(cur)) {
        memset((void **) cur + 1, 0xBD, slot->size - sizeof(void *));
    }
#endif

    ngx_block_pool_free_list_internal(block_pool, slot, head, tail);
}

size_t
ngx_block_pool_get_size(ngx_block_pool_t *block_pool, ngx_uint_t index)
{
    ngx_block_pool_slot_t  *slot;

    if (index >= block_pool->count) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_free_list: invalid index %ui", index);
        return 0;
    }

    slot = &block_pool->slots[index];

    return slot->size;
}


void *
ngx_block_pool_auto_alloc(ngx_block_pool_t *block_pool, size_t size,
    ngx_uint_t min_index, ngx_uint_t max_index)
{
    ngx_uint_t                     index;
    ngx_block_pool_slot_t         *slot;
    ngx_block_pool_auto_header_t  *ptr;

    if (!max_index) {
        max_index = block_pool->count;
    }

    /* TODO: consider changing the implementation to binary search,
        if the number of configured sizes will grow */

    size += sizeof(*ptr);
    for (index = min_index; ; index++) {
        if (index >= max_index) {
            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_alloc_auto: no slot found matching size %uz",
                size);
            return NULL;
        }

        slot = &block_pool->slots[index];
        if (size <= slot->size) {
            break;
        }
    }

    ptr = ngx_block_pool_alloc_internal(block_pool, slot);
    if (ptr == NULL) {
        return NULL;
    }

    slot->used += size;
    ptr->slot = index;
    return ptr + 1;
}

void
ngx_block_pool_auto_free(ngx_block_pool_t *block_pool, void *ptr)
{
    ngx_block_pool_auto_header_t  *p;

    p = (ngx_block_pool_auto_header_t *) ptr - 1;

    ngx_block_pool_free(block_pool, p->slot, p);
}

size_t
ngx_block_pool_auto_json_get_size(ngx_block_pool_t *block_pool,
    ngx_uint_t min_index, ngx_uint_t max_index)
{
    size_t  slot_size;

    if (!max_index) {
        max_index = block_pool->count;
    }

    slot_size = sizeof("{\"size\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"nalloc\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"used\":") - 1 + NGX_SIZE_T_LEN +
        sizeof("}") - 1;

    return sizeof("[]") - 1 +
        (max_index - min_index) * (slot_size + sizeof(",") - 1);
}

u_char *
ngx_block_pool_auto_json_write(u_char *p, ngx_block_pool_t *block_pool,
    ngx_uint_t min_index, ngx_uint_t max_index)
{
    ngx_flag_t              comma;
    ngx_block_pool_slot_t  *cur, *end;

    if (!max_index) {
        max_index = block_pool->count;
    }

    *p++ = '[';

    comma = 0;
    end = &block_pool->slots[max_index];

    for (cur = &block_pool->slots[min_index]; cur < end; cur++) {
        if (comma) {
            *p++ = ',';
        } else {
            comma = 1;
        }

        p = ngx_copy_fix(p, "{\"size\":");
        p = ngx_sprintf(p, "%uz", cur->size -
            sizeof(ngx_block_pool_auto_header_t));
        p = ngx_copy_fix(p, ",\"nalloc\":");
        p = ngx_sprintf(p, "%ui", cur->nalloc);
        p = ngx_copy_fix(p, ",\"used\":");
        p = ngx_sprintf(p, "%uz", cur->used);
        *p++ = '}';
    }

    *p++ = ']';

    return p;
}
