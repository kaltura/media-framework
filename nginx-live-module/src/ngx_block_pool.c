#include <ngx_config.h>
#include <ngx_core.h>
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
                "ngx_block_pool_validate: "
                "free tail mismatch, size: %uz", cur->size);
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
    if ((size_t) (slot->end - ptr) < slot->size) {

        if (*block_pool->mem_limit < slot->alloc) {
            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_alloc_internal: "
                "memory limit exceeded, size: %uz", slot->size);
            return NULL;
        }

        ptr = ngx_palloc(block_pool->pool, slot->alloc);
        if (ptr == NULL) {
            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_alloc_internal: "
                "alloc failed, size: %uz", slot->size);
            return NULL;
        }

        slot->end = ptr + slot->alloc;
        slot->total_size += slot->alloc;
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

    *block_pool->mem_limit -= slot->size;

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
                "ngx_block_pool_free_list_internal: non-matching slot");
            ngx_debug_point();
        }

        ngx_pfree(block_pool->pool, ptr);

        *block_pool->mem_limit += slot->size;
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
            "ngx_block_pool_create: alloc failed, count: %ui", count);
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
        cur_slot->total_size = 0;

        cur_slot->auto_used = 0;
        cur_slot->auto_nalloc = 0;

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
    if (ngx_block_pool_free_next(tail) != NULL) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_free_list: tail does not point to null");
        ngx_debug_point();
    }

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
            "ngx_block_pool_get_size: invalid index %ui", index);
        return 0;
    }

    slot = &block_pool->slots[index];

    return slot->size;
}


void *
ngx_block_pool_auto_alloc(ngx_block_pool_t *block_pool, size_t size)
{
    ngx_int_t                      left, right, index;
    ngx_block_pool_slot_t         *slot;
    ngx_block_pool_auto_header_t  *ptr;

    size += sizeof(*ptr);

    left = 0;
    right = block_pool->count - 1;
    for ( ;; ) {

        if (left > right) {
            if ((ngx_uint_t) left < block_pool->count) {
                index = left;
                slot = &block_pool->slots[index];
                break;
            }

            ngx_log_error(NGX_LOG_ERR, block_pool->pool->log, 0,
                "ngx_block_pool_auto_alloc: "
                "no matching slot found, size: %uz", size);
            return NULL;
        }

        index = (left + right) / 2;
        slot = &block_pool->slots[index];
        if (slot->size < size) {
            left = index + 1;

        } else if (slot->size > size) {
            right = index - 1;

        } else {
            break;
        }
    }

#if (NGX_DEBUG)
    if (slot->size < size) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_auto_alloc: "
            "invalid slot selected, size: %uz, slot: %uz",
            size, slot->size);
        ngx_debug_point();
    }

    if (slot > block_pool->slots && slot[-1].size >= size) {
        ngx_log_error(NGX_LOG_ALERT, block_pool->pool->log, 0,
            "ngx_block_pool_auto_alloc: "
            "invalid slot selected, size: %uz, slot: %uz, prev: %uz",
            size, slot->size, slot[-1].size);
        ngx_debug_point();
    }
#endif

    ptr = ngx_block_pool_alloc_internal(block_pool, slot);
    if (ptr == NULL) {
        return NULL;
    }

    slot->auto_used += size;
    slot->auto_nalloc++;
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
ngx_block_pool_json_get_size(ngx_block_pool_t *block_pool)
{
    size_t  slot_size;

    slot_size = sizeof("{\"block_size\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"nalloc\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"size\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"auto_used\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"auto_nalloc\":") - 1 + NGX_INT64_LEN +
        sizeof("}") - 1;

    return sizeof("[]") - 1 +
        block_pool->count * (slot_size + sizeof(",") - 1);
}


u_char *
ngx_block_pool_json_write(u_char *p, ngx_block_pool_t *block_pool)
{
    ngx_flag_t              comma;
    ngx_block_pool_slot_t  *cur, *end;

    *p++ = '[';

    comma = 0;
    end = &block_pool->slots[block_pool->count];

    for (cur = block_pool->slots; cur < end; cur++) {

        if (comma) {
            *p++ = ',';

        } else {
            comma = 1;
        }

        p = ngx_copy_fix(p, "{\"block_size\":");
        p = ngx_sprintf(p, "%uz", cur->size);
        p = ngx_copy_fix(p, ",\"nalloc\":");
        p = ngx_sprintf(p, "%ui", cur->nalloc);
        p = ngx_copy_fix(p, ",\"size\":");
        p = ngx_sprintf(p, "%uz", cur->total_size);
        p = ngx_copy_fix(p, ",\"auto_used\":");
        p = ngx_sprintf(p, "%uz", cur->auto_used);
        p = ngx_copy_fix(p, ",\"auto_nalloc\":");
        p = ngx_sprintf(p, "%ui", cur->auto_nalloc);
        *p++ = '}';
    }

    *p++ = ']';

    return p;
}
