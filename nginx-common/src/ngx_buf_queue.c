#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_queue.h"


ngx_int_t
ngx_buf_queue_init(ngx_buf_queue_t *buf_queue, ngx_log_t *log,
    ngx_lba_t *lba, ngx_uint_t max_free_buffers, size_t *mem_left)
{
    size_t  buffer_size = ngx_lba_buf_size(lba);

    if (buffer_size <= sizeof(ngx_buf_queue_node_t)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_buf_queue_init: buffer size %uz too small", buffer_size);
        return NGX_ERROR;
    }

    buf_queue->log = log;
    buf_queue->lba = lba;
    buf_queue->alloc_size = buffer_size;
    buf_queue->used_size = buffer_size - sizeof(ngx_buf_queue_node_t);
    buf_queue->used_head = NULL;
    buf_queue->used_tail = &buf_queue->used_head;
    buf_queue->free = NULL;
    buf_queue->free_left = max_free_buffers;
    buf_queue->mem_left = mem_left;
    buf_queue->nbuffers = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, buf_queue->log, 0,
        "ngx_buf_queue_init: %p called", buf_queue);

    return NGX_OK;
}


void
ngx_buf_queue_delete(ngx_buf_queue_t *buf_queue)
{
    ngx_buf_queue_node_t  *node;
    ngx_buf_queue_node_t  *next;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, buf_queue->log, 0,
        "ngx_buf_queue_delete: %p called", buf_queue);

    for (node = buf_queue->free; node != NULL; node = next) {
        next = ngx_buf_queue_next(node);
        ngx_lba_free(buf_queue->lba, node);
        buf_queue->free_left++;
    }

    buf_queue->free = NULL;

    for (node = ngx_buf_queue_head(buf_queue); node != NULL; node = next) {
        next = ngx_buf_queue_next(node);
        ngx_lba_free(buf_queue->lba, node);
    }

    buf_queue->used_head = NULL;
    buf_queue->used_tail = &buf_queue->used_head;

    if (buf_queue->mem_left != NULL) {
        *buf_queue->mem_left += buf_queue->alloc_size * buf_queue->nbuffers;
    }

    buf_queue->nbuffers = 0;
}


void
ngx_buf_queue_detach(ngx_buf_queue_t *buf_queue)
{
    buf_queue->log = ngx_cycle->log;
    buf_queue->mem_left = NULL;
}


#if (NGX_DEBUG)
static void
ngx_buf_queue_validate(ngx_buf_queue_t *buf_queue)
{
    ngx_uint_t              nbuffers;
    ngx_buf_queue_node_t   *node;
    ngx_buf_queue_node_t  **next;


    nbuffers = 0;

    if (ngx_buf_queue_head(buf_queue) != NULL) {

        for (node = ngx_buf_queue_head(buf_queue);; node = *next)
        {
            nbuffers++;

            next = &node->next;
            if (*next != NULL) {
                continue;
            }

            if (buf_queue->used_tail != next) {
                ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
                    "ngx_buf_queue_validate: used tail doesn't match actual");
                ngx_debug_point();
            }

            break;
        }

    } else if (buf_queue->used_tail != &buf_queue->used_head) {
        ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
            "ngx_buf_queue_validate: "
            "used tail not pointing to head when empty");
        ngx_debug_point();
    }

    for (node = buf_queue->free;
        node != NULL;
        node = ngx_buf_queue_next(node))
    {
        nbuffers++;
    }

    if (buf_queue->nbuffers != nbuffers) {
        ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
            "ngx_buf_queue_validate: nbuffers %ui doesn't match actual %ui",
            buf_queue->nbuffers, nbuffers);
        ngx_debug_point();
    }
}
#else
#define ngx_buf_queue_validate(buf_queue)
#endif


u_char *
ngx_buf_queue_get(ngx_buf_queue_t *buf_queue)
{
    ngx_buf_queue_node_t  *result;

    if (buf_queue->free != NULL) {
        result = buf_queue->free;
        buf_queue->free = result->next;
        buf_queue->free_left++;

    } else {

        if (*buf_queue->mem_left < buf_queue->alloc_size) {
            ngx_log_error(NGX_LOG_ERR, buf_queue->log, 0,
                "ngx_buf_queue_get: memory limit exceeded");
            return NULL;
        }

        result = ngx_lba_alloc(buf_queue->lba);
        if (result == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, buf_queue->log, 0,
                "ngx_buf_queue_get: alloc failed");
            return NULL;
        }

        *buf_queue->mem_left -= buf_queue->alloc_size;
        buf_queue->nbuffers++;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, buf_queue->log, 0,
        "ngx_buf_queue_get: %p allocating %p", buf_queue, result);

    *buf_queue->used_tail = result;
    buf_queue->used_tail = &result->next;

    result->next = NULL;

    ngx_buf_queue_validate(buf_queue);

    return ngx_buf_queue_start(result);
}


void
ngx_buf_queue_free(ngx_buf_queue_t *buf_queue, u_char *limit)
{
    ngx_buf_queue_node_t  *next;
    ngx_buf_queue_node_t  *cur;

#if (NGX_DEBUG)
    /* Validating 'limit' is in the queue before making any changes,
        makes it somewhat easier to debug if it's not */
    for (cur = ngx_buf_queue_head(buf_queue); ;
        cur = ngx_buf_queue_next(cur))
    {
        if (cur == NULL) {
            ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
                "ngx_buf_queue_free: limit %p not found in queue", limit);
            ngx_debug_point();
            break;
        }

        if (limit >= ngx_buf_queue_start(cur) &&
            limit < ngx_buf_queue_end(buf_queue, cur))
        {
            break;
        }
    }
#endif

    cur = ngx_buf_queue_head(buf_queue);
    if (cur == NULL) {
        ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
            "ngx_buf_queue_free: called when empty");
        ngx_debug_point();
        return;
    }

    for ( ;; ) {

        if (limit >= ngx_buf_queue_start(cur) &&
            limit < ngx_buf_queue_end(buf_queue, cur))
        {
            break;  /* the buffer contains the given ptr, stop */
        }

        next = ngx_buf_queue_next(cur);
        if (next == NULL) {
            ngx_log_error(NGX_LOG_ALERT, buf_queue->log, 0,
                "ngx_buf_queue_free: limit %p not found in queue", limit);
            ngx_debug_point();
            break;  /* don't free the last buffer, may be used for reading */
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, buf_queue->log, 0,
            "ngx_buf_queue_free: %p freeing %p", buf_queue, cur);

        if (buf_queue->free_left <= 0) {
            ngx_lba_free(buf_queue->lba, cur);
            if (buf_queue->mem_left != NULL) {
                *buf_queue->mem_left += buf_queue->alloc_size;
            }

            buf_queue->nbuffers--;

        } else {

            cur->next = buf_queue->free;
            buf_queue->free = cur;
            buf_queue->free_left--;
        }

        cur = next;
    }

    buf_queue->used_head = cur;

    ngx_buf_queue_validate(buf_queue);
}
