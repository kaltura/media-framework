#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_queue.h"

ngx_int_t
ngx_buf_queue_init(ngx_buf_queue_t *buf_queue, ngx_log_t *log,
    size_t buffer_size, ngx_uint_t max_free_buffers, size_t *memory_limit)
{
    if (buffer_size <= sizeof(ngx_buf_queue_node_t)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_buf_queue_init: buffer size %uz too small", buffer_size);
        return NGX_ERROR;
    }

    buf_queue->log = log;
    buf_queue->alloc_size = buffer_size;
    buf_queue->used_size = buffer_size - sizeof(ngx_buf_queue_node_t);
    buf_queue->used_head = NULL;
    buf_queue->used_tail = &buf_queue->used_head;
    buf_queue->free = NULL;
    buf_queue->free_left = max_free_buffers;
    buf_queue->memory_limit = memory_limit;
    return NGX_OK;
}

void
ngx_buf_queue_delete(ngx_buf_queue_t *buf_queue)
{
    ngx_buf_queue_node_t  *node;
    ngx_buf_queue_node_t  *next;

    // Note: not bothering to update memory_limit in this case

    for (node = buf_queue->free; node != NULL; node = next) {
        next = ngx_buf_queue_next(node);
        ngx_free(node);
    }
    buf_queue->free = NULL;

    for (node = ngx_buf_queue_head(buf_queue); node != NULL; node = next) {
        next = ngx_buf_queue_next(node);
        ngx_free(node);
    }
    buf_queue->used_head = NULL;
}

u_char*
ngx_buf_queue_get(ngx_buf_queue_t *buf_queue)
{
    ngx_buf_queue_node_t  *result;

    if (buf_queue->free != NULL) {
        result = buf_queue->free;
        buf_queue->free = result->next;
        buf_queue->free_left++;

    } else {
        if (*buf_queue->memory_limit < buf_queue->alloc_size) {
            ngx_log_error(NGX_LOG_ERR, buf_queue->log, 0,
                "ngx_buf_queue_get: memory limit exceeded");
            return NULL;
        }

        result = ngx_alloc(buf_queue->alloc_size, buf_queue->log);
        if (result == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, buf_queue->log, 0,
                "ngx_buf_queue_get: alloc failed");
            return NULL;
        }

        *buf_queue->memory_limit -= buf_queue->alloc_size;
    }

    *buf_queue->used_tail = result;
    buf_queue->used_tail = &result->next;

    result->next = NULL;
    return ngx_buf_queue_start(result);
}

void
ngx_buf_queue_free(ngx_buf_queue_t *buf_queue, u_char *limit)
{
    ngx_buf_queue_node_t  *next;
    ngx_buf_queue_node_t  *cur;

    for (cur = ngx_buf_queue_head(buf_queue); cur != NULL; cur = next) {

        if (limit >= ngx_buf_queue_start(cur) &&
            limit < ngx_buf_queue_end(buf_queue, cur)) {
            break;      // the buffer contains the given ptr, stop
        }

        next = ngx_buf_queue_next(cur);
        if (next == NULL) {
            break;      // don't free the last buffer, may be used for reading
        }

        if (buf_queue->free_left <= 0) {
            ngx_free(cur);
            *buf_queue->memory_limit += buf_queue->alloc_size;
            continue;
        }

        cur->next = buf_queue->free;
        buf_queue->free = cur;
        buf_queue->free_left--;
    }

    buf_queue->used_head = cur;
}
