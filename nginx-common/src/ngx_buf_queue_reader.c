#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_queue_reader.h"

void
ngx_buf_queue_reader_init(ngx_buf_queue_reader_t *reader,
    ngx_buf_queue_t *buf_queue)
{
    reader->buf_queue = buf_queue;
    reader->node = ngx_buf_queue_head(buf_queue);
    reader->start = ngx_buf_queue_start(reader->node);
}

void *
ngx_buf_queue_reader_copy(ngx_buf_queue_reader_t *reader, void *buffer,
    size_t size)
{
    ngx_buf_queue_node_t  *node;
    u_char                *start;
    u_char                *end;
    u_char                *p;
    size_t                 copy;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);
    p = buffer;

    while (size > 0) {
        copy = ngx_min(size, (size_t)(end - start));
        p = ngx_copy(p, start, copy);
        start += copy;
        size -= copy;

        if (start >= end) {
            node = ngx_buf_queue_next(node);
            if (node == NULL) {
                return NULL;
            }
            reader->node = node;

            start = ngx_buf_queue_start(node);
            end = ngx_buf_queue_end(reader->buf_queue, node);
        }
    }

    reader->start = start;

    return buffer;
}

void *
ngx_buf_queue_reader_read(ngx_buf_queue_reader_t *reader, void *buffer,
    size_t size)
{
    ngx_buf_queue_node_t  *node;
    u_char                *start;
    u_char                *end;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);
    if ((size_t)(end - start) >= size) {
        reader->start += size;
        return start;
    }

    return ngx_buf_queue_reader_copy(reader, buffer, size);
}

ngx_int_t
ngx_buf_queue_reader_skip(ngx_buf_queue_reader_t *reader, size_t size)
{
    ngx_buf_queue_node_t  *node;
    u_char                *start;
    u_char                *end;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);

    for (;;) {
        if (size <= (size_t)(end - start)) {
            reader->start = start + size;
            return NGX_OK;
        }

        size -= end - start;

        node = ngx_buf_queue_next(node);
        if (node == NULL) {
            return NGX_ERROR;
        }

        start = ngx_buf_queue_start(node);
        end = ngx_buf_queue_end(reader->buf_queue, node);
        reader->node = node;
    }
}
