#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include "ngx_buf_queue_reader.h"


/* Note: the reader must ensure the start pointer is within a node (=not at
    the end of a node). this is required so that it would be safe to call
    ngx_buf_queue_free with the start pointer.
    an implication of this is that it's not possible to read until the end -
    another buffer must always be allocated. */

void
ngx_buf_queue_reader_init(ngx_buf_queue_reader_t *reader,
    ngx_buf_queue_t *buf_queue)
{
    reader->buf_queue = buf_queue;
    reader->node = ngx_buf_queue_head(buf_queue);
    reader->start = ngx_buf_queue_start(reader->node);
}


void
ngx_buf_queue_reader_init_tail(ngx_buf_queue_reader_t *reader,
    ngx_buf_queue_t *buf_queue, u_char *pos)
{
    reader->buf_queue = buf_queue;
    reader->node = ngx_buf_queue_tail(buf_queue);
    reader->start = pos;
}


ngx_int_t
ngx_buf_queue_reader_md5(ngx_buf_queue_reader_t *reader, size_t size,
    u_char result[16])
{
    u_char                *start;
    u_char                *end;
    size_t                 chunk;
    ngx_md5_t              md5;
    ngx_buf_queue_node_t  *node;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);

    ngx_md5_init(&md5);

    while (size > 0) {
        chunk = end - start;
        if (chunk > size) {
            chunk = size;
        }

        ngx_md5_update(&md5, start, chunk);
        start += chunk;
        size -= chunk;

        if (start >= end) {
            node = ngx_buf_queue_next(node);
            if (node == NULL) {
                return NGX_ERROR;
            }

            reader->node = node;

            start = ngx_buf_queue_start(node);
            end = ngx_buf_queue_end(reader->buf_queue, node);
        }
    }

    ngx_md5_final(result, &md5);

    reader->start = start;

    return NGX_OK;
}


void *
ngx_buf_queue_reader_write(ngx_buf_queue_reader_t *reader, void *buffer,
    size_t size)
{
    u_char                *start;
    u_char                *end;
    u_char                *p;
    size_t                 chunk;
    ngx_buf_queue_node_t  *node;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);
    p = buffer;

    while (size > 0) {
        chunk = end - start;
        if (chunk > size) {
            chunk = size;
        }

        start = ngx_copy(start, p, chunk);
        p += chunk;
        size -= chunk;

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
ngx_buf_queue_reader_copy(ngx_buf_queue_reader_t *reader, void *buffer,
    size_t size)
{
    u_char                *start;
    u_char                *end;
    u_char                *p;
    size_t                 chunk;
    ngx_buf_queue_node_t  *node;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);
    p = buffer;

    while (size > 0) {
        chunk = end - start;
        if (chunk > size) {
            chunk = size;
        }

        p = ngx_copy(p, start, chunk);
        start += chunk;
        size -= chunk;

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


ngx_int_t
ngx_buf_queue_reader_skip(ngx_buf_queue_reader_t *reader, size_t size)
{
    u_char                *start;
    u_char                *end;
    ngx_buf_queue_node_t  *node;

    node = reader->node;
    start = reader->start;
    end = ngx_buf_queue_end(reader->buf_queue, node);

    for ( ;; ) {
        if (size < (size_t) (end - start)) {
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
