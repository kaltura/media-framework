#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include "ngx_buf_queue_stream.h"


/* Note: the reader must ensure the 'pos' pointer is within a node (=not at
    the end of a node). this is required so that it would be safe to call
    ngx_buf_queue_free with the 'pos' pointer.
    an implication of this is that it's not possible to read until the end -
    another buffer must always be allocated. */

void
ngx_buf_queue_stream_init(ngx_buf_queue_stream_t *stream,
    ngx_buf_queue_t *buf_queue)
{
    stream->buf_queue = buf_queue;
    stream->node = ngx_buf_queue_head(buf_queue);
    stream->pos = ngx_buf_queue_start(stream->node);
}


void
ngx_buf_queue_stream_init_tail(ngx_buf_queue_stream_t *stream,
    ngx_buf_queue_t *buf_queue, u_char *pos)
{
    stream->buf_queue = buf_queue;
    stream->node = ngx_buf_queue_tail(buf_queue);
    stream->pos = pos;
}


ngx_int_t
ngx_buf_queue_stream_md5(ngx_buf_queue_stream_t *stream, size_t size,
    u_char result[16])
{
    u_char                *pos;
    u_char                *end;
    size_t                 chunk;
    ngx_md5_t              md5;
    ngx_buf_queue_node_t  *node;

    node = stream->node;
    pos = stream->pos;
    end = ngx_buf_queue_end(stream->buf_queue, node);

    ngx_md5_init(&md5);

    while (size > 0) {
        chunk = end - pos;
        if (chunk > size) {
            chunk = size;
        }

        ngx_md5_update(&md5, pos, chunk);
        pos += chunk;
        size -= chunk;

        if (pos >= end) {
            node = ngx_buf_queue_next(node);
            if (node == NULL) {
                return NGX_ERROR;
            }

            stream->node = node;

            pos = ngx_buf_queue_start(node);
            end = ngx_buf_queue_end(stream->buf_queue, node);
        }
    }

    ngx_md5_final(result, &md5);

    stream->pos = pos;

    return NGX_OK;
}


void *
ngx_buf_queue_stream_write(ngx_buf_queue_stream_t *stream, void *buffer,
    size_t size)
{
    u_char                *pos;
    u_char                *end;
    u_char                *p;
    size_t                 chunk;
    ngx_buf_queue_node_t  *node;

    node = stream->node;
    pos = stream->pos;
    end = ngx_buf_queue_end(stream->buf_queue, node);
    p = buffer;

    while (size > 0) {
        chunk = end - pos;
        if (chunk > size) {
            chunk = size;
        }

        pos = ngx_copy(pos, p, chunk);
        p += chunk;
        size -= chunk;

        if (pos >= end) {
            node = ngx_buf_queue_next(node);
            if (node == NULL) {
                return NULL;
            }

            stream->node = node;

            pos = ngx_buf_queue_start(node);
            end = ngx_buf_queue_end(stream->buf_queue, node);
        }
    }

    stream->pos = pos;

    return buffer;
}


void *
ngx_buf_queue_stream_read(ngx_buf_queue_stream_t *stream, void *buffer,
    size_t size)
{
    u_char                *pos;
    u_char                *end;
    u_char                *p;
    size_t                 chunk;
    ngx_buf_queue_node_t  *node;

    node = stream->node;
    pos = stream->pos;
    end = ngx_buf_queue_end(stream->buf_queue, node);
    p = buffer;

    while (size > 0) {
        chunk = end - pos;
        if (chunk > size) {
            chunk = size;
        }

        p = ngx_copy(p, pos, chunk);
        pos += chunk;
        size -= chunk;

        if (pos >= end) {
            node = ngx_buf_queue_next(node);
            if (node == NULL) {
                return NULL;
            }

            stream->node = node;

            pos = ngx_buf_queue_start(node);
            end = ngx_buf_queue_end(stream->buf_queue, node);
        }
    }

    stream->pos = pos;

    return buffer;
}


ngx_int_t
ngx_buf_queue_stream_skip(ngx_buf_queue_stream_t *stream, size_t size)
{
    u_char                *pos;
    u_char                *end;
    ngx_buf_queue_node_t  *node;

    node = stream->node;
    pos = stream->pos;
    end = ngx_buf_queue_end(stream->buf_queue, node);

    for ( ;; ) {
        if (size < (size_t) (end - pos)) {
            stream->pos = pos + size;
            return NGX_OK;
        }

        size -= end - pos;

        node = ngx_buf_queue_next(node);
        if (node == NULL) {
            return NGX_ERROR;
        }

        pos = ngx_buf_queue_start(node);
        end = ngx_buf_queue_end(stream->buf_queue, node);
        stream->node = node;
    }
}
