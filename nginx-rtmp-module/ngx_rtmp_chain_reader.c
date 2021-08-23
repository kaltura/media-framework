#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_chain_reader.h"


void
ngx_rtmp_chain_reader_init(ngx_rtmp_chain_reader_t *reader, ngx_chain_t *in)
{
    reader->cl = in;
    reader->buf = in->buf;
    reader->pos = reader->buf->pos;
}

ngx_int_t
ngx_rtmp_chain_reader_read(ngx_rtmp_chain_reader_t *reader, void *dst,
    size_t size)
{
    size_t  left;

    for ( ;; ) {
        left = reader->buf->last - reader->pos;

        if (left >= size) {
            ngx_memcpy(dst, reader->pos, size);
            reader->pos += size;
            return NGX_OK;
        }

        if (reader->cl->next == NULL) {
            return NGX_ERROR;
        }

        dst = ngx_copy(dst, reader->pos, left);
        size -= left;

        reader->cl = reader->cl->next;
        reader->buf = reader->cl->buf;
        reader->pos = reader->buf->pos;
    }
}

ngx_int_t
ngx_rtmp_chain_reader_skip(ngx_rtmp_chain_reader_t *reader, size_t size)
{
    size_t  left;

    for ( ;; ) {
        left = reader->buf->last - reader->pos;

        if (left >= size) {
            reader->pos += size;
            return NGX_OK;
        }

        if (reader->cl->next == NULL) {
            return NGX_ERROR;
        }

        size -= left;

        reader->cl = reader->cl->next;
        reader->buf = reader->cl->buf;
        reader->pos = reader->buf->pos;
    }
}


void
ngx_rtmp_chain_reader_ep_init(ngx_rtmp_chain_reader_ep_t *reader,
    ngx_rtmp_chain_reader_t *src)
{
    reader->base = *src;
    reader->last_three = 1;
}

ngx_int_t
ngx_rtmp_chain_reader_ep_read(ngx_rtmp_chain_reader_ep_t *reader,
    u_char *dst, size_t size)
{
    u_char   b;
    u_char  *dst_end;

    if (size > reader->left) {
        return NGX_ERROR;
    }
    reader->left -= size;

    dst_end = dst + size;
    while (dst < dst_end) {

        for ( ;; ) {

            if (reader->base.pos < reader->base.buf->last) {
                b = *reader->base.pos++;
                break;
            }

            if (reader->base.cl->next == NULL) {
                return NGX_ERROR;
            }

            reader->base.cl = reader->base.cl->next;
            reader->base.buf = reader->base.cl->buf;
            reader->base.pos = reader->base.buf->pos;
        }

        reader->last_three = ((reader->last_three << 8) | b) & 0xffffff;
        if (reader->last_three == 3) {
            if (reader->left <= 0) {
                return NGX_ERROR;
            }
            reader->left--;
            continue;
        }

        *dst++ = b;
    }

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_chain_reader_ep_skip(ngx_rtmp_chain_reader_ep_t *reader, size_t size)
{
    u_char  b;

    if (size > reader->left) {
        return NGX_ERROR;
    }
    reader->left -= size;

    while (size > 0) {

        for ( ;; ) {

            if (reader->base.pos < reader->base.buf->last) {
                b = *reader->base.pos++;
                break;
            }

            if (reader->base.cl->next == NULL) {
                return NGX_ERROR;
            }

            reader->base.cl = reader->base.cl->next;
            reader->base.buf = reader->base.cl->buf;
            reader->base.pos = reader->base.buf->pos;
        }


        reader->last_three = ((reader->last_three << 8) | b) & 0xffffff;
        if (reader->last_three == 3) {
            if (reader->left <= 0) {
                return NGX_ERROR;
            }
            reader->left--;
            continue;
        }

        size--;
    }

    return NGX_OK;
}
