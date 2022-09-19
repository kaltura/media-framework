#include "ngx_buf_chain_reader.h"


ngx_int_t
ngx_buf_chain_reader_read(ngx_buf_chain_t *reader, void *dst, size_t size)
{
    size_t  left;

    for ( ;; ) {
        left = reader->size;

        if (left >= size) {
            ngx_memcpy(dst, reader->data, size);
            reader->data += size;
            reader->size -= size;
            return NGX_OK;
        }

        if (reader->next == NULL) {
            return NGX_ERROR;
        }

        dst = ngx_copy(dst, reader->data, left);
        size -= left;

        *reader = *reader->next;
    }
}


ngx_int_t
ngx_buf_chain_reader_skip(ngx_buf_chain_t *reader, size_t size)
{
    size_t  left;

    for ( ;; ) {
        left = reader->size;

        if (left >= size) {
            reader->data += size;
            reader->size -= size;
            return NGX_OK;
        }

        if (reader->next == NULL) {
            return NGX_ERROR;
        }

        size -= left;

        *reader = *reader->next;
    }
}


void
ngx_buf_chain_reader_ep_init(ngx_buf_chain_reader_ep_t *reader,
    ngx_buf_chain_t *src)
{
    reader->base = *src;
    reader->last_three = 1;
}


ngx_int_t
ngx_buf_chain_reader_ep_read(ngx_buf_chain_reader_ep_t *reader,
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

            if (reader->base.size > 0) {
                b = *reader->base.data++;
                reader->base.size--;
                break;
            }

            if (reader->base.next == NULL) {
                return NGX_ERROR;
            }

            reader->base = *reader->base.next;
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
ngx_buf_chain_reader_ep_skip(ngx_buf_chain_reader_ep_t *reader, size_t size)
{
    u_char  b;

    if (size > reader->left) {
        return NGX_ERROR;
    }

    reader->left -= size;

    while (size > 0) {

        for ( ;; ) {

            if (reader->base.size > 0) {
                b = *reader->base.data++;
                reader->base.size--;
                break;
            }

            if (reader->base.next == NULL) {
                return NGX_ERROR;
            }

            reader->base = *reader->base.next;
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
