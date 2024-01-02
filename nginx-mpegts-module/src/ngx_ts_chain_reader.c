#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_ts_chain_reader.h"


void
ngx_ts_chain_reader_init(ngx_ts_chain_reader_t *reader, ngx_chain_t *in)
{
    reader->cl = in;
    reader->buf = in->buf;
    reader->pos = reader->buf->pos;
}


ngx_int_t
ngx_ts_chain_reader_read(ngx_ts_chain_reader_t *reader, void *dst, size_t size)
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
ngx_ts_chain_reader_skip(ngx_ts_chain_reader_t *reader, size_t size)
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
