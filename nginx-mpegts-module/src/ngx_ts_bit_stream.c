#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_ts_bit_stream.h"


void
ngx_ts_bit_stream_init(ngx_ts_bit_stream_t *bs, u_char *buf, size_t len)
{
    ngx_memzero(bs, sizeof(ngx_ts_bit_stream_t));

    bs->pos = buf;
    bs->last = buf + len;
    bs->bits_left = 8;
}


uint32_t
ngx_ts_bit_stream_read_one(ngx_ts_bit_stream_t *bs)
{
    uint32_t  v;

    if (bs->err) {
        return 0;
    }

    if (bs->pos >= bs->last) {
        bs->err = 1;
        return 0;
    }

    bs->bits_left--;
    v = (*bs->pos >> bs->bits_left) & 0x01;

    if (bs->bits_left <= 0) {
        bs->pos++;
        bs->bits_left = 8;
    }

    return v;
}


uint64_t
ngx_ts_bit_stream_read(ngx_ts_bit_stream_t *bs, ngx_uint_t bits)
{
    uint64_t    cv;
    uint64_t    v;
    ngx_uint_t  k, n;

    if (bs->err) {
        return 0;
    }

    v = 0;
    n = bits;

    while (n) {
        if (bs->pos >= bs->last) {
            bs->err = 1;
            break;
        }

        k = ngx_min(bs->bits_left, n);

        n -= k;

        /*
        * v:
        * [-------------|||||||||--------------]
        *                   k          n
        */

        bs->bits_left -= k;
        cv = (*bs->pos >> bs->bits_left) & (0xff >> (8 - k));

        v |= cv << n;

        if (bs->bits_left > 0) {
            break;
        }

        bs->pos++;
        bs->bits_left = 8;
    }

    return v;
}


void
ngx_ts_bit_stream_write_one(ngx_ts_bit_stream_t *bs, uint32_t v)
{
    if (bs->err) {
        return;
    }

    if (bs->pos >= bs->last) {
        bs->err = 1;
        return;
    }

    bs->bits_left--;
    *bs->pos |= (v & 0x01) << bs->bits_left;

    if (bs->bits_left <= 0) {
        bs->pos++;
        bs->bits_left = 8;
    }
}


void
ngx_ts_bit_stream_write(ngx_ts_bit_stream_t *bs, ngx_uint_t bits, uint64_t v)
{
    u_char      cv;
    ngx_uint_t  k, n;

    if (bs->err) {
        return;
    }

    n = bits;

    while (n) {
        if (bs->pos >= bs->last) {
            bs->err = 1;
            break;
        }

        k = ngx_min(bs->bits_left, n);

        n -= k;

        /*
        * v:
        * [-------------|||||||||--------------]
        *                   k          n
        */

        cv = (v >> n) & (0xff >> (8 - k));

        bs->bits_left -= k;
        *bs->pos |= cv << bs->bits_left;

        if (bs->bits_left > 0) {
            break;
        }

        bs->pos++;
        bs->bits_left = 8;
    }
}
