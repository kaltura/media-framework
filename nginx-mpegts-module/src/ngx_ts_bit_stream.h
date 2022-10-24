#ifndef _NGX_TS_BIT_STREAM_H_INCLUDED_
#define _NGX_TS_BIT_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    u_char      *pos;
    u_char      *last;
    ngx_uint_t   bits_left;
    ngx_uint_t   err;
} ngx_ts_bit_stream_t;


void ngx_ts_bit_stream_init(ngx_ts_bit_stream_t *bs, u_char *buf, size_t len);

uint32_t ngx_ts_bit_stream_read_one(ngx_ts_bit_stream_t *bs);
uint64_t ngx_ts_bit_stream_read(ngx_ts_bit_stream_t *bs, ngx_uint_t bits);

void ngx_ts_bit_stream_write_one(ngx_ts_bit_stream_t *bs, uint32_t v);
void ngx_ts_bit_stream_write(ngx_ts_bit_stream_t *bs, ngx_uint_t bits,
    uint64_t v);


static ngx_inline size_t
ngx_ts_bit_stream_size(ngx_ts_bit_stream_t *bs, u_char *start)
{
    size_t  size;

    size = bs->pos - start;
    if (bs->bits_left < 8) {
        size++;
    }

    return size;
}

#endif /* _NGX_TS_BIT_STREAM_H_INCLUDED_ */
