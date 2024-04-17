
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_bitop.h"


//ngx_log_debug increase buffer, e.g.:
//sed -i 's/#define NGX_MAX_ERROR_STR   2048/#define NGX_MAX_ERROR_STR   1024*1024/' ./src/core/ngx_log.h
void
ngx_rtmp_hex_dump(ngx_log_t *log, const char * tag, u_char * start, u_char * end)
{
    u_char buf[1024*1024], *p, *pp;
    u_char hex[] = "0123456789abcdef";

    for (pp = buf, p = start;
         p < end && pp < buf + sizeof(buf) - 1;
         ++p)
    {
        *pp++ = hex[*p >> 4];
        *pp++ = hex[*p & 0x0f];
        *pp++ = ' ';
    }

    *pp = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0, "[hex][%s][%s] ", tag, buf);
}



void
ngx_rtmp_bit_init_reader(ngx_rtmp_bit_reader_t *br, u_char *pos, u_char *last)
{
    ngx_memzero(br, sizeof(ngx_rtmp_bit_reader_t));

    br->pos = pos;
    br->last = last;
}


uint64_t
ngx_rtmp_bit_read(ngx_rtmp_bit_reader_t *br, ngx_uint_t n)
{
    uint64_t    v;
    ngx_uint_t  d;

    v = 0;

    while (n) {

        if (br->pos >= br->last) {
            br->err = 1;
            return 0;
        }

        d = (br->offs + n > 8 ? (ngx_uint_t) (8 - br->offs) : n);

        v <<= d;
        v += (*br->pos >> (8 - br->offs - d)) & ((u_char) 0xff >> (8 - d));

        br->offs += d;
        n -= d;

        if (br->offs == 8) {
            br->pos++;
            br->offs = 0;
        }
    }

    return v;
}


uint64_t
ngx_rtmp_bit_read_golomb(ngx_rtmp_bit_reader_t *br)
{
    ngx_uint_t  n;

    for (n = 0; ngx_rtmp_bit_read(br, 1) == 0 && !br->err; n++);

    return ((uint64_t) 1 << n) + ngx_rtmp_bit_read(br, n) - 1;
}


int64_t
ngx_rtmp_bit_read_golomb_signed(ngx_rtmp_bit_reader_t *br)
{
    int64_t  value;

    value = ngx_rtmp_bit_read_golomb(br);
    if (value > 0) {
        if (value & 1) {        /* positive */
            value = (value + 1) / 2;

        } else {
            value = -(value / 2);
        }
    }

    return value;
}
