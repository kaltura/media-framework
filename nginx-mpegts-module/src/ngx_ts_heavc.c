#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_heavc.h"


typedef struct {
    ngx_chain_t                *cl;
    ngx_buf_t                  *buf;
    u_char                     *pos;
} ngx_ts_avc_chain_reader_t;


typedef struct {
    ngx_ts_avc_chain_reader_t   base;
    uint32_t                    last_three;
    size_t                      left;
} ngx_ts_avc_chain_reader_ep_t;


/* user_data_registered_itu_t_t35 */
static u_char  ngx_ts_avc_cea_header[] = {
    0xb5,    /* itu_t_t35_country_code   */
    0x00,    /* Itu_t_t35_provider_code  */
    0x31,
    0x47,    /* user_identifier ('GA94') */
    0x41,
    0x39,
    0x34,
};


void
ngx_ts_avc_init_reader(ngx_ts_avc_reader_t *br, u_char *buf, size_t len,
    ngx_log_t *log, char *codec)
{
    ngx_memzero(br, sizeof(ngx_ts_avc_reader_t));

    br->pos = buf;
    br->last = buf + len;

    br->log = log;
    br->codec = codec;

    if (len > 0) {
        br->last_three = *buf;
    }
}


static ngx_inline void
ngx_ts_avc_next_byte(ngx_ts_avc_reader_t *br)
{
    for ( ;; ) {
        br->pos++;

        /* decode emulation prevention */
        br->last_three = ((br->last_three << 8) | *br->pos) & 0xffffff;
        if (br->last_three != 3) {
            break;
        }

        if (br->pos >= br->last) {
            br->err = 1;
            break;
        }
    }

    br->shift = 0;
}


uint32_t
ngx_ts_avc_read_one(ngx_ts_avc_reader_t *br)
{
    uint32_t  v;

    if (br->err) {
        return 0;
    }

    if (br->pos >= br->last) {
        br->err = 1;
        return 0;
    }

    v = (*br->pos >> (8 - 1 - br->shift)) & 0x01;

    br->shift++;
    if (br->shift >= 8) {
        ngx_ts_avc_next_byte(br);
    }

    return v;
}


uint64_t
ngx_ts_avc_read(ngx_ts_avc_reader_t *br, ngx_uint_t bits)
{
    uint64_t    v;
    ngx_uint_t  k, n;

    if (br->err) {
        return 0;
    }

    v = 0;
    n = bits;

    while (n) {
        if (br->pos >= br->last) {
            br->err = 1;
            break;
        }

        k = ngx_min(8 - br->shift, n);

        /*
         * [-------------|||||||||--------------]
         *    br->shift      k
         */

        v = (v << k) | (*br->pos & (0xff >> br->shift)) >> (8 - br->shift - k);

        n -= k;
        br->shift += k;

        if (br->shift < 8) {
            break;
        }

        ngx_ts_avc_next_byte(br);
    }

    return v;
}


uint64_t
ngx_ts_avc_read_golomb_unsigned(ngx_ts_avc_reader_t *br)
{
    /*
     * ISO/IEC 14496-10:2004(E)
     * 9.1 Parsing process for Exp-Golomb codes, p. 159
     */

    uint64_t    v;
    ngx_uint_t  n;

    if (br->err) {
        return 0;
    }

    n = 0;

    while (ngx_ts_avc_read_one(br) == 0) {
        if (br->err) {
            return 0;
        }

        n++;
    }

    v = ((uint64_t) 1 << n) - 1 + ngx_ts_avc_read(br, n);

    return v;
}


int64_t
ngx_ts_avc_read_golomb_signed(ngx_ts_avc_reader_t *br)
{
    int64_t  value;

    value = ngx_ts_avc_read_golomb_unsigned(br);
    if (value > 0) {
        if (value & 1) {        /* positive */
            value = (value + 1) / 2;

        } else {
            value = -(value / 2);
        }
    }

    return value;
}


ngx_flag_t
ngx_ts_avc_rbsp_trailing_bits(ngx_ts_avc_reader_t *br)
{
    uint32_t one_bit;

    if (br->err) {
        return 0;
    }

    one_bit = ngx_ts_avc_read_one(br);
    if (one_bit != 1) {
        return 0;
    }

    while (!br->err) {
        if (ngx_ts_avc_read_one(br) != 0) {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_ts_avc_chain_reader_ep_read(ngx_ts_avc_chain_reader_ep_t *reader,
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
ngx_ts_avc_chain_reader_ep_skip(ngx_ts_avc_chain_reader_ep_t *reader,
    size_t size)
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


ngx_flag_t
ngx_ts_avc_sei_detect_cea(ngx_log_t *log, ngx_chain_t *in, u_char *pos,
    size_t size, size_t nal_header_size)
{
    u_char                        b;
    u_char                        buf[sizeof(ngx_ts_avc_cea_header)];
    uint32_t                      payload_type;
    uint32_t                      payload_size;
    ngx_ts_avc_chain_reader_ep_t  payload;
    ngx_ts_avc_chain_reader_ep_t  reader;

    reader.base.cl = in;
    reader.base.buf = in->buf;
    reader.base.pos = pos;
    reader.left = size;
    reader.last_three = 1;

    if (ngx_ts_avc_chain_reader_ep_skip(&reader, nal_header_size) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "ngx_ts_avc_sei_detect_cea: skip nal header failed");
        return 0;
    }

    while (reader.left >= 2 + sizeof(buf)) {

        payload_type = 0;
        do {
            if (ngx_ts_avc_chain_reader_ep_read(&reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "ngx_ts_avc_sei_detect_cea: read payload type failed");
                return 0;
            }

            payload_type += b;
        } while (b == 0xff);

        payload_size = 0;
        do {
            if (ngx_ts_avc_chain_reader_ep_read(&reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "ngx_ts_avc_sei_detect_cea: read payload size failed");
                return 0;
            }

            payload_size += b;
        } while (b == 0xff);

        payload = reader;

        if (ngx_ts_avc_chain_reader_ep_skip(&reader, payload_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "ngx_ts_avc_sei_detect_cea: skip payload failed");
            return 0;
        }

        if (payload_type != 4) {    /* user data registered */
            continue;
        }

        payload.left = payload_size;

        if (ngx_ts_avc_chain_reader_ep_read(&payload, buf, sizeof(buf))
            != NGX_OK)
        {
            continue;
        }

        if (ngx_memcmp(buf, ngx_ts_avc_cea_header, sizeof(buf)) == 0) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                "ngx_ts_avc_sei_detect_cea: cea captions detected");
            return 1;
        }
    }

    return 0;
}
