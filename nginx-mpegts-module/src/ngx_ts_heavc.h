#ifndef _NGX_TS_HEAVC_H_INCLUDED_
#define _NGX_TS_HEAVC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define ngx_ts_heavc_skip_u   ngx_ts_heavc_read_u
#define ngx_ts_heavc_skip_u1  ngx_ts_heavc_read_u1


typedef struct {
    u_char      *pos;
    u_char      *last;
    ngx_uint_t   shift;
    ngx_uint_t   err;
    uint32_t     last_three;
    ngx_log_t   *log;
    char        *codec;
} ngx_ts_heavc_reader_t;


void ngx_ts_heavc_init_reader(ngx_ts_heavc_reader_t *br, u_char *buf,
    size_t len, ngx_log_t *log, char *codec);


uint32_t ngx_ts_heavc_read_one(ngx_ts_heavc_reader_t *br);

uint64_t ngx_ts_heavc_read(ngx_ts_heavc_reader_t *br, ngx_uint_t bits);

uint64_t ngx_ts_heavc_read_golomb_unsigned(ngx_ts_heavc_reader_t *br);

int64_t ngx_ts_heavc_read_golomb_signed(ngx_ts_heavc_reader_t *br);


ngx_flag_t ngx_ts_heavc_rbsp_trailing_bits(ngx_ts_heavc_reader_t *br);


ngx_flag_t ngx_ts_heavc_sei_detect_cea(ngx_log_t *log, ngx_chain_t *in,
    u_char *pos, size_t size, size_t nal_header_size);


static ngx_inline uint32_t
ngx_ts_heavc_read_u1(ngx_ts_heavc_reader_t *br, char *name)
{
    uint32_t  v;

    v = ngx_ts_heavc_read_one(br);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, br->log, 0,
        "ts %s u(1) %s:%uD", br->codec, name, v);

    return v;
}


static ngx_inline uint64_t
ngx_ts_heavc_read_u(ngx_ts_heavc_reader_t *br, ngx_uint_t bits, char *name)
{
    uint64_t  v;

    v = ngx_ts_heavc_read(br, bits);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, br->log, 0,
        "ts %s u(%ui) %s:%uL", br->codec, bits, name, v);

    return v;
}


static ngx_inline uint64_t
ngx_ts_heavc_read_ue(ngx_ts_heavc_reader_t *br, char *name)
{
    uint64_t  v;

    v = ngx_ts_heavc_read_golomb_unsigned(br);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, br->log, 0,
        "ts %s ue(v) %s:%uL", br->codec, name, v);

    return v;
}


static ngx_inline int64_t
ngx_ts_heavc_read_se(ngx_ts_heavc_reader_t *br, char *name)
{
    int64_t  v;

    v = ngx_ts_heavc_read_golomb_signed(br);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, br->log, 0,
        "ts %s se(v) %s:%L", br->codec, name, v);

    return v;
}

#endif /* _NGX_TS_HEAVC_H_INCLUDED_ */
