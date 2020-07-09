#ifndef _NGX_MEM_RSTREAM_H_INCLUDED_
#define _NGX_MEM_RSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_BAD_DATA          NGX_ABORT


#define ngx_mem_rstream_left(rs)   ((size_t) ((rs)->end - (rs)->pos))
#define ngx_mem_rstream_eof(rs)    ((rs)->pos >= (rs)->end)

#define ngx_mem_rstream_pos(rs)    ((rs)->pos)
#define ngx_mem_rstream_end(rs)    ((rs)->end)
#define ngx_mem_rstream_scope(rs)  ((rs)->scope)


typedef struct {
    u_char     *pos;
    u_char     *end;
    ngx_log_t  *log;
    void       *scope;
} ngx_mem_rstream_t;


/*
 * NGX_BAD_DATA - end of stream
 * NGX_ERROR    - alloc error
 */


static ngx_inline void
ngx_mem_rstream_set(ngx_mem_rstream_t *rs, void *start, void *end,
    ngx_log_t *log, void *scope)
{
    rs->pos = start;
    rs->end = end;
    rs->log = log;
    rs->scope = scope;
}


static ngx_inline ngx_int_t
ngx_mem_rstream_read(ngx_mem_rstream_t *rs, void *buf, size_t size)
{
    if (size > ngx_mem_rstream_left(rs)) {
        return NGX_BAD_DATA;
    }

    ngx_memcpy(buf, rs->pos, size);
    rs->pos += size;

    return NGX_OK;
}


static ngx_inline void *
ngx_mem_rstream_get_ptr(ngx_mem_rstream_t *rs, size_t size)
{
    void  *rv;

    if (size > ngx_mem_rstream_left(rs)) {
        return NULL;
    }

    rv = rs->pos;
    rs->pos += size;

    return rv;
}


static ngx_inline ngx_int_t
ngx_mem_rstream_get_stream(ngx_mem_rstream_t *rs, size_t size,
    ngx_mem_rstream_t *out)
{
    u_char  *pos;

    pos = ngx_mem_rstream_get_ptr(rs, size);
    if (pos == NULL) {
        return NGX_BAD_DATA;
    }

    out->end = rs->pos;     /* must be first, in case out == rs */
    out->pos = pos;
    out->log = rs->log;
    out->scope = rs->scope;

    return NGX_OK;
}


static ngx_inline void
ngx_mem_rstream_get_left(ngx_mem_rstream_t *rs, ngx_str_t *buf)
{
    buf->data = rs->pos;
    buf->len = ngx_mem_rstream_left(rs);
}


static ngx_inline ngx_int_t
ngx_mem_rstream_str_get(ngx_mem_rstream_t *rs, ngx_str_t *s)
{
    uint32_t  len;

    if (ngx_mem_rstream_read(rs, &len, sizeof(len)) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    s->data = ngx_mem_rstream_get_ptr(rs, len);
    if (s->data == NULL) {
        return NGX_BAD_DATA;
    }

    s->len = len;

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_mem_rstream_str_fixed(ngx_mem_rstream_t *rs, ngx_str_t *s, size_t max)
{
    uint32_t   len;

    if (ngx_mem_rstream_read(rs, &len, sizeof(len)) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    if (len > max) {
        return NGX_BAD_DATA;
    }

    s->len = len;

    return ngx_mem_rstream_read(rs, s->data, len);
}


ngx_int_t ngx_mem_rstream_read_list(ngx_mem_rstream_t *rs, ngx_list_t *l,
    ngx_uint_t count);

#endif /* _NGX_MEM_RSTREAM_H_INCLUDED_ */
