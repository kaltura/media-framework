#ifndef _NGX_WSTREAM_H_INCLUDED_
#define _NGX_WSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_int_t (*ngx_wstream_write_pt)(void *ctx, void *buf, size_t size);


typedef struct {
    ngx_wstream_write_pt   write;
    void                  *ctx;
} ngx_wstream_t;


static ngx_inline ngx_int_t
ngx_wstream_str(ngx_wstream_t *ws, ngx_str_t *s)
{
    uint32_t   len;
    ngx_int_t  rc;

    len = s->len;

    rc = ws->write(ws->ctx, &len, sizeof(len));
    if (rc != NGX_OK) {
        return rc;
    }

    return ws->write(ws->ctx, s->data, len);
}

#endif /* _NGX_WSTREAM_H_INCLUDED_ */
