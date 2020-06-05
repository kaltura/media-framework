#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_mem_rstream.h"


ngx_int_t
ngx_mem_rstream_read_list(ngx_mem_rstream_t *rs, ngx_list_t *l,
    ngx_uint_t count)
{
    void             *elt;
    ngx_uint_t        left, chunk;
    ngx_list_part_t  *last;

    last = l->last;

    for (left = count; left > 0; left -= chunk) {

        if (last->nelts >= l->nalloc) {
            last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
            if (last == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                    "ngx_mem_rstream_read_list: alloc failed (1)");
                return NGX_ERROR;
            }

            last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
            if (last->elts == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                    "ngx_mem_rstream_read_list: alloc failed (2)");
                return NGX_ERROR;
            }

            last->nelts = 0;
            last->next = NULL;

            l->last->next = last;
            l->last = last;
        }

        chunk = l->nalloc - last->nelts;
        if (chunk > left) {
            chunk = left;
        }

        elt = (u_char *) last->elts + l->size * last->nelts;

        if (ngx_mem_rstream_read(rs, elt, l->size * chunk) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_mem_rstream_read_list: read failed");
            return NGX_ABORT;
        }

        last->nelts += chunk;
    }

    return NGX_OK;
}
