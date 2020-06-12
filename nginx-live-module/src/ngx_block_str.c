#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_block_str.h"


struct ngx_block_str_node_s {
    ngx_block_str_node_t *next;
};


ngx_int_t
ngx_block_str_set(ngx_block_str_t *dest, ngx_block_pool_t *pool,
    ngx_uint_t index, ngx_str_t *src)
{
    size_t                  copy;
    size_t                  left;
    size_t                  block_len;
    u_char                 *p;
    ngx_block_str_node_t   *cur;
    ngx_block_str_node_t   *data;
    ngx_block_str_node_t  **last;

    block_len = ngx_block_pool_get_size(pool, index);
    if (block_len <= sizeof(ngx_block_str_node_t)) {
        ngx_log_error(NGX_LOG_ALERT, pool->pool->log, 0,
            "ngx_block_str_set: slot size smaller than node header");
        return NGX_ERROR;
    }
    block_len -= sizeof(ngx_block_str_node_t);

    last = &data;

    p = src->data;
    for (left = src->len; left > 0; left -= copy) {

        cur = ngx_block_pool_alloc(pool, index);
        if (cur == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->pool->log, 0,
                "ngx_block_str_set: alloc failed");
            *last = NULL;
            ngx_block_str_free_data(data, pool, index);
            return NGX_ERROR;
        }

        *last = cur;
        last = &cur->next;

        copy = ngx_min(left, block_len);

        ngx_memcpy(cur + 1, p, copy);
        p += copy;
    }

    *last = NULL;

    ngx_block_str_free(dest, pool, index);

    dest->data = data;
    dest->len = src->len;
    dest->block_len = block_len;

    return NGX_OK;
}

void
ngx_block_str_free_data(ngx_block_str_node_t *data, ngx_block_pool_t *pool,
    ngx_uint_t index)
{
    ngx_block_str_node_t  *cur;

    for (cur = data; cur != NULL; cur = cur->next) {
        ngx_block_pool_free(pool, index, cur);
    }
}

u_char *
ngx_block_str_copy(u_char *p, ngx_block_str_t *str)
{
    size_t                 left;
    ngx_block_str_node_t  *cur;

    for (left = str->len, cur = str->data;
        left > str->block_len;
        left -= str->block_len, cur = cur->next)
    {
        p = ngx_copy(p, cur + 1, str->block_len);
    }

    p = ngx_copy(p, cur + 1, left);

    return p;
}


ngx_int_t
ngx_block_str_write(ngx_wstream_t *ws, ngx_block_str_t *str)
{
    uint32_t               left;
    ngx_int_t              rc;
    ngx_block_str_node_t  *cur;

    left = str->len;

    rc = ws->write(ws->ctx, &left, sizeof(left));
    if (rc != NGX_OK) {
        return rc;
    }

    for (cur = str->data;
        left > str->block_len;
        left -= str->block_len, cur = cur->next)
    {
        rc = ws->write(ws->ctx, cur + 1, str->block_len);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ws->write(ws->ctx, cur + 1, left);
}

ngx_int_t
ngx_block_str_read(ngx_mem_rstream_t *rs, ngx_block_str_t *str,
    ngx_block_pool_t *pool, ngx_uint_t index)
{
    ngx_str_t  src;

    if (ngx_mem_rstream_str_get(rs, &src) != NGX_OK) {
        return NGX_BAD_DATA;
    }

    return ngx_block_str_set(str, pool, index, &src);
}
