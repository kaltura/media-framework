#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_json_pretty.h"


/* nginx stubs */

void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return malloc(size);
}

ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_palloc(pool, sizeof(*b));
    if (b == NULL) {
        return NULL;
    }
    ngx_memzero(b, sizeof(*b));

    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}

ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    return ngx_palloc(pool, sizeof(ngx_chain_t));
}


int ngx_cdecl
main(int argc, char *const *argv)
{
    size_t        size;
    size_t        cur_size;
    size_t        write_size;
    ngx_str_t     json;
    ngx_pool_t    pool;
    ngx_chain_t  *out;
    ngx_chain_t  *last, *cl;

    ngx_memzero(&pool, sizeof(pool));

    json.data = argv[1];
    json.len = ngx_strlen(json.data);

    last = ngx_json_pretty(&pool, &json, 0, &out, &size);

    last->next = NULL;

    write_size = 0;
    for (cl = out; cl; cl = cl->next) {
        cur_size = cl->buf->last - cl->buf->pos;
        write(STDOUT_FILENO, cl->buf->pos, cur_size);
        write_size += cur_size;
    }

    if (write_size != size) {
        printf("Error: size mismatch %zu != %zu\n", write_size, size);
    }

    return 0;
}
