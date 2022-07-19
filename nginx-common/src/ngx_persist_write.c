#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_persist_write.h"

#include <zlib.h>


#define NGX_PERSIST_WRITE_BUF_SIZE       (2048)
#define NGX_PERSIST_WRITE_COMP_BUF_SIZE  (2048)


typedef struct {
    ngx_persist_write_marker_t    marker;
    ngx_persist_block_header_t    header;
} ngx_persist_write_block_t;


struct ngx_persist_write_ctx_s {
    ngx_persist_write_base_t      base;       /* must be first */

    ngx_pool_t                   *pool;
    ngx_pool_cleanup_t           *cln;
    ngx_pool_t                   *final_pool;
    int                           comp_level;

    ngx_chain_t                  *out;
    ngx_chain_t                 **last;
    ngx_buf_t                    *buf;
    size_t                        size;
    ngx_persist_file_header_t    *header;

    ngx_persist_write_block_t     blocks[NGX_PERSIST_MAX_BLOCK_DEPTH];
    ngx_uint_t                    depth;
};


static ngx_int_t
ngx_persist_write_alloc_temp_buf(ngx_persist_write_ctx_t *ctx)
{
    ctx->buf = ngx_create_temp_buf(ctx->pool, NGX_PERSIST_WRITE_BUF_SIZE);
    if (ctx->buf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_alloc_temp_buf: create buf failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_persist_write_set_temp_buf(ngx_persist_write_ctx_t *ctx,
    u_char *start, u_char *end)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_set_temp_buf: alloc buf failed");
        return NGX_ERROR;
    }

    b->start = b->pos = b->last = start;
    b->end = end;
    b->temporary = 1;

    ctx->buf = b;

    return NGX_OK;
}


static ngx_buf_t *
ngx_persist_write_alloc_mem_buf(ngx_persist_write_ctx_t *ctx,
    u_char *buf, size_t size)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_alloc_mem_buf: alloc buf failed");
        return NULL;
    }

    b->start = b->pos = buf;
    b->end = b->last = buf + size;
    b->memory = 1;

    return b;
}


/* Note: buffers are appended to the chain as soon as they get the first
    byte of data, empty buffers must not be appended */

static ngx_int_t
ngx_persist_write_append_buf(ngx_persist_write_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_append_buf: alloc chain failed");
        return NGX_ERROR;
    }

    cl->buf = b;

    *ctx->last = cl;
    ctx->last = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_persist_write_flush_buf(ngx_persist_write_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ctx->buf;
    if (b->last >= b->end) {
        /* allocate a new buffer */
        return ngx_persist_write_alloc_temp_buf(ctx);
    }

    /* allocate a buf for the remainder */
    if (ngx_persist_write_set_temp_buf(ctx, b->last, b->end) != NGX_OK) {
        return NGX_ERROR;
    }

    b->end = b->last;

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_append(ngx_persist_write_ctx_t *ctx, void *buf, size_t size)
{
    ngx_buf_t  *b;

    ctx->size += size;

    if (ctx->buf->last > ctx->buf->pos &&
        ngx_persist_write_flush_buf(ctx) != NGX_OK)
    {
        return NGX_ERROR;
    }

    b = ngx_persist_write_alloc_mem_buf(ctx, buf, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ngx_persist_write_append_buf(ctx, b) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_write(ngx_persist_write_ctx_t *ctx, void *buf,
    size_t size)
{
    size_t      left;
    u_char     *p;
    ngx_buf_t  *b;

    if (size <= 0) {
        return NGX_OK;
    }

    ctx->size += size;

    b = ctx->buf;
    if (b->last <= b->pos &&
        ngx_persist_write_append_buf(ctx, b) != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = buf;

    for ( ;; ) {

        left = b->end - b->last;
        if (size <= left) {
            b->last = ngx_copy(b->last, p, size);
            break;
        }

        ngx_memcpy(b->last, p, left);
        b->last = b->end;

        if (ngx_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        b = ctx->buf;
        if (ngx_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NGX_ERROR;
        }

        p += left;
        size -= left;
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_reserve(ngx_persist_write_ctx_t *ctx, size_t size,
    ngx_persist_write_marker_t *marker)
{
    size_t      left;
    ngx_buf_t  *b;

    if (size <= 0) {
        return NGX_OK;
    }

    b = ctx->buf;
    if (b->last <= b->pos &&
        ngx_persist_write_append_buf(ctx, b) != NGX_OK)
    {
        return NGX_ERROR;
    }

    marker->size = ctx->size;
    marker->next = ctx->last;
    marker->buf = b;
    marker->pos = b->last;

    ctx->size += size;

    for ( ;; ) {

        left = b->end - b->last;
        if (size <= left) {
            b->last += size;
            break;
        }

        b->last = b->end;

        if (ngx_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        b = ctx->buf;
        if (ngx_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NGX_ERROR;
        }

        size -= left;
    }

    return NGX_OK;
}


void
ngx_persist_write_marker_write(ngx_persist_write_marker_t *marker,
    void *buf, size_t size)
{
    size_t        left;
    u_char       *p;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    p = buf;
    b = marker->buf;

    for ( ;; ) {

        left = b->last - marker->pos;

        if (size <= left) {
            marker->pos = ngx_copy(marker->pos, p, size);
            break;
        }

        ngx_memcpy(marker->pos, p, left);

        cl = *marker->next;
        marker->next = &cl->next;

        b = cl->buf;
        marker->buf = b;
        marker->pos = b->pos;

        p += left;
        size -= left;
    }
}


ngx_persist_write_ctx_t *
ngx_persist_write_init(ngx_pool_t *pool, uint32_t type, int comp_level)
{
    ngx_buf_t                  *b;
    ngx_persist_write_ctx_t    *ctx;
    ngx_persist_file_header_t  *header;

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_persist_write_init: alloc failed");
        return NULL;
    }

    if (comp_level) {

        /* use a temporary pool, allocate only the compressed buffers on
            the provided pool */

        ctx->cln = ngx_pool_cleanup_add(pool, 0);
        if (ctx->cln == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_persist_write_init: cleanup add failed");
            return NULL;
        }

        ctx->pool = ngx_create_pool(1024, pool->log);
        if (ctx->pool == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_persist_write_init: create pool failed");
            return NULL;
        }

        ctx->cln->handler = (ngx_pool_cleanup_pt) ngx_destroy_pool;
        ctx->cln->data = ctx->pool;

        ctx->final_pool = pool;
        ctx->comp_level = comp_level;

    } else {
        ctx->pool = pool;
    }

    ctx->last = &ctx->out;

    if (ngx_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
        return NULL;
    }

    if (type) {
        b = ctx->buf;
        header = (void *) b->last;

        header->magic = NGX_PERSIST_FILE_MAGIC;
        header->header_size = sizeof(*header) |
            NGX_PERSIST_HEADER_FLAG_CONTAINER;
        header->uncomp_size = 0;
        header->version = NGX_PERSIST_FILE_VERSION;
        header->type = type;
        header->created = ngx_time();

        if (ngx_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NULL;
        }

        b->last += sizeof(*header);
        ctx->size = sizeof(*header);

        ctx->header = header;
    }

    ctx->base.ws.write = (ngx_wstream_write_pt) ngx_persist_write;
    ctx->base.ws.ctx = ctx;

    return ctx;
}


ngx_pool_t *
ngx_persist_write_pool(ngx_persist_write_ctx_t *ctx)
{
    return ctx->pool;
}


size_t
ngx_persist_write_get_size(ngx_persist_write_ctx_t *ctx)
{
    return ctx->size;
}


void
ngx_persist_write_block_set_header(ngx_persist_write_ctx_t *ctx,
    uint32_t flags)
{
    ngx_persist_write_block_t  *block;

    if (ctx->depth <= 0) {
        return;
    }

    block = &ctx->blocks[ctx->depth - 1];
    if (block->header.header_size) {
        return;
    }

    block->header.header_size = (ctx->size - block->marker.size) | flags;
}


ngx_int_t
ngx_persist_write_block_open(ngx_persist_write_ctx_t *ctx,
    uint32_t id)
{
    ngx_persist_write_block_t  *block;

    if (ctx->depth >= NGX_PERSIST_MAX_BLOCK_DEPTH) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_persist_write_block_open: exceeded max depth, id: %*s",
            (size_t) sizeof(id), &id);
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(ctx,
        NGX_PERSIST_HEADER_FLAG_CONTAINER);

    block = &ctx->blocks[ctx->depth];
    ctx->depth++;

    block->header.id = id;
    block->header.header_size = 0;

    if (ngx_persist_write_reserve(ctx, sizeof(ngx_persist_block_hdr_t),
            &block->marker) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_block_open: reserve failed, id: %*s",
            (size_t) sizeof(id), &id);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_persist_write_block_close(ngx_persist_write_ctx_t *ctx)
{
    ngx_persist_write_block_t  *block;

    if (ctx->depth <= 0) {
        ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
            "ngx_persist_write_block_close: zero depth");
        ngx_debug_point();
    }

    ctx->depth--;
    block = &ctx->blocks[ctx->depth];

    block->header.size = ctx->size - block->marker.size;

    if (!block->header.header_size) {
        block->header.header_size = sizeof(block->header);
    }

    ngx_persist_write_marker_write(&block->marker, &block->header,
        sizeof(block->header));
}


ngx_int_t
ngx_persist_write_block(ngx_persist_write_ctx_t *ctx,
    ngx_persist_block_header_t *header, void *buf, size_t size)
{
    ngx_persist_write_block_set_header(ctx, NGX_PERSIST_HEADER_FLAG_CONTAINER);

    header->size = sizeof(*header) + size;

    if (ngx_persist_write(ctx, header, sizeof(*header)) != NGX_OK ||
        ngx_persist_write(ctx, buf, size) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_block: write failed, id: %*s",
            (size_t) sizeof(header->id), &header->id);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_persist_write_alloc(void *opaque, u_int items, u_int size)
{
    return ngx_palloc(opaque, items * size);
}


static void
ngx_persist_write_free(void *opaque, void *address)
{
}


static ngx_chain_t *
ngx_persist_write_deflate(ngx_persist_write_ctx_t *ctx, size_t *size,
    ngx_chain_t ***lastp)
{
    int                          rc;
    int                          flush;
    z_stream                     zstream;
    ngx_buf_t                   *ib;
    ngx_buf_t                   *ob;
    ngx_pool_t                  *pool;
    ngx_chain_t                 *ocl;
    ngx_chain_t                 *icl;
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_persist_file_header_t   *header;

    /* init zlib */
    ngx_memzero(&zstream, sizeof(zstream));

    zstream.zalloc = ngx_persist_write_alloc;
    zstream.zfree = ngx_persist_write_free;
    zstream.opaque = ctx->pool;

    rc = deflateInit2(&zstream, ctx->comp_level, Z_DEFLATED, MAX_WBITS,
        MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_persist_write_deflate: deflateInit2 failed: %d", rc);
        return NULL;
    }

    /* init output */
    pool = ctx->final_pool;

    ob = ngx_create_temp_buf(pool, NGX_PERSIST_WRITE_COMP_BUF_SIZE);
    if (ob == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_persist_write_deflate: create buf failed (1)");
        return NULL;
    }

    header = (void *) ob->pos;

    zstream.next_out = (void *) (header + 1);
    zstream.avail_out = ob->end - zstream.next_out;

    last = &out;

    /* init input */
    *ctx->last = NULL;
    icl = ctx->out;
    ib = icl->buf;

    zstream.next_in = (void *) (ctx->header + 1);
    zstream.avail_in = ib->last - zstream.next_in;

    for ( ;; ) {

        icl = icl->next;
        flush = icl == NULL ? Z_FINISH : Z_NO_FLUSH;

        for ( ;; ) {

            rc = deflate(&zstream, flush);
            if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_persist_write_deflate: deflate failed: %d", rc);
                return NULL;
            }

            if (zstream.avail_out > 0) {
                break;
            }

            ob->last = ob->end;

            ocl = ngx_alloc_chain_link(pool);
            if (ocl == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_persist_write_deflate: alloc chain failed (1)");
                return NULL;
            }

            *last = ocl;
            last = &ocl->next;
            ocl->buf = ob;

            ob = ngx_create_temp_buf(pool, NGX_PERSIST_WRITE_COMP_BUF_SIZE);
            if (ob == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_persist_write_deflate: create buf failed (2)");
                return NULL;
            }

            zstream.next_out = ob->pos;
            zstream.avail_out = ob->end - zstream.next_out;
        }

        if (icl == NULL) {
            break;
        }

        ib = icl->buf;

        zstream.next_in = ib->pos;
        zstream.avail_in = ib->last - zstream.next_in;
    }

    ob->last = zstream.next_out;

    if (ob->last > ob->pos) {
        ocl = ngx_alloc_chain_link(pool);
        if (ocl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_persist_write_deflate: alloc chain failed (2)");
            return NULL;
        }

        *last = ocl;
        last = &ocl->next;
        ocl->buf = ob;
    }

    *header = *ctx->header;
    header->size = sizeof(*header) + zstream.total_out;
    header->header_size |= NGX_PERSIST_HEADER_FLAG_COMPRESSED;
    header->uncomp_size = ctx->size;

    rc = deflateEnd(&zstream);
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_persist_write_deflate: deflateEnd failed %d", rc);
        return NULL;
    }

    ctx->cln->handler = NULL;
    ngx_destroy_pool(ctx->pool);

    *last = NULL;

    *size = header->size;
    if (lastp != NULL) {
        *lastp = last;
    }

    return out;
}


ngx_chain_t *
ngx_persist_write_close(ngx_persist_write_ctx_t *ctx, size_t *size,
    ngx_chain_t ***last)
{
    if (ctx->depth != 0) {
        ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
            "ngx_persist_write_close: nonzero depth");
        ngx_debug_point();
        return NULL;
    }

    if (ctx->comp_level) {
        return ngx_persist_write_deflate(ctx, size, last);
    }

    if (ctx->header) {
        ctx->header->size = ctx->size;
    }

    *ctx->last = NULL;

    *size = ctx->size;
    if (last != NULL) {
        *last = ctx->last;
    }
    return ctx->out;
}


ngx_int_t
ngx_persist_write_chain(ngx_persist_write_ctx_t *ctx1,
    ngx_persist_write_ctx_t *ctx2)
{
    size_t         size;
    ngx_chain_t   *cl;
    ngx_chain_t  **last;

    cl = ngx_persist_write_close(ctx2, &size, &last);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (size <= 0) {
        return NGX_OK;
    }

    if (ctx1->buf->last > ctx1->buf->pos &&
        ngx_persist_write_flush_buf(ctx1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx1->size += size;

    *ctx1->last = cl;
    ctx1->last = last;

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_list_data(ngx_persist_write_ctx_t *ctx, ngx_list_t *list)
{
    ngx_list_part_t  *part;

    for (part = &list->part; part != NULL; part = part->next) {

        if (ngx_persist_write(ctx, part->elts, part->nelts * list->size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_list_data_n(ngx_persist_write_ctx_t *ctx,
    ngx_list_part_t *part, ngx_uint_t count, size_t size)
{
    for ( ;; ) {

        if (part->nelts >= count) {
            if (ngx_persist_write(ctx, part->elts, count * size) != NGX_OK) {
                return NGX_ERROR;
            }

            break;
        }

        if (ngx_persist_write(ctx, part->elts, part->nelts * size) != NGX_OK) {
            return NGX_ERROR;
        }

        count -= part->nelts;
        part = part->next;
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_append_buf_chain(ngx_persist_write_ctx_t *ctx,
    ngx_buf_chain_t *chain)
{
    for (; chain != NULL; chain = chain->next) {

        if (ngx_persist_write_append(ctx, chain->data, chain->size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_write_append_buf_chain_n(ngx_persist_write_ctx_t *ctx,
    ngx_buf_chain_t *chain, size_t offset, size_t size)
{
    size_t   chain_size;
    u_char  *chain_data;

    chain_data = chain->data + offset;
    chain_size = chain->size - offset;

    for ( ;; ) {

        if (size <= chain_size) {
            return ngx_persist_write_append(ctx, chain_data, size);
        }

        if (ngx_persist_write_append(ctx, chain_data, chain_size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        size -= chain_size;

        chain = chain->next;
        chain_data = chain->data;
        chain_size = chain->size;
    }

    return NGX_OK;
}
