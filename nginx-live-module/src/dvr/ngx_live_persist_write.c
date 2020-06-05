#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_format.h"
#include "ngx_live_persist_write.h"
#include "../ngx_wstream.h"


#define NGX_LIVE_PERSIST_WRITE_BUF_SIZE  (2048)


typedef struct {
    size_t                            size;
    ngx_chain_t                     **next;
    ngx_buf_t                        *buf;
    u_char                           *pos;
} ngx_live_persist_write_marker_t;


typedef struct {
    ngx_live_persist_write_marker_t   marker;
    ngx_live_persist_block_header_t   header;
} ngx_live_persist_write_block_t;


struct ngx_live_persist_write_ctx_s {
    ngx_wstream_t                     ws;       /* must be first */

    ngx_pool_t                       *pool;
    ngx_chain_t                      *out;
    ngx_chain_t                     **last;
    ngx_buf_t                        *buf;
    size_t                            size;
    ngx_live_persist_file_header_t   *header;

    ngx_live_persist_write_block_t    blocks[NGX_LIVE_PERSIST_MAX_BLOCK_DEPTH];
    ngx_uint_t                        depth;
};


static ngx_int_t
ngx_live_persist_write_alloc_temp_buf(ngx_live_persist_write_ctx_t *ctx)
{
    ctx->buf = ngx_create_temp_buf(ctx->pool, NGX_LIVE_PERSIST_WRITE_BUF_SIZE);
    if (ctx->buf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_write_alloc_temp_buf: create buf failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_write_set_temp_buf(ngx_live_persist_write_ctx_t *ctx,
    u_char *start, u_char *end)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_write_set_temp_buf: alloc buf failed");
        return NGX_ERROR;
    }

    b->start = b->pos = b->last = start;
    b->end = end;
    b->temporary = 1;

    ctx->buf = b;

    return NGX_OK;
}

static ngx_buf_t *
ngx_live_persist_write_alloc_mem_buf(ngx_live_persist_write_ctx_t *ctx,
    u_char *buf, size_t size)
{
    ngx_buf_t  *b;

    b = ngx_calloc_buf(ctx->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_write_alloc_mem_buf: alloc buf failed");
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
ngx_live_persist_write_append_buf(ngx_live_persist_write_ctx_t *ctx,
    ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_write_append_buf: alloc chain failed");
        return NGX_ERROR;
    }

    cl->buf = b;

    *ctx->last = cl;
    ctx->last = &cl->next;

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_write_flush_buf(ngx_live_persist_write_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ctx->buf;
    if (b->last >= b->end) {
        /* allocate a new buffer */
        return ngx_live_persist_write_alloc_temp_buf(ctx);
    }

    /* allocate a buf for the remainder */
    if (ngx_live_persist_write_set_temp_buf(ctx, b->last, b->end) != NGX_OK) {
        return NGX_ERROR;
    }

    b->end = b->last;

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_write_append(ngx_live_persist_write_ctx_t *ctx, void *buf,
    size_t size)
{
    ngx_buf_t  *b;

    ctx->size += size;

    if (ctx->buf->last > ctx->buf->pos &&
        ngx_live_persist_write_flush_buf(ctx) != NGX_OK)
    {
        return NGX_ERROR;
    }

    b = ngx_live_persist_write_alloc_mem_buf(ctx, buf, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (ngx_live_persist_write_append_buf(ctx, b) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_persist_write(ngx_live_persist_write_ctx_t *ctx, void *buf,
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
        ngx_live_persist_write_append_buf(ctx, b) != NGX_OK)
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

        if (ngx_live_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        b = ctx->buf;
        if (ngx_live_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NGX_ERROR;
        }

        p += left;
        size -= left;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_write_reserve(ngx_live_persist_write_ctx_t *ctx, size_t size,
    ngx_live_persist_write_marker_t *marker)
{
    size_t      left;
    ngx_buf_t  *b;

    if (size <= 0) {
        return NGX_OK;
    }

    b = ctx->buf;
    if (b->last <= b->pos &&
        ngx_live_persist_write_append_buf(ctx, b) != NGX_OK)
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

        if (ngx_live_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        b = ctx->buf;
        if (ngx_live_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NGX_ERROR;
        }

        size -= left;
    }

    return NGX_OK;
}

static void
ngx_live_persist_write_marker_write(ngx_live_persist_write_marker_t *marker,
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


ngx_live_persist_write_ctx_t *
ngx_live_persist_write_init(ngx_pool_t *pool, uint32_t type)
{
    ngx_buf_t                       *b;
    ngx_live_persist_write_ctx_t    *ctx;
    ngx_live_persist_file_header_t  *header;

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_write_init: alloc failed");
        return NULL;
    }

    ctx->pool = pool;
    ctx->last = &ctx->out;

    if (ngx_live_persist_write_alloc_temp_buf(ctx) != NGX_OK) {
        return NULL;
    }

    if (type) {
        b = ctx->buf;
        header = (void *) b->last;

        header->magic = NGX_LIVE_PERSIST_FILE_MAGIC;
        header->header_size = sizeof(*header) |
            NGX_LIVE_PERSIST_HEADER_FLAG_CONTAINER;
        header->flags = 0;
        header->version = NGX_LIVE_PERSIST_FILE_VERSION;
        header->type = type;
        header->created = ngx_time();

        if (ngx_live_persist_write_append_buf(ctx, b) != NGX_OK) {
            return NULL;
        }

        b->last += sizeof(*header);
        ctx->size = sizeof(*header);

        ctx->header = header;
    }

    ctx->ws.write = (ngx_wstream_write_pt) ngx_live_persist_write;
    ctx->ws.ctx = ctx;

    return ctx;
}

size_t
ngx_live_persist_write_get_size(ngx_live_persist_write_ctx_t *ctx)
{
    return ctx->size;
}

void
ngx_live_persist_write_block_set_header(ngx_live_persist_write_ctx_t *ctx,
    uint32_t flags)
{
    ngx_live_persist_write_block_t  *block;

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
ngx_live_persist_write_block_open(ngx_live_persist_write_ctx_t *ctx,
    uint32_t id)
{
    ngx_live_persist_write_block_t  *block;

    if (ctx->depth >= NGX_LIVE_PERSIST_MAX_BLOCK_DEPTH) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_persist_write_block_open: exceeded max depth, id: %*s",
            (size_t) sizeof(id), &id);
        return NGX_ERROR;
    }

    ngx_live_persist_write_block_set_header(ctx,
        NGX_LIVE_PERSIST_HEADER_FLAG_CONTAINER);

    block = &ctx->blocks[ctx->depth];
    ctx->depth++;

    block->header.id = id;
    block->header.header_size = 0;

    if (ngx_live_persist_write_reserve(ctx,
        sizeof(ngx_live_persist_block_header_t), &block->marker) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_live_persist_write_block_close(ngx_live_persist_write_ctx_t *ctx)
{
    ngx_live_persist_write_block_t  *block;

    if (ctx->depth <= 0) {
        ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
            "ngx_live_persist_write_block_close: zero depth");
        ngx_debug_point();
    }

    ctx->depth--;
    block = &ctx->blocks[ctx->depth];

    block->header.size = ctx->size - block->marker.size;

    if (!block->header.header_size) {
        block->header.header_size = sizeof(block->header);
    }

    ngx_live_persist_write_marker_write(&block->marker, &block->header,
        sizeof(block->header));
}

ngx_int_t
ngx_live_persist_write_block(ngx_live_persist_write_ctx_t *ctx,
    ngx_live_persist_block_header_t *header, void *buf, size_t size)
{
    ngx_live_persist_write_block_set_header(ctx,
        NGX_LIVE_PERSIST_HEADER_FLAG_CONTAINER);

    header->size = sizeof(*header) + size;

    if (ngx_live_persist_write(ctx, header, sizeof(*header)) != NGX_OK ||
        ngx_live_persist_write(ctx, buf, size) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_chain_t *
ngx_live_persist_write_close(ngx_live_persist_write_ctx_t *ctx, size_t *size)
{
    if (ctx->depth != 0) {
        ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
            "ngx_live_persist_write_close: nonzero depth");
        ngx_debug_point();
        return NULL;
    }

    if (ctx->header) {
        ctx->header->size = ctx->size;
    }

    *ctx->last = NULL;

    *size = ctx->size;
    return ctx->out;
}

ngx_int_t
ngx_live_persist_write_chain(ngx_live_persist_write_ctx_t *ctx1,
    ngx_live_persist_write_ctx_t *ctx2)
{
    size_t        size;
    ngx_chain_t  *cl;

    cl = ngx_live_persist_write_close(ctx2, &size);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (size <= 0) {
        return NGX_OK;
    }

    if (ctx1->buf->last > ctx1->buf->pos &&
        ngx_live_persist_write_flush_buf(ctx1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx1->size += size;

    *ctx1->last = cl;
    ctx1->last = ctx2->last;

    return NGX_OK;
}


ngx_int_t
ngx_live_persist_write_list_data(ngx_live_persist_write_ctx_t *ctx,
    ngx_list_t *list)
{
    ngx_list_part_t  *part;

    for (part = &list->part; part != NULL; part = part->next) {

        if (ngx_live_persist_write(ctx, part->elts, part->nelts * list->size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_persist_write_append_buf_chain(ngx_live_persist_write_ctx_t *ctx,
    ngx_buf_chain_t *chain)
{
    for (; chain != NULL; chain = chain->next) {

        if (ngx_live_persist_write_append(ctx, chain->data, chain->size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_persist_write_append_buf_chain_n(ngx_live_persist_write_ctx_t *ctx,
    ngx_buf_chain_t *chain, size_t size)
{
    for (; size > 0; chain = chain->next) {

        if (ngx_live_persist_write_append(ctx, chain->data, chain->size)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        size -= chain->size;
    }

    return NGX_OK;
}
