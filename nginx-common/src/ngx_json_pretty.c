#include <ngx_config.h>
#include <ngx_core.h>
#include <ctype.h>


#define NGX_JSON_PRETTY_INDENT       4
#define NGX_JSON_PRETTY_MAX_DEPTH    16
#define NGX_JSON_PRETTY_MAX_SEP_LEN  (1 +                                    \
    NGX_JSON_PRETTY_MAX_DEPTH * NGX_JSON_PRETTY_INDENT)

#define NGX_JSON_PRETTY_BUF_SIZE     1024


typedef struct {
    ngx_pool_t    *pool;
    ngx_buf_t     *b;
    ngx_chain_t   *cl;
    ngx_chain_t  **last;
    size_t         size;
} ngx_json_pretty_writer_t;


static ngx_int_t
ngx_json_pretty_write_alloc(ngx_json_pretty_writer_t *ctx)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    b = ngx_create_temp_buf(ctx->pool, NGX_JSON_PRETTY_BUF_SIZE);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    *ctx->last = cl;
    ctx->last = &cl->next;

    ctx->b = b;
    ctx->cl = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_json_pretty_write(ngx_json_pretty_writer_t *ctx, u_char *p, u_char *end)
{
    size_t      src_left;
    size_t      dst_left;
    ngx_buf_t  *b;

    for ( ;; ) {

        b = ctx->b;

        src_left = end - p;
        dst_left = b->end - b->last;

        if (src_left <= dst_left) {
            b->last = ngx_copy(b->last, p, src_left);
            break;
        }

        b->last = ngx_copy(b->last, p, dst_left);
        p += dst_left;

        ctx->size += b->last - b->start;

        if (ngx_json_pretty_write_alloc(ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_json_pretty_write_init(ngx_json_pretty_writer_t *ctx, ngx_pool_t *pool,
    ngx_chain_t **last)
{
    ctx->pool = pool;
    ctx->last = last;
    ctx->size = 0;

    return ngx_json_pretty_write_alloc(ctx);
}


static ngx_chain_t *
ngx_json_pretty_write_close(ngx_json_pretty_writer_t *ctx, size_t *size)
{
    ngx_buf_t  *b;

    b = ctx->b;

    ctx->size += b->last - b->start;
    *ctx->last = NULL;

    *size = ctx->size;

    return ctx->cl;
}


ngx_chain_t *
ngx_json_pretty(ngx_pool_t *pool, ngx_str_t *json, ngx_uint_t level,
    ngx_chain_t **last, size_t *size)
{
    u_char                     space;
    u_char                    *p, *end, *start;
    u_char                     sep[NGX_JSON_PRETTY_MAX_SEP_LEN];
    ngx_uint_t                 sep_len;
    ngx_json_pretty_writer_t   ctx;

    if (ngx_json_pretty_write_init(&ctx, pool, last) != NGX_OK) {
        return NULL;
    }

    space = ' ';

    sep[0] = '\n';
    ngx_memset(sep + 1, ' ', sizeof(sep) - 1);

    sep_len = 1 + level * NGX_JSON_PRETTY_INDENT;
    if (sep_len > sizeof(sep)) {
        sep_len = sizeof(sep);
    }

    p = json->data;
    end = p + json->len;

    start = p;

    while (p < end) {

        switch (*p) {

        case ' ':
        case '\r':
        case '\n':
        case '\t':
            if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
                return NULL;
            }

            p++;
            start = p;
            continue;

        case '[':
        case '{':
            p++;
            if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
                return NULL;
            }

            for (; p < end && isspace(*p); p++);

            start = p;

            if (p >= end) {
                break;
            }

            if (*p == '}' || *p == ']') {
                p++;
                break;
            }

            sep_len += NGX_JSON_PRETTY_INDENT;
            if (sep_len > sizeof(sep)) {
                sep_len = sizeof(sep);
            }

            if (ngx_json_pretty_write(&ctx, sep, sep + sep_len) != NGX_OK) {
                return NULL;
            }
            break;

        case ',':
            p++;
            if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
                return NULL;
            }

            start = p;

            if (ngx_json_pretty_write(&ctx, sep, sep + sep_len) != NGX_OK) {
                return NULL;
            }
            break;

        case ':':
            p++;
            if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
                return NULL;
            }

            start = p;

            if (ngx_json_pretty_write(&ctx, &space, &space + 1) != NGX_OK) {
                return NULL;
            }

            continue;

        case ']':
        case '}':
            if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
                return NULL;
            }

            start = p;
            p++;

            if (sep_len > NGX_JSON_PRETTY_INDENT) {
                sep_len -= NGX_JSON_PRETTY_INDENT;
            }

            if (ngx_json_pretty_write(&ctx, sep, sep + sep_len) != NGX_OK) {
                return NULL;
            }
            break;

        case '"':
            for (p++; p < end; p++) {

                if (*p == '"') {
                    p++;
                    break;
                }

                if (*p == '\\' && p + 1 < end) {
                    p++;
                }
            }
            break;

        default:

            /* true / false / null / number */

            for (p++; p < end; p++) {

                switch (*p) {

                case '}':
                case ']':
                case ',':
                case ' ':
                case '\r':
                case '\n':
                case '\t':
                    break;

                default:
                    continue;
                }

                break;
            }
        }
    }

    if (ngx_json_pretty_write(&ctx, start, p) != NGX_OK) {
        return NULL;
    }

    return ngx_json_pretty_write_close(&ctx, size);
}
