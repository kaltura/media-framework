#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http_call.h>
#include "ngx_kmp_push_utils.h"


#define NGX_HTTP_OK                        200


static ngx_str_t ngx_kmp_push_json_type = ngx_string("application/json");


ngx_chain_t *
ngx_kmp_push_alloc_chain_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_alloc_chain_temp_buf: ngx_alloc_chain_link failed");
        return NULL;
    }

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_alloc_chain_temp_buf: "
            "ngx_create_temp_buf failed, size: %uz", size);
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

ngx_chain_t *
ngx_kmp_push_alloc_chain_buf(ngx_pool_t *pool, void *pos, void *last)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_alloc_chain_buf: ngx_alloc_chain_link failed");
        return NULL;
    }

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_alloc_chain_buf: ngx_calloc_buf failed");
        return NULL;
    }

    cl->buf = b;
    b->tag = (ngx_buf_tag_t)&ngx_kmp_push_alloc_chain_buf;
    b->temporary = 1;

    b->start = b->pos = pos;
    b->end = b->last = last;

    return cl;
}

#if 0       // XXXXX
ngx_chain_t *
ngx_kmp_push_copy_chain(ngx_pool_t *pool, ngx_chain_t *src)
{
    size_t        size;
    u_char       *p;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    ngx_chain_t  *cur;

    size = 0;
    for (cur = src; cur != NULL; cur = cur->next) {
        size += cur->buf->last - cur->buf->start;
    }

    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_copy_chain: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;
    p = b->last;
    for (cur = src; cur != NULL; cur = cur->next) {
        p = ngx_copy(p, cur->buf->start, cur->buf->last - cur->buf->start);
    }

    b->last = p;

    return cl;
}
#endif

ngx_chain_t *
ngx_kmp_push_format_json_http_request(ngx_pool_t *pool, ngx_str_t *host,
    ngx_str_t *uri, ngx_chain_t *body)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    size_t        content_length;
    size_t        alloc_size;

    static const char rq_tmpl[] = "POST %V HTTP/1.0\r\n"
        "Host: %V\r\n"
        "Content-Type: %V\r\n"
        "Connection: Close\r\n"
        "Content-Length: %uz\r\n"
        "\r\n";

    content_length = 0;
    for (cl = body; cl; cl = cl->next) {
        content_length += cl->buf->last - cl->buf->pos;
    }

    alloc_size = sizeof(rq_tmpl) + uri->len + host->len +
        ngx_kmp_push_json_type.len + NGX_SIZE_T_LEN;
    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, alloc_size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_format_json_http_request: "
            "ngx_kmp_push_alloc_chain_temp_buf failed");
        return NULL;
    }

    b = cl->buf;

    b->last = ngx_sprintf(b->last, rq_tmpl,
        uri, host, &ngx_kmp_push_json_type, content_length);

    if ((size_t)(b->last - b->pos) > alloc_size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_push_format_json_http_request: "
            "result length %uz greater than allocated length %uz",
            (size_t)(b->last - b->pos), alloc_size);
        return NULL;
    }

    cl->next = body;

    return cl;
}

ngx_int_t
ngx_kmp_push_parse_json_response(ngx_pool_t *pool, ngx_log_t *log,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body,
    ngx_json_value_t *json)
{
    ngx_int_t   rc;
    ngx_uint_t  level;
    u_char      error[128];

    if (code != NGX_HTTP_OK) {
        level = (code >= NGX_HTTP_CALL_ERROR_COUNT) ? NGX_LOG_ERR :
            NGX_LOG_NOTICE;

        ngx_log_error(level, log, 0,
            "ngx_kmp_push_parse_json_response: invalid http status %ui", code);
        return NGX_ERROR;
    }

    if (content_type->len < ngx_kmp_push_json_type.len
        || ngx_strncasecmp(content_type->data,
            ngx_kmp_push_json_type.data,
            ngx_kmp_push_json_type.len)
        != 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_push_parse_json_response: invalid content type %V",
            content_type);
        return NGX_ERROR;
    }

    if (body->last >= body->end) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_push_parse_json_response: no room for null terminator");
        return NGX_ERROR;
    }

    *body->last = '\0';

    rc = ngx_json_parse(pool, body->pos, json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_push_parse_json_response: ngx_json_parse failed %i, %s",
            rc, error);
        return NGX_ERROR;
    }

    if (json->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_push_parse_json_response: "
            "invalid type %d, expected object",
            json->type);
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_kmp_push_float_to_rational(double f, int64_t md, int64_t *num,
    int64_t *denom)
{
    /*  a: continued fraction coefficients. */
    int64_t a, h[3] = { 0, 1, 0 }, k[3] = { 1, 0, 0 };
    int64_t x, d, n = 1;
    int i, neg = 0;

    if (md <= 1) {
        *denom = 1;
        *num = (int64_t)f;
        return;
    }

    if (f < 0) {
        neg = 1;
        f = -f;
    }

    while (f != (int64_t)f) {
        n <<= 1;
        if (!n) {
            *num = 0;
            *denom = 1;
            return;
        }
        f *= 2;
    }
    d = f;

    /* continued fraction and check denominator each step */
    for (i = 0; i < 64; i++) {
        a = d / n;
        if (i && !a) {
            break;
        }

        x = a;
        if (k[1] * a + k[0] >= md) {
            x = (md - k[0]) / k[1];
            if (x * 2 >= a || k[1] >= md) {
                i = 65;
            } else {
                break;
            }
        }

        h[2] = x * h[1] + h[0]; h[0] = h[1]; h[1] = h[2];
        k[2] = x * k[1] + k[0]; k[0] = k[1]; k[1] = k[2];

        x = d; d = n; n = x % n;
        if (!n) {
            break;
        }
    }

    *denom = k[1];
    *num = neg ? -h[1] : h[1];
}
