#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_api.h"
#include "ngx_json_pretty.h"


#define ngx_str_equals(s1, s2)                                              \
    ((s1).len == (s2).len && ngx_strncmp((s1).data, (s2).data, (s1).len) == 0)

#define ngx_str_equals_c(ns, s)                                             \
    ((ns).len == sizeof(s) - 1 &&                                           \
     ngx_strncmp((ns).data, (s), sizeof(s) - 1) == 0)


#define NGX_HTTP_API_MAX_ROUTE_PARAMS  (2)

#define NGX_HTTP_API_MULTI_CODE  "{\"code\":"
#define NGX_HTTP_API_MULTI_BODY  ",\"body\":"


typedef struct {
    ngx_http_api_route_handler_pt       handler;
    ngx_http_api_route_data_handler_pt  data_handler;
    ngx_str_t                           params[NGX_HTTP_API_MAX_ROUTE_PARAMS];
} ngx_http_api_handler_t;


typedef struct {
    ngx_str_t                    name;
    ngx_uint_t                   method;
} ngx_http_api_method_t;


typedef struct {
    ngx_str_t                    uri;
    ngx_uint_t                   method;
    ngx_json_value_t             body;
} ngx_http_api_request_t;


typedef struct {
    ngx_http_api_handler_t       handler;
    ngx_http_api_route_node_t   *root;

    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    size_t                       size;

    ngx_array_part_t            *part;
    ngx_json_object_t           *obj;

    ngx_event_t                  event;

    unsigned                     multi:1;
    unsigned                     pretty:1;
} ngx_http_api_ctx_t;


static ngx_http_module_t  ngx_http_api_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_api_module = {
    NGX_MODULE_V1,
    &ngx_http_api_module_ctx,              /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_api_json_type = ngx_string("application/json");

static ngx_str_t  ngx_http_api_multi_end = ngx_string("}]");


static ngx_http_api_method_t  methods[] = {
    { ngx_string("GET"),    NGX_HTTP_GET },
    { ngx_string("POST"),   NGX_HTTP_POST },
    { ngx_string("PUT"),    NGX_HTTP_PUT },
    { ngx_string("DELETE"), NGX_HTTP_DELETE },
    { ngx_null_string, 0 }
};


static ngx_int_t
ngx_http_api_append_buf(ngx_http_request_t *r, ngx_str_t *buf, ngx_flag_t last)
{
    size_t               size;
    ngx_buf_t           *b;
    ngx_uint_t           level;
    ngx_chain_t         *cl;
    ngx_http_api_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    size = buf->len;

    if (ctx->pretty && size > 0) {

        level = ctx->out == NULL ? 0 : 2;

        cl = ngx_json_pretty(r->pool, buf, level, ctx->last, &size);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_append_buf: json pretty failed");
            return NGX_ERROR;
        }

        b = cl->buf;

    } else {

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_append_buf: alloc chain failed");
            return NGX_ERROR;
        }

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_append_buf: alloc buf failed");
            return NGX_ERROR;
        }

        if (size > 0) {
            b->pos = buf->data;
            b->last = buf->data + size;
            b->memory = 1;
        }

        cl->buf = b;

        *ctx->last = cl;
    }

    ctx->last = &cl->next;
    ctx->size += size;

    if (last) {
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        *ctx->last = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *response)
{
    ngx_int_t            rc;
    ngx_http_api_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    if (ngx_http_api_append_buf(r, response, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_send_response: append failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (status == NGX_OK) {
        status = ctx->size > 0 ? NGX_HTTP_OK : NGX_HTTP_NO_CONTENT;
    }

    r->headers_out.content_type = ngx_http_api_json_type;
    r->headers_out.content_length_n = ctx->size;
    r->headers_out.status = status;

    if (r->method == NGX_HTTP_HEAD || (r != r->main && ctx->size == 0)) {
        return ngx_http_send_header(r);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, ctx->out);
}


static ngx_int_t
ngx_http_api_get_route_node(ngx_http_request_t *r, ngx_http_api_request_t *req,
    ngx_http_api_route_node_t *root, ngx_http_api_handler_t *handler)
{
    u_char                      *pos;
    u_char                      *last;
    u_char                      *slash;
    ngx_uint_t                   param_count;
    ngx_http_api_route_node_t   *node;
    ngx_http_api_route_child_t  *child;

    node = root;
    param_count = 0;

    pos = req->uri.data;
    last = pos + req->uri.len;

    if (req->uri.len && *pos == '/') {
        pos++;
    }

    while (pos < last) {

        slash = ngx_strlchr(pos, last, '/');
        if (slash == NULL) {
            slash = last;
        }

        child = node->children;
        if (child == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_api_get_route_node: route \"%V\" not found (1)",
                &req->uri);
            return NGX_HTTP_BAD_REQUEST;
        }

        for ( ;; ) {

            if (child->name.len == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_api_get_route_node: route \"%V\" not found (2)",
                    &req->uri);
                return NGX_HTTP_BAD_REQUEST;
            }

            if (child->name.len == 1 && child->name.data[0] == '%') {
                handler->params[param_count].data = pos;
                handler->params[param_count].len = slash - pos;
                param_count++;
                break;
            }

            if (child->name.len == (size_t) (slash - pos) &&
                ngx_memcmp(child->name.data, pos, child->name.len) == 0)
            {
                break;
            }

            child++;
        }

        node = child->node;
        pos = slash + 1;
    }

    handler->data_handler = NULL;
    handler->handler = NULL;

    switch (req->method) {

    case NGX_HTTP_PUT:
        handler->data_handler = node->put;
        break;

    case NGX_HTTP_POST:
        handler->data_handler = node->post;
        break;

    case NGX_HTTP_GET:
        handler->handler = node->get;
        break;

    case NGX_HTTP_DELETE:
        handler->handler = node->del;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_get_route_node: unsupported method %ui",
            req->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (!handler->handler && !handler->data_handler) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_get_route_node: "
            "method %ui not allowed in route \"%V\"", req->method, &req->uri);
        return NGX_HTTP_NOT_ALLOWED;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_http_api_multi_get_method(ngx_str_t *str)
{
    ngx_http_api_method_t  *cur;

    for (cur = methods; cur->name.len; cur++) {
        if (ngx_str_equals(cur->name, *str)) {
            return cur->method;
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_api_multi_parse(ngx_http_request_t *r, ngx_json_object_t *obj,
    ngx_http_api_request_t *req)
{
    ngx_uint_t             i, n;
    ngx_json_key_value_t  *elts;

    ngx_memzero(req, sizeof(*req));

    elts = obj->elts;
    n = obj->nelts;

    for (i = 0; i < n; i++) {

        if (elts[i].value.type == NGX_JSON_STRING) {
            if (ngx_str_equals_c(elts[i].key, "uri")) {
                req->uri = elts[i].value.v.str.s;
                continue;

            } else if (ngx_str_equals_c(elts[i].key, "method")) {
                req->method = ngx_http_api_multi_get_method(
                    &elts[i].value.v.str.s);
                if (!req->method) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "ngx_http_api_multi_parse: invalid method \"%V\"",
                        &elts[i].value.v.str);
                    return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
                }
                continue;
            }
        }

        if (ngx_str_equals_c(elts[i].key, "body")) {
            req->body = elts[i].value;
        }
    }

    if (!req->method || !req->uri.len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_multi_parse: missing \"method\" / \"uri\"");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_api_multi_run_single(ngx_http_request_t *r,
    ngx_http_api_route_node_t *root, ngx_json_object_t *obj,
    ngx_str_t *response)
{
    ngx_int_t               rc;
    ngx_http_api_request_t  req;
    ngx_http_api_handler_t  handler;

    rc = ngx_http_api_multi_parse(r, obj, &req);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_http_api_multi_run_single: "
        "method: %ui, uri: %V", req.method, &req.uri);

    rc = ngx_http_api_get_route_node(r, &req, root, &handler);
    if (rc != NGX_OK) {
        return rc;
    }

    if (handler.handler != NULL) {
        if (req.body.type != NGX_JSON_NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_api_multi_run_single: "
                "\"body\" not allowed in GET/DELETE");
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        rc = handler.handler(r, handler.params, response);

    } else {
        if (req.body.type == NGX_JSON_NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_api_multi_run_single: missing \"body\" in POST/PUT");
            return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        rc = handler.data_handler(r, handler.params, &req.body);
    }

    return rc;
}


static ngx_int_t
ngx_http_api_multi_append(ngx_http_request_t *r, ngx_int_t rc,
    ngx_str_t *response)
{
    size_t               size;
    u_char              *p;
    ngx_str_t            buf;
    ngx_http_api_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    size = sizeof("}," NGX_HTTP_API_MULTI_CODE "000") - 1;
    if (response->len) {
        size += sizeof(NGX_HTTP_API_MULTI_BODY) - 1;
    }

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_multi_append: alloc buf failed");
        return NGX_ERROR;
    }

    buf.data = p;

    if (ctx->out == NULL) {
        *p++ = '[';

    } else {
        *p++ = '}';
        *p++ = ',';
    }

    if (rc == NGX_OK) {
        rc = response->len ? NGX_HTTP_OK : NGX_HTTP_NO_CONTENT;

    } else if (rc < 200 || rc > 599) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_copy(p, NGX_HTTP_API_MULTI_CODE,
        sizeof(NGX_HTTP_API_MULTI_CODE) - 1);
    p = ngx_sprintf(p, "%i", rc);

    if (response->len) {
        p = ngx_copy(p, NGX_HTTP_API_MULTI_BODY,
            sizeof(NGX_HTTP_API_MULTI_BODY) - 1);
        buf.len = p - buf.data;

        if (ngx_http_api_append_buf(r, &buf, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        buf = *response;

    } else {
        buf.len = p - buf.data;
    }

    if (ngx_http_api_append_buf(r, &buf, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_api_multi_state_machine(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_str_t            response;
    ngx_http_api_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    for ( ;; ) {

        if ((void *) ctx->obj >= ctx->part->last) {
            if (ctx->part->next == NULL) {
                break;
            }

            ctx->part = ctx->part->next;
            ctx->obj = ctx->part->first;
        }

        response.len = 0;
        rc = ngx_http_api_multi_run_single(r, ctx->root, ctx->obj, &response);

        ctx->obj++;

        if (rc == NGX_DONE) {
            return;
        }

        if (ngx_http_api_multi_append(r, rc, &response) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    rc = ngx_http_api_send_response(r, NGX_OK, &ngx_http_api_multi_end);

done:

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_api_multi_event_handler(ngx_event_t *ev)
{
    ngx_http_request_t  *r = ev->data;

    ngx_http_api_multi_state_machine(r);
}


static void
ngx_http_api_multi_handler(ngx_http_request_t *r, ngx_json_value_t *body)
{
    ngx_http_api_ctx_t  *ctx;

    if (body->type != NGX_JSON_ARRAY
        || body->v.arr.type != NGX_JSON_OBJECT
        || !body->v.arr.count)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_multi_handler: "
            "request body must be an array of objects");
        ngx_http_finalize_request(r, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    ctx->part = &body->v.arr.part;
    ctx->obj = ctx->part->first;
    ctx->multi = 1;

    ctx->event.data = r;
    ctx->event.handler = ngx_http_api_multi_event_handler;
    ctx->event.log = r->connection->log;

    ngx_http_api_multi_state_machine(r);
}


void
ngx_http_api_done(ngx_http_request_t *r, ngx_int_t rc, ngx_str_t *response)
{
    ngx_http_api_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    if (ctx->multi) {
        if (ngx_http_api_multi_append(r, rc, response) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        ngx_post_event(&ctx->event, &ngx_posted_events);
        return;
    }

    if (rc == NGX_OK) {
        rc = ngx_http_api_send_response(r, NGX_OK, response);
    }

done:

    ngx_http_finalize_request(r, rc);
}

static void
ngx_http_api_body_handler(ngx_http_request_t *r)
{
    size_t               size;
    ngx_buf_t           *b, *nb;
    ngx_int_t            rc;
    ngx_str_t            response;
    ngx_uint_t           status;
    ngx_chain_t         *cl;
    ngx_json_value_t    *json;
    ngx_http_api_ctx_t  *ctx;
    u_char               error[128];

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_body_handler: no request body");
        rc = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        goto done;
    }

    if (r->request_body->temp_file) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_body_handler: request body was saved to temp file");
        rc = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        goto done;
    }

    cl = r->request_body->bufs;
    b = cl->buf;
    if (cl->next || b->last >= b->end) {

        size = b->last - b->pos;
        for (cl = cl->next; cl != NULL; cl = cl->next) {
            b = cl->buf;
            size += b->last - b->pos;
        }

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_body_handler: "
            "copying request body, size: %uz", size);

        nb = ngx_create_temp_buf(r->connection->pool, size + 1);
        if (nb == NULL) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            b = cl->buf;
            nb->last = ngx_copy(nb->last, b->pos, b->last - b->pos);
        }

        b = nb;
    }

    *b->last = '\0';

    /* Note: json must be allocated on heap for multirequest - it contains
        the first list part */

    json = ngx_palloc(r->pool, sizeof(*json));
    if (json == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_body_handler: failed to alloc json");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_http_api_body_handler: body: %s", b->pos);

    rc = ngx_json_parse(r->pool, b->pos, json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_body_handler: failed to parse json %i, %s",
            rc, error);
        rc = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        goto done;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    if (ctx->handler.data_handler == NULL) {
        ngx_http_api_multi_handler(r, json);
        return;
    }

    rc = ctx->handler.data_handler(r, ctx->handler.params, json);
    if (rc == NGX_OK) {
        status = NGX_HTTP_NO_CONTENT;

    } else if (rc >= NGX_HTTP_OK && rc < NGX_HTTP_SPECIAL_RESPONSE) {
        status = rc;

    } else if (rc == NGX_DONE) {
        return;

    } else {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_body_handler: handler failed %i", rc);
        goto done;
    }

    response.len = 0;
    rc = ngx_http_api_send_response(r, status, &response);

done:
    ngx_http_finalize_request(r, rc);
}


ngx_int_t
ngx_http_api_handler(ngx_http_request_t *r, ngx_http_api_route_node_t *root)
{
    ngx_int_t                  rc;
    ngx_str_t                  value;
    ngx_str_t                  response;
    ngx_table_elt_t           *content_type;
    ngx_http_api_ctx_t        *ctx;
    ngx_http_api_request_t     req;
    ngx_http_api_handler_t     handler;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_http_api_handler: called");

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* get the route */
    req.uri = r->uri;
    if (clcf->regex == NULL && clcf->name.len <= req.uri.len) {
        req.uri.data += clcf->name.len;
        req.uri.len -= clcf->name.len;
    }

    if (req.uri.len && req.uri.data[0] == '/') {
        req.uri.data++;
        req.uri.len--;
    }

    req.method = r->method;

    if (req.method == NGX_HTTP_POST && ngx_str_equals_c(req.uri, "multi")) {
        handler.handler = NULL;
        handler.data_handler = NULL;

    } else {
        rc = ngx_http_api_get_route_node(r, &req, root, &handler);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_handler: failed to alloc ctx");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->last = &ctx->out;

    ctx->pretty = ngx_http_arg(r, (u_char *) "pretty", 6, &value) == NGX_OK &&
        value.len == 1 && value.data[0] == '1';

    ngx_http_set_ctx(r, ctx, ngx_http_api_module);

    if (handler.handler != NULL) {

        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_handler: discard request body failed %i", rc);
            return rc;
        }

        response.len = 0;
        rc = handler.handler(r, handler.params, &response);
        if (rc != NGX_OK) {
            if (rc == NGX_DONE) {
                r->main->count++;
                return rc;
            }

            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_handler: handler failed %i", rc);
            return rc;
        }

        return ngx_http_api_send_response(r, NGX_OK, &response);
    }

    content_type = r->headers_in.content_type;
    if (content_type == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_handler: missing content type");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (content_type->value.len < ngx_http_api_json_type.len
        || ngx_strncasecmp(content_type->value.data,
            ngx_http_api_json_type.data,
            ngx_http_api_json_type.len)
        != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_handler: invalid content type %V",
            &content_type->value);
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ctx->handler = handler;
    ctx->root = root;

    r->request_body_in_single_buf = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_api_body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_handler: read request body failed %i", rc);
        return rc;
    }

    return NGX_DONE;
}

char *
ngx_http_api_parse_options(ngx_conf_t *cf, ngx_http_api_options_t *options)
{
    u_char                    *s;
    ngx_str_t                 *value;
    ngx_uint_t                 i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "write=", 6) == 0) {

            s = &value[i].data[6];
            if (ngx_strcmp(s, "on") == 0) {
                options->write = 1;

            } else if (ngx_strcmp(s, "off") == 0) {
                options->write = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid parameter: %V", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "upsert=", 7) == 0) {

            s = &value[i].data[7];
            if (ngx_strcmp(s, "on") == 0) {
                options->upsert = 1;

            } else if (ngx_strcmp(s, "off") == 0) {
                options->upsert = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid parameter: %V", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
