#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_api.h"


#define NGX_HTTP_API_MAX_ROUTE_PARAMS  (2)


typedef struct {
    ngx_http_api_route_data_handler_pt  handler;
    ngx_str_t                           params[NGX_HTTP_API_MAX_ROUTE_PARAMS];
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


ngx_int_t
ngx_http_api_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *response)
{
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t   out;

    r->headers_out.content_type = ngx_http_api_json_type;
    r->headers_out.content_length_n = response->len;
    r->headers_out.status = status;

    if (r->method == NGX_HTTP_HEAD || (r != r->main && response->len == 0)) {
        return ngx_http_send_header(r);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_send_response: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (response->len) {
        b->pos = response->data;
        b->last = response->data + response->len;
        b->memory = 1;
    }

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void
ngx_http_api_body_handler(ngx_http_request_t *r)
{
    ngx_buf_t           *b;
    ngx_int_t            rc;
    ngx_str_t            response;
    ngx_uint_t           status;
    ngx_json_value_t     json;
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

    b = r->request_body->bufs->buf;
    if (b->last >= b->end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_body_handler: no room for null terminator");
        rc = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        goto done;
    }

    *b->last = '\0';

    rc = ngx_json_parse(r->pool, b->pos, &json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_body_handler: failed to parse json %i, %s",
            rc, error);
        rc = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
        goto done;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_api_module);

    rc = ctx->handler(r, ctx->params, &json);
    if (rc >= NGX_HTTP_OK && rc < NGX_HTTP_SPECIAL_RESPONSE) {
        status = rc;

    } else if (rc == NGX_OK) {
        status = NGX_HTTP_NO_CONTENT;

    } else if (rc == NGX_DONE) {
        goto done;

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

static ngx_http_api_route_node_t*
ngx_http_api_get_route_node(ngx_http_request_t *r,
    ngx_http_api_route_node_t *root, ngx_str_t *params,
    ngx_uint_t *param_count)
{
    u_char                      *pos;
    u_char                      *last;
    u_char                      *slash;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_api_route_node_t   *node;
    ngx_http_api_route_child_t  *child;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* get the route */
    pos = r->uri.data;
    if (clcf->regex == NULL && clcf->name.len <= r->uri.len) {
        pos += clcf->name.len;
    }

    last = r->uri.data + r->uri.len;

    if (pos < last && *pos == '/') {
        pos++;
    }

    /* find the route handler */
    node = root;
    *param_count = 0;

    while (pos < last) {

        slash = ngx_strlchr(pos, last, '/');
        if (slash == NULL) {
            slash = last;
        }

        if (node->children == NULL) {
            return NULL;
        }

        for (child = node->children; ; child++) {

            if (child->name.len == 0) {
                return NULL;
            }

            if (child->name.len == 1 && child->name.data[0] == '%') {
                params[*param_count].data = pos;
                params[*param_count].len = slash - pos;
                (*param_count)++;
                break;
            }

            if (child->name.len == (size_t)(slash - pos) &&
                ngx_memcmp(child->name.data, pos, child->name.len) == 0)
            {
                break;
            }
        }

        node = child->node;
        pos = slash + 1;
    }

    return node;
}

ngx_int_t
ngx_http_api_handler(ngx_http_request_t *r, ngx_http_api_route_node_t *root)
{
    ngx_int_t                            rc;
    ngx_str_t                            params[NGX_HTTP_API_MAX_ROUTE_PARAMS];
    ngx_str_t                            response;
    ngx_uint_t                           status;
    ngx_uint_t                           param_count;
    ngx_table_elt_t                     *content_type;
    ngx_http_api_ctx_t                  *ctx;
    ngx_http_api_route_node_t           *node;
    ngx_http_api_route_handler_pt        handler;
    ngx_http_api_route_data_handler_pt   data_handler;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "ngx_http_api_handler: called");

    node = ngx_http_api_get_route_node(r, root, params, &param_count);
    if (node == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_handler: route not found");
        return NGX_HTTP_BAD_REQUEST;
    }

    data_handler = NULL;
    handler = NULL;
    switch (r->method) {

    case NGX_HTTP_PUT:
        data_handler = node->put;
        break;

    case NGX_HTTP_POST:
        data_handler = node->post;
        break;

    case NGX_HTTP_GET:
        handler = node->get;
        break;

    case NGX_HTTP_DELETE:
        handler = node->del;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_handler: unsupported method %ui", r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (handler != NULL) {

        rc = ngx_http_discard_request_body(r);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_handler: discard request body failed %i", rc);
            return rc;
        }

        response.len = 0;
        rc = handler(r, params, &response);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_api_handler: handler failed %i", rc);
            return rc;
        }

        status = response.len > 0 ? NGX_HTTP_OK : NGX_HTTP_NO_CONTENT;
        return ngx_http_api_send_response(r, status, &response);
    }

    if (data_handler == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_api_handler: method %ui not allowed", r->method);
        return NGX_HTTP_NOT_ALLOWED;
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

    ctx = ngx_palloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_api_handler: failed to alloc ctx");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_api_module);
    ctx->handler = data_handler;
    ngx_memcpy(ctx->params, params, sizeof(params));

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
