#ifndef _NGX_HTTP_API_H_INCLUDED_
#define _NGX_HTTP_API_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_json_parser.h"


typedef ngx_int_t(*ngx_http_api_route_handler_pt)(ngx_http_request_t *r,
    ngx_str_t *params, ngx_str_t *response);

typedef ngx_int_t(*ngx_http_api_route_data_handler_pt)(ngx_http_request_t *r,
    ngx_str_t *params, ngx_json_value_t *body);

typedef struct ngx_http_api_route_child_s ngx_http_api_route_child_t;

typedef struct {
    ngx_http_api_route_child_t          *children;
    ngx_http_api_route_handler_pt        get;
    ngx_http_api_route_handler_pt        del;
    ngx_http_api_route_data_handler_pt   post;
    ngx_http_api_route_data_handler_pt   put;
} ngx_http_api_route_node_t;

struct ngx_http_api_route_child_s {
    ngx_str_t                            name;
    ngx_http_api_route_node_t           *node;
};


typedef struct {
    unsigned    write:1;
    unsigned  upsert:1;
} ngx_http_api_options_t;


ngx_int_t ngx_http_api_handler(ngx_http_request_t *r,
    ngx_http_api_route_node_t *root);

char *ngx_http_api_parse_options(ngx_conf_t *cf,
    ngx_http_api_options_t *options);


#endif /* _NGX_HTTP_API_H_INCLUDED_ */