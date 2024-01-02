/* auto-generated by generate_routes_header.py */

#ifndef _NGX_HTTP_TS_KMP_API_ROUTES_H_INCLUDED_
#define _NGX_HTTP_TS_KMP_API_ROUTES_H_INCLUDED_

static ngx_http_api_route_node_t  ngx_http_ts_kmp_api_route_sessions_param = {
    NULL,
    NULL,
    NULL,
    &ngx_http_ts_kmp_api_session_delete,
    NULL,
    NULL,
};


static ngx_http_api_route_child_t
    ngx_http_ts_kmp_api_route_sessions_children[] =
{
    { ngx_string("%"), &ngx_http_ts_kmp_api_route_sessions_param },
    { ngx_null_string, NULL },
};


static ngx_http_api_route_node_t  ngx_http_ts_kmp_api_route_sessions = {
    ngx_http_ts_kmp_api_route_sessions_children,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};


static ngx_http_api_route_child_t  ngx_http_ts_kmp_api_route_children[] = {
    { ngx_string("sessions"), &ngx_http_ts_kmp_api_route_sessions },
    { ngx_null_string, NULL },
};


static ngx_int_t ngx_http_ts_kmp_api_list(ngx_http_request_t *r, ngx_str_t
    *params, ngx_str_t *response)
{
    ngx_str_set(response, "[\"multi\",\"sessions\"]");
    return NGX_OK;
}


static ngx_http_api_route_node_t  ngx_http_ts_kmp_api_route = {
    ngx_http_ts_kmp_api_route_children,
    &ngx_http_ts_kmp_api_get,
    &ngx_http_ts_kmp_api_list,
    NULL,
    NULL,
    NULL,
};


#endif /* _NGX_HTTP_TS_KMP_API_ROUTES_H_INCLUDED_ */
