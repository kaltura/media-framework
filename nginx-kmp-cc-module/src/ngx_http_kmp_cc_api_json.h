/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

/* ngx_http_kmp_cc_api_json writer */

static size_t
ngx_http_kmp_cc_api_json_get_size(void *obj)
{
    size_t  result;

    result =
        sizeof("{\"version\":\"") - 1 + ngx_kmp_cc_version.len +
            ngx_escape_json(NULL, ngx_kmp_cc_version.data,
            ngx_kmp_cc_version.len) +
        sizeof("\",\"nginx_version\":\"") - 1 + ngx_kmp_cc_nginx_version.len +
            ngx_escape_json(NULL, ngx_kmp_cc_nginx_version.data,
            ngx_kmp_cc_nginx_version.len) +
        sizeof("\",\"compiler\":\"") - 1 + ngx_kmp_cc_compiler.len +
            ngx_escape_json(NULL, ngx_kmp_cc_compiler.data,
            ngx_kmp_cc_compiler.len) +
        sizeof("\",\"built\":\"") - 1 + ngx_kmp_cc_built.len +
            ngx_escape_json(NULL, ngx_kmp_cc_built.data, ngx_kmp_cc_built.len)
            +
        sizeof("\",\"pid\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"uptime\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"stream\":") - 1 +
            ngx_stream_kmp_cc_stream_json_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_http_kmp_cc_api_json_write(u_char *p, void *obj)
{
    p = ngx_copy_fix(p, "{\"version\":\"");
    p = (u_char *) ngx_escape_json(p, ngx_kmp_cc_version.data,
        ngx_kmp_cc_version.len);
    p = ngx_copy_fix(p, "\",\"nginx_version\":\"");
    p = (u_char *) ngx_escape_json(p, ngx_kmp_cc_nginx_version.data,
        ngx_kmp_cc_nginx_version.len);
    p = ngx_copy_fix(p, "\",\"compiler\":\"");
    p = (u_char *) ngx_escape_json(p, ngx_kmp_cc_compiler.data,
        ngx_kmp_cc_compiler.len);
    p = ngx_copy_fix(p, "\",\"built\":\"");
    p = (u_char *) ngx_escape_json(p, ngx_kmp_cc_built.data,
        ngx_kmp_cc_built.len);
    p = ngx_copy_fix(p, "\",\"pid\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) ngx_getpid());
    p = ngx_copy_fix(p, ",\"uptime\":");
    p = ngx_sprintf(p, "%i", (ngx_int_t) (ngx_cached_time->sec -
        ngx_kmp_cc_start_time));
    p = ngx_copy_fix(p, ",\"stream\":");
    p = ngx_stream_kmp_cc_stream_json_write(p, obj);
    *p++ = '}';

    return p;
}
