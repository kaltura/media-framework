/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

#ifndef ngx_copy_str
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)
#endif

/* ngx_http_rtmp_kmp_api_json writer */

static size_t
ngx_http_rtmp_kmp_api_json_get_size(void *obj)
{
    size_t  result;

    result =
        sizeof("{\"version\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_rtmp_kmp_version) +
        sizeof("\",\"nginx_version\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_rtmp_kmp_nginx_version) +
        sizeof("\",\"rtmp_version\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_rtmp_kmp_rtmp_version) +
        sizeof("\",\"compiler\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_rtmp_kmp_compiler) +
        sizeof("\",\"built\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_rtmp_kmp_built) +
        sizeof("\",\"pid\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"uptime\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"naccepted\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"bw_in\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"bytes_in\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"bw_out\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"bytes_out\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"servers\":") - 1 +
            ngx_rtmp_kmp_api_servers_json_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_http_rtmp_kmp_api_json_write(u_char *p, void *obj)
{
    p = ngx_copy_fix(p, "{\"version\":\"");
    p = ngx_json_str_write(p, &ngx_http_rtmp_kmp_version);
    p = ngx_copy_fix(p, "\",\"nginx_version\":\"");
    p = ngx_json_str_write(p, &ngx_http_rtmp_kmp_nginx_version);
    p = ngx_copy_fix(p, "\",\"rtmp_version\":\"");
    p = ngx_json_str_write(p, &ngx_http_rtmp_kmp_rtmp_version);
    p = ngx_copy_fix(p, "\",\"compiler\":\"");
    p = ngx_json_str_write(p, &ngx_http_rtmp_kmp_compiler);
    p = ngx_copy_fix(p, "\",\"built\":\"");
    p = ngx_json_str_write(p, &ngx_http_rtmp_kmp_built);
    p = ngx_copy_fix(p, "\",\"pid\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) ngx_getpid());
    p = ngx_copy_fix(p, ",\"uptime\":");
    p = ngx_sprintf(p, "%i", (ngx_int_t) (ngx_cached_time->sec -
        ngx_http_rtmp_kmp_start_time));
    p = ngx_copy_fix(p, ",\"naccepted\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) ngx_rtmp_naccepted);
    p = ngx_copy_fix(p, ",\"bw_in\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) (ngx_rtmp_bw_in.bandwidth * 8));
    p = ngx_copy_fix(p, ",\"bytes_in\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) ngx_rtmp_bw_in.bytes);
    p = ngx_copy_fix(p, ",\"bw_out\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) (ngx_rtmp_bw_out.bandwidth * 8));
    p = ngx_copy_fix(p, ",\"bytes_out\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) ngx_rtmp_bw_out.bytes);
    p = ngx_copy_fix(p, ",\"servers\":");
    p = ngx_rtmp_kmp_api_servers_json_write(p, obj);
    *p++ = '}';

    return p;
}