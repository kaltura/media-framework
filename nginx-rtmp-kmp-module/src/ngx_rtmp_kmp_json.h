/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

#ifndef ngx_copy_str
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)
#endif

/* ngx_rtmp_kmp_connect_rtmp_json writer */

static size_t
ngx_rtmp_kmp_connect_rtmp_json_get_size(ngx_rtmp_kmp_connect_t *obj,
    ngx_rtmp_session_t *s)
{
    size_t  result;

    result =
        sizeof("{\"app\":\"") - 1 + ngx_json_str_get_size(&obj->app) +
        sizeof("\",\"flashver\":\"") - 1 +
            ngx_json_str_get_size(&obj->flashver) +
        sizeof("\",\"swf_url\":\"") - 1 + ngx_json_str_get_size(&obj->swf_url)
            +
        sizeof("\",\"tc_url\":\"") - 1 + ngx_json_str_get_size(&obj->tc_url) +
        sizeof("\",\"page_url\":\"") - 1 +
            ngx_json_str_get_size(&obj->page_url) +
        sizeof("\",\"addr\":\"") - 1 + ngx_json_str_get_size(&obj->addr) +
        sizeof("\",\"connection\":") - 1 + NGX_INT_T_LEN +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_rtmp_kmp_connect_rtmp_json_write(u_char *p, ngx_rtmp_kmp_connect_t *obj,
    ngx_rtmp_session_t *s)
{
    p = ngx_copy_fix(p, "{\"app\":\"");
    p = ngx_json_str_write(p, &obj->app);
    p = ngx_copy_fix(p, "\",\"flashver\":\"");
    p = ngx_json_str_write(p, &obj->flashver);
    p = ngx_copy_fix(p, "\",\"swf_url\":\"");
    p = ngx_json_str_write(p, &obj->swf_url);
    p = ngx_copy_fix(p, "\",\"tc_url\":\"");
    p = ngx_json_str_write(p, &obj->tc_url);
    p = ngx_copy_fix(p, "\",\"page_url\":\"");
    p = ngx_json_str_write(p, &obj->page_url);
    p = ngx_copy_fix(p, "\",\"addr\":\"");
    p = ngx_json_str_write(p, &obj->addr);
    p = ngx_copy_fix(p, "\",\"connection\":");
    p = ngx_sprintf(p, "%uA", (ngx_atomic_uint_t) s->connection->number);
    *p++ = '}';

    return p;
}


/* ngx_rtmp_kmp_connect_json writer */

static size_t
ngx_rtmp_kmp_connect_json_get_size(ngx_rtmp_kmp_connect_t *obj,
    ngx_rtmp_session_t *s)
{
    size_t  result;

    result =
        sizeof("{\"event_type\":\"connect\"" ",\"input_type\":\"rtmp\""
            ",\"rtmp\":") - 1 + ngx_rtmp_kmp_connect_rtmp_json_get_size(obj,
            s) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_rtmp_kmp_connect_json_write(u_char *p, ngx_rtmp_kmp_connect_t *obj,
    ngx_rtmp_session_t *s)
{
    p = ngx_copy_fix(p, "{\"event_type\":\"connect\""
        ",\"input_type\":\"rtmp\"" ",\"rtmp\":");
    p = ngx_rtmp_kmp_connect_rtmp_json_write(p, obj, s);
    *p++ = '}';

    return p;
}
