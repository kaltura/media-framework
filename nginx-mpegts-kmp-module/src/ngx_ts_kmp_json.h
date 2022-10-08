/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

#ifndef ngx_copy_str
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)
#endif

/* ngx_ts_kmp_connect_mpegts_json writer */

static size_t
ngx_ts_kmp_connect_mpegts_json_get_size(ngx_ts_kmp_connect_t *obj,
    ngx_connection_t *c)
{
    size_t  result;

    result =
        sizeof("{\"stream_id\":\"") - 1 + obj->stream_id.len +
            ngx_escape_json(NULL, obj->stream_id.data, obj->stream_id.len) +
        sizeof("\",\"addr\":\"") - 1 + c->addr_text.len +
            ngx_escape_json(NULL, c->addr_text.data, c->addr_text.len) +
        sizeof("\",\"connection\":") - 1 + NGX_INT_T_LEN +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_ts_kmp_connect_mpegts_json_write(u_char *p, ngx_ts_kmp_connect_t *obj,
    ngx_connection_t *c)
{
    p = ngx_copy_fix(p, "{\"stream_id\":\"");
    p = (u_char *) ngx_escape_json(p, obj->stream_id.data, obj->stream_id.len);
    p = ngx_copy_fix(p, "\",\"addr\":\"");
    p = (u_char *) ngx_escape_json(p, c->addr_text.data, c->addr_text.len);
    p = ngx_copy_fix(p, "\",\"connection\":");
    p = ngx_sprintf(p, "%uA", (ngx_atomic_uint_t) c->number);
    *p++ = '}';

    return p;
}


/* ngx_ts_kmp_connect_json writer */

static size_t
ngx_ts_kmp_connect_json_get_size(ngx_ts_kmp_connect_t *obj, ngx_connection_t
    *c)
{
    size_t  result;

    result =
        sizeof("{\"event_type\":\"connect\"" ",\"input_type\":\"mpegts\""
            ",\"mpegts\":") - 1 + ngx_ts_kmp_connect_mpegts_json_get_size(obj,
            c) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_ts_kmp_connect_json_write(u_char *p, ngx_ts_kmp_connect_t *obj,
    ngx_connection_t *c)
{
    p = ngx_copy_fix(p, "{\"event_type\":\"connect\""
        ",\"input_type\":\"mpegts\"" ",\"mpegts\":");
    p = ngx_ts_kmp_connect_mpegts_json_write(p, obj, c);
    *p++ = '}';

    return p;
}
