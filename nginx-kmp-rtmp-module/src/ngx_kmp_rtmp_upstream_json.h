/* auto-generated by generate_json_header.py */

#ifndef ngx_array_entries
#define ngx_array_entries(x)     (sizeof(x) / sizeof(x[0]))
#endif

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

#ifndef ngx_copy_str
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)
#endif

/* ngx_kmp_rtmp_connect_data_json reader */

typedef struct {
    ngx_str_t  upstream_id;
    ngx_str_t  url;
    ngx_str_t  header;
    ngx_str_t  opaque;
    ngx_str_t  app;
    ngx_str_t  name;
    ngx_str_t  flash_ver;
    ngx_str_t  swf_url;
    ngx_str_t  tc_url;
    ngx_str_t  page_url;
} ngx_kmp_rtmp_connect_data_json_t;


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_upstream_id = {
    ngx_string("upstream_id"),
    98959125351178751ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, upstream_id),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_url = {
    ngx_string("url"),
    116079ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, url),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_header = {
    ngx_string("header"),
    3073696397ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, header),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_opaque = {
    ngx_string("opaque"),
    3284272161ULL,
    NGX_JSON_STRING,
    ngx_json_set_raw_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, opaque),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_app = {
    ngx_string("app"),
    96801ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, app),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_name = {
    ngx_string("name"),
    3373707ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, name),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_flash_ver = {
    ngx_string("flash_ver"),
    90055727345364ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, flash_ver),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_swf_url = {
    ngx_string("swf_url"),
    105566937650ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, swf_url),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_tc_url = {
    ngx_string("tc_url"),
    3415356319ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, tc_url),
    NULL
};


static ngx_json_prop_t  ngx_kmp_rtmp_connect_data_json_page_url = {
    ngx_string("page_url"),
    3170545661887ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_kmp_rtmp_connect_data_json_t, page_url),
    NULL
};


static ngx_json_prop_t  *ngx_kmp_rtmp_connect_data_json[] = {
    NULL,
    &ngx_kmp_rtmp_connect_data_json_opaque,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_app,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_header,
    NULL,
    NULL,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_upstream_id,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_tc_url,
    NULL,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_flash_ver,
    &ngx_kmp_rtmp_connect_data_json_url,
    NULL,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_swf_url,
    &ngx_kmp_rtmp_connect_data_json_page_url,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &ngx_kmp_rtmp_connect_data_json_name,
};


/* ngx_kmp_rtmp_upstream_streams_json writer */

size_t
ngx_kmp_rtmp_upstream_streams_json_get_size(ngx_kmp_rtmp_upstream_t *obj)
{
    size_t                  result;
    ngx_queue_t            *q;
    ngx_kmp_rtmp_stream_t  *cur;

    result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&obj->streams.queue);
        q != ngx_queue_sentinel(&obj->streams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);
        result += cur->sn.str.len + cur->id_escape;
        result += ngx_kmp_rtmp_stream_json_get_size(cur) + sizeof(",\"\":") -
            1;
    }

    return result;
}


u_char *
ngx_kmp_rtmp_upstream_streams_json_write(u_char *p, ngx_kmp_rtmp_upstream_t
    *obj)
{
    ngx_queue_t            *q;
    ngx_kmp_rtmp_stream_t  *cur;

    *p++ = '{';

    for (q = ngx_queue_head(&obj->streams.queue);
        q != ngx_queue_sentinel(&obj->streams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);

        if (p[-1] != '{') {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
        *p++ = ':';
        p = ngx_kmp_rtmp_stream_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}


/* ngx_kmp_rtmp_upstream_stream_ids_json writer */

size_t
ngx_kmp_rtmp_upstream_stream_ids_json_get_size(ngx_kmp_rtmp_upstream_t *obj)
{
    size_t                  result;
    ngx_queue_t            *q;
    ngx_kmp_rtmp_stream_t  *cur;

    result =
        sizeof("[") - 1 +
        sizeof("]") - 1;

    for (q = ngx_queue_head(&obj->streams.queue);
        q != ngx_queue_sentinel(&obj->streams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);
        result += cur->sn.str.len + cur->id_escape + sizeof(",\"\"") - 1;
    }

    return result;
}


u_char *
ngx_kmp_rtmp_upstream_stream_ids_json_write(u_char *p, ngx_kmp_rtmp_upstream_t
    *obj)
{
    ngx_queue_t            *q;
    ngx_kmp_rtmp_stream_t  *cur;

    *p++ = '[';

    for (q = ngx_queue_head(&obj->streams.queue);
        q != ngx_queue_sentinel(&obj->streams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_stream_t, queue);

        if (p[-1] != '[') {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
    }

    *p++ = ']';

    return p;
}


/* ngx_kmp_rtmp_upstream_json writer */

size_t
ngx_kmp_rtmp_upstream_json_get_size(ngx_kmp_rtmp_upstream_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"url\":\"") - 1 + ngx_json_str_get_size(&obj->url) +
        sizeof("\",\"header\":\"") - 1 + ngx_json_str_get_size(&obj->header) +
        sizeof("\",\"opaque\":\"") - 1 + obj->opaque.len +
        sizeof("\",\"remote_addr\":\"") - 1 +
            ngx_json_str_get_size(&obj->remote_addr) +
        sizeof("\",\"local_addr\":\"") - 1 +
            ngx_json_str_get_size(&obj->local_addr) +
        sizeof("\",\"connection\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"mem_limit\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"mem_left\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"written_bytes\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"sent_bytes\":") - 1 + NGX_OFF_T_LEN +
        sizeof(",\"received_bytes\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"streams\":") - 1 +
            ngx_kmp_rtmp_upstream_streams_json_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


u_char *
ngx_kmp_rtmp_upstream_json_write(u_char *p, ngx_kmp_rtmp_upstream_t *obj)
{
    p = ngx_copy_fix(p, "{\"url\":\"");
    p = ngx_json_str_write(p, &obj->url);
    p = ngx_copy_fix(p, "\",\"header\":\"");
    p = ngx_json_str_write(p, &obj->header);
    p = ngx_copy_fix(p, "\",\"opaque\":\"");
    p = ngx_copy_str(p, obj->opaque);
    p = ngx_copy_fix(p, "\",\"remote_addr\":\"");
    p = ngx_json_str_write(p, &obj->remote_addr);
    p = ngx_copy_fix(p, "\",\"local_addr\":\"");
    p = ngx_json_str_write(p, &obj->local_addr);
    p = ngx_copy_fix(p, "\",\"connection\":");
    p = ngx_sprintf(p, "%uA", (ngx_atomic_uint_t) obj->log.connection);
    p = ngx_copy_fix(p, ",\"mem_limit\":");
    p = ngx_sprintf(p, "%uz", (size_t) obj->mem_limit);
    p = ngx_copy_fix(p, ",\"mem_left\":");
    p = ngx_sprintf(p, "%uz", (size_t) obj->mem_left);
    p = ngx_copy_fix(p, ",\"written_bytes\":");
    p = ngx_sprintf(p, "%uz", (size_t) obj->written_bytes);
    p = ngx_copy_fix(p, ",\"sent_bytes\":");
    p = ngx_sprintf(p, "%O", (off_t) (obj->peer.connection ?
        obj->peer.connection->sent : 0));
    p = ngx_copy_fix(p, ",\"received_bytes\":");
    p = ngx_sprintf(p, "%uz", (size_t) obj->received_bytes);
    p = ngx_copy_fix(p, ",\"streams\":");
    p = ngx_kmp_rtmp_upstream_streams_json_write(p, obj);
    *p++ = '}';

    return p;
}


/* ngx_kmp_rtmp_upstream_free_json writer */

static size_t
ngx_kmp_rtmp_upstream_free_json_get_size(ngx_kmp_rtmp_upstream_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"event_type\":\"rtmp_close\",\"reason\":\"") - 1 +
            ngx_json_str_get_size(&obj->free_reason) +
        sizeof("\",\"upstream_id\":\"") - 1 + obj->sn.str.len + obj->id_escape
            +
        sizeof("\",\"url\":\"") - 1 + ngx_json_str_get_size(&obj->url) +
        sizeof("\",\"header\":\"") - 1 + ngx_json_str_get_size(&obj->header) +
        sizeof("\",\"opaque\":\"") - 1 + obj->opaque.len +
        sizeof("\"}") - 1;

    return result;
}


static u_char *
ngx_kmp_rtmp_upstream_free_json_write(u_char *p, ngx_kmp_rtmp_upstream_t *obj)
{
    p = ngx_copy_fix(p, "{\"event_type\":\"rtmp_close\",\"reason\":\"");
    p = ngx_json_str_write(p, &obj->free_reason);
    p = ngx_copy_fix(p, "\",\"upstream_id\":\"");
    p = ngx_json_str_write_escape(p, &obj->sn.str, obj->id_escape);
    p = ngx_copy_fix(p, "\",\"url\":\"");
    p = ngx_json_str_write(p, &obj->url);
    p = ngx_copy_fix(p, "\",\"header\":\"");
    p = ngx_json_str_write(p, &obj->header);
    p = ngx_copy_fix(p, "\",\"opaque\":\"");
    p = ngx_copy_str(p, obj->opaque);
    p = ngx_copy_fix(p, "\"}");

    return p;
}


/* ngx_kmp_rtmp_upstreams_json writer */

size_t
ngx_kmp_rtmp_upstreams_json_get_size(void *obj)
{
    size_t                    result;
    ngx_queue_t              *q;
    ngx_kmp_rtmp_upstream_t  *cur;

    result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&ngx_kmp_rtmp_upstreams.queue);
        q != ngx_queue_sentinel(&ngx_kmp_rtmp_upstreams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_upstream_t, queue);
        result += cur->sn.str.len + cur->id_escape;
        result += ngx_kmp_rtmp_upstream_json_get_size(cur) + sizeof(",\"\":")
            - 1;
    }

    return result;
}


u_char *
ngx_kmp_rtmp_upstreams_json_write(u_char *p, void *obj)
{
    ngx_queue_t              *q;
    ngx_kmp_rtmp_upstream_t  *cur;

    *p++ = '{';

    for (q = ngx_queue_head(&ngx_kmp_rtmp_upstreams.queue);
        q != ngx_queue_sentinel(&ngx_kmp_rtmp_upstreams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_upstream_t, queue);

        if (p[-1] != '{') {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
        *p++ = ':';
        p = ngx_kmp_rtmp_upstream_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}


/* ngx_kmp_rtmp_upstream_ids_json writer */

size_t
ngx_kmp_rtmp_upstream_ids_json_get_size(void *obj)
{
    size_t                    result;
    ngx_queue_t              *q;
    ngx_kmp_rtmp_upstream_t  *cur;

    result =
        sizeof("[") - 1 +
        sizeof("]") - 1;

    for (q = ngx_queue_head(&ngx_kmp_rtmp_upstreams.queue);
        q != ngx_queue_sentinel(&ngx_kmp_rtmp_upstreams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_upstream_t, queue);
        result += cur->sn.str.len + cur->id_escape + sizeof(",\"\"") - 1;
    }

    return result;
}


u_char *
ngx_kmp_rtmp_upstream_ids_json_write(u_char *p, void *obj)
{
    ngx_queue_t              *q;
    ngx_kmp_rtmp_upstream_t  *cur;

    *p++ = '[';

    for (q = ngx_queue_head(&ngx_kmp_rtmp_upstreams.queue);
        q != ngx_queue_sentinel(&ngx_kmp_rtmp_upstreams.queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_rtmp_upstream_t, queue);

        if (p[-1] != '[') {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
    }

    *p++ = ']';

    return p;
}
