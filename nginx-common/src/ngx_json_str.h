#ifndef _NGX_JSON_STR_H_INCLUDED_
#define _NGX_JSON_STR_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define ngx_json_str_get_size(js)     ((js)->s.len + (js)->escape)

#define ngx_json_str_set_escape(js)                                          \
    (js)->escape = ngx_escape_json(NULL, (js)->s.data, (js)->s.len);

#define ngx_json_str_get_escape(s)                                           \
    ngx_escape_json(NULL, (s)->data, (s)->len);


typedef struct {
    ngx_str_t  s;
    uintptr_t  escape;
} ngx_json_str_t;


static ngx_inline u_char *
ngx_json_str_write(u_char *p, ngx_json_str_t *str)
{
    if (str->escape) {
        return (u_char *) ngx_escape_json(p, str->s.data, str->s.len);
    }

    return ngx_copy(p, str->s.data, str->s.len);
}


static ngx_inline u_char *
ngx_json_str_write_escape(u_char *p, ngx_str_t *str, uintptr_t escape)
{
    if (escape) {
        return (u_char *) ngx_escape_json(p, str->data, str->len);
    }

    return ngx_copy(p, str->data, str->len);
}

#endif /* _NGX_JSON_STR_H_INCLUDED_ */
