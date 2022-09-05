#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_kmp_out_utils.h"
#include "ngx_kmp_out_connect.h"
#include "ngx_kmp_out_connect_json.h"


static ngx_str_t  ngx_kmp_out_connect_code_ok = ngx_string("ok");


ngx_int_t
ngx_kmp_out_connect_parse(ngx_pool_t *pool, ngx_log_t *log, ngx_uint_t code,
    ngx_str_t *content_type, ngx_buf_t *body, ngx_str_t *desc)
{
    ngx_json_value_t            obj;
    ngx_kmp_out_connect_json_t  json;

    if (ngx_kmp_out_parse_json_response(pool, log, code, content_type,
        body, &obj) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_out_connect_parse: parse response failed");
        return NGX_ERROR;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(pool, &obj.v.obj, ngx_kmp_out_connect_json,
        ngx_array_entries(ngx_kmp_out_connect_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_out_connect_parse: failed to parse object");
        return NGX_ERROR;
    }


    if (json.code.data == NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_out_connect_parse: missing \"code\" element in json");
        return NGX_ERROR;
    }

    if (json.code.len != ngx_kmp_out_connect_code_ok.len ||
        ngx_strncasecmp(json.code.data, ngx_kmp_out_connect_code_ok.data,
            ngx_kmp_out_connect_code_ok.len) != 0)
    {
        if (json.message.data != NGX_JSON_UNSET_PTR) {
            *desc = json.message;
            desc->data[desc->len] = '\0';

        } else {
            desc->len = 0;
            desc->data = NULL;
        }

        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_out_connect_parse: "
            "bad code \"%V\" in json, message=\"%V\"", &json.code, desc);

        return NGX_DECLINED;
    }

    return NGX_OK;
}
