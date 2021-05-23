#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_pckg_utils.h"


static ngx_int_t  ngx_http_pckg_error_map[VOD_ERROR_LAST - VOD_ERROR_FIRST] = {
    NGX_HTTP_NOT_FOUND,                 /* VOD_BAD_DATA             */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_ALLOC_FAILED         */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_UNEXPECTED           */
    NGX_HTTP_BAD_REQUEST,               /* VOD_BAD_REQUEST          */
    NGX_HTTP_SERVICE_UNAVAILABLE,       /* VOD_BAD_MAPPING          */
    NGX_HTTP_NOT_FOUND,                 /* VOD_EXPIRED              */
    NGX_HTTP_NOT_FOUND,                 /* VOD_NO_STREAMS           */
    NGX_HTTP_NOT_FOUND,                 /* VOD_EMPTY_MAPPING        */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_NOT_FOUND (internal) */
    NGX_HTTP_INTERNAL_SERVER_ERROR,     /* VOD_REDIRECT (internal)  */
};

u_char  ngx_http_pckg_media_type_code[KMP_MEDIA_COUNT] = {
    'v',
    'a',
};


/* uri parsing */

static u_char *
ngx_http_pckg_parse_uint32(u_char *start_pos, u_char *end_pos,
    uint32_t *result)
{
    uint32_t  value = 0;

    for (;
        start_pos < end_pos && *start_pos >= '0' && *start_pos <= '9';
        start_pos++)
    {
        value = value * 10 + *start_pos - '0';
    }

    *result = value;
    return start_pos;
}


static u_char *
ngx_http_pckg_extract_string(u_char *start_pos, u_char *end_pos,
    ngx_str_t *result)
{
    result->data = start_pos;
    start_pos = ngx_strlchr(start_pos, end_pos, '-');
    if (start_pos == NULL) {
        start_pos = end_pos;
    }

    result->len = start_pos - result->data;
    return start_pos;
}


#define expect_char(start_pos, end_pos, ch)                 \
    if (start_pos >= end_pos || *start_pos != ch) {         \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,   \
            "ngx_http_pckg_parse_uri_file_name: "      \
            "expected \"%c\"", ch);                         \
        return NGX_HTTP_BAD_REQUEST;                        \
    }                                                       \
    start_pos++;

ngx_int_t
ngx_http_pckg_parse_uri_file_name(ngx_http_request_t *r,
    u_char *start_pos, u_char *end_pos, uint32_t flags,
    ngx_pckg_ksmp_req_t *result)
{
    u_char     *p;
    uint32_t    media_type;
    ngx_str_t   cur;

    /* required params */

    if ((flags & NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX) != 0) {
        expect_char(start_pos, end_pos, '-');

        start_pos = ngx_http_pckg_parse_uint32(start_pos, end_pos,
            &result->segment_index);
        if (result->segment_index <= 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_parse_uri_file_name: "
                "failed to parse segment index");
            return NGX_HTTP_BAD_REQUEST;
        }
        result->segment_index--;
    }

    if ((flags & NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT) != 0) {
        expect_char(start_pos, end_pos, '-');
        expect_char(start_pos, end_pos, 's');

        start_pos = ngx_http_pckg_extract_string(start_pos, end_pos,
            &result->variant_ids);
        if (ngx_strlchr(result->variant_ids.data, start_pos, ',') != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_parse_uri_file_name: "
                "invalid variant id \"%V\"", &result->variant_ids);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    /* optional params */

    if (start_pos >= end_pos) {
        return NGX_OK;
    }

    if (*start_pos != '-' || end_pos - start_pos < 2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_parse_uri_file_name: "
            "expected \"-\" followed by a specifier");
        return NGX_HTTP_BAD_REQUEST;
    }

    start_pos++;    /* skip the - */

    if (*start_pos == 's' &&
        (flags & NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS) != 0)
    {
        p = ngx_pnalloc(r->pool, end_pos - start_pos);
        if (p == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_parse_uri_file_name: alloc failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        result->variant_ids.data = p;

        do {

            start_pos++;    /* skip the s */

            if (p > result->variant_ids.data) {
                *p++ = ',';
            }

            start_pos = ngx_http_pckg_extract_string(start_pos, end_pos,
                &cur);

            p = ngx_copy(p, cur.data, cur.len);

            if (start_pos >= end_pos) {
                result->variant_ids.len = p - result->variant_ids.data;
                return NGX_OK;
            }

            if (*start_pos != '-' || end_pos - start_pos < 2) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_pckg_parse_uri_file_name: "
                    "expected \"-\" followed by a specifier");
                return NGX_HTTP_BAD_REQUEST;
            }

            start_pos++;    /* skip the - */

        } while (*start_pos == 's');

        result->variant_ids.len = p - result->variant_ids.data;
    }

    if ((*start_pos == 'v' || *start_pos == 'a') &&
        (flags & NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE) != 0)
    {
        result->media_type_mask = 0;

        while (*start_pos != '-') {

            switch (*start_pos) {

            case 'v':
                media_type = KMP_MEDIA_VIDEO;
                break;

            case 'a':
                media_type = KMP_MEDIA_AUDIO;
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_pckg_parse_uri_file_name: "
                    "invalid media type \"%c\"", *start_pos);
                return NGX_HTTP_BAD_REQUEST;
            }

            if (result->media_type_mask & (1 << media_type)) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_pckg_parse_uri_file_name: "
                    "media type repeats more than once");
                return NGX_HTTP_BAD_REQUEST;
            }

            result->media_type_mask |= (1 << media_type);

            start_pos++;

            if (start_pos >= end_pos) {
                return NGX_OK;
            }
        }

        start_pos++;    /* skip the - */

        if (start_pos >= end_pos) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_parse_uri_file_name: "
                "trailing dash in file name");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "ngx_http_pckg_parse_uri_file_name: "
        "did not consume the whole name");
    return NGX_HTTP_BAD_REQUEST;
}


/* Implemented according to nginx's ngx_http_range_parse,
    dropped multi range support */

ngx_int_t
ngx_http_pckg_range_parse(ngx_str_t *range, off_t content_length,
    off_t *out_start, off_t *out_end)
{
    u_char            *p;
    off_t              start, end, cutoff, cutlim;
    ngx_uint_t         suffix;

    if (range->len < 7
        || ngx_strncasecmp(range->data,
                        (u_char *) "bytes=", 6) != 0)
    {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    p = range->data + 6;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    suffix = 0;

    while (*p == ' ') { p++; }

    if (*p != '-') {
        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            start = start * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p++ != '-') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p == ' ') { p++; }

        if (*p == '\0') {
            end = content_length;
            goto found;
        }

    } else {
        suffix = 1;
        p++;
    }

    if (*p < '0' || *p > '9') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        end = end * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (suffix) {
        start = content_length - end;
        end = content_length - 1;
    }

    if (end >= content_length) {
        end = content_length;

    } else {
        end++;
    }

found:

    if (start >= end) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    *out_start = start;
    *out_end = end;

    return NGX_OK;
}


static u_char *
ngx_http_pckg_write_media_type_mask(u_char *p, uint32_t media_type_mask)
{
    uint32_t  i;

    if (media_type_mask == KMP_MEDIA_TYPE_MASK) {
        return p;
    }

    *p++ = '-';
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {
        if (media_type_mask & (1 << i)) {
            *p++ = ngx_http_pckg_media_type_code[i];
        }
    }

    return p;
}


size_t
ngx_http_pckg_selector_get_size(ngx_pckg_variant_t *variant)
{
    return sizeof("-s-") - 1 + variant->id.len + KMP_MEDIA_COUNT;
}


u_char *
ngx_http_pckg_selector_write(u_char *p, ngx_pckg_variant_t *variant,
    uint32_t media_type_mask)
{
    *p++ = '-';
    *p++ = 's';
    p = ngx_copy_str(p, variant->id);

    p = ngx_http_pckg_write_media_type_mask(p, media_type_mask);

    return p;
}


/* response headers */

/* A run down version of ngx_http_set_expires */
static ngx_int_t
ngx_http_pckg_set_expires(ngx_http_request_t *r, time_t expires_time)
{
    size_t            len;
    time_t            now, max_age;
    ngx_uint_t        i;
    ngx_table_elt_t  *e, *cc, **ccp;

    e = r->headers_out.expires;

    if (e == NULL) {

        e = ngx_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        ngx_str_set(&e->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    e->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    e->value.data = ngx_pnalloc(r->pool, len);
    if (e->value.data == NULL) {
        return NGX_ERROR;
    }

    if (expires_time == 0) {
        ngx_memcpy(e->value.data, ngx_cached_http_time.data,
            ngx_cached_http_time.len + 1);
        ngx_str_set(&cc->value, "max-age=0");
        return NGX_OK;
    }

    now = ngx_time();

    max_age = expires_time;
    expires_time += now;

    ngx_http_time(e->value.data, expires_time);

    if (max_age < 0) {
        ngx_str_set(&cc->value, "no-cache");
        return NGX_OK;
    }

    cc->value.data = ngx_pnalloc(r->pool,
        sizeof("max-age=") + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", max_age)
        - cc->value.data;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_gone(ngx_http_request_t *r)
{
    time_t                          expires_time;
    ngx_int_t                       rc;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    expires_time = plcf->expires[NGX_HTTP_PCKG_EXPIRES_INDEX_GONE];
    if (expires_time >= 0) {
        rc = ngx_http_pckg_set_expires(r, expires_time);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_gone: set expires failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return NGX_HTTP_GONE;
}


ngx_int_t
ngx_http_pckg_send_header(ngx_http_request_t *r, off_t content_length_n,
    ngx_str_t *content_type, time_t last_modified_time,
    ngx_uint_t expires_type)
{
    time_t                          expires_time;
    ngx_int_t                       rc;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    if (content_type != NULL) {
        r->headers_out.content_type = *content_type;
        r->headers_out.content_type_len = content_type->len;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_length_n;

    /* last modified */
    if (last_modified_time >= 0) {
        r->headers_out.last_modified_time = last_modified_time;

    } else if (plcf->last_modified_static >= 0) {
        r->headers_out.last_modified_time = plcf->last_modified_static;
    }

    /* expires */
    expires_time = plcf->expires[expires_type];
    if (expires_time >= 0) {
        rc = ngx_http_pckg_set_expires(r, expires_time);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_send_header: set expires failed %i", rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* etag */
    rc = ngx_http_set_etag(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_send_header: set etag failed %i", rc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* send the response headers */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_send_header: sed header failed %i", rc);
        return rc;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_send_response(ngx_http_request_t *r, ngx_str_t *response)
{
    ngx_buf_t    *b;
    ngx_int_t     rc;
    ngx_chain_t   out;

    if (r->header_only || r->method == NGX_HTTP_HEAD) {
        return NGX_OK;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_send_response: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = response->data;
    b->last = response->data + response->len;
    b->temporary = (response->len > 0) ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_send_response: output filter failed %i", rc);
        return rc;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_status_to_ngx_error(ngx_http_request_t *r, vod_status_t rc)
{
    if (rc < VOD_ERROR_FIRST || rc >= VOD_ERROR_LAST) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_pckg_error_map[rc - VOD_ERROR_FIRST];
}


void
ngx_http_pckg_get_bitrate_estimator(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, media_bitrate_estimator_t *result)
{
    if (container->get_bitrate_estimator == NULL) {
        media_null_bitrate_estimator(*result);
        return;
    }

    container->get_bitrate_estimator(r, media_infos, count, result);
}


uint32_t
ngx_http_pckg_estimate_bitrate(ngx_http_request_t *r,
    ngx_http_pckg_container_t *container, media_info_t **media_infos,
    uint32_t count, uint32_t segment_duration)
{
    uint32_t                    i;
    uint32_t                    result;
    media_bitrate_estimator_t  *est;
    media_bitrate_estimator_t   estimators[KMP_MEDIA_COUNT];

    ngx_http_pckg_get_bitrate_estimator(r, container, media_infos, count,
        estimators);

    result = 0;
    for (i = 0; i < count; i++) {

        est = &estimators[i];
        result += media_bitrate_estimate(*est, media_infos[i]->bitrate,
            segment_duration);
    }

    return result;
}
