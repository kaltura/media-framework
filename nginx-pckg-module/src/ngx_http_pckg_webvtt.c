#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_webvtt.h"
#include "ngx_http_pckg_utils.h"

#include "media/subtitle/subtitle_format.h"
#include "media/subtitle/webvtt_builder.h"


static ngx_int_t ngx_http_pckg_webvtt_preconfiguration(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_pckg_webvtt_module_ctx = {
    ngx_http_pckg_webvtt_preconfiguration, /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_webvtt_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_webvtt_module_ctx,      /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_pckg_webvtt_content_type =
    ngx_string("text/vtt");

static ngx_str_t  ngx_http_pckg_webvtt_ext = ngx_string(".vtt");


static void
ngx_http_pckg_webvtt_get_content_type(media_info_t *media_info,
    ngx_str_t *content_type)
{
    *content_type = ngx_http_pckg_webvtt_content_type;
}


static ngx_int_t
ngx_http_pckg_webvtt_init_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment, ngx_http_pckg_frame_processor_t *processor)
{
    vod_status_t               rc;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    rc = subtitle_trim_timestamps(&ctx->request_context, segment);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_webvtt_init_frame_processor: "
            "trim timestamps failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    rc = webvtt_builder_build(&ctx->request_context, segment,
        &processor->output);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_webvtt_init_frame_processor: "
            "build webvtt failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    processor->response_size = processor->output.len;

    processor->content_type = ngx_http_pckg_webvtt_content_type;

    return NGX_OK;
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_webvtt_seg_handler = {
    NULL,
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_webvtt_init_frame_processor,
};


static ngx_int_t
ngx_http_pckg_webvtt_parse_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t  flags;

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_seg))
    {
        start_pos += ngx_http_pckg_prefix_seg.len;
        flags = 0;

    } else if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_part))
    {
        start_pos += ngx_http_pckg_prefix_part.len;
        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_PART_INDEX;

    } else {
        return NGX_DECLINED;
    }

    *handler = &ngx_http_pckg_webvtt_seg_handler;

    flags |= NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX
        | NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT
        | NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

    result->flags = NGX_KSMP_FLAG_MEDIA | NGX_KSMP_FLAG_MEDIA_INFO
        | NGX_KSMP_FLAG_SEGMENT_TIME;

    result->parse_flags = NGX_PCKG_KSMP_PARSE_FLAG_EXTRA_DATA;

    result->media_type_mask = 1 << KMP_MEDIA_SUBTITLE;
    result->media_type_count = 1;

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_int_t
ngx_http_pckg_webvtt_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_webvtt_ext,
        ngx_http_pckg_webvtt_parse_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_http_pckg_container_t  ngx_http_pckg_webvtt_container = {
    NULL,
    &ngx_http_pckg_webvtt_ext,
    NULL,
    ngx_http_pckg_webvtt_get_content_type,
};
