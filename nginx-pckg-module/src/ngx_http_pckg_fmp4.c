#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_fmp4.h"
#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_enc.h"

#include "media/mp4/mp4_init_segment.h"
#include "media/mp4/mp4_cbcs_encrypt.h"
#include "media/mp4/mp4_muxer.h"
#include "media/mp4/mp4_defs.h"

#include "media/subtitle/subtitle_format.h"
#include "media/subtitle/ttml_builder.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include "media/mp4/mp4_dash_encrypt.h"
#include "media/aes_cbc_encrypt.h"
#endif /* NGX_HAVE_OPENSSL_EVP */


static ngx_int_t ngx_http_pckg_fmp4_preconfiguration(ngx_conf_t *cf);


enum {
    NGX_HTTP_PCKG_FMP4_SUBTITLE_WVTT,
    NGX_HTTP_PCKG_FMP4_SUBTITLE_STPP,
};


typedef struct {
    ngx_uint_t  subtitle_format;
} ngx_http_pckg_fmp4_ctx_t;


static ngx_http_module_t  ngx_http_pckg_fmp4_module_ctx = {
    ngx_http_pckg_fmp4_preconfiguration, /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    NULL,                                /* create location configuration */
    NULL                                 /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_fmp4_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_fmp4_module_ctx,      /* module context */
    NULL,                                /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_pckg_fmp4_content_type_video =
    ngx_string("video/mp4");
static ngx_str_t  ngx_http_pckg_fmp4_content_type_audio =
    ngx_string("audio/mp4");
static ngx_str_t  ngx_http_pckg_fmp4_content_type_application =
    ngx_string("application/mp4");

static ngx_str_t  ngx_http_pckg_fmp4_ext_seg = ngx_string(".m4s");
static ngx_str_t  ngx_http_pckg_fmp4_ext_init = ngx_string(".mp4");

static ngx_str_t  ngx_http_pckg_fmp4_suffix_wvtt =
    ngx_string("-" NGX_HTTP_PCKG_FMP4_PARAM_WVTT);
static ngx_str_t  ngx_http_pckg_fmp4_suffix_stpp =
    ngx_string("-" NGX_HTTP_PCKG_FMP4_PARAM_STPP);


static void
ngx_http_pckg_fmp4_get_bitrate_estimator(ngx_http_request_t *r,
    media_info_t **media_infos, uint32_t count,
    media_bitrate_estimator_t *result)
{
    mp4_muxer_get_bitrate_estimator(media_infos, count, result);
}


static void
ngx_http_pckg_fmp4_get_content_type(media_info_t *media_info,
    ngx_str_t *content_type)
{
    switch (media_info->media_type) {

    case MEDIA_TYPE_VIDEO:
        *content_type = ngx_http_pckg_fmp4_content_type_video;
        break;

    case MEDIA_TYPE_AUDIO:
        *content_type = ngx_http_pckg_fmp4_content_type_audio;
        break;

    default:    /* MEDIA_TYPE_SUBTITLE */
        *content_type = ngx_http_pckg_fmp4_content_type_application;
        break;
    }
}


#if (NGX_HAVE_OPENSSL_EVP)
static ngx_int_t
ngx_http_pckg_fmp4_get_enc_scheme(ngx_http_request_t *r, ngx_uint_t *scheme)
{
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    switch (elcf->scheme) {

    case NGX_HTTP_PCKG_ENC_NONE:
    case NGX_HTTP_PCKG_ENC_AES_128:
    case NGX_HTTP_PCKG_ENC_CBCS:
    case NGX_HTTP_PCKG_ENC_CENC:
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_fmp4_get_enc_scheme: "
            "scheme %ui not supported", elcf->scheme);
        return NGX_HTTP_BAD_REQUEST;
    }

    *scheme = elcf->scheme;
    return NGX_OK;
}
#endif /* NGX_HAVE_OPENSSL_EVP */


static ngx_int_t
ngx_http_pckg_fmp4_handle_init_segment(ngx_http_request_t *r)
{
    bool_t                     size_only;
    ngx_str_t                  response;
    ngx_str_t                  content_type;
    vod_status_t               rc;
    atom_writer_t             *stsd_atom_writers = NULL;
    media_init_segment_t       segment;
    ngx_http_pckg_core_ctx_t  *ctx;
    ngx_http_pckg_fmp4_ctx_t  *fctx;

    rc = ngx_http_pckg_media_init_segment(r, &segment);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    if (ctx->channel->media_types & (1 << KMP_MEDIA_SUBTITLE)) {
        fctx = ngx_http_get_module_ctx(r, ngx_http_pckg_fmp4_module);

        if (fctx->subtitle_format == NGX_HTTP_PCKG_FMP4_SUBTITLE_STPP) {
            rc = ttml_builder_convert_init_segment(&ctx->request_context,
                &segment);
            if (rc != VOD_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_pckg_fmp4_handle_init_segment: "
                    "convert to ttml failed %i", rc);
                return ngx_http_pckg_status_to_ngx_error(r, rc);
            }
        }
    }

#if (NGX_HAVE_OPENSSL_EVP)
    ngx_uint_t                  scheme;
    media_enc_t                *enc;
    aes_cbc_encrypt_context_t  *enc_write_ctx;

    rc = ngx_http_pckg_fmp4_get_enc_scheme(r, &scheme);
    if (rc != NGX_OK) {
        return rc;
    }

    enc = segment.first[0].enc;
    if (enc == NULL) {
        scheme = NGX_HTTP_PCKG_ENC_NONE;
    }

    switch (scheme) {

    case NGX_HTTP_PCKG_ENC_CBCS:
        rc = mp4_init_segment_get_encrypted_stsd_writers(&ctx->request_context,
            &segment, SCHEME_TYPE_CBCS, FALSE, &stsd_atom_writers);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_handle_init_segment: "
                "mp4_init_segment_get_encrypted_stsd_writers failed %i (1)",
                rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        break;

    case NGX_HTTP_PCKG_ENC_CENC:
        rc = mp4_init_segment_get_encrypted_stsd_writers(&ctx->request_context,
            &segment, SCHEME_TYPE_CENC, FALSE, &stsd_atom_writers);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_handle_init_segment: "
                "mp4_init_segment_get_encrypted_stsd_writers failed %i (2)",
                rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        break;
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    size_only = r->header_only || r->method == NGX_HTTP_HEAD;

    rc = mp4_init_segment_build(&ctx->request_context, &segment, size_only,
        NULL, stsd_atom_writers, &response);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_fmp4_handle_init_segment: "
            "mp4_init_segment_build failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

#if (NGX_HAVE_OPENSSL_EVP)
    if (scheme == NGX_HTTP_PCKG_ENC_AES_128) {
        rc = aes_cbc_encrypt_init(&enc_write_ctx, &ctx->request_context,
            NULL, NULL, NULL, enc->key, enc->iv);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_handle_init_segment: "
                "aes_cbc_encrypt_init failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        rc = aes_cbc_encrypt(enc_write_ctx, &response, &response, TRUE);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_handle_init_segment: "
                "aes_cbc_encrypt failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    ngx_http_pckg_fmp4_get_content_type(segment.first[0].media_info,
        &content_type);

    rc = ngx_http_pckg_send_header(r, response.len, &content_type, -1,
        NGX_HTTP_PCKG_EXPIRES_STATIC);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_int_t
ngx_http_pckg_fmp4_init_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment, ngx_http_pckg_frame_processor_t *processor)
{
    bool_t                     size_only;
    bool_t                     per_stream_writer;
    bool_t                     reuse_input_buffers;
    vod_status_t               rc;
    segment_writer_t          *segment_writers;
    mp4_muxer_state_t         *muxer_state;
    ngx_http_pckg_core_ctx_t  *ctx;
    ngx_http_pckg_fmp4_ctx_t  *fctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    if (ctx->channel->media_types & (1 << KMP_MEDIA_SUBTITLE)) {
        rc = subtitle_trim_timestamps(&ctx->request_context, segment);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "trim timestamps failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        fctx = ngx_http_get_module_ctx(r, ngx_http_pckg_fmp4_module);

        if (fctx->subtitle_format == NGX_HTTP_PCKG_FMP4_SUBTITLE_STPP) {
            rc = ttml_builder_convert_segment(&ctx->request_context, segment);
            if (rc != VOD_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_pckg_fmp4_init_frame_processor: "
                    "convert to ttml failed %i", rc);
                return ngx_http_pckg_status_to_ngx_error(r, rc);
            }
        }
    }

    segment_writers = &ctx->segment_writer;
    per_stream_writer = FALSE;
    reuse_input_buffers = FALSE;

    size_only = r->header_only || r->method == NGX_HTTP_HEAD;

#if (NGX_HAVE_OPENSSL_EVP)
    ngx_uint_t                  scheme;
    media_enc_t                *enc;
    aes_cbc_encrypt_context_t  *enc_write_ctx;

    rc = ngx_http_pckg_fmp4_get_enc_scheme(r, &scheme);
    if (rc != NGX_OK) {
        return rc;
    }

    enc = segment->tracks[0].enc;
    if (enc == NULL) {
        scheme = NGX_HTTP_PCKG_ENC_NONE;
    }

    reuse_input_buffers = scheme != NGX_HTTP_PCKG_ENC_NONE;
    muxer_state = NULL;

    switch (scheme) {

    case NGX_HTTP_PCKG_ENC_AES_128:
        /* Note: cant use buffer pool for fmp4 - the buffer sizes vary */
        rc = aes_cbc_encrypt_init(&enc_write_ctx,
            &ctx->request_context, segment_writers->write_tail,
            segment_writers->context, NULL, enc->key, enc->iv);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "aes_cbc_encrypt_init failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        segment_writers->write_tail = (write_callback_t) aes_cbc_encrypt_write;
        segment_writers->context = enc_write_ctx;
        break;

    case NGX_HTTP_PCKG_ENC_CBCS:
        rc = mp4_cbcs_encrypt_get_writers(&ctx->request_context, segment,
            segment_writers, &segment_writers);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "mp4_cbcs_encrypt_get_writers failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        per_stream_writer = TRUE;
        break;

    case NGX_HTTP_PCKG_ENC_CENC:
        if (segment->track_count > 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "multiple streams not supported for cenc");
            return ngx_http_pckg_status_to_ngx_error(r, VOD_BAD_REQUEST);
        }

        rc = mp4_dash_encrypt_get_fragment_writer(
            &ctx->segment_writer,
            &ctx->request_context,
            segment,
            FALSE,
            size_only,
            &processor->output,
            &processor->response_size,
            &muxer_state);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "mp4_dash_encrypt_get_fragment_writer failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
        break;
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    if (muxer_state == NULL) {
        rc = mp4_muxer_init_fragment(&ctx->request_context, segment,
            segment_writers, per_stream_writer, reuse_input_buffers, size_only,
            &processor->output, &processor->response_size, &muxer_state);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_fmp4_init_frame_processor: "
                "mp4_muxer_init_fragment failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
    }

    processor->process = (ngx_http_pckg_frame_processor_pt)
        mp4_muxer_process_frames;
    processor->ctx = muxer_state;

#if (NGX_HAVE_OPENSSL_EVP)
    if (scheme == NGX_HTTP_PCKG_ENC_AES_128) {
        processor->response_size = aes_round_up_to_block(
            processor->response_size);
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    /* set the 'Content-type' header */
    ngx_http_pckg_fmp4_get_content_type(segment->tracks->media_info,
        &processor->content_type);
    return NGX_OK;
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_fmp4_fmp4_seg_handler = {
    NULL,
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_fmp4_init_frame_processor,
};


static ngx_http_pckg_request_handler_t  ngx_http_pckg_fmp4_init_seg_handler = {
    NULL,
    ngx_http_pckg_fmp4_handle_init_segment,
    NULL,
};


static u_char *
ngx_http_pckg_fmp4_init_ctx(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos)
{
    ngx_http_pckg_fmp4_ctx_t  *fctx;

    fctx = ngx_pcalloc(r->pool, sizeof(*fctx));
    if (fctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_fmp4_init_ctx: alloc failed");
        return NULL;
    }

    ngx_http_set_ctx(r, fctx, ngx_http_pckg_fmp4_module);

    if (ngx_http_pckg_match_suffix(start_pos, end_pos,
        ngx_http_pckg_fmp4_suffix_wvtt))
    {
        end_pos -= ngx_http_pckg_fmp4_suffix_wvtt.len;
        fctx->subtitle_format = NGX_HTTP_PCKG_FMP4_SUBTITLE_WVTT;

    } else if (ngx_http_pckg_match_suffix(start_pos, end_pos,
        ngx_http_pckg_fmp4_suffix_stpp))
    {
        end_pos -= ngx_http_pckg_fmp4_suffix_stpp.len;
        fctx->subtitle_format = NGX_HTTP_PCKG_FMP4_SUBTITLE_STPP;

    } else {
        fctx->subtitle_format = NGX_HTTP_PCKG_FMP4_SUBTITLE_STPP;
    }

    return end_pos;
}


static ngx_int_t
ngx_http_pckg_fmp4_parse_m4s_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t   flags;
    ngx_int_t  rc;

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

    end_pos = ngx_http_pckg_fmp4_init_ctx(r, start_pos, end_pos);
    if (end_pos == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *handler = &ngx_http_pckg_fmp4_fmp4_seg_handler;

    flags |= NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX
        | NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT
        | NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

    rc = ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
    if (rc != NGX_OK) {
        return rc;
    }

    result->flags = NGX_KSMP_FLAG_MEDIA | NGX_KSMP_FLAG_MEDIA_INFO;

    if (result->media_type_mask & (1 << KMP_MEDIA_SUBTITLE)) {
        result->flags |= NGX_KSMP_FLAG_SEGMENT_TIME;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_fmp4_parse_mp4_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t  flags;

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_init_seg))
    {
        start_pos += ngx_http_pckg_prefix_init_seg.len;

    } else {
        return NGX_DECLINED;
    }

    end_pos = ngx_http_pckg_fmp4_init_ctx(r, start_pos, end_pos);
    if (end_pos == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *handler = &ngx_http_pckg_fmp4_init_seg_handler;

    flags = NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX
        | NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT
        | NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

    result->flags = NGX_KSMP_FLAG_MEDIA_INFO;

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_int_t
ngx_http_pckg_fmp4_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_fmp4_ext_seg,
        ngx_http_pckg_fmp4_parse_m4s_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_fmp4_ext_init,
        ngx_http_pckg_fmp4_parse_mp4_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_http_pckg_container_t  ngx_http_pckg_fmp4_container = {
    &ngx_http_pckg_fmp4_ext_init,
    &ngx_http_pckg_fmp4_ext_seg,
    ngx_http_pckg_fmp4_get_bitrate_estimator,
    ngx_http_pckg_fmp4_get_content_type,
};
