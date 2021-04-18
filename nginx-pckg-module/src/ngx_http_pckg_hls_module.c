#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include "ngx_http_pckg_hls_module.h"
#include "ngx_http_pckg_core_module.h"
#include "ngx_http_pckg_hls_m3u8.h"

#include "media/mp4/mp4_init_segment.h"
#include "media/mp4/mp4_cbcs_encrypt.h"
#include "media/mp4/mp4_fragment.h"
#include "media/mp4/mp4_muxer.h"
#include "media/mp4/mp4_defs.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include "media/hls/aes_cbc_encrypt.h"
#endif /* NGX_HAVE_OPENSSL_EVP */

#include "ngx_pckg_ksmp.h"


static char *ngx_http_pckg_hls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_pckg_hls_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_hls_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


#if (NGX_HAVE_OPENSSL_EVP)
static ngx_conf_enum_t  ngx_http_pckg_hls_encryption_methods[] = {
    { ngx_string("none"),               HLS_ENC_NONE },
    { ngx_string("aes-128"),            HLS_ENC_AES_128 },
    { ngx_string("sample-aes"),         HLS_ENC_SAMPLE_AES },
    { ngx_string("sample-aes-cenc"),    HLS_ENC_SAMPLE_AES_CENC },
    { ngx_null_string, 0 }
};
#endif /* NGX_HAVE_OPENSSL_EVP */

static ngx_conf_enum_t  ngx_http_pckg_hls_container_formats[] = {
    { ngx_string("auto"),       NGX_HTTP_PCKG_HLS_CONTAINER_AUTO },
    { ngx_string("mpegts"),     NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS },
    { ngx_string("fmp4"),       NGX_HTTP_PCKG_HLS_CONTAINER_FMP4 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_hls_commands[] = {

    { ngx_string("pckg_hls"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_pckg_hls,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("pckg_hls_container_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, m3u8_config.container_format),
      ngx_http_pckg_hls_container_formats },

    { ngx_string("pckg_hls_mpegts_interleave_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, mpegts_muxer.interleave_frames),
      NULL },

    { ngx_string("pckg_hls_mpegts_align_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, mpegts_muxer.align_frames),
      NULL },

#if (NGX_HAVE_OPENSSL_EVP)
    { ngx_string("pckg_hls_encryption_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, encryption_method),
      ngx_http_pckg_hls_encryption_methods },

    { ngx_string("pckg_hls_encryption_key_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, m3u8_config.enc_key_uri),
      NULL },

    { ngx_string("pckg_hls_encryption_key_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t, m3u8_config.enc_key_format),
      NULL },

    { ngx_string("pckg_hls_encryption_key_format_versions"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_hls_loc_conf_t,
        m3u8_config.enc_key_format_versions),
      NULL },
#endif /* NGX_HAVE_OPENSSL_EVP */

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_hls_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_pckg_hls_create_loc_conf,  /* create location configuration */
    ngx_http_pckg_hls_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_hls_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_hls_module_ctx,      /* module context */
    ngx_http_pckg_hls_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_pckg_hls_content_type_m3u8 =
    ngx_string("application/vnd.apple.mpegurl");

static ngx_str_t  ngx_http_pckg_hls_content_type_mpeg_ts =
    ngx_string("video/mp2t");

static ngx_str_t  ngx_http_pckg_hls_content_type_enc_key =
    ngx_string("application/octet-stream");


#if (NGX_HAVE_OPENSSL_EVP)

/* some random salt to prevent the iv from being equal to key
    in case encryption_iv_seed is null */
static ngx_str_t  ngx_http_pckg_hls_iv_salt =
    ngx_string("\xa7\xc6\x17\xab\x52\x2c\x40\x3c\xf6\x8a");

static ngx_int_t
ngx_http_pckg_hls_init_encryption_params(ngx_http_request_t *r,
    hls_encryption_params_t *enc_params)
{
    ngx_int_t                      rc;
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    enc_params->type = hlcf->encryption_method;
    if (enc_params->type == HLS_ENC_NONE) {
        return NGX_OK;
    }

    /* TODO: support drm */

    enc_params->iv = enc_params->iv_buf;
    enc_params->key = enc_params->key_buf;
    enc_params->return_iv = FALSE;

    rc = ngx_http_pckg_generate_key(r, 0, NULL, enc_params->key_buf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_generate_key(r, 1, &ngx_http_pckg_hls_iv_salt,
        enc_params->iv_buf);
    if (rc != NGX_OK) {
        return rc;
    }

    enc_params->return_iv = TRUE;
    return NGX_OK;
}

static ngx_int_t
ngx_http_pckg_hls_init_segment_encryption(ngx_http_request_t *r,
    segment_writer_t *segment_writer, ngx_uint_t container_format,
    hls_encryption_params_t *enc_params)
{
    vod_status_t                rc;
    buffer_pool_t              *buffer_pool;
    ngx_http_pckg_core_ctx_t   *ctx;
    aes_cbc_encrypt_context_t  *encrypted_write_context;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    rc = ngx_http_pckg_hls_init_encryption_params(r, enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    if (enc_params->type != HLS_ENC_AES_128) {
        return NGX_OK;
    }

    if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS) {
        buffer_pool = ctx->request_context.output_buffer_pool;

    } else {
        /* Note: cant use buffer pool for fmp4 - the buffer sizes vary */
        buffer_pool = NULL;
    }

    rc = aes_cbc_encrypt_init(&encrypted_write_context, &ctx->request_context,
        segment_writer->write_tail, segment_writer->context, buffer_pool,
        enc_params->key, enc_params->iv);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_init_segment_encryption: "
            "aes_cbc_encrypt_init failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    segment_writer->write_tail = (write_callback_t) aes_cbc_encrypt_write;
    segment_writer->context = encrypted_write_context;
    return NGX_OK;
}

#endif /* NGX_HAVE_OPENSSL_EVP */


static ngx_int_t
ngx_http_pckg_hls_handle_encryption_key(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_str_t                      response;
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    if (hlcf->encryption_method == HLS_ENC_NONE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_hls_handle_encryption_key: "
            "encryption not enabled in conf");
        return NGX_HTTP_BAD_REQUEST;
    }

    response.len = AES_BLOCK_SIZE;
    response.data = ngx_palloc(r->pool, response.len);
    if (response.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_handle_encryption_key: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_pckg_generate_key(r, 0, NULL, response.data);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_hls_content_type_enc_key, -1, 0);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_int_t
ngx_http_pckg_hls_handle_init_segment(ngx_http_request_t *r)
{
    bool_t                      size_only;
    ngx_str_t                   response;
    ngx_str_t                   content_type;
    vod_status_t                rc;
    atom_writer_t              *stsd_atom_writers = NULL;
    media_init_segment_t        segment;
    ngx_http_pckg_core_ctx_t   *ctx;

    rc = ngx_http_pckg_media_init_segment(r, &segment);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

#if (NGX_HAVE_OPENSSL_EVP)
    hls_encryption_params_t     enc_params;
    aes_cbc_encrypt_context_t  *encrypted_write_context;

    rc = ngx_http_pckg_hls_init_encryption_params(r, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    switch (enc_params.type) {

    case HLS_ENC_SAMPLE_AES:
        rc = mp4_init_segment_get_encrypted_stsd_writers(&ctx->request_context,
            &segment, SCHEME_TYPE_CBCS, FALSE, NULL, enc_params.iv,
            &stsd_atom_writers);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_hls_handle_init_segment: "
                "mp4_init_segment_get_encrypted_stsd_writers failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
        break;

    case HLS_ENC_SAMPLE_AES_CENC:
        // TODO: add when supporting drm
        break;

    default:;
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    size_only = r->header_only || r->method == NGX_HTTP_HEAD;

    rc = mp4_init_segment_build(&ctx->request_context, &segment, size_only,
        NULL, stsd_atom_writers, &response);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_handle_init_segment: "
            "mp4_init_segment_build failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

#if (NGX_HAVE_OPENSSL_EVP)
    if (enc_params.type == HLS_ENC_AES_128) {
        rc = aes_cbc_encrypt_init(&encrypted_write_context,
            &ctx->request_context, NULL, NULL, NULL,
            enc_params.key, enc_params.iv);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_hls_handle_init_segment: "
                "aes_cbc_encrypt_init failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        rc = aes_cbc_encrypt(encrypted_write_context, &response, &response,
            TRUE);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_hls_handle_init_segment: "
                "aes_cbc_encrypt failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    mp4_fragment_get_content_type(
        segment.first[0].media_info->media_type == KMP_MEDIA_VIDEO,
        &content_type);

    rc = ngx_http_pckg_send_header(r, response.len, &content_type, -1, 0);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_int_t
ngx_http_pckg_hls_handle_master_playlist(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_str_t                  response;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_hls_m3u8_build_master(r, channel, &response);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_hls_content_type_m3u8, channel->header->last_modified,
        NGX_HTTP_PCKG_EXPIRES_MASTER);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_int_t
ngx_http_pckg_hls_handle_index_playlist(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_str_t                      response;
    ngx_pckg_channel_t            *channel;
    hls_encryption_params_t        enc_params;
    ngx_http_pckg_core_ctx_t      *ctx;

#if (NGX_HAVE_OPENSSL_EVP)
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    rc = ngx_http_pckg_hls_init_encryption_params(r, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    if (enc_params.type != HLS_ENC_NONE) {

        if (hlcf->m3u8_config.enc_key_uri != NULL) {

            if (ngx_http_complex_value(r, hlcf->m3u8_config.enc_key_uri,
                &enc_params.key_uri) != NGX_OK)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_pckg_hls_handle_index_playlist: "
                    "ngx_http_complex_value failed");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            enc_params.key_uri.len = 0;
        }
    }
#else
    enc_params.type = HLS_ENC_NONE;
#endif /* NGX_HAVE_OPENSSL_EVP */

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_hls_m3u8_build_index(r, channel, &enc_params,
        &response);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_hls_content_type_m3u8,
        channel->timeline.header->last_modified,
        NGX_HTTP_PCKG_EXPIRES_INDEX);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_int_t
ngx_http_pckg_hls_init_ts_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment,
    ngx_http_pckg_frame_processor_pt *processor, void **processor_ctx,
    ngx_str_t *output_buffer, size_t *response_size, ngx_str_t *content_type)
{
    bool_t                         reuse_output_buffers;
    vod_status_t                   rc;
    hls_muxer_state_t             *state;
    hls_encryption_params_t        enc_params;
    ngx_http_pckg_core_ctx_t      *ctx;
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

#if (NGX_HAVE_OPENSSL_EVP)
    rc = ngx_http_pckg_hls_init_segment_encryption(r, &ctx->segment_writer,
        NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    if (enc_params.type == HLS_ENC_SAMPLE_AES_CENC) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_hls_init_ts_frame_processor: "
            "sample aes cenc not supported with mpeg ts container");
        return ngx_http_pckg_status_to_ngx_error(r, VOD_BAD_REQUEST);
    }

    reuse_output_buffers = enc_params.type == HLS_ENC_AES_128;
#else
    enc_params.type = HLS_ENC_NONE;
    reuse_output_buffers = FALSE;
#endif /* NGX_HAVE_OPENSSL_EVP */

    rc = hls_muxer_init_segment(&ctx->request_context, &hlcf->mpegts_muxer,
        &enc_params, segment, ctx->segment_writer.write_tail,
        ctx->segment_writer.context, reuse_output_buffers,
        response_size, output_buffer, &state);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_init_ts_frame_processor: "
            "init segment failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    if (enc_params.type == HLS_ENC_AES_128 && *response_size != 0) {
        *response_size = aes_round_up_to_block(*response_size);
    }

    *processor = (ngx_http_pckg_frame_processor_pt) hls_muxer_process;
    *processor_ctx = state;

    *content_type = ngx_http_pckg_hls_content_type_mpeg_ts;

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_hls_init_fmp4_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment,
    ngx_http_pckg_frame_processor_pt *processor, void **processor_ctx,
    ngx_str_t *output_buffer, size_t *response_size, ngx_str_t *content_type)
{
    bool_t                     size_only;
    bool_t                     per_stream_writer;
    bool_t                     reuse_input_buffers;
    vod_status_t               rc;
    segment_writer_t          *segment_writers;
    mp4_muxer_state_t         *muxer_state;
    ngx_http_pckg_core_ctx_t  *ctx;

    reuse_input_buffers = FALSE;
    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

#if (NGX_HAVE_OPENSSL_EVP)
    hls_encryption_params_t    enc_params;

    rc = ngx_http_pckg_hls_init_segment_encryption(r, &ctx->segment_writer,
        NGX_HTTP_PCKG_HLS_CONTAINER_FMP4, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    reuse_input_buffers = enc_params.type != HLS_ENC_NONE;

    if (enc_params.type == HLS_ENC_SAMPLE_AES) {

        rc = mp4_cbcs_encrypt_get_writers(&ctx->request_context, segment,
            &ctx->segment_writer, enc_params.key, enc_params.iv,
            &segment_writers);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_hls_init_fmp4_frame_processor: "
                "mp4_cbcs_encrypt_get_writers failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }
        per_stream_writer = TRUE;

    } else {
        segment_writers = &ctx->segment_writer;
        per_stream_writer = FALSE;
    }
#else
    segment_writers = &ctx->segment_writer;
    per_stream_writer = FALSE;
#endif /* NGX_HAVE_OPENSSL_EVP */

#if (NGX_HAVE_OPENSSL_EVP)
    if (enc_params.type == HLS_ENC_SAMPLE_AES_CENC &&
        segment->track_count > 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_hls_init_fmp4_frame_processor: "
            "multiple streams not supported for sample aes cenc");
        return ngx_http_pckg_status_to_ngx_error(r, VOD_BAD_REQUEST);
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    /* TODO: add support for sample aes cenc after adding drm */

    /* muxed segment */
    size_only = r->header_only || r->method == NGX_HTTP_HEAD;

    rc = mp4_muxer_init_fragment(&ctx->request_context, segment,
        segment_writers, per_stream_writer, reuse_input_buffers, size_only,
        output_buffer, response_size, &muxer_state);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_init_fmp4_frame_processor: "
            "mp4_muxer_init_fragment failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    *processor = (ngx_http_pckg_frame_processor_pt) mp4_muxer_process_frames;
    *processor_ctx = muxer_state;

#if (NGX_HAVE_OPENSSL_EVP)
    if (enc_params.type == HLS_ENC_AES_128) {
        *response_size = aes_round_up_to_block(*response_size);
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    /* set the 'Content-type' header */
    mp4_fragment_get_content_type(
        segment->tracks->media_info->media_type == KMP_MEDIA_VIDEO,
        content_type);
    return NGX_OK;
}

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_ts_seg_handler = {
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_hls_init_ts_frame_processor,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_fmp4_seg_handler = {
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_hls_init_fmp4_frame_processor,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_index_handler = {
    ngx_http_pckg_hls_handle_index_playlist,
    NULL,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_master_handler = {
    ngx_http_pckg_hls_handle_master_playlist,
    NULL,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_enc_key_handler = {
    ngx_http_pckg_hls_handle_encryption_key,
    NULL,
};

static ngx_http_pckg_request_handler_t  ngx_http_pckg_hls_init_seg_handler = {
    ngx_http_pckg_hls_handle_init_segment,
    NULL,
};

static ngx_int_t
ngx_http_pckg_hls_parse_uri_file_name(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t  flags;

    if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_seg, ngx_http_pckg_hls_ext_seg_ts))
    {
        start_pos += ngx_http_pckg_hls_prefix_seg.len;
        end_pos -= ngx_http_pckg_hls_ext_seg_ts.len;

        *handler = &ngx_http_pckg_hls_ts_seg_handler;

        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX |
            NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_DYNAMIC_VAR
            | NGX_KSMP_FLAG_MEDIA;

    } else if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_seg, ngx_http_pckg_hls_ext_seg_m4s))
    {
        start_pos += ngx_http_pckg_hls_prefix_seg.len;
        end_pos -= ngx_http_pckg_hls_ext_seg_m4s.len;

        *handler = &ngx_http_pckg_hls_fmp4_seg_handler;

        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX |
            NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_DYNAMIC_VAR
            | NGX_KSMP_FLAG_MEDIA;

    } else if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_index, ngx_http_pckg_hls_ext_m3u8))
    {
        start_pos += ngx_http_pckg_hls_prefix_index.len;
        end_pos -= ngx_http_pckg_hls_ext_m3u8.len;

        *handler = &ngx_http_pckg_hls_index_handler;

        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_ACTIVE_ONLY | NGX_KSMP_FLAG_CHECK_EXPIRY
            | NGX_KSMP_FLAG_TIMELINE | NGX_KSMP_FLAG_PERIODS
            | NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_SEGMENT_INFO
            | NGX_KSMP_FLAG_DYNAMIC_VAR;

    } else if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_master, ngx_http_pckg_hls_ext_m3u8))
    {
        start_pos += ngx_http_pckg_hls_prefix_master.len;
        end_pos -= ngx_http_pckg_hls_ext_m3u8.len;

        *handler = &ngx_http_pckg_hls_master_handler;
        flags = NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_ACTIVE_ONLY | NGX_KSMP_FLAG_TIMELINE
            | NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_DYNAMIC_VAR;

    } else if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_enc_key, ngx_http_pckg_hls_ext_enc_key))
    {
        start_pos += ngx_http_pckg_hls_prefix_enc_key.len;
        end_pos -= ngx_http_pckg_hls_ext_enc_key.len;

        *handler = &ngx_http_pckg_hls_enc_key_handler;
        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_DYNAMIC_VAR;

    } else if (ngx_http_pckg_match_file_name(start_pos, end_pos,
        ngx_http_pckg_hls_prefix_init_seg, ngx_http_pckg_hls_ext_init_seg))
    {
        start_pos += ngx_http_pckg_hls_prefix_init_seg.len;
        end_pos -= ngx_http_pckg_hls_ext_init_seg.len;

        *handler = &ngx_http_pckg_hls_init_seg_handler;
        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX |
            NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_DYNAMIC_VAR;

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_hls_parse_uri_file_name: unidentified request");
        return NGX_HTTP_BAD_REQUEST;
    }

    return ngx_http_pckg_core_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_http_pckg_submodule_t  ngx_http_pckg_hls_submodule = {
    ngx_http_pckg_hls_parse_uri_file_name,
};

static ngx_int_t
ngx_http_pckg_hls_handler(ngx_http_request_t *r)
{
    return ngx_http_pckg_core_handler(r, &ngx_http_pckg_hls_submodule);
}


static char *
ngx_http_pckg_hls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_pckg_hls_handler;

    return NGX_OK;
}


static void *
ngx_http_pckg_hls_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_hls_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_hls_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_pckg_hls_create_loc_conf: ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    conf->encryption_method = NGX_CONF_UNSET_UINT;
    conf->m3u8_config.container_format = NGX_CONF_UNSET_UINT;
    conf->mpegts_muxer.interleave_frames = NGX_CONF_UNSET;
    conf->mpegts_muxer.align_frames = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_pckg_hls_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_hls_loc_conf_t  *prev = parent;
    ngx_http_pckg_hls_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->encryption_method,
                              prev->encryption_method, HLS_ENC_NONE);

    ngx_conf_merge_uint_value(conf->m3u8_config.container_format,
                              prev->m3u8_config.container_format,
                              NGX_HTTP_PCKG_HLS_CONTAINER_AUTO);

    if (conf->m3u8_config.enc_key_uri == NULL) {
        conf->m3u8_config.enc_key_uri =
            prev->m3u8_config.enc_key_uri;
    }

    ngx_conf_merge_str_value(conf->m3u8_config.enc_key_format,
                             prev->m3u8_config.enc_key_format, "");

    ngx_conf_merge_str_value(conf->m3u8_config.enc_key_format_versions,
                             prev->m3u8_config.enc_key_format_versions, "");

    ngx_conf_merge_value(conf->mpegts_muxer.interleave_frames,
                         prev->mpegts_muxer.interleave_frames, 0);

    ngx_conf_merge_value(conf->mpegts_muxer.align_frames,
                         prev->mpegts_muxer.align_frames, 1);

    if (conf->encryption_method == HLS_ENC_SAMPLE_AES ||
        conf->encryption_method == HLS_ENC_SAMPLE_AES_CENC ||
        conf->m3u8_config.enc_key_format.len != 0 ||
        conf->m3u8_config.enc_key_format_versions.len != 0)
    {
        conf->m3u8_config.m3u8_version = 5;

    } else {
        conf->m3u8_config.m3u8_version = 3;
    }

    return NGX_CONF_OK;
}
