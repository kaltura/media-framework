#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_mpegts.h"
#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_enc.h"

#include "media/mpegts/mpegts_muxer.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include "media/mpegts/aes_cbc_encrypt.h"
#endif /* NGX_HAVE_OPENSSL_EVP */


static ngx_int_t ngx_http_pckg_mpegts_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_mpegts_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_mpegts_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    mpegts_muxer_conf_t  muxer;
} ngx_http_pckg_mpegts_loc_conf_t;


static ngx_command_t  ngx_http_pckg_mpegts_commands[] = {

    { ngx_string("pckg_mpegts_interleave_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_mpegts_loc_conf_t, muxer.interleave_frames),
      NULL },

    { ngx_string("pckg_mpegts_align_frames"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_mpegts_loc_conf_t, muxer.align_frames),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_mpegts_module_ctx = {
    ngx_http_pckg_mpegts_preconfiguration, /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_pckg_mpegts_create_loc_conf,  /* create location configuration */
    ngx_http_pckg_mpegts_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_mpegts_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_mpegts_module_ctx,      /* module context */
    ngx_http_pckg_mpegts_commands,         /* module directives */
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


static ngx_str_t  ngx_http_pckg_mpegts_content_type =
    ngx_string("video/mp2t");

static ngx_str_t  ngx_http_pckg_mpegts_ext = ngx_string(".ts");


static void
ngx_http_pckg_mpegts_get_bitrate_estimator(ngx_http_request_t *r,
    media_info_t **media_infos, uint32_t count,
    media_bitrate_estimator_t *result)
{
    ngx_http_pckg_mpegts_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_mpegts_module);

    mpegts_muxer_get_bitrate_estimator(&mlcf->muxer, media_infos, count,
        result);
}


static void
ngx_http_pckg_mpegts_get_content_type(media_info_t *media_info,
    ngx_str_t *content_type)
{
    *content_type = ngx_http_pckg_mpegts_content_type;
}


#if (NGX_HAVE_OPENSSL_EVP)
static ngx_int_t
ngx_http_pckg_mpegts_init_enc_params(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, hls_encryption_params_t *enc_params)
{
    ngx_pckg_track_t              *track;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    switch (elcf->scheme) {

    case NGX_HTTP_PCKG_ENC_NONE:
        enc_params->type = HLS_ENC_NONE;
        return NGX_OK;

    case NGX_HTTP_PCKG_ENC_AES_128:
        enc_params->type = HLS_ENC_AES_128;
        break;

    case NGX_HTTP_PCKG_ENC_CBCS:
        enc_params->type = HLS_ENC_SAMPLE_AES;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_mpegts_init_enc_params: "
            "scheme %ui not supported", elcf->scheme);
        return NGX_HTTP_BAD_REQUEST;
    }

    track = channel->tracks.elts;

    enc_params->key = track->enc->key;
    enc_params->iv = track->enc->iv;

    return NGX_OK;
}
#endif /* NGX_HAVE_OPENSSL_EVP */


static ngx_int_t
ngx_http_pckg_mpegts_init_frame_processor(ngx_http_request_t *r,
    media_segment_t *segment, ngx_http_pckg_frame_processor_t *processor)
{
    bool_t                            reuse_output_buffers;
    vod_status_t                      rc;
    mpegts_muxer_state_t             *state;
    hls_encryption_params_t           enc_params;
    ngx_http_pckg_core_ctx_t         *ctx;
    ngx_http_pckg_mpegts_loc_conf_t  *mlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_mpegts_module);

    enc_params.type = HLS_ENC_NONE;
    reuse_output_buffers = FALSE;

#if (NGX_HAVE_OPENSSL_EVP)
    buffer_pool_t              *buffer_pool;
    aes_cbc_encrypt_context_t  *enc_write_ctx;

    rc = ngx_http_pckg_mpegts_init_enc_params(r, ctx->channel, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }

    if (enc_params.type == HLS_ENC_AES_128) {
        buffer_pool = ctx->request_context.output_buffer_pool;

        rc = aes_cbc_encrypt_init(&enc_write_ctx, &ctx->request_context,
            ctx->segment_writer.write_tail, ctx->segment_writer.context,
            buffer_pool, enc_params.key, enc_params.iv);
        if (rc != VOD_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_mpegts_init_frame_processor: "
                "aes_cbc_encrypt_init failed %i", rc);
            return ngx_http_pckg_status_to_ngx_error(r, rc);
        }

        ctx->segment_writer.write_tail =
            (write_callback_t) aes_cbc_encrypt_write;
        ctx->segment_writer.context = enc_write_ctx;

        reuse_output_buffers = TRUE;
    }
#endif /* NGX_HAVE_OPENSSL_EVP */

    rc = mpegts_muxer_init_segment(&ctx->request_context, &mlcf->muxer,
        &enc_params, segment, ctx->segment_writer.write_tail,
        ctx->segment_writer.context, reuse_output_buffers,
        &processor->response_size, &processor->output, &state);
    if (rc != VOD_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_mpegts_init_frame_processor: "
            "init segment failed %i", rc);
        return ngx_http_pckg_status_to_ngx_error(r, rc);
    }

    if (enc_params.type == HLS_ENC_AES_128 && processor->response_size != 0) {
        processor->response_size = aes_round_up_to_block(
            processor->response_size);
    }

    processor->process = (ngx_http_pckg_frame_processor_pt)
        mpegts_muxer_process;
    processor->ctx = state;

    processor->content_type = ngx_http_pckg_mpegts_content_type;

    return NGX_OK;
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_mpegts_ts_seg_handler = {
    NULL,
    ngx_http_pckg_core_write_segment,
    ngx_http_pckg_mpegts_init_frame_processor,
};


static ngx_int_t
ngx_http_pckg_mpegts_parse_ts_request(ngx_http_request_t *r, u_char *start_pos,
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

    *handler = &ngx_http_pckg_mpegts_ts_seg_handler;

    flags |= NGX_HTTP_PCKG_PARSE_REQUIRE_INDEX
        | NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT
        | NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

    result->flags = NGX_KSMP_FLAG_MEDIA | NGX_KSMP_FLAG_MEDIA_INFO;

    result->parse_flags = NGX_PCKG_KSMP_PARSE_FLAG_EXTRA_DATA;

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_int_t
ngx_http_pckg_mpegts_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_mpegts_ext,
        ngx_http_pckg_mpegts_parse_ts_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_pckg_mpegts_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_mpegts_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_mpegts_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_pckg_mpegts_create_loc_conf: ngx_pcalloc failed");
        return NULL;
    }

    conf->muxer.interleave_frames = NGX_CONF_UNSET;
    conf->muxer.align_frames = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_pckg_mpegts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_mpegts_loc_conf_t  *prev = parent;
    ngx_http_pckg_mpegts_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->muxer.interleave_frames,
                         prev->muxer.interleave_frames, 0);

    ngx_conf_merge_value(conf->muxer.align_frames,
                         prev->muxer.align_frames, 1);

    return NGX_CONF_OK;
}


ngx_http_pckg_container_t  ngx_http_pckg_mpegts_container = {
    NULL,
    &ngx_http_pckg_mpegts_ext,
    ngx_http_pckg_mpegts_get_bitrate_estimator,
    ngx_http_pckg_mpegts_get_content_type,
};
