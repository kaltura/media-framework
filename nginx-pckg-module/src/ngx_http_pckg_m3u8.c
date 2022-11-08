#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_api.h>

#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_enc.h"
#include "ngx_http_pckg_fmp4.h"
#include "ngx_http_pckg_mpegts.h"
#include "ngx_http_pckg_captions.h"
#include "ngx_http_pckg_webvtt.h"
#include "ngx_http_pckg_data.h"

#include "ngx_pckg_media_group.h"
#include "ngx_pckg_media_info.h"
#include "ngx_pckg_segment_info.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include "media/mp4/mp4_dash_encrypt.h"
#endif


static char *ngx_http_pckg_m3u8_low_latency(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_pckg_m3u8_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_m3u8_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_m3u8_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


/* master playlist */
#define NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN  (3)

#define M3U8_MASTER_HEADER           "#EXTM3U\n#EXT-X-INDEPENDENT-SEGMENTS\n"

#define M3U8_SESSION_DATA_ID         "#EXT-X-SESSION-DATA:DATA-ID=\""
#define M3U8_SESSION_DATA_VALUE      ",VALUE=\""
#define M3U8_SESSION_DATA_URI        ",URI=\""
#define M3U8_SESSION_DATA_LANG       ",LANGUAGE=\""

#define M3U8_STREAM_BASE             "#EXT-X-STREAM-INF:PROGRAM-ID=1"        \
    ",BANDWIDTH=%uD"
#define M3U8_STREAM_AVG_BANDWIDTH    ",AVERAGE-BANDWIDTH=%uD"
#define M3U8_STREAM_VIDEO            ",RESOLUTION=%uDx%uD"                   \
    ",FRAME-RATE=%uD.%03uD,CODECS=\"%V"
#define M3U8_STREAM_VIDEO_RANGE_SDR  ",VIDEO-RANGE=SDR"
#define M3U8_STREAM_VIDEO_RANGE_PQ   ",VIDEO-RANGE=PQ"
#define M3U8_STREAM_CODECS           ",CODECS=\"%V"
#define M3U8_STREAM_CODEC_STPP       ",stpp.ttml.im1t"
#define M3U8_STREAM_TAG_AUDIO        ",AUDIO=\"%V%uD\""
#define M3U8_STREAM_TAG_SUBTITLE     ",SUBTITLES=\"%V%uD\""
#define M3U8_STREAM_TAG_CC           ",CLOSED-CAPTIONS=\"CC\""
#define M3U8_STREAM_TAG_NO_CC        ",CLOSED-CAPTIONS=NONE"

#define M3U8_MEDIA_BASE              "#EXT-X-MEDIA:TYPE=%V"                  \
    ",GROUP-ID=\"%V%uD\",NAME=\""
#define M3U8_MEDIA_LANG              ",LANGUAGE=\""
#define M3U8_MEDIA_DEFAULT           ",AUTOSELECT=YES,DEFAULT=YES"
#define M3U8_MEDIA_NON_DEFAULT       ",AUTOSELECT=NO,DEFAULT=NO"
#define M3U8_MEDIA_CHANNELS          ",CHANNELS=\"%uD\""
#define M3U8_MEDIA_URI               ",URI=\""
#define M3U8_MEDIA_CC1               "#EXT-X-MEDIA:TYPE=CLOSED-CAPTIONS"     \
    ",GROUP-ID=\"CC\",NAME=\""
#define M3U8_MEDIA_CC2               "\",INSTREAM-ID=\"%V\""

/* index playlist */
#define M3U8_INDEX_HEADER            "#EXTM3U\n#EXT-X-TARGETDURATION:%uD\n"  \
    "#EXT-X-VERSION:%uD\n#EXT-X-MEDIA-SEQUENCE:%uD\n"                        \
    "#EXT-X-DISCONTINUITY-SEQUENCE:%uD\n#EXT-X-INDEPENDENT-SEGMENTS\n"       \
    "#EXT-X-ALLOW-CACHE:YES\n"

#define M3U8_EXTINF                  "#EXTINF:"
#define M3U8_GAP                     "#EXT-X-GAP\n"
#define M3U8_BITRATE                 "#EXT-X-BITRATE:"
#define M3U8_DISCONTINUITY           "#EXT-X-DISCONTINUITY\n"
#define M3U8_PROGRAM_DATE_TIME                                               \
    "#EXT-X-PROGRAM-DATE-TIME:%4d-%02d-%02dT%02d:%02d:%02d.%03d+00:00\n"
#define M3U8_PROGRAM_DATE_TIME_LEN                                           \
    (sizeof("#EXT-X-PROGRAM-DATE-TIME:2000-01-01T00:00:00.000+00:00\n") - 1)
#define M3U8_MAP_BASE                "#EXT-X-MAP:URI=\""
#define M3U8_END_LIST                "#EXT-X-ENDLIST\n"

#define M3U8_ENC_KEY                 "#EXT-X-KEY:"
#define M3U8_ENC_KEY_METHOD          "METHOD="
#define M3U8_ENC_KEY_URI             ",URI=\""
#define M3U8_ENC_KEY_IV              ",IV=0x"
#define M3U8_ENC_KEY_KEY_FORMAT      ",KEYFORMAT=\""
#define M3U8_ENC_KEY_KEY_FORMAT_VER  ",KEYFORMATVERSIONS=\""
#define M3U8_ENC_SESSION_KEY         "#EXT-X-SESSION-KEY:"

#define M3U8_ENC_METHOD_AES_128      "AES-128"
#define M3U8_ENC_METHOD_SAMPLE_AES   "SAMPLE-AES"
#define M3U8_ENC_METHOD_SAMPLE_AES_CTR                                       \
    "SAMPLE-AES-CTR"

#define M3U8_URI_BASE64_DATA         "data:text/plain;base64,"

#define M3U8_SERVER_CONTROL          "#EXT-X-SERVER-CONTROL:"
#define M3U8_CTL_BLOCK_RELOAD        "CAN-BLOCK-RELOAD=YES"
#define M3U8_CTL_CAN_SKIP_UNTIL      "CAN-SKIP-UNTIL=%uD.%03uD"
#define M3U8_CTL_PART_HOLD_BACK      "PART-HOLD-BACK=%uD.%03uD"

#define M3U8_PART_INF                "#EXT-X-PART-INF:PART-TARGET=%uD.%03uD\n"
#define M3U8_PART_PRELOAD_HINT       "#EXT-X-PRELOAD-HINT:TYPE=PART"
#define M3U8_PART_DURATION           "#EXT-X-PART:DURATION=%uD.%03uD"
#define M3U8_PART_INDEPENDENT        ",INDEPENDENT=YES"
#define M3U8_PART_GAP                ",GAP=YES"
#define M3U8_PART_URI                ",URI=\"%V-%uD-%uD"

#define M3U8_SKIPPED_SEGMENTS        "#EXT-X-SKIP:SKIPPED-SEGMENTS=%uD\n"

#define M3U8_RENDITION_REPORT_URI    "#EXT-X-RENDITION-REPORT:URI=\""
#define M3U8_RENDITION_REPORT_ATTRS  "\",LAST-MSN=%uD,LAST-PART=%uD\n"


#define M3U8_ARG_PREFIX              "_HLS_"
#define M3U8_ARG_SKIP                "skip"
#define M3U8_ARG_MSN                 "msn"
#define M3U8_ARG_PART                "part"


enum {
    NGX_HTTP_PCKG_M3U8_CONTAINER_AUTO,
    NGX_HTTP_PCKG_M3U8_CONTAINER_MPEGTS,
    NGX_HTTP_PCKG_M3U8_CONTAINER_FMP4,
};


enum {
    NGX_HTTP_PCKG_M3U8_SUBTITLE_WEBVTT,
    NGX_HTTP_PCKG_M3U8_SUBTITLE_IMSC,
};


typedef struct {
    ngx_flag_t                      output_iv;
    ngx_http_complex_value_t       *key_uri;
    ngx_str_t                       key_format;
    ngx_str_t                       key_format_versions;
} ngx_http_pckg_m3u8_enc_conf_t;


typedef struct {
    ngx_http_complex_value_t       *block_reload;
    ngx_http_complex_value_t       *part_hold_back_percent;
    ngx_http_complex_value_t       *skip_boundary_percent;
} ngx_http_pckg_m3u8_ctl_conf_t;


typedef struct {
    ngx_uint_t                      version;
    ngx_uint_t                      container;
    ngx_uint_t                      subtitle_format;
    ngx_flag_t                      mux_segments;
    ngx_flag_t                      parts;
    ngx_flag_t                      rendition_reports;
    ngx_http_complex_value_t       *program_date_time;
    ngx_http_pckg_m3u8_ctl_conf_t   ctl;
    ngx_http_pckg_m3u8_enc_conf_t   enc;
} ngx_http_pckg_m3u8_loc_conf_t;


typedef struct {
    ngx_str_t                       key_uri;
} ngx_http_pckg_m3u8_enc_ctx_t;


static ngx_conf_enum_t  ngx_http_pckg_m3u8_containers[] = {
    { ngx_string("auto"),   NGX_HTTP_PCKG_M3U8_CONTAINER_AUTO },
    { ngx_string("mpegts"), NGX_HTTP_PCKG_M3U8_CONTAINER_MPEGTS },
    { ngx_string("fmp4"),   NGX_HTTP_PCKG_M3U8_CONTAINER_FMP4 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_pckg_m3u8_subtitle_formats[] = {
    { ngx_string("webvtt"), NGX_HTTP_PCKG_M3U8_SUBTITLE_WEBVTT },
    { ngx_string("imsc"),   NGX_HTTP_PCKG_M3U8_SUBTITLE_IMSC },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_m3u8_commands[] = {

    { ngx_string("pckg_m3u8_low_latency"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_pckg_m3u8_low_latency,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pckg_m3u8_container"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, container),
      &ngx_http_pckg_m3u8_containers },

    { ngx_string("pckg_m3u8_subtitle_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, subtitle_format),
      &ngx_http_pckg_m3u8_subtitle_formats },

    { ngx_string("pckg_m3u8_mux_segments"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, mux_segments),
      NULL },

    { ngx_string("pckg_m3u8_parts"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, parts),
      NULL },

    { ngx_string("pckg_m3u8_rendition_reports"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, rendition_reports),
      NULL },

    { ngx_string("pckg_m3u8_program_date_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, program_date_time),
      NULL },

    { ngx_string("pckg_m3u8_ctl_block_reload"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, ctl.block_reload),
      NULL },

    { ngx_string("pckg_m3u8_ctl_part_hold_back_percent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_percent_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, ctl.part_hold_back_percent),
      NULL },

    { ngx_string("pckg_m3u8_ctl_skip_boundary_percent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_percent_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, ctl.skip_boundary_percent),
      NULL },

#if (NGX_HAVE_OPENSSL_EVP)
    { ngx_string("pckg_m3u8_enc_output_iv"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, enc.output_iv),
      NULL },

    { ngx_string("pckg_m3u8_enc_key_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, enc.key_uri),
      NULL },

    { ngx_string("pckg_m3u8_enc_key_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, enc.key_format),
      NULL },

    { ngx_string("pckg_m3u8_enc_key_format_versions"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, enc.key_format_versions),
      NULL },
#endif /* NGX_HAVE_OPENSSL_EVP */

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_m3u8_module_ctx = {
    ngx_http_pckg_m3u8_preconfiguration, /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_pckg_m3u8_create_loc_conf,  /* create location configuration */
    ngx_http_pckg_m3u8_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_m3u8_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_m3u8_module_ctx,     /* module context */
    ngx_http_pckg_m3u8_commands,        /* module directives */
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


static ngx_str_t  ngx_http_pckg_m3u8_ext = ngx_string(".m3u8");

static ngx_str_t  ngx_http_pckg_m3u8_content_type =
    ngx_string("application/vnd.apple.mpegurl");


static ngx_str_t  ngx_http_pckg_m3u8_media_group_id[KMP_MEDIA_COUNT] = {
    ngx_string("vid"),
    ngx_string("aud"),
    ngx_string("sub"),
};


static ngx_str_t  ngx_http_pckg_m3u8_media_type_name[KMP_MEDIA_COUNT] = {
    ngx_string("VIDEO"),
    ngx_string("AUDIO"),
    ngx_string("SUBTITLES"),
};


static ngx_str_t  ngx_http_pckg_m3u8_default_label = ngx_string("default");


/* shared */

static u_char *
ngx_http_pckg_m3u8_quoted_str_write(u_char *dst, ngx_str_t *str)
{
    u_char       ch;
    u_char      *src;
    ngx_uint_t   n;

    src = str->data;
    n = str->len;

    while (n) {
        ch = *src++;
        n--;

        switch (ch) {

        case '"':
        case '\n':
        case '\r':
            continue;
        }

        *dst++ = ch;
    }

    return dst;
}


static ngx_http_pckg_container_t *
ngx_http_pckg_m3u8_get_container(ngx_http_request_t *r,
    ngx_pckg_variant_t *variant)
{
    ngx_uint_t                         media_type;
    media_info_t                      *media_info;
    ngx_pckg_track_t                  *video;
    ngx_http_pckg_container_t         *container;
    ngx_http_pckg_m3u8_loc_conf_t     *mlcf;
#if (NGX_HAVE_OPENSSL_EVP)
    ngx_http_pckg_enc_loc_conf_t      *elcf;
#endif

    /* Note: must match NGX_HTTP_PCKG_M3U8_XXX in order */
    static ngx_http_pckg_container_t  *containers[] = {
        NULL,
        &ngx_http_pckg_mpegts_container,
        &ngx_http_pckg_fmp4_container,
    };

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        if (variant->tracks[media_type] != NULL) {
            break;
        }
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    if (media_type == KMP_MEDIA_SUBTITLE) {
        switch (mlcf->subtitle_format) {

        case NGX_HTTP_PCKG_M3U8_SUBTITLE_IMSC:
            return &ngx_http_pckg_fmp4_container;

        default:
            return &ngx_http_pckg_webvtt_container;
        }
    }

    container = containers[mlcf->container];
    if (container != NULL) {
        return container;
    }

    if (variant->channel->header.part_duration) {
        /* prefer fmp4 when parts are used - mpegts can add significant
            overhead due to null packets added for consistent cc */
        return &ngx_http_pckg_fmp4_container;
    }

#if (NGX_HAVE_OPENSSL_EVP)
    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (elcf->scheme == NGX_HTTP_PCKG_ENC_CENC) {
        return &ngx_http_pckg_fmp4_container;
    }
#endif

    video = variant->tracks[KMP_MEDIA_VIDEO];
    if (video == NULL) {
        return &ngx_http_pckg_mpegts_container;
    }

    media_info = &video->last_media_info->media_info;
    if (media_info != NULL && media_info->codec_id == VOD_CODEC_ID_HEVC) {
        return &ngx_http_pckg_fmp4_container;
    }

    return &ngx_http_pckg_mpegts_container;
}


#if (NGX_HAVE_OPENSSL_EVP)

static ngx_str_t  ngx_http_pckg_m3u8_key =
    ngx_string(M3U8_ENC_KEY);

static ngx_str_t  ngx_http_pckg_m3u8_session_key =
    ngx_string(M3U8_ENC_SESSION_KEY);


static ngx_int_t
ngx_http_pckg_m3u8_init_enc(ngx_http_request_t *r, media_enc_t *enc)
{
    ngx_str_t                       key_uri;
    ngx_http_pckg_m3u8_enc_ctx_t   *ctx;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);
    if (mlcf->enc.key_uri == NULL) {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, mlcf->enc.key_uri, &key_uri) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_m3u8_init_enc: complex value failed");
        return NGX_ERROR;
    }

    if (key_uri.len <= 0) {
        return NGX_OK;
    }

    ctx = ngx_palloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_m3u8_init_enc: alloc failed");
        return NGX_ERROR;
    }

    ctx->key_uri = key_uri;

    enc->ctx = ctx;

    return NGX_OK;
}


static size_t
ngx_http_pckg_m3u8_enc_key_get_size(ngx_http_request_t *r, ngx_str_t *tag,
    ngx_pckg_variant_t *variant, ngx_pckg_track_t *track)
{
    size_t                          size;
    media_enc_t                    *enc;
    ngx_http_pckg_enc_loc_conf_t   *elcf;
    ngx_http_pckg_m3u8_enc_ctx_t   *ctx;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    enc = track->enc;
    if (enc == NULL) {
        return 0;
    }

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);
    ctx = enc->ctx;

    size = tag->len + sizeof(M3U8_ENC_KEY_METHOD) - 1 +
        sizeof(M3U8_ENC_METHOD_SAMPLE_AES_CTR) - 1 +
        sizeof(M3U8_ENC_KEY_URI) - 1 +
        sizeof("\"\n") - 1;

    if (ctx != NULL) {
        size += ctx->key_uri.len;

    } else if (elcf->scheme == NGX_HTTP_PCKG_ENC_CENC) {
        size += sizeof(M3U8_URI_BASE64_DATA) - 1 +
            mp4_dash_encrypt_base64_psshs_get_size(enc);

    } else {
        size += ngx_http_pckg_enc_key_uri_get_size(elcf->scope, variant);
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    if (mlcf->enc.output_iv) {
        size += sizeof(M3U8_ENC_KEY_IV) - 1 +
            sizeof(enc->iv) * 2;
    }

    if (mlcf->enc.key_format.len != 0) {
        size += sizeof(M3U8_ENC_KEY_KEY_FORMAT) +         /* '"' */
            mlcf->enc.key_format.len;
    }

    if (mlcf->enc.key_format_versions.len != 0) {
        size += sizeof(M3U8_ENC_KEY_KEY_FORMAT_VER) +     /* '"' */
            mlcf->enc.key_format_versions.len;
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_enc_key_write(u_char *p, ngx_http_request_t *r,
    ngx_str_t *tag, ngx_pckg_variant_t *variant, ngx_pckg_track_t *track)
{
    media_enc_t                    *enc;
    ngx_http_pckg_enc_loc_conf_t   *elcf;
    ngx_http_pckg_m3u8_enc_ctx_t   *ctx;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    enc = track->enc;
    if (enc == NULL) {
        return p;
    }

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);
    ctx = enc->ctx;

    p = ngx_copy_str(p, *tag);
    p = ngx_copy_fix(p, M3U8_ENC_KEY_METHOD);

    switch (elcf->scheme) {

    case NGX_HTTP_PCKG_ENC_AES_128:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_AES_128);
        break;

    case NGX_HTTP_PCKG_ENC_CBCS:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES);
        break;

    case NGX_HTTP_PCKG_ENC_CENC:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES_CTR);
        break;
    }

    /* uri */
    p = ngx_copy_fix(p, M3U8_ENC_KEY_URI);
    if (ctx != NULL) {
        p = ngx_http_pckg_m3u8_quoted_str_write(p, &ctx->key_uri);

    } else if (elcf->scheme == NGX_HTTP_PCKG_ENC_CENC) {
        p = ngx_copy_fix(p, M3U8_URI_BASE64_DATA);
        p = mp4_dash_encrypt_base64_psshs_write(p, enc);

    } else {
        p = ngx_http_pckg_enc_key_uri_write(p, elcf->scope, variant,
            1 << track->header.media_type);
    }

    *p++ = '"';

    /* iv */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    if (mlcf->enc.output_iv) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_IV);
        p = vod_append_hex_string(p, enc->iv, sizeof(enc->iv));
    }

    /* keyformat */
    if (mlcf->enc.key_format.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT);
        p = ngx_http_pckg_m3u8_quoted_str_write(p, &mlcf->enc.key_format);
        *p++ = '"';
    }

    /* keyformatversions */
    if (mlcf->enc.key_format_versions.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT_VER);
        p = ngx_http_pckg_m3u8_quoted_str_write(p,
            &mlcf->enc.key_format_versions);
        *p++ = '"';
    }

    *p++ = '\n';

    return p;
}
#else
#define ngx_http_pckg_m3u8_init_enc  NULL
#endif


/* master */

#if (NGX_HAVE_OPENSSL_EVP)
static size_t
ngx_http_pckg_m3u8_session_key_get_size(ngx_http_request_t *r)
{
    size_t                         size;
    ngx_uint_t                     i, n;
    ngx_uint_t                     media_type;
    ngx_pckg_track_t              *track;
    ngx_pckg_variant_t            *variant, *variants;
    ngx_pckg_channel_t            *channel;
    ngx_http_pckg_core_ctx_t      *ctx;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);
    if (elcf->scheme == NGX_HTTP_PCKG_ENC_NONE) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    size = sizeof("\n") - 1;

    switch (elcf->scope) {

    case NGX_HTTP_PCKG_ENC_SCOPE_CHANNEL:
        variant = channel->variants.elts;
        track = channel->tracks.elts;

        size += ngx_http_pckg_m3u8_enc_key_get_size(r,
            &ngx_http_pckg_m3u8_session_key, variant, track);
        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_MEDIA_TYPE:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            for (i = 0; i < n; i++) {
                variant = &variants[i];
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                size += ngx_http_pckg_m3u8_enc_key_get_size(r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
                break;
            }
        }

        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_VARIANT:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (i = 0; i < n; i++) {
            variant = &variants[i];

            for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                size += ngx_http_pckg_m3u8_enc_key_get_size(r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
                break;
            }
        }

        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_TRACK:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            for (i = 0; i < n; i++) {
                variant = &variants[i];
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                size += ngx_http_pckg_m3u8_enc_key_get_size(r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
            }
        }

        break;
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_session_key_write(u_char *p, ngx_http_request_t *r)
{
    ngx_uint_t                     i, n;
    ngx_uint_t                     media_type;
    ngx_pckg_track_t              *track;
    ngx_pckg_variant_t            *variant, *variants;
    ngx_pckg_channel_t            *channel;
    ngx_http_pckg_core_ctx_t      *ctx;
    ngx_http_pckg_enc_loc_conf_t  *elcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);
    if (elcf->scheme == NGX_HTTP_PCKG_ENC_NONE) {
        return p;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    *p++ = '\n';

    switch (elcf->scope) {

    case NGX_HTTP_PCKG_ENC_SCOPE_CHANNEL:
        variant = channel->variants.elts;
        track = channel->tracks.elts;

        p = ngx_http_pckg_m3u8_enc_key_write(p, r,
            &ngx_http_pckg_m3u8_session_key, variant, track);
        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_MEDIA_TYPE:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            for (i = 0; i < n; i++) {
                variant = &variants[i];
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                p = ngx_http_pckg_m3u8_enc_key_write(p, r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
                break;
            }
        }

        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_VARIANT:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (i = 0; i < n; i++) {
            variant = &variants[i];

            for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                p = ngx_http_pckg_m3u8_enc_key_write(p, r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
                break;
            }
        }

        break;

    case NGX_HTTP_PCKG_ENC_SCOPE_TRACK:
        variants = channel->variants.elts;
        n = channel->variants.nelts;

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            for (i = 0; i < n; i++) {
                variant = &variants[i];
                track = variant->tracks[media_type];

                if (track == NULL) {
                    continue;
                }

                p = ngx_http_pckg_m3u8_enc_key_write(p, r,
                    &ngx_http_pckg_m3u8_session_key, variant, track);
            }
        }

        break;
    }

    return p;
}
#endif


static size_t
ngx_http_pckg_m3u8_media_group_get_size(ngx_pckg_media_group_t *group,
    uint32_t media_type)
{
    size_t               result;
    size_t               base_size;
    ngx_str_t           *label;
    ngx_uint_t           i, n;
    ngx_pckg_variant_t  *variant, **variants;

    base_size = sizeof(M3U8_MEDIA_BASE) - 1 +
        ngx_http_pckg_m3u8_media_type_name[media_type].len +
        NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN + NGX_INT32_LEN +
        sizeof(M3U8_MEDIA_LANG) - 1 +
        sizeof(M3U8_MEDIA_DEFAULT) - 1 +
        sizeof(M3U8_MEDIA_URI) - 1 +
        ngx_http_pckg_prefix_index.len +
        sizeof("\"\"\"\n") - 1 +
        ngx_http_pckg_m3u8_ext.len;

    if (media_type == KMP_MEDIA_AUDIO) {
        base_size += sizeof(M3U8_MEDIA_CHANNELS) + NGX_INT32_LEN;
    }

    result = sizeof("\n") - 1 + base_size * group->variants.nelts;

    variants = group->variants.elts;
    n = group->variants.nelts;

    for (i = 0; i < n; i++) {
        variant = variants[i];

        label = variant->label.len > 0 ? &variant->label :
            &ngx_http_pckg_m3u8_default_label;

        result += label->len + variant->lang.len
            + ngx_pckg_sep_selector_get_size(&variant->id);
    }

    return result;
}


static u_char *
ngx_http_pckg_m3u8_media_group_write(u_char *p, ngx_pckg_media_group_t *group,
    uint32_t media_type)
{
    ngx_str_t           *label;
    ngx_uint_t           i, n;
    media_info_t        *media_info;
    ngx_pckg_track_t    *track;
    ngx_pckg_variant_t  *variant, **variants;

    *p++ = '\n';

    variants = group->variants.elts;
    n = group->variants.nelts;

    for (i = 0; i < n; i++) {
        variant = variants[i];

        track = variant->tracks[media_type];
        media_info = &track->last_media_info->media_info;

        label = variant->label.len > 0 ? &variant->label :
            &ngx_http_pckg_m3u8_default_label;

        p = ngx_sprintf(p, M3U8_MEDIA_BASE,
            &ngx_http_pckg_m3u8_media_type_name[media_type],
            &ngx_http_pckg_m3u8_media_group_id[media_type],
            media_info->codec_id);

        p = ngx_http_pckg_m3u8_quoted_str_write(p, label);
        *p++ = '"';

        if (variant->lang.len) {
            p = ngx_copy_fix(p, M3U8_MEDIA_LANG);
            p = ngx_http_pckg_m3u8_quoted_str_write(p, &variant->lang);
            *p++ = '"';
        }

        if (variant->header.is_default) {
            p = ngx_copy_fix(p, M3U8_MEDIA_DEFAULT);

        } else {
            p = ngx_copy_fix(p, M3U8_MEDIA_NON_DEFAULT);
        }

        if (media_type == KMP_MEDIA_AUDIO) {
            p = ngx_sprintf(p, M3U8_MEDIA_CHANNELS,
                (uint32_t) media_info->u.audio.channels);
        }

        p = ngx_copy_fix(p, M3U8_MEDIA_URI);

        p = ngx_copy_str(p, ngx_http_pckg_prefix_index);
        p = ngx_pckg_sep_selector_write(p, &variant->id, 1 << media_type);
        p = ngx_copy_str(p, ngx_http_pckg_m3u8_ext);

        *p++ = '"';
        *p++ = '\n';
    }

    return p;
}


static void
ngx_http_pckg_m3u8_upper(ngx_str_t *str)
{
    size_t   n;
    u_char  *p;

    n = str->len;
    p = str->data;

    while (n) {
        *p = ngx_toupper(*p);
        p++;
        n--;
    }
}


static size_t
ngx_http_pckg_m3u8_closed_captions_get_size(ngx_pckg_channel_t *channel)
{
    size_t                        size;
    ngx_uint_t                    i, n;
    ngx_pckg_captions_service_t  *css, *cs;

    css = channel->css.elts;
    n = channel->css.nelts;

    size = sizeof("\n") - 1 + (sizeof(M3U8_MEDIA_CC1) - 1
        + sizeof(M3U8_MEDIA_CC2) - 1 + sizeof(M3U8_MEDIA_LANG) - 1
        + sizeof("\"\n") - 1) * n;

    for (i = 0; i < n; i++) {
        cs = &css[i];
        size += cs->label.len + cs->id.len + cs->lang.len;

        if (cs->is_default) {
            size += sizeof(M3U8_MEDIA_DEFAULT) - 1;
        }
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_closed_captions_write(u_char *p,
    ngx_pckg_channel_t *channel)
{
    ngx_uint_t                    i, n;
    ngx_pckg_captions_service_t  *css, *cs;

    n = channel->css.nelts;
    if (n <= 0) {
        return p;
    }

    css = channel->css.elts;

    *p++ = '\n';

    for (i = 0; i < n; i++) {
        cs = &css[i];

        ngx_http_pckg_m3u8_upper(&cs->id);

        p = ngx_copy_fix(p, M3U8_MEDIA_CC1);
        p = ngx_http_pckg_m3u8_quoted_str_write(p, &cs->label);
        p = ngx_sprintf(p, M3U8_MEDIA_CC2, &cs->id);

        if (cs->lang.len) {
            p = ngx_copy_fix(p, M3U8_MEDIA_LANG);
            p = ngx_http_pckg_m3u8_quoted_str_write(p, &cs->lang);
            *p++ = '"';
        }

        if (cs->is_default) {
            p = ngx_copy_fix(p, M3U8_MEDIA_DEFAULT);
        }

        *p++ = '\n';
    }

    return p;
}


static size_t
ngx_http_pckg_m3u8_session_data_get_size(ngx_array_t *arr)
{
    size_t                  size;
    ngx_uint_t              i, n;
    ngx_pckg_data_value_t  *dvs, *dv;

    dvs = arr->elts;
    n = arr->nelts;

    size = sizeof("\n") - 1 + (sizeof(M3U8_SESSION_DATA_ID) - 1
        + sizeof(M3U8_SESSION_DATA_VALUE) - 1
        + sizeof(M3U8_SESSION_DATA_URI) - 1
        + sizeof(M3U8_SESSION_DATA_LANG) - 1
        + sizeof("\"\"\"\"\n") - 1) * n;

    for (i = 0; i < n; i++) {
        dv = &dvs[i];
        size += dv->id.len + dv->value.len + dv->uri.len + dv->lang.len;
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_session_data_write(u_char *p, ngx_array_t *arr)
{
    ngx_uint_t              i, n;
    ngx_pckg_data_value_t  *dvs, *dv;

    n = arr->nelts;
    if (n <= 0) {
        return p;
    }

    dvs = arr->elts;

    *p++ = '\n';

    for (i = 0; i < n; i++) {
        dv = &dvs[i];

        p = ngx_copy_fix(p, M3U8_SESSION_DATA_ID);
        p = ngx_http_pckg_m3u8_quoted_str_write(p, &dv->id);
        *p++ = '"';

        if (dv->value.len > 0) {
            p = ngx_copy_fix(p, M3U8_SESSION_DATA_VALUE);
            p = ngx_http_pckg_m3u8_quoted_str_write(p, &dv->value);
            *p++ = '"';
        }

        if (dv->uri.len > 0) {
            p = ngx_copy_fix(p, M3U8_SESSION_DATA_URI);
            p = ngx_http_pckg_m3u8_quoted_str_write(p, &dv->uri);
            *p++ = '"';
        }

        if (dv->lang.len > 0) {
            p = ngx_copy_fix(p, M3U8_SESSION_DATA_LANG);
            p = ngx_http_pckg_m3u8_quoted_str_write(p, &dv->lang);
            *p++ = '"';
        }

        *p++ = '\n';
    }

    return p;
}


static u_char *
ngx_http_pckg_m3u8_write_video_range(u_char *p, u_char transfer_char)
{
    switch (transfer_char) {

    case 1:
        p = ngx_copy_fix(p, M3U8_STREAM_VIDEO_RANGE_SDR);
        break;

    case 16:
    case 18:
        p = ngx_copy_fix(p, M3U8_STREAM_VIDEO_RANGE_PQ);
        break;
    }

    return p;
}


static size_t
ngx_http_pckg_m3u8_streams_get_size(ngx_array_t *streams)
{
    size_t              result;
    size_t              base_size;
    ngx_pckg_stream_t  *cur, *last;

    base_size = sizeof(M3U8_STREAM_BASE) - 1 + NGX_INT32_LEN +
        sizeof(M3U8_STREAM_AVG_BANDWIDTH) - 1 + NGX_INT32_LEN +
        sizeof(M3U8_STREAM_VIDEO) - 1 + 4 * NGX_INT32_LEN +
        MAX_CODEC_NAME_SIZE * 2 + sizeof(",\"\n") - 1 +
        sizeof(M3U8_STREAM_VIDEO_RANGE_SDR) - 1 +
        sizeof(M3U8_STREAM_TAG_CC) - 1 +    /* CC / NO_CC have same length */
        ngx_http_pckg_prefix_index.len +
        ngx_http_pckg_m3u8_ext.len + sizeof("\n") - 1;

    result = sizeof("\n") - 1 + base_size * streams->nelts;

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {
        result += ngx_pckg_sep_selector_get_size(&cur->variant->id);

        if (cur->groups[KMP_MEDIA_AUDIO] != NULL) {
            result += sizeof(M3U8_STREAM_TAG_AUDIO) - 1
                + NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN + NGX_INT32_LEN;
        }

        if (cur->groups[KMP_MEDIA_SUBTITLE] != NULL) {
            result += sizeof(M3U8_STREAM_CODEC_STPP) - 1
                + sizeof(M3U8_STREAM_TAG_SUBTITLE) - 1
                + NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN + NGX_INT32_LEN;
        }
    }

    return result;
}


static u_char *
ngx_http_pckg_m3u8_streams_write(u_char *p, ngx_http_request_t *r,
    ngx_array_t *streams, ngx_pckg_channel_t *channel,
    uint32_t segment_duration)
{
    uint32_t                         bitrate;
    uint32_t                         avg_bitrate;
    uint64_t                         frame_rate;
    ngx_str_t                        cc_group;
    media_info_t                    *video;
    media_info_t                    *audio;
    media_info_t                    *media_infos[KMP_MEDIA_COUNT];
    ngx_pckg_track_t               **tracks;
    ngx_pckg_stream_t               *cur;
    ngx_pckg_stream_t               *last;
    ngx_pckg_variant_t              *variant;
    ngx_pckg_media_group_t          *audio_group;
    ngx_pckg_media_group_t          *subtitle_group;
    ngx_http_pckg_container_t       *container;
    ngx_http_pckg_m3u8_loc_conf_t   *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    if (channel->css.elts) {
        if (channel->css.nelts) {
            ngx_str_set(&cc_group, M3U8_STREAM_TAG_CC);

        } else {
            ngx_str_set(&cc_group, M3U8_STREAM_TAG_NO_CC);
        }

    } else {
        ngx_str_null(&cc_group);
    }

    *p++ = '\n';

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {

        variant = cur->variant;
        tracks = variant->tracks;

        container = ngx_http_pckg_m3u8_get_container(r, variant);

        audio_group = cur->groups[KMP_MEDIA_AUDIO];
        if (audio_group != NULL) {
            audio = audio_group->media_info;

        } else if (tracks[KMP_MEDIA_AUDIO] != NULL) {
            audio = &tracks[KMP_MEDIA_AUDIO]->last_media_info->media_info;

        } else {
            audio = NULL;
        }

        subtitle_group = cur->groups[KMP_MEDIA_SUBTITLE];

        if (tracks[KMP_MEDIA_VIDEO] != NULL) {
            video = &tracks[KMP_MEDIA_VIDEO]->last_media_info->media_info;

            avg_bitrate = 0;

            if (audio != NULL) {
                if (audio_group != NULL) {
                    bitrate = ngx_http_pckg_estimate_max_bitrate(r, container,
                            &video, 1, segment_duration) +
                        ngx_http_pckg_estimate_max_bitrate(r, container,
                            &audio, 1, segment_duration);

                    if (video->avg_bitrate > 0 && audio->avg_bitrate > 0) {
                        avg_bitrate = ngx_http_pckg_estimate_avg_bitrate(r,
                                container, &video, 1, segment_duration) +
                            ngx_http_pckg_estimate_avg_bitrate(r, container,
                                &audio, 1, segment_duration);
                    }

                } else {
                    media_infos[0] = video;
                    media_infos[1] = audio;
                    bitrate = ngx_http_pckg_estimate_max_bitrate(r, container,
                        media_infos, 2, segment_duration);

                    if (video->avg_bitrate > 0 && audio->avg_bitrate > 0) {
                        avg_bitrate = ngx_http_pckg_estimate_avg_bitrate(r,
                            container, media_infos, 2, segment_duration);
                    }
                }

            } else {
                bitrate = ngx_http_pckg_estimate_max_bitrate(r, container,
                    &video, 1, segment_duration);

                if (video->avg_bitrate > 0) {
                    avg_bitrate = ngx_http_pckg_estimate_avg_bitrate(r,
                        container, &video, 1, segment_duration);
                }
            }

            frame_rate = (uint64_t) video->u.video.frame_rate_num * 1000 /
                video->u.video.frame_rate_denom;

            p = ngx_sprintf(p, M3U8_STREAM_BASE, bitrate);

            if (avg_bitrate > 0) {
                p = ngx_sprintf(p, M3U8_STREAM_AVG_BANDWIDTH, avg_bitrate);
            }

            p = ngx_sprintf(p, M3U8_STREAM_VIDEO,
                (uint32_t) video->u.video.width,
                (uint32_t) video->u.video.height,
                (uint32_t) (frame_rate / 1000),
                (uint32_t) (frame_rate % 1000),
                &video->codec_name);

            if (audio != NULL) {
                *p++ = ',';
                p = ngx_copy_str(p, audio->codec_name);
            }

            if (subtitle_group != NULL
                && mlcf->subtitle_format == NGX_HTTP_PCKG_M3U8_SUBTITLE_IMSC)
            {
                p = ngx_copy_fix(p, M3U8_STREAM_CODEC_STPP);
            }

            *p++ = '\"';

            p = ngx_http_pckg_m3u8_write_video_range(p,
                video->u.video.transfer_characteristics);

        } else if (audio != NULL) {

            bitrate = ngx_http_pckg_estimate_max_bitrate(r, container,
                &audio, 1, segment_duration);

            p = ngx_sprintf(p, M3U8_STREAM_BASE, bitrate);

            if (audio->avg_bitrate > 0) {
                avg_bitrate = ngx_http_pckg_estimate_avg_bitrate(r, container,
                    &audio, 1, segment_duration);

                p = ngx_sprintf(p, M3U8_STREAM_AVG_BANDWIDTH, avg_bitrate);
            }

            p = ngx_sprintf(p, M3U8_STREAM_CODECS, &audio->codec_name);

            if (subtitle_group != NULL
                && mlcf->subtitle_format == NGX_HTTP_PCKG_M3U8_SUBTITLE_IMSC)
            {
                p = ngx_copy_fix(p, M3U8_STREAM_CODEC_STPP);
            }

            *p++ = '\"';

        } else {
            continue;
        }

        if (audio_group != NULL) {
            p = ngx_sprintf(p, M3U8_STREAM_TAG_AUDIO,
                &ngx_http_pckg_m3u8_media_group_id[KMP_MEDIA_AUDIO],
                audio->codec_id);
        }

        if (subtitle_group != NULL) {
            p = ngx_sprintf(p, M3U8_STREAM_TAG_SUBTITLE,
                &ngx_http_pckg_m3u8_media_group_id[KMP_MEDIA_SUBTITLE],
                subtitle_group->media_info->codec_id);
        }

        if (tracks[KMP_MEDIA_VIDEO] != NULL) {
            p = ngx_copy_str(p, cc_group);
        }

        *p++ = '\n';

        p = ngx_copy_str(p, ngx_http_pckg_prefix_index);
        p = ngx_pckg_sep_selector_write(p, &variant->id, cur->media_types);
        p = ngx_copy_str(p, ngx_http_pckg_m3u8_ext);
        *p++ = '\n';
    }

    return p;
}


static ngx_int_t
ngx_http_pckg_m3u8_master_build(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_str_t *result)
{
    u_char                         *p;
    size_t                          size;
    uint32_t                        media_type;
    uint32_t                        segment_duration;
    ngx_int_t                       rc;
    ngx_queue_t                    *q;
    ngx_array_t                     dvs;
    ngx_pckg_media_group_t         *group;
    ngx_pckg_media_groups_t         groups;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    rc = ngx_http_pckg_captions_init(r);
    if (rc != NGX_OK && rc != NGX_BAD_DATA) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_pckg_data_init(r, &dvs);
    if (rc != NGX_OK && rc != NGX_BAD_DATA) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* group the variants */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    groups.channel = channel;

    groups.flags = 0;
    if (mlcf->mux_segments) {
        groups.flags |= NGX_PCKG_MEDIA_GROUP_MUX_SEGMENTS;
    }

    rc = ngx_pckg_media_groups_init(&groups);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (groups.streams.nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_m3u8_master_build: no streams found");
        return NGX_HTTP_BAD_REQUEST;
    }

    /* get the response size */
    size = sizeof(M3U8_MASTER_HEADER) - 1;

    size += ngx_http_pckg_m3u8_session_data_get_size(&dvs);

#if (NGX_HAVE_OPENSSL_EVP)
    size += ngx_http_pckg_m3u8_session_key_get_size(r);
#endif

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        for (q = ngx_queue_head(&groups.queue[media_type]);
            q != ngx_queue_sentinel(&groups.queue[media_type]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);

            size += ngx_http_pckg_m3u8_media_group_get_size(group, media_type);
        }
    }

    size += ngx_http_pckg_m3u8_closed_captions_get_size(channel);

    size += ngx_http_pckg_m3u8_streams_get_size(&groups.streams);

    /* allocate */
    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_master_build: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    p = ngx_copy_fix(p, M3U8_MASTER_HEADER);

    p = ngx_http_pckg_m3u8_session_data_write(p, &dvs);

#if (NGX_HAVE_OPENSSL_EVP)
    p = ngx_http_pckg_m3u8_session_key_write(p, r);
#endif

    /* write media groups */
    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        for (q = ngx_queue_head(&groups.queue[media_type]);
            q != ngx_queue_sentinel(&groups.queue[media_type]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);

            p = ngx_http_pckg_m3u8_media_group_write(p, group, media_type);
        }
    }

    p = ngx_http_pckg_m3u8_closed_captions_write(p, channel);

    /* write streams */
    segment_duration = rescale_time(channel->timeline.header.target_duration,
        channel->header.timescale, 1000);
    if (segment_duration <= 0) {
        segment_duration = 1;
    }

    p = ngx_http_pckg_m3u8_streams_write(p, r, &groups.streams, channel,
        segment_duration);

    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_m3u8_master_build: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_m3u8_master_handle(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_str_t                  response;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_m3u8_master_build(r, channel, &response);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_m3u8_content_type, channel->header.last_modified,
        NGX_HTTP_PCKG_EXPIRES_MASTER);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_m3u8_master_handler = {
    ngx_http_pckg_m3u8_init_enc,
    ngx_http_pckg_m3u8_master_handle,
    NULL,
};


/* index */

static size_t
ngx_http_pckg_m3u8_get_gap_size(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_pckg_segment_info_ctx_t *bi)
{
    uint32_t              cur;
    uint32_t              total;
    uint32_t              last_segment;
    uint32_t              first_segment;
    ngx_uint_t            i, n;
    ngx_pckg_period_t    *periods, *period;
    ngx_pckg_timeline_t  *timeline;

    total = 0;

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        first_segment = period->header.segment_index;
        last_segment = first_segment + period->segment_count;

        /* Note: using the min gap count since a gap is returned only if
            ALL tracks have a gap */

        cur = ngx_pckg_segment_info_min_gap_count(bi, first_segment,
            last_segment);

        total += cur;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_m3u8_get_gap_size: "
            "period %uD..%uD, gaps: %uD",
            first_segment, last_segment, cur);
    }

    return (size_t) total * (sizeof(M3U8_GAP) - 1);
}


static void
ngx_http_pckg_m3u8_period_get_bitrate_count(ngx_pckg_period_t *period,
    ngx_pckg_segment_info_ctx_t *bi, uint32_t milliscale,
    uint32_t *gap_count, uint32_t *bitrate_count)
{
    int64_t                     time;
    int64_t                     start, end;
    uint32_t                    bitrate;
    uint32_t                    duration;
    uint32_t                    last_bitrate;
    uint32_t                    last_segment;
    uint32_t                    segment_index;
    ngx_uint_t                  i, n;
    ngx_ksmp_segment_repeat_t  *elt;

    segment_index = period->header.segment_index;

    time = period->header.time;
    start = time / milliscale;

    last_bitrate = 0;

    n = period->nelts;
    for (i = 0; i < n; i++) {
        elt = &period->elts[i];

        for (last_segment = segment_index + elt->count;
            segment_index < last_segment;
            segment_index++)
        {
            time += elt->duration;
            end = time / milliscale;
            duration = end - start;

            bitrate = ngx_pckg_segment_info_get(bi, segment_index, duration);

            if (bitrate == 0) {
                (*gap_count)++;

            } else {
                /* bps -> kbps */
                bitrate = bitrate > 1000 ? bitrate / 1000 : 1;

                if (bitrate != NGX_KSMP_SEGMENT_NO_BITRATE &&
                    bitrate != last_bitrate)
                {
                    (*bitrate_count)++;

                    last_bitrate = bitrate;
                }
            }

            start = end;
        }
    }
}


static size_t
ngx_http_pckg_m3u8_get_bitrate_size(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_pckg_media_info_ctx_t *mi,
    ngx_pckg_segment_info_ctx_t *bi, ngx_http_pckg_container_t *container)
{
    uint32_t              ignore;
    uint32_t              gap_count;
    uint32_t              bitrate_count;
    uint32_t              milliscale;
    ngx_uint_t            i, n;
    ngx_pckg_period_t    *periods, *period;
    ngx_pckg_timeline_t  *timeline;

    milliscale = channel->header.timescale / 1000;

    gap_count = 0;
    bitrate_count = 0;

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        ngx_pckg_media_info_get(mi, period->header.segment_index, &ignore);

        ngx_http_pckg_get_bitrate_estimator(r, container,
            mi->media_infos, channel->tracks.nelts, bi->estimators);

        ngx_http_pckg_m3u8_period_get_bitrate_count(period, bi, milliscale,
            &gap_count, &bitrate_count);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_m3u8_get_bitrate_size: "
            "period %uD..%ui, accum_gaps: %uD, accum_bitrate: %uD",
            period->header.segment_index,
            (ngx_uint_t) period->header.segment_index + period->segment_count,
            gap_count, bitrate_count);
    }

    return
        (size_t) bitrate_count * (sizeof(M3U8_BITRATE) + NGX_INT32_LEN) +
        (size_t) gap_count * (sizeof(M3U8_GAP) - 1);
}


static ngx_inline u_char *
ngx_http_pckg_m3u8_append_extinf_tag(u_char *p, uint32_t duration)
{
    p = ngx_copy_fix(p, M3U8_EXTINF);
    p = ngx_sprintf(p, "%uD.%03uD", duration / 1000, duration % 1000);
    *p++ = ',';
    *p++ = '\n';
    return p;
}


static size_t
ngx_http_pckg_m3u8_parts_get_size(ngx_pckg_segment_parts_t *parts,
    ngx_str_t *seg_suffix)
{
    size_t    size;
    uint32_t  i;
    uint32_t  part;

    /* Note: not handling M3U8_PART_PRELOAD_HINT since its length is less
        than M3U8_PART_DURATION + M3U8_PART_INDEPENDENT + M3U8_PART_GAP */

    size = (sizeof(M3U8_PART_DURATION) - 1 + NGX_INT32_LEN + sizeof(".000") - 1
        + sizeof(M3U8_PART_URI) - 1 + ngx_http_pckg_prefix_part.len
        + 2 * NGX_INT32_LEN + seg_suffix->len - 1 + sizeof("\"\n") - 1)
        * parts->count;

    for (i = 0; i < parts->count; i++) {
        part = parts->duration[i];

        if (part & NGX_KSMP_PART_INDEPENDENT) {
            size += sizeof(M3U8_PART_INDEPENDENT) - 1;

        } else if (part & NGX_KSMP_PART_GAP) {
            size += sizeof(M3U8_PART_GAP) - 1;
        }
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_parts_write(u_char *p, ngx_pckg_segment_parts_t *parts,
    ngx_str_t *seg_suffix, int64_t time, uint32_t milliscale)
{
    int64_t   start, end;
    uint32_t  i;
    uint32_t  segment_index;
    uint32_t  part, duration;

    start = time / milliscale;
    segment_index = parts->segment_index + 1;

    i = 0;
    while (i < parts->count) {

        part = parts->duration[i];
        i++;

        if (part == NGX_KSMP_PART_PRELOAD_HINT) {

            p = ngx_copy_fix(p, M3U8_PART_PRELOAD_HINT);

        } else {

            duration = part & NGX_KSMP_PART_DURATION_MASK;

            time += duration;
            end = time / milliscale;
            duration = end - start;
            start = end;

            p = ngx_sprintf(p, M3U8_PART_DURATION,
                duration / 1000, duration % 1000);

            if (part & NGX_KSMP_PART_INDEPENDENT) {
                p = ngx_copy_fix(p, M3U8_PART_INDEPENDENT);

            } else if (part & NGX_KSMP_PART_GAP) {
                p = ngx_copy_fix(p, M3U8_PART_GAP);
            }
        }

        p = ngx_sprintf(p, M3U8_PART_URI, &ngx_http_pckg_prefix_part,
            segment_index, i);
        p = ngx_copy(p, seg_suffix->data, seg_suffix->len - 1);
        *p++ = '"';

        *p++ = '\n';
    }

    return p;
}


static size_t
ngx_http_pckg_m3u8_track_parts_get_size(ngx_pckg_channel_t *channel,
    ngx_str_t *seg_suffix)
{
    size_t                     size;
    ngx_pckg_track_t          *track;
    ngx_pckg_segment_parts_t  *cur;

    if (channel->tracks.nelts != 1) {
        return 0;
    }

    track = channel->tracks.elts;

    size = 0;
    for (cur = track->parts_cur; cur < track->parts_end; cur++) {
        size += ngx_http_pckg_m3u8_parts_get_size(cur, seg_suffix);
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_write_period_segments(u_char *p, ngx_pckg_period_t *period,
    ngx_str_t *seg_suffix, uint32_t milliscale,
    ngx_pckg_segment_info_ctx_t *bi)
{
    int64_t                     time;
    int64_t                     start, end;
    uint32_t                    bitrate;
    uint32_t                    duration;
    uint32_t                    last_bitrate;
    uint32_t                    last_segment;
    uint32_t                    segment_index;
    uint32_t                    part_segment_index;
    ngx_uint_t                  i, n;
    ngx_flag_t                  pending_segment;
    ngx_pckg_track_t           *track;
    ngx_pckg_channel_t         *channel;
    ngx_ksmp_segment_repeat_t  *elt;

    segment_index = period->header.segment_index;

    /* get the segment index of the first part */

    channel = period->timeline->channel;
    if (channel->tracks.nelts == 1) {
        track = channel->tracks.elts;

        for ( ;; ) {

            if (track->parts_cur >= track->parts_end) {
                part_segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
                break;
            }

            part_segment_index = track->parts_cur->segment_index;
            if (part_segment_index >= segment_index) {
                break;
            }

            track->parts_cur++;
        }

    } else {
        track = NULL;
        part_segment_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
    }

    time = period->header.time;
    start = time / milliscale;

    last_bitrate = 0;

    n = period->nelts;
    if (period->elts[n - 1].duration == NGX_KSMP_PENDING_SEGMENT_DURATION) {
        n--;
        pending_segment = 1;

    } else {
        pending_segment = 0;
    }

    for (i = 0; i < n; i++) {
        elt = &period->elts[i];

        last_segment = segment_index + elt->count;

        while (segment_index < last_segment) {

            /* write parts */

            if (segment_index == part_segment_index) {
                p = ngx_http_pckg_m3u8_parts_write(p, track->parts_cur,
                    seg_suffix, time, milliscale);

                track->parts_cur++;
                part_segment_index = track->parts_cur < track->parts_end
                    ? track->parts_cur->segment_index
                    : NGX_KSMP_INVALID_SEGMENT_INDEX;
            }

            /* write extinf */

            time += elt->duration;
            end = time / milliscale;
            duration = end - start;
            start = end;

            p = ngx_http_pckg_m3u8_append_extinf_tag(p, duration);

            /* write gap / bitrate */

            bitrate = ngx_pckg_segment_info_get(bi, segment_index, duration);

            if (bitrate == 0) {
                p = ngx_copy_fix(p, M3U8_GAP);

            } else {
                /* bps -> kbps */
                bitrate = bitrate > 1000 ? bitrate / 1000 : 1;

                if (bitrate != NGX_KSMP_SEGMENT_NO_BITRATE &&
                    bitrate != last_bitrate)
                {
                    p = ngx_copy_fix(p, M3U8_BITRATE);
                    p = ngx_sprintf(p, "%uD", bitrate);
                    *p++ = '\n';

                    last_bitrate = bitrate;
                }
            }

            /* write uri */

            segment_index++;
            p = ngx_copy_str(p, ngx_http_pckg_prefix_seg);
            p = ngx_sprintf(p, "-%uD", segment_index);
            p = ngx_copy_str(p, *seg_suffix);
        }
    }

    /* write pending segment parts */

    if (pending_segment && segment_index == part_segment_index) {
        p = ngx_http_pckg_m3u8_parts_write(p, track->parts_cur,
            seg_suffix, time, milliscale);

        track->parts_cur++;
    }

    return p;
}


static ngx_int_t
ngx_http_pckg_m3u8_get_selector(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_str_t *result)
{
    u_char              *p;
    size_t               size;
    ngx_pckg_variant_t  *variant;

    variant = channel->variants.elts;

    size = ngx_pckg_sep_selector_get_size(&variant->id);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_get_selector: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;
    p = ngx_pckg_sep_selector_write(p, &variant->id, channel->media_types);
    result->len = p - result->data;

    return NGX_OK;
}


static size_t
ngx_http_pckg_m3u8_server_control_get_size(void)
{
    return sizeof(M3U8_SERVER_CONTROL) - 1
        + sizeof(M3U8_CTL_BLOCK_RELOAD) - 1
        + sizeof(M3U8_CTL_CAN_SKIP_UNTIL) - 1 + 2 * NGX_INT32_LEN
        + sizeof(M3U8_CTL_PART_HOLD_BACK) - 1 + 2 * NGX_INT32_LEN
        + sizeof(",,\n") - 1;
}


static u_char *
ngx_http_pckg_m3u8_server_control_write(u_char *p, ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, uint32_t target_duration)
{
    ngx_flag_t                      comma;
    ngx_uint_t                      value;
    ngx_flag_t                      block_reload;
    ngx_uint_t                      part_hold_back_percent;
    ngx_uint_t                      skip_boundary_percent;
    ngx_pckg_timeline_t            *timeline;
    ngx_http_pckg_core_ctx_t       *ctx;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);
    timeline = &channel->timeline;

    skip_boundary_percent = ngx_http_complex_value_percent(r,
        mlcf->ctl.skip_boundary_percent, 0);

    if (ctx->params.media_type_count == 1) {

        /* iPhone player does not allow CAN-BLOCK-RELOAD=YES when the stream
            has EXT-X-ENDLIST */

        if (!timeline->header.end_list) {
            block_reload = ngx_http_complex_value_flag(r,
                mlcf->ctl.block_reload, 0);

        } else {
            block_reload = 0;
        }

        /* PART-HOLD-BACK is REQUIRED if the Playlist contains the EXT-X-
            PART-INF tag */

        if (mlcf->parts && channel->header.part_duration) {
            part_hold_back_percent = ngx_http_complex_value_percent(r,
                mlcf->ctl.part_hold_back_percent, 300);

        } else {
            part_hold_back_percent = 0;
        }

    } else {
        block_reload = 0;
        part_hold_back_percent = 0;
    }

    if (!block_reload && !skip_boundary_percent && !part_hold_back_percent) {
        return p;
    }

    p = ngx_copy_fix(p, M3U8_SERVER_CONTROL);

    if (block_reload) {
        comma = 1;
        p = ngx_copy_fix(p, M3U8_CTL_BLOCK_RELOAD);

    } else {
        comma = 0;
    }

    if (skip_boundary_percent) {
        if (comma) {
            *p++ = ',';

        } else {
            comma = 1;
        }

        value = target_duration * skip_boundary_percent * 10;

        p = ngx_sprintf(p, M3U8_CTL_CAN_SKIP_UNTIL,
            value / 1000, value % 1000);
    }

    if (part_hold_back_percent) {
        if (comma) {
            *p++ = ',';

        } else {
            comma = 1;
        }

        value = channel->header.part_duration
            * part_hold_back_percent * 10
            / channel->header.timescale;

        p = ngx_sprintf(p, M3U8_CTL_PART_HOLD_BACK,
            value / 1000, value % 1000);
    }

    *p++ = '\n';

    return p;
}


static size_t
ngx_http_pckg_m3u8_redition_reports_get_size(ngx_pckg_channel_t *channel)
{
    size_t                        size;
    ngx_uint_t                    i, n;
    ngx_pckg_rendition_report_t  *rrs, *variant_rr;

    size = 0;

    rrs = channel->rrs.elts;
    n = channel->rrs.nelts;
    for (i = 0; i < n; i++) {

        variant_rr = &rrs[i];

        size += (sizeof(M3U8_RENDITION_REPORT_URI) - 1
            + ngx_http_pckg_prefix_index.len
            + ngx_pckg_sep_selector_get_size(&variant_rr->variant_id)
            + ngx_http_pckg_m3u8_ext.len
            + sizeof(M3U8_RENDITION_REPORT_ATTRS) - 1 + 2 * NGX_INT32_LEN)
            * variant_rr->nelts;
    }

    return size;
}


static u_char *
ngx_http_pckg_m3u8_redition_reports_write(u_char *p,
    ngx_pckg_channel_t *channel)
{
    ngx_uint_t                    i, j, n;
    ngx_ksmp_rendition_report_t  *track_rr;
    ngx_pckg_rendition_report_t  *rrs, *variant_rr;

    rrs = channel->rrs.elts;
    n = channel->rrs.nelts;
    for (i = 0; i < n; i++) {

        variant_rr = &rrs[i];
        for (j = 0; j < variant_rr->nelts; j++) {
            track_rr = &variant_rr->elts[j];

            p = ngx_copy_fix(p, M3U8_RENDITION_REPORT_URI);
            p = ngx_copy_str(p, ngx_http_pckg_prefix_index);
            p = ngx_pckg_sep_selector_write(p, &variant_rr->variant_id,
                1 << track_rr->media_type);
            p = ngx_copy_str(p, ngx_http_pckg_m3u8_ext);
            p = ngx_sprintf(p, M3U8_RENDITION_REPORT_ATTRS,
                track_rr->last_sequence, track_rr->last_part_index);
        }
    }

    return p;
}


static ngx_int_t
ngx_http_pckg_m3u8_index_build(ngx_http_request_t *r, ngx_str_t *result)
{
    u_char                         *p;
    size_t                          size, period_size, segment_size;
    ngx_tm_t                        gmt;
    uint32_t                        version;
    uint32_t                        part_target;
    uint32_t                        target_duration;
    uint32_t                        segment_index_size;
    uint32_t                        timescale, milliscale;
    uint32_t                        map_index, last_map_index;
    ngx_int_t                       rc;
    ngx_str_t                       selector, seg_suffix;
    ngx_uint_t                      i, n;
    ngx_flag_t                      program_date_time;
#if (NGX_HAVE_OPENSSL_EVP)
    ngx_pckg_track_t               *track;
#endif
    ngx_pckg_period_t              *periods, *period;
    ngx_pckg_variant_t             *variant;
    ngx_pckg_channel_t             *channel;
    ngx_pckg_timeline_t            *timeline;
    ngx_http_pckg_core_ctx_t       *ctx;
    ngx_ksmp_period_header_t       *ph;
    ngx_http_pckg_container_t      *container;
    media_bitrate_estimator_t      *estimators;
    ngx_pckg_media_info_ctx_t      *mi;
    ngx_ksmp_timeline_header_t     *th;
    ngx_pckg_segment_info_ctx_t    *bi;
    ngx_http_pckg_enc_loc_conf_t   *elcf;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    /* get the container format */

    channel = ctx->channel;
    variant = channel->variants.elts;

    container = ngx_http_pckg_m3u8_get_container(r, variant);

    /* build the segment track selector */

    rc = ngx_http_pckg_m3u8_get_selector(r, channel, &selector);
    if (rc != NGX_OK) {
        return rc;
    }

    /* build the segment url suffix */

    p = ngx_pnalloc(r->pool, selector.len + container->seg_file_ext->len + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_index_build: alloc suffix failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    seg_suffix.data = p;
    p = ngx_copy_str(p, selector);
    p = ngx_copy_str(p, *container->seg_file_ext);
    *p++ = '\n';
    seg_suffix.len = p - seg_suffix.data;

    /* get response size limit */

    estimators = ngx_palloc(r->pool,
        channel->tracks.nelts * sizeof(estimators[0]));
    if (estimators == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_index_build: alloc estimators failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    mi = ngx_pckg_media_info_create(channel);
    if (mi == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    bi = ngx_pckg_segment_info_create(channel, estimators);
    if (bi == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    timeline = &channel->timeline;
    th = &timeline->header;

    periods = timeline->periods.elts;
    period = &periods[timeline->periods.nelts - 1];
    segment_index_size = vod_get_int_print_len(
        period->header.segment_index + period->segment_count);

    segment_size =
        sizeof(M3U8_EXTINF) - 1 + NGX_INT32_LEN + sizeof(".000,\n") - 1 +
        ngx_http_pckg_prefix_seg.len + sizeof("-") - 1 +
        segment_index_size + seg_suffix.len;

    period_size = sizeof(M3U8_DISCONTINUITY) - 1;

    program_date_time = ngx_http_complex_value_flag(r,
        mlcf->program_date_time, 1);

    if (program_date_time) {
        period_size += M3U8_PROGRAM_DATE_TIME_LEN;
    }

    if (container->init_file_ext) {
        period_size +=
            sizeof(M3U8_MAP_BASE) - 1 + sizeof("-\"\n") - 1 +
            ngx_http_pckg_prefix_init_seg.len + segment_index_size +
            selector.len + container->init_file_ext->len;
    }

    size = sizeof(M3U8_INDEX_HEADER) + 4 * NGX_INT32_LEN +
        ngx_http_pckg_m3u8_server_control_get_size() +
        sizeof(M3U8_PART_INF) - 1 + 2 * NGX_INT32_LEN +
        sizeof(M3U8_SKIPPED_SEGMENTS) - 1 + NGX_INT32_LEN +
        period_size * timeline->periods.nelts +
        segment_size * timeline->segment_count +
        ngx_http_pckg_m3u8_track_parts_get_size(channel, &seg_suffix) +
        ngx_http_pckg_m3u8_redition_reports_get_size(channel) +
        sizeof(M3U8_END_LIST) - 1;

#if (NGX_HAVE_OPENSSL_EVP)
    track = channel->tracks.elts;

    size += ngx_http_pckg_m3u8_enc_key_get_size(r, &ngx_http_pckg_m3u8_key,
        variant, track);
#endif

    if (ngx_pckg_segment_info_has_bitrate(bi)) {
        size += ngx_http_pckg_m3u8_get_bitrate_size(r, channel,
            mi, bi, container);
        ngx_pckg_media_info_reset(mi, channel);

    } else {
        /* more optimized implementation that only counts gaps */
        size += ngx_http_pckg_m3u8_get_gap_size(r, channel, bi);
    }

    ngx_pckg_segment_info_reset(bi, channel);

    /* allocate the buffer */

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_index_build: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    /* Note: assuming timescale is a multiple of 1000, if it's not, this will
            cause drift over time */
    timescale = channel->header.timescale;
    milliscale = timescale / 1000;

    /* write the header */

    target_duration = (th->target_duration + timescale / 2) / timescale;

    if (th->skipped_segments > 0) {
        version = 9;    /* EXT-X-SKIP requires version 9 */

    } else if (container->init_file_ext) {
        version = 6;    /* EXT-X-MAP requires version 6 */

    } else if (elcf->scheme == NGX_HTTP_PCKG_ENC_CBCS ||
        elcf->scheme == NGX_HTTP_PCKG_ENC_CENC ||
        mlcf->enc.key_format.len != 0 ||
        mlcf->enc.key_format_versions.len != 0)
    {
        version = 5;

    } else {
        version = 3;
    }

    p = ngx_sprintf(p, M3U8_INDEX_HEADER, target_duration, version,
        th->sequence, th->first_period_index - th->skipped_periods);

    p = ngx_http_pckg_m3u8_server_control_write(p, r, channel,
        target_duration);

    if (channel->header.part_duration > 0 && mlcf->parts
        && ctx->params.media_type_count == 1)
    {
        part_target = rescale_time(channel->header.part_duration, timescale,
            1000);
        p = ngx_sprintf(p, M3U8_PART_INF,
            part_target / 1000, part_target % 1000);
    }

    if (th->skipped_segments > 0) {
        p = ngx_sprintf(p, M3U8_SKIPPED_SEGMENTS, th->skipped_segments);

        ngx_pckg_media_info_get(mi, th->last_skipped_index, &last_map_index);

    } else {
        last_map_index = NGX_KSMP_INVALID_SEGMENT_INDEX;
    }

#if (NGX_HAVE_OPENSSL_EVP)
    p = ngx_http_pckg_m3u8_enc_key_write(p, r, &ngx_http_pckg_m3u8_key,
        variant, track);
#endif

    /* write the periods */

    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {

        period = &periods[i];
        ph = &period->header;

        ngx_pckg_media_info_get(mi, ph->segment_index, &map_index);

        ngx_http_pckg_get_bitrate_estimator(r, container,
            mi->media_infos, channel->tracks.nelts, estimators);

        if (i > 0 || (th->skipped_segments > 0
            && ph->segment_index == th->first_period_initial_segment_index))
        {
            p = ngx_copy_fix(p, M3U8_DISCONTINUITY);
        }

        if (container->init_file_ext && map_index != last_map_index) {

            if (i > 0 || th->skipped_segments <= 0
                || ph->segment_index == th->first_period_initial_segment_index)
            {
                p = ngx_copy_fix(p, M3U8_MAP_BASE);
                p = ngx_copy_str(p, ngx_http_pckg_prefix_init_seg);
                p = ngx_sprintf(p, "-%uD", map_index + 1);
                p = ngx_copy_str(p, selector);
                p = ngx_copy_str(p, *container->init_file_ext);
                *p++ = '"';
                *p++ = '\n';
            }

            last_map_index = map_index;
        }

        if (program_date_time) {
            ngx_gmtime(ph->time / timescale, &gmt);

            p = ngx_sprintf(p, M3U8_PROGRAM_DATE_TIME,
                gmt.ngx_tm_year, gmt.ngx_tm_mon, gmt.ngx_tm_mday,
                gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec,
                (int) ((ph->time / milliscale) % 1000));
        }

        p = ngx_http_pckg_m3u8_write_period_segments(p, period,
            &seg_suffix, milliscale, bi);
    }

    /* write the footer */

    p = ngx_http_pckg_m3u8_redition_reports_write(p, channel);

    if (th->end_list) {
        p = ngx_copy_fix(p, M3U8_END_LIST);
    }

    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_m3u8_index_build: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_m3u8_index_handle(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_str_t                  response;
    ngx_uint_t                 expires_type;
    ngx_http_pckg_core_ctx_t  *ctx;

    rc = ngx_http_pckg_m3u8_index_build(r, &response);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);

    if (ctx->params.flags & NGX_KSMP_FLAG_WAIT) {
        expires_type = NGX_HTTP_PCKG_EXPIRES_INDEX_BLOCKING;

    } else {
        expires_type = NGX_HTTP_PCKG_EXPIRES_INDEX;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_m3u8_content_type,
        ctx->channel->timeline.header.last_modified, expires_type);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_m3u8_index_handler = {
    ngx_http_pckg_m3u8_init_enc,
    ngx_http_pckg_m3u8_index_handle,
    NULL,
};


/* init */

static ngx_int_t
ngx_http_pckg_m3u8_args_handler(ngx_http_request_t *r, void *data,
    ngx_str_t *key, ngx_str_t *value)
{
    ngx_int_t                       int_val;
    ngx_uint_t                      skip_boundary_percent;
    ngx_pckg_ksmp_req_t            *params = data;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    if (key->len <= sizeof(M3U8_ARG_PREFIX) - 1
        || ngx_memcmp(key->data, M3U8_ARG_PREFIX, sizeof(M3U8_ARG_PREFIX) - 1)
            != 0)
    {
        return NGX_OK;
    }

    key->data += sizeof(M3U8_ARG_PREFIX) - 1;
    key->len -= sizeof(M3U8_ARG_PREFIX) - 1;

    if (key->len == sizeof(M3U8_ARG_SKIP) - 1
        && ngx_memcmp(key->data, M3U8_ARG_SKIP, sizeof(M3U8_ARG_SKIP) - 1)
            == 0)
    {
        mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

        skip_boundary_percent = ngx_http_complex_value_percent(r,
            mlcf->ctl.skip_boundary_percent, 0);
        if (!skip_boundary_percent) {
            return NGX_OK;
        }

        if ((value->len == sizeof("YES") - 1
            && ngx_memcmp(value->data, "YES", sizeof("YES") - 1) == 0)
            || (value->len == sizeof("v2") - 1
                && ngx_memcmp(value->data, "v2", sizeof("v2") - 1) == 0))
        {
            params->flags |= NGX_KSMP_FLAG_SKIP_SEGMENTS;
            params->skip_boundary_percent = skip_boundary_percent;

        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ngx_http_pckg_m3u8_args_handler: "
                "unknown _HLS_skip value \"%V\"", value);
        }

    } else if (key->len == sizeof(M3U8_ARG_MSN) - 1
        && ngx_memcmp(key->data, M3U8_ARG_MSN, sizeof(M3U8_ARG_MSN) - 1) == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_m3u8_args_handler: "
                "invalid _HLS_msn \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->flags |= NGX_KSMP_FLAG_WAIT;
        params->segment_index = int_val;

    } else if (key->len == sizeof(M3U8_ARG_PART) - 1
        && ngx_memcmp(key->data, M3U8_ARG_PART, sizeof(M3U8_ARG_PART) - 1)
            == 0)
    {
        int_val = ngx_atoi(value->data, value->len);
        if (int_val == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_m3u8_args_handler: "
                "invalid _HLS_part \"%V\"", value);
            return NGX_HTTP_BAD_REQUEST;
        }

        params->flags |= NGX_KSMP_FLAG_WAIT;
        params->part_index = int_val;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_m3u8_parse_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t                        flags;
    ngx_int_t                       rc;
    ngx_http_pckg_core_loc_conf_t  *plcf;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_index))
    {
        rc = ngx_http_api_parse_args(r, ngx_http_pckg_m3u8_args_handler,
            result);
        if (rc != NGX_OK) {
            return rc;
        }

        if (result->part_index != NGX_KSMP_INVALID_PART_INDEX
            && result->segment_index == NGX_KSMP_INVALID_SEGMENT_INDEX)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_pckg_m3u8_parse_request: "
                "request for _HLS_part without _HLS_msn");
            return NGX_HTTP_BAD_REQUEST;
        }

        start_pos += ngx_http_pckg_prefix_index.len;

        *handler = &ngx_http_pckg_m3u8_index_handler;

        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags |= plcf->active_policy | NGX_KSMP_FLAG_CHECK_EXPIRY
            | NGX_KSMP_FLAG_TIMELINE | NGX_KSMP_FLAG_PERIODS
            | NGX_KSMP_FLAG_MEDIA_INFO | NGX_KSMP_FLAG_SEGMENT_INFO;

        rc = ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos, flags,
            result);
        if (rc != NGX_OK) {
            return rc;
        }

        if (result->media_type_count == 1) {
            mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

            if (mlcf->parts) {
                result->flags |= NGX_KSMP_FLAG_SEGMENT_PARTS;
            }

            if (mlcf->rendition_reports) {
                result->flags |= NGX_KSMP_FLAG_RENDITION_REPORTS;
            }

        } else {
            if (result->flags & NGX_KSMP_FLAG_WAIT) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_pckg_m3u8_parse_request: "
                    "wait request on multiple tracks");
                return NGX_HTTP_BAD_REQUEST;
            }
        }

        return NGX_OK;

    } else if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_master))
    {
        start_pos += ngx_http_pckg_prefix_master.len;

        *handler = &ngx_http_pckg_m3u8_master_handler;
        flags = NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = plcf->active_policy
            | NGX_KSMP_FLAG_TIMELINE | NGX_KSMP_FLAG_MEDIA_INFO
            | NGX_KSMP_FLAG_LAST_SEGMENT_ONLY | NGX_KSMP_FLAG_MAX_PENDING;

        result->parse_flags = NGX_PCKG_KSMP_PARSE_FLAG_TRANSFER_CHAR
            | NGX_PCKG_KSMP_PARSE_FLAG_CODEC_NAME;

    } else {
        return NGX_DECLINED;
    }

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static char *
ngx_http_pckg_m3u8_low_latency(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                      *value;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf = conf;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        ngx_conf_init_value(mlcf->mux_segments, 0);
        ngx_conf_init_value(mlcf->parts, 1);
        ngx_conf_init_value(mlcf->rendition_reports, 1);

        ngx_conf_init_complex_int_value(mlcf->ctl.block_reload, 1);
        ngx_conf_init_complex_int_value(mlcf->ctl.skip_boundary_percent, 600);
        ngx_conf_init_complex_int_value(mlcf->ctl.part_hold_back_percent, 300);

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        ngx_conf_init_value(mlcf->mux_segments, 1);
        ngx_conf_init_value(mlcf->parts, 0);
        ngx_conf_init_value(mlcf->rendition_reports, 0);

        ngx_conf_init_complex_int_value(mlcf->ctl.block_reload, 0);
        ngx_conf_init_complex_int_value(mlcf->ctl.skip_boundary_percent, 0);
        ngx_conf_init_complex_int_value(mlcf->ctl.part_hold_back_percent, 0);

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"%s\" in \"%s\" directive, "
            "it must be \"on\" or \"off\"",
            value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_pckg_m3u8_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_m3u8_ext,
        ngx_http_pckg_m3u8_parse_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_pckg_m3u8_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_m3u8_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_m3u8_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_pckg_m3u8_create_loc_conf: ngx_pcalloc failed");
        return NULL;
    }

    conf->container = NGX_CONF_UNSET_UINT;
    conf->subtitle_format = NGX_CONF_UNSET_UINT;
    conf->mux_segments = NGX_CONF_UNSET;
    conf->parts = NGX_CONF_UNSET;
    conf->rendition_reports = NGX_CONF_UNSET;

    conf->enc.output_iv = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_pckg_m3u8_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_m3u8_loc_conf_t  *prev = parent;
    ngx_http_pckg_m3u8_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->container,
                              prev->container,
                              NGX_HTTP_PCKG_M3U8_CONTAINER_AUTO);

    ngx_conf_merge_uint_value(conf->subtitle_format,
                              prev->subtitle_format,
                              NGX_HTTP_PCKG_M3U8_SUBTITLE_WEBVTT);

    ngx_conf_merge_value(conf->mux_segments,
                         prev->mux_segments, 1);

    ngx_conf_merge_value(conf->parts,
                         prev->parts, 0);

    ngx_conf_merge_value(conf->rendition_reports,
                         prev->rendition_reports, 0);

    if (conf->program_date_time == NULL) {
        conf->program_date_time = prev->program_date_time;
    }


    if (conf->ctl.block_reload == NULL) {
        conf->ctl.block_reload = prev->ctl.block_reload;
    }

    if (conf->ctl.part_hold_back_percent == NULL) {
        conf->ctl.part_hold_back_percent = prev->ctl.part_hold_back_percent;
    }

    if (conf->ctl.skip_boundary_percent == NULL) {
        conf->ctl.skip_boundary_percent = prev->ctl.skip_boundary_percent;
    }


    ngx_conf_merge_value(conf->enc.output_iv,
                         prev->enc.output_iv, 1);

    if (conf->enc.key_uri == NULL) {
        conf->enc.key_uri = prev->enc.key_uri;
    }

    ngx_conf_merge_str_value(conf->enc.key_format,
                             prev->enc.key_format, "");

    ngx_conf_merge_str_value(conf->enc.key_format_versions,
                             prev->enc.key_format_versions, "");

    return NGX_CONF_OK;
}
