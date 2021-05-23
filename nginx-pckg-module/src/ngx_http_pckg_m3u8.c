#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_enc.h"
#include "ngx_http_pckg_fmp4.h"
#include "ngx_http_pckg_mpegts.h"

#include "ngx_pckg_media_group.h"
#include "ngx_pckg_media_info.h"
#include "ngx_pckg_segment_info.h"


static ngx_int_t ngx_http_pckg_m3u8_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_m3u8_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_m3u8_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


/* master playlist */
#define NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN  (3)

#define M3U8_MASTER_HEADER           "#EXTM3U\n#EXT-X-INDEPENDENT-SEGMENTS\n"

#define M3U8_STREAM_VIDEO            "#EXT-X-STREAM-INF:PROGRAM-ID=1"       \
    ",BANDWIDTH=%uD,RESOLUTION=%uDx%uD,FRAME-RATE=%uD.%03uD,CODECS=\"%V"
#define M3U8_STREAM_AUDIO            "#EXT-X-STREAM-INF:PROGRAM-ID=1"       \
    ",BANDWIDTH=%uD,CODECS=\"%V"
#define M3U8_STREAM_VIDEO_RANGE_SDR  ",VIDEO-RANGE=SDR"
#define M3U8_STREAM_VIDEO_RANGE_PQ   ",VIDEO-RANGE=PQ"
#define M3U8_STREAM_TAG_AUDIO        ",AUDIO=\"%V%uD\""

#define M3U8_MEDIA_BASE              "#EXT-X-MEDIA:TYPE=%V"                 \
    ",GROUP-ID=\"%V%uD\",NAME=\"%V\","
#define M3U8_MEDIA_LANG              "LANGUAGE=\"%V\","
#define M3U8_MEDIA_DEFAULT           "AUTOSELECT=YES,DEFAULT=YES,"
#define M3U8_MEDIA_NON_DEFAULT       "AUTOSELECT=NO,DEFAULT=NO,"
#define M3U8_MEDIA_CHANNELS          "CHANNELS=\"%uD\","
#define M3U8_MEDIA_URI               "URI=\""

/* index playlist */
#define M3U8_INDEX_HEADER            "#EXTM3U\n#EXT-X-TARGETDURATION:%uD\n" \
    "#EXT-X-VERSION:%uD\n#EXT-X-MEDIA-SEQUENCE:%uD\n"                       \
    "#EXT-X-DISCONTINUITY-SEQUENCE:%uD\n#EXT-X-INDEPENDENT-SEGMENTS\n"      \
    "#EXT-X-ALLOW-CACHE:YES\n"
#define M3U8_EXTINF                  "#EXTINF:"
#define M3U8_GAP                     "#EXT-X-GAP\n"
#define M3U8_BITRATE                 "#EXT-X-BITRATE:"
#define M3U8_DISCONTINUITY           "#EXT-X-DISCONTINUITY\n"
#define M3U8_PROGRAM_DATE_TIME                                              \
    "#EXT-X-PROGRAM-DATE-TIME:%4d-%02d-%02dT%02d:%02d:%02d.%03d+00:00\n"
#define M3U8_PROGRAM_DATE_TIME_LEN                                          \
    (sizeof("#EXT-X-PROGRAM-DATE-TIME:2000-01-01T00:00:00.000+00:00\n") - 1)
#define M3U8_MAP_BASE                "#EXT-X-MAP:URI=\""
#define M3U8_END_LIST                "#EXT-X-ENDLIST\n"

#define M3U8_ENC_KEY_BASE            "#EXT-X-KEY:METHOD="
#define M3U8_ENC_KEY_URI             ",URI=\""
#define M3U8_ENC_KEY_IV              ",IV=0x"
#define M3U8_ENC_KEY_KEY_FORMAT      ",KEYFORMAT=\""
#define M3U8_ENC_KEY_KEY_FORMAT_VER  ",KEYFORMATVERSIONS=\""

#define M3U8_ENC_METHOD_AES_128      "AES-128"
#define M3U8_ENC_METHOD_SAMPLE_AES   "SAMPLE-AES"
#define M3U8_ENC_METHOD_SAMPLE_AES_CENC                                     \
    "SAMPLE-AES-CENC"


enum {
    NGX_HTTP_PCKG_M3U8_CONTAINER_AUTO,
    NGX_HTTP_PCKG_M3U8_CONTAINER_MPEGTS,
    NGX_HTTP_PCKG_M3U8_CONTAINER_FMP4,
};


typedef struct {
    ngx_flag_t                      output_iv;
    ngx_http_complex_value_t       *key_uri;
    ngx_str_t                       key_format;
    ngx_str_t                       key_format_versions;
}  ngx_http_pckg_m3u8_enc_conf_t;

typedef struct {
    ngx_uint_t                      version;
    ngx_uint_t                      container;
    ngx_flag_t                      mux_segments;
    ngx_http_pckg_m3u8_enc_conf_t   enc;
}  ngx_http_pckg_m3u8_loc_conf_t;


typedef struct {
    ngx_uint_t                      type;
    ngx_str_t                       key_uri;
    ngx_str_t                       iv;
    u_char                          iv_buf[AES_BLOCK_SIZE];
} ngx_http_pckg_m3u8_enc_params_t;


static ngx_conf_enum_t  ngx_http_pckg_m3u8_containers[] = {
    { ngx_string("auto"),   NGX_HTTP_PCKG_M3U8_CONTAINER_AUTO },
    { ngx_string("mpegts"), NGX_HTTP_PCKG_M3U8_CONTAINER_MPEGTS },
    { ngx_string("fmp4"),   NGX_HTTP_PCKG_M3U8_CONTAINER_FMP4 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_pckg_m3u8_commands[] = {

    { ngx_string("pckg_m3u8_container"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, container),
      &ngx_http_pckg_m3u8_containers },

    { ngx_string("pckg_m3u8_mux_segments"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_m3u8_loc_conf_t, mux_segments),
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
};

static ngx_str_t  ngx_http_pckg_m3u8_media_type_name[KMP_MEDIA_COUNT] = {
    ngx_string("VIDEO"),
    ngx_string("AUDIO"),
};

static ngx_str_t  ngx_http_pckg_m3u8_default_label = ngx_string("default");


/* shared */

static ngx_http_pckg_container_t *
ngx_http_pckg_m3u8_get_container(ngx_http_request_t *r,
    ngx_pckg_track_t **tracks)
{
    media_info_t                      *media_info;
    ngx_http_pckg_container_t         *container;
    ngx_http_pckg_enc_loc_conf_t      *elcf;
    ngx_http_pckg_m3u8_loc_conf_t     *mlcf;

    /* Note: must match NGX_HTTP_PCKG_M3U8_XXX in order */
    static ngx_http_pckg_container_t  *containers[] = {
        NULL,
        &ngx_http_pckg_mpegts_container,
        &ngx_http_pckg_fmp4_container,
    };

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    container = containers[mlcf->container];
    if (container != NULL) {
        return container;
    }

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    if (elcf->scheme == NGX_HTTP_PCKG_ENC_CENC) {
        return &ngx_http_pckg_fmp4_container;
    }

    if (tracks[KMP_MEDIA_VIDEO] == NULL) {
        return &ngx_http_pckg_mpegts_container;
    }

    media_info = &tracks[KMP_MEDIA_VIDEO]->last_media_info->media_info;
    if (media_info != NULL && media_info->codec_id == VOD_CODEC_ID_HEVC) {
        return &ngx_http_pckg_fmp4_container;
    }

    return &ngx_http_pckg_mpegts_container;
}


/* master */

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
        sizeof("-s-v\"\n") - 1 +
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

        result += label->len + variant->lang.len + variant->id.len;
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

        p = vod_sprintf(p, M3U8_MEDIA_BASE,
            &ngx_http_pckg_m3u8_media_type_name[media_type],
            &ngx_http_pckg_m3u8_media_group_id[media_type],
            media_info->codec_id,
            label);

        if (variant->lang.len) {
            p = vod_sprintf(p, M3U8_MEDIA_LANG, &variant->lang);
        }

        if (variant->header->is_default) {
            p = ngx_copy_fix(p, M3U8_MEDIA_DEFAULT);

        } else {
            p = ngx_copy_fix(p, M3U8_MEDIA_NON_DEFAULT);
        }

        if (media_type == KMP_MEDIA_AUDIO) {
            p = vod_sprintf(p, M3U8_MEDIA_CHANNELS,
                (uint32_t) media_info->u.audio.channels);
        }

        p = ngx_copy_fix(p, M3U8_MEDIA_URI);

        p = ngx_sprintf(p, "%V-s%V-%c%V", &ngx_http_pckg_prefix_index,
            &variant->id, ngx_http_pckg_media_type_code[media_type],
            &ngx_http_pckg_m3u8_ext);

        *p++ = '"';
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

    base_size = sizeof(M3U8_STREAM_VIDEO) - 1 + 5 * NGX_INT32_LEN +
        MAX_CODEC_NAME_SIZE * 2 + sizeof(",\"\n") - 1 +
        sizeof(M3U8_STREAM_VIDEO_RANGE_SDR) - 1 +
        ngx_http_pckg_prefix_index.len +
        ngx_http_pckg_m3u8_ext.len + sizeof("\n") - 1;

    result = sizeof("\n") - 1 + base_size * streams->nelts;

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {
        result += ngx_http_pckg_selector_get_size(cur->variant);

        if (cur->groups[KMP_MEDIA_AUDIO] != NULL) {
            base_size += sizeof(M3U8_STREAM_TAG_AUDIO) - 1 +
                NGX_HTTP_PCKG_M3U8_MAX_GROUP_ID_LEN + NGX_INT32_LEN;
        }
    }

    return result;
}


static u_char *
ngx_http_pckg_m3u8_streams_write(u_char *p, ngx_http_request_t *r,
    ngx_array_t *streams, ngx_pckg_channel_t *channel,
    uint32_t segment_duration)
{
    uint32_t                     bitrate;
    uint64_t                     frame_rate;
    media_info_t                *video;
    media_info_t                *audio;
    media_info_t                *media_infos[KMP_MEDIA_COUNT];
    ngx_pckg_track_t           **tracks;
    ngx_pckg_stream_t           *cur;
    ngx_pckg_stream_t           *last;
    ngx_pckg_variant_t          *variant;
    ngx_pckg_media_group_t      *audio_group;
    ngx_http_pckg_container_t   *container;

    *p++ = '\n';

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {

        variant = cur->variant;
        tracks = variant->tracks;

        container = ngx_http_pckg_m3u8_get_container(r, tracks);

        audio_group = cur->groups[KMP_MEDIA_AUDIO];
        if (audio_group != NULL) {
            audio = audio_group->media_info;

        } else if (tracks[KMP_MEDIA_AUDIO] != NULL) {
            audio = &tracks[KMP_MEDIA_AUDIO]->last_media_info->media_info;

        } else {
            audio = NULL;
        }

        if (tracks[KMP_MEDIA_VIDEO] != NULL) {
            video = &tracks[KMP_MEDIA_VIDEO]->last_media_info->media_info;

            if (audio != NULL) {
                if (audio_group != NULL) {
                    bitrate = ngx_http_pckg_estimate_bitrate(r, container,
                            &video, 1, segment_duration) +
                        ngx_http_pckg_estimate_bitrate(r, container,
                            &audio, 1, segment_duration);

                } else {
                    media_infos[0] = video;
                    media_infos[1] = audio;
                    bitrate = ngx_http_pckg_estimate_bitrate(r, container,
                        media_infos, 2, segment_duration);
                }

            } else {
                bitrate = ngx_http_pckg_estimate_bitrate(r, container,
                    &video, 1, segment_duration);
            }

            frame_rate = (uint64_t) video->u.video.frame_rate_num * 1000 /
                video->u.video.frame_rate_denom;

            p = ngx_sprintf(p, M3U8_STREAM_VIDEO, bitrate,
                (uint32_t) video->u.video.width,
                (uint32_t) video->u.video.height,
                (uint32_t) (frame_rate / 1000),
                (uint32_t) (frame_rate % 1000),
                &video->codec_name);
            if (audio != NULL) {
                *p++ = ',';
                p = ngx_copy_str(p, audio->codec_name);
            }

            *p++ = '\"';

            p = ngx_http_pckg_m3u8_write_video_range(p,
                video->u.video.transfer_characteristics);

        } else if (audio != NULL) {

            bitrate = ngx_http_pckg_estimate_bitrate(r, container,
                &audio, 1, segment_duration);

            p = ngx_sprintf(p, M3U8_STREAM_AUDIO, bitrate,
                &audio->codec_name);

            *p++ = '\"';

        } else {
            continue;
        }

        if (audio_group != NULL) {
            p = vod_sprintf(p, M3U8_STREAM_TAG_AUDIO,
                &ngx_http_pckg_m3u8_media_group_id[KMP_MEDIA_AUDIO],
                audio->codec_id);
        }

        *p++ = '\n';

        p = ngx_copy_str(p, ngx_http_pckg_prefix_index);
        p = ngx_http_pckg_selector_write(p, variant, cur->media_types);
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
    ngx_pckg_media_group_t         *group;
    ngx_pckg_media_groups_t         groups;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    /* group the variants */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    groups.channel = channel;

    groups.flags = 0;
    if (mlcf->mux_segments) {
        groups.flags |= NGX_PCKG_MEDIA_GROUP_MUX_SEGMENTS;
    }

    rc = ngx_pckg_media_groups_init(&groups);
    if (rc != NGX_OK) {
        return rc;
    }

    /* get the response size */
    size = sizeof(M3U8_MASTER_HEADER) - 1;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        for (q = ngx_queue_head(&groups.queue[media_type]);
            q != ngx_queue_sentinel(&groups.queue[media_type]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);

            size += ngx_http_pckg_m3u8_media_group_get_size(group, media_type);
        }
    }

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

    /* write streams */
    segment_duration = rescale_time(channel->timeline.header->target_duration,
        channel->header->timescale, 1000);
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
        &ngx_http_pckg_m3u8_content_type, channel->header->last_modified,
        NGX_HTTP_PCKG_EXPIRES_MASTER);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_m3u8_master_handler = {
    ngx_http_pckg_m3u8_master_handle,
    NULL,
};


/* index */

#if (NGX_HAVE_OPENSSL_EVP)
static ngx_int_t
ngx_http_pckg_m3u8_enc_init(ngx_http_request_t *r,
    ngx_http_pckg_m3u8_enc_params_t *enc_params)
{
    ngx_int_t                       rc;
    ngx_http_pckg_enc_loc_conf_t   *elcf;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    elcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_enc_module);

    enc_params->type = elcf->scheme;
    switch (enc_params->type) {

    case NGX_HTTP_PCKG_ENC_NONE:
        return NGX_OK;

    case NGX_HTTP_PCKG_ENC_AES_128:
    case NGX_HTTP_PCKG_ENC_CBCS:
    case NGX_HTTP_PCKG_ENC_CENC:
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_m3u8_enc_init: "
            "scheme %ui not supported", enc_params->type);
        return NGX_HTTP_BAD_REQUEST;
    }

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    if (mlcf->enc.key_uri != NULL) {

        if (ngx_http_complex_value(r, mlcf->enc.key_uri, &enc_params->key_uri)
            != NGX_OK)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "ngx_http_pckg_m3u8_enc_init: "
                "ngx_http_complex_value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        enc_params->key_uri.len = 0;
    }

    if (mlcf->enc.output_iv) {
        rc = ngx_http_pckg_enc_get_iv(r, enc_params->iv_buf);
        if (rc != NGX_OK) {
            return rc;
        }

        enc_params->iv.data = enc_params->iv_buf;
        enc_params->iv.len = sizeof(enc_params->iv_buf);

    } else {
        enc_params->iv.len = 0;
    }

    return NGX_OK;
}
#endif


static size_t
ngx_http_pckg_m3u8_enc_key_get_size(ngx_http_pckg_m3u8_loc_conf_t *mlcf,
    ngx_pckg_channel_t *channel, ngx_http_pckg_m3u8_enc_params_t *enc_params)
{
    size_t               result;
    ngx_pckg_variant_t  *variant;

    result = sizeof(M3U8_ENC_KEY_BASE) - 1 +
        sizeof(M3U8_ENC_METHOD_SAMPLE_AES_CENC) - 1 +
        sizeof(M3U8_ENC_KEY_URI) - 1 +
        sizeof("\"\n") - 1;

    if (enc_params->key_uri.len != 0) {
        result += enc_params->key_uri.len;

    } else {
        variant = channel->variants.elts;
        result += ngx_http_pckg_enc_key_prefix.len +
            sizeof("-s") - 1 + variant->id.len +
            ngx_http_pckg_enc_key_ext.len;
    }

    if (enc_params->iv.len > 0) {
        result += sizeof(M3U8_ENC_KEY_IV) - 1 +
            enc_params->iv.len * 2;
    }

    if (mlcf->enc.key_format.len != 0) {
        result += sizeof(M3U8_ENC_KEY_KEY_FORMAT) +         /* '"' */
            mlcf->enc.key_format.len;
    }

    if (mlcf->enc.key_format_versions.len != 0) {
        result += sizeof(M3U8_ENC_KEY_KEY_FORMAT_VER) +     /* '"' */
            mlcf->enc.key_format_versions.len;
    }

    return result;
}


static u_char *
ngx_http_pckg_m3u8_enc_key_write(u_char *p,
    ngx_http_pckg_m3u8_loc_conf_t *mlcf,
    ngx_pckg_channel_t *channel,
    ngx_http_pckg_m3u8_enc_params_t *enc_params)
{
    ngx_pckg_variant_t  *variant;

    p = ngx_copy_fix(p, M3U8_ENC_KEY_BASE);

    switch (enc_params->type) {

    case NGX_HTTP_PCKG_ENC_AES_128:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_AES_128);
        break;

    case NGX_HTTP_PCKG_ENC_CBCS:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES);
        break;

    case NGX_HTTP_PCKG_ENC_CENC:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES_CENC);
        break;
    }

    /* uri */
    p = ngx_copy_fix(p, M3U8_ENC_KEY_URI);
    if (enc_params->key_uri.len != 0) {
        p = ngx_copy_str(p, enc_params->key_uri);

    } else {
        variant = channel->variants.elts;
        p = ngx_copy_str(p, ngx_http_pckg_enc_key_prefix);
        p = vod_sprintf(p, "-s%V", &variant->id);
        p = ngx_copy_str(p, ngx_http_pckg_enc_key_ext);
    }
    *p++ = '"';

    /* iv */
    if (enc_params->iv.len > 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_IV);
        p = vod_append_hex_string(p, enc_params->iv.data, enc_params->iv.len);
    }

    /* keyformat */
    if (mlcf->enc.key_format.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT);
        p = ngx_copy_str(p, mlcf->enc.key_format);
        *p++ = '"';
    }

    /* keyformatversions */
    if (mlcf->enc.key_format_versions.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT_VER);
        p = ngx_copy_str(p, mlcf->enc.key_format_versions);
        *p++ = '"';
    }

    *p++ = '\n';

    return p;
}


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

        first_segment = period->header->segment_index;
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

    segment_index = period->header->segment_index;

    time = period->header->time;
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

    milliscale = channel->header->timescale / 1000;

    gap_count = 0;
    bitrate_count = 0;

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        ngx_pckg_media_info_get(mi, period->header->segment_index, &ignore);

        ngx_http_pckg_get_bitrate_estimator(r, container,
            mi->media_infos, channel->tracks.nelts, bi->estimators);

        ngx_http_pckg_m3u8_period_get_bitrate_count(period, bi, milliscale,
            &gap_count, &bitrate_count);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_m3u8_get_bitrate_size: "
            "period %uD..%ui, accum_gaps: %uD, accum_bitrate: %uD",
            period->header->segment_index,
            (ngx_uint_t) period->header->segment_index + period->segment_count,
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
    p = ngx_sprintf(p, "%uD.%03uD",
        (uint32_t) (duration / 1000),
        (uint32_t) (duration % 1000));
    *p++ = ',';
    *p++ = '\n';
    return p;
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
    ngx_uint_t                  i, n;
    ngx_ksmp_segment_repeat_t  *elt;

    segment_index = period->header->segment_index;

    time = period->header->time;
    start = time / milliscale;

    last_bitrate = 0;

    n = period->nelts;
    for (i = 0; i < n; i++) {
        elt = &period->elts[i];

        last_segment = segment_index + elt->count;

        for (; segment_index < last_segment; )
        {
            time += elt->duration;
            end = time / milliscale;
            duration = end - start;

            p = ngx_http_pckg_m3u8_append_extinf_tag(p, duration);

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

            segment_index++;
            p = ngx_copy_str(p, ngx_http_pckg_prefix_seg);
            p = ngx_sprintf(p, "-%uD", segment_index);
            p = ngx_copy_str(p, *seg_suffix);

            start = end;
        }
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

    size = ngx_http_pckg_selector_get_size(variant);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_m3u8_get_selector: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;
    p = ngx_http_pckg_selector_write(p, variant,
        channel->header->req_media_types);
    result->len = p - result->data;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_m3u8_index_build(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel,
    ngx_http_pckg_m3u8_enc_params_t *enc_params, ngx_str_t *result)
{
    u_char                         *p;
    size_t                          size, period_size, segment_size;
    ngx_tm_t                        gmt;
    uint32_t                        version;
    uint32_t                        target_duration;
    uint32_t                        segment_index_size;
    uint32_t                        timescale, milliscale;
    uint32_t                        map_index, last_map_index;
    ngx_int_t                       rc;
    ngx_str_t                       selector, seg_suffix;
    ngx_uint_t                      i, n;
    ngx_pckg_period_t              *periods, *period;
    ngx_pckg_variant_t             *variant;
    ngx_pckg_timeline_t            *timeline;
    ngx_http_pckg_container_t      *container;
    media_bitrate_estimator_t      *estimators;
    ngx_pckg_media_info_ctx_t      *mi;
    ngx_pckg_segment_info_ctx_t    *bi;
    ngx_http_pckg_m3u8_loc_conf_t  *mlcf;

    /* get the container format */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_m3u8_module);

    variant = channel->variants.elts;

    container = ngx_http_pckg_m3u8_get_container(r, variant->tracks);

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

    periods = timeline->periods.elts;
    period = &periods[timeline->periods.nelts - 1];
    segment_index_size = vod_get_int_print_len(
        period->header->segment_index + period->segment_count);

    segment_size =
        sizeof(M3U8_EXTINF) - 1 + NGX_INT32_LEN + sizeof(".000,\n") - 1 +
        ngx_http_pckg_prefix_seg.len + sizeof("-") - 1 +
        segment_index_size + seg_suffix.len;

    period_size = sizeof(M3U8_DISCONTINUITY) - 1 + M3U8_PROGRAM_DATE_TIME_LEN;

    if (container->init_file_ext) {
        period_size +=
            sizeof(M3U8_MAP_BASE) - 1 + sizeof("-\"\n") - 1 +
            ngx_http_pckg_prefix_init_seg.len + segment_index_size +
            selector.len + container->init_file_ext->len;
    }

    size = sizeof(M3U8_INDEX_HEADER) + 4 * NGX_INT32_LEN +
        period_size * timeline->periods.nelts +
        segment_size * timeline->segment_count +
        sizeof(M3U8_END_LIST) - 1;

    if (enc_params->type != NGX_HTTP_PCKG_ENC_NONE) {
        size += ngx_http_pckg_m3u8_enc_key_get_size(mlcf, channel,
            enc_params);
    }

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
    timescale = channel->header->timescale;
    milliscale = timescale / 1000;

    /* header */
    target_duration = (timeline->header->target_duration + timescale / 2)
        / timescale;

    if (container->init_file_ext) {
        version = 6;    /* EXT-X-MAP requires version 6 */

    } else if (enc_params->type == NGX_HTTP_PCKG_ENC_CBCS ||
        enc_params->type == NGX_HTTP_PCKG_ENC_CENC ||
        mlcf->enc.key_format.len != 0 ||
        mlcf->enc.key_format_versions.len != 0)
    {
        version = 5;

    } else {
        version = 3;
    }

    p = ngx_sprintf(p, M3U8_INDEX_HEADER, target_duration, version,
        timeline->header->sequence - timeline->segment_count,
        timeline->header->first_period_index);

    if (enc_params->type != NGX_HTTP_PCKG_ENC_NONE) {
        p = ngx_http_pckg_m3u8_enc_key_write(p, mlcf, channel, enc_params);
    }

    last_map_index = NGX_KSMP_INVALID_SEGMENT_INDEX;

    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {

        period = &periods[i];
        if (i > 0) {
            p = ngx_copy_fix(p, M3U8_DISCONTINUITY);
        }

        ngx_gmtime(period->header->time / timescale, &gmt);

        p = ngx_sprintf(p, M3U8_PROGRAM_DATE_TIME,
            gmt.ngx_tm_year, gmt.ngx_tm_mon, gmt.ngx_tm_mday,
            gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec,
            (int) ((period->header->time / milliscale) % 1000));

        ngx_pckg_media_info_get(mi, period->header->segment_index,
            &map_index);

        if (container->init_file_ext && map_index != last_map_index) {
            p = ngx_copy_fix(p, M3U8_MAP_BASE);
            p = ngx_copy_str(p, ngx_http_pckg_prefix_init_seg);
            p = ngx_sprintf(p, "-%uD", map_index + 1);
            p = ngx_copy_str(p, selector);
            p = ngx_copy_str(p, *container->init_file_ext);
            *p++ = '"';
            *p++ = '\n';

            last_map_index = map_index;
        }

        ngx_http_pckg_get_bitrate_estimator(r, container,
            mi->media_infos, channel->tracks.nelts, estimators);

        p = ngx_http_pckg_m3u8_write_period_segments(p, period,
            &seg_suffix, milliscale, bi);
    }

    /* write the footer */
    if (timeline->header->end_list) {
        p = ngx_copy_fix(p, M3U8_END_LIST);
    }

    result->len = p - result->data;

    if (result->len > size) {
        vod_log_error(VOD_LOG_ALERT, r->connection->log, 0,
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
    ngx_int_t                         rc;
    ngx_str_t                         response;
    ngx_pckg_channel_t               *channel;
    ngx_http_pckg_core_ctx_t         *ctx;
    ngx_http_pckg_m3u8_enc_params_t   enc_params;

#if (NGX_HAVE_OPENSSL_EVP)
    rc = ngx_http_pckg_m3u8_enc_init(r, &enc_params);
    if (rc != NGX_OK) {
        return rc;
    }
#else
    enc_params.type = NGX_HTTP_PCKG_ENC_NONE;
#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_m3u8_index_build(r, channel, &enc_params, &response);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_m3u8_content_type,
        channel->timeline.header->last_modified,
        NGX_HTTP_PCKG_EXPIRES_INDEX);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_m3u8_index_handler = {
    ngx_http_pckg_m3u8_index_handle,
    NULL,
};


/* init */

static ngx_int_t
ngx_http_pckg_m3u8_parse_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t  flags;

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_index))
    {
        start_pos += ngx_http_pckg_prefix_index.len;

        *handler = &ngx_http_pckg_m3u8_index_handler;

        flags = NGX_HTTP_PCKG_PARSE_REQUIRE_SINGLE_VARIANT |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_ACTIVE_ONLY | NGX_KSMP_FLAG_CHECK_EXPIRY
            | NGX_KSMP_FLAG_DYNAMIC_VAR | NGX_KSMP_FLAG_MEDIA_INFO
            | NGX_KSMP_FLAG_TIMELINE | NGX_KSMP_FLAG_PERIODS
            | NGX_KSMP_FLAG_SEGMENT_INFO;

    } else if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_master))
    {
        start_pos += ngx_http_pckg_prefix_master.len;

        *handler = &ngx_http_pckg_m3u8_master_handler;
        flags = NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = NGX_KSMP_FLAG_ACTIVE_ONLY
            | NGX_KSMP_FLAG_DYNAMIC_VAR | NGX_KSMP_FLAG_MEDIA_INFO
            | NGX_KSMP_FLAG_TIMELINE;

    } else {
        return NGX_DECLINED;
    }

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
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
        return NGX_CONF_ERROR;
    }

    conf->container = NGX_CONF_UNSET_UINT;
    conf->mux_segments = NGX_CONF_UNSET;
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

    ngx_conf_merge_value(conf->mux_segments,
                         prev->mux_segments, 1);

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
