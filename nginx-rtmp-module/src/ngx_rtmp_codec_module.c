
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_chain_reader.h"
#include "ngx_rtmp_bitop.h"


#define NGX_RTMP_CODEC_META_OFF     0
#define NGX_RTMP_CODEC_META_ON      1
#define NGX_RTMP_CODEC_META_COPY    2

#define NGX_RTMP_CODEC_CAPTION_TRIES  10

#define HEVC_HVCC_HEADER_SIZE         22
#define HEVC_HVCC_NAL_SEI_PREFIX      39
#define HEVC_HVCC_NAL_SEI_SUFFIX      40


static void *ngx_rtmp_codec_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_codec_merge_app_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_codec_reconstruct_meta(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_codec_copy_meta(ngx_rtmp_session_t *s,
    ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_codec_prepare_meta(ngx_rtmp_session_t *s,
    uint32_t timestamp);
static void ngx_rtmp_codec_parse_aac_header(ngx_rtmp_session_t *s,
    ngx_chain_t *in);
static void ngx_rtmp_codec_parse_avc_header(ngx_rtmp_session_t *s,
    ngx_chain_t *in);
#if (NGX_DEBUG)
static void ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *type,
    ngx_chain_t *in);
#endif
static ngx_int_t ngx_rtmp_codec_parse_extended_header(ngx_rtmp_session_t *s,
       ngx_chain_t *in, ngx_uint_t packet_type);
static ngx_int_t ngx_rtmp_codec_parse_hevc_header(ngx_rtmp_session_t *s,
       ngx_chain_t *in);
#if (NGX_DEBUG)
static size_t codec_config_hvcc_nal_units_get_size(ngx_log_t *log,
    ngx_rtmp_codec_ctx_t  *ctx, ngx_chain_t *in);
#endif


typedef struct {
    ngx_uint_t                      meta;
} ngx_rtmp_codec_app_conf_t;


static ngx_conf_enum_t  ngx_rtmp_codec_meta_slots[] = {
    { ngx_string("on"),             NGX_RTMP_CODEC_META_ON   },
    { ngx_string("copy"),           NGX_RTMP_CODEC_META_COPY },
    { ngx_string("off"),            NGX_RTMP_CODEC_META_OFF  },
    { ngx_null_string,              0 }
};


static ngx_command_t  ngx_rtmp_codec_commands[] = {

    { ngx_string("meta"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_codec_app_conf_t, meta),
      &ngx_rtmp_codec_meta_slots },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_codec_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_codec_postconfiguration,       /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_codec_create_app_conf,         /* create app configuration */
    ngx_rtmp_codec_merge_app_conf           /* merge app configuration */
};


ngx_module_t  ngx_rtmp_codec_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_codec_module_ctx,             /* module context */
    ngx_rtmp_codec_commands,                /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static const char *
audio_codecs[] = {
    "",
    "ADPCM",
    "MP3",
    "LinearLE",
    "Nellymoser16",
    "Nellymoser8",
    "Nellymoser",
    "G711A",
    "G711U",
    "",
    "AAC",
    "Speex",
    "",
    "",
    "MP3-8K",
    "DeviceSpecific",
    "Uncompressed"
};


static const char *
video_codecs[] = {
    "",
    "Jpeg",
    "Sorenson-H263",
    "ScreenVideo",
    "On2-VP6",
    "On2-VP6-Alpha",
    "ScreenVideo2",
    "H264",
};


u_char *
ngx_rtmp_get_audio_codec_name(ngx_uint_t id)
{
    return (u_char *) (id < sizeof(audio_codecs) / sizeof(audio_codecs[0])
        ? audio_codecs[id]
        : "");
}


static const char *
ngx_rtmp_get_video_codec_name_from_fourcc(ngx_uint_t id)
{
    switch (id) {

    case NGX_RTMP_CODEC_FOURCC_HEV1:
        return "HEV1";

    case NGX_RTMP_CODEC_FOURCC_HVC1:
        return "HVC1";

    default:
        return "";
    }
}


u_char *
ngx_rtmp_get_video_codec_name(ngx_uint_t id)
{
    return (u_char *) (id < sizeof(video_codecs) / sizeof(video_codecs[0])
        ? video_codecs[id]
        : ngx_rtmp_get_video_codec_name_from_fourcc(id));
}


static ngx_uint_t
ngx_rtmp_codec_get_next_version(void)
{
    ngx_uint_t          v;
    static ngx_uint_t   version;

    do {
        v = ++version;
    } while (v == 0);

    return v;
}


static ngx_int_t
ngx_rtmp_codec_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_int_t                           i;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cscf->max_streams; i++) {

        if (s->in_streams[i].ctx == NULL) {
            continue;
        }

        ctx = s->in_streams[i].ctx[ngx_rtmp_codec_module.ctx_index];
        if (ctx == NULL) {
            continue;
        }

        if (ctx->avc_header) {
            ngx_rtmp_free_shared_chain(cscf, ctx->avc_header);
            ctx->avc_header = NULL;
        }

        if (ctx->aac_header) {
            ngx_rtmp_free_shared_chain(cscf, ctx->aac_header);
            ctx->aac_header = NULL;
        }

        if (ctx->meta) {
            ngx_rtmp_free_shared_chain(cscf, ctx->meta);
            ctx->meta = NULL;
        }
    }

    return NGX_OK;
}


/* user_data_registered_itu_t_t35 */
static u_char ngx_rtmp_codec_cea_header[] = {
    0xb5,    /* itu_t_t35_country_code   */
    0x00,    /* Itu_t_t35_provider_code  */
    0x31,
    0x47,    /* user_identifier ('GA94') */
    0x41,
    0x39,
    0x34,
};


static ngx_flag_t
ngx_rtmp_codec_sei_detect_cea(ngx_rtmp_session_t *s,
    ngx_rtmp_chain_reader_ep_t *reader)
{
    u_char                      b;
    u_char                      buf[sizeof(ngx_rtmp_codec_cea_header)];
    uint32_t                    payload_type;
    uint32_t                    payload_size;
    ngx_rtmp_chain_reader_ep_t  payload;

    while (reader->left >= 2 + sizeof(buf)) {

        payload_type = 0;
        do {
            if (ngx_rtmp_chain_reader_ep_read(reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "ngx_rtmp_codec_sei_detect_cea: read payload type failed");
                return 0;
            }

            payload_type += b;
        } while (b == 0xff);

        payload_size = 0;
        do {
            if (ngx_rtmp_chain_reader_ep_read(reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "ngx_rtmp_codec_sei_detect_cea: read payload size failed");
                return 0;
            }

            payload_size += b;
        } while (b == 0xff);

        payload = *reader;

        if (ngx_rtmp_chain_reader_ep_skip(reader, payload_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "ngx_rtmp_codec_sei_detect_cea: skip payload failed");
            return 0;
        }

        if (payload_type != 4) {    /* user data registered */
            continue;
        }

        payload.left = payload_size;

        if (ngx_rtmp_chain_reader_ep_read(&payload, buf, sizeof(buf))
            != NGX_OK)
        {
            continue;
        }

        if (ngx_memcmp(buf, ngx_rtmp_codec_cea_header, sizeof(buf)) == 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "ngx_rtmp_codec_sei_detect_cea: cea captions detected");
            return 1;
        }
    }

    return 0;
}


static ngx_flag_t
ngx_rtmp_codec_detect_cea(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    u_char                       nal_type;
    u_char                      *nalp;
    u_char                       frame_info;
    u_char                       packet_type;
    uint32_t                     size;
    uint32_t                     skip_size;
    uint32_t                     sei_type;
    uint32_t                     nal_type_shift;
    uint32_t                     nal_type_mask;
    ngx_rtmp_codec_ctx_t        *ctx;
    ngx_rtmp_chain_reader_t      reader;
    ngx_rtmp_chain_reader_ep_t   nal_reader;

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    if (!ctx->avc_nal_bytes) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "ngx_rtmp_codec_detect_cea: avc_nal_bytes not set");
        return 0;
    }

    ngx_rtmp_chain_reader_init(&reader, in);

    if (ngx_rtmp_chain_reader_read(&reader, &frame_info, sizeof(frame_info))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
              "ngx_rtmp_codec_detect_cea: read frame_info failed");
        return 0;
    }

    if (frame_info & NGX_RTMP_EXT_HEADER_MASK) {

        /* extended header */
        skip_size = 4;  /* fourcc */
        packet_type = frame_info & 0x0f;
        switch (packet_type) {

        case NGX_RTMP_PKT_TYPE_CODED_FRAMES:
            skip_size += 3;  /* pts_delay */
            break;

        case NGX_RTMP_PKT_TYPE_CODED_FRAMES_X:
            break;

        default:
             ngx_log_debug1(NGX_LOG_WARN, s->connection->log, 0,
                 "ngx_rtmp_codec_detect_cea: skipping packet type %uD",
                 (uint32_t) packet_type);
            return 0;
        }

        sei_type = HEVC_HVCC_NAL_SEI_PREFIX;
        nal_type_shift = 1;
        nal_type_mask = 0x3f;

    } else {
        skip_size = 4;  /* packet_type + pts_delay */
        sei_type = 6;
        nal_type_shift = 0;
        nal_type_mask = 0x1f;
    }

    if (ngx_rtmp_chain_reader_skip(&reader, skip_size) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
            "ngx_rtmp_codec_detect_cea: skip codec header failed");
        return 0;
    }

    nalp = (u_char *) &size + sizeof(size) - ctx->avc_nal_bytes;

    for ( ;; ) {

        /* nal unit */
        size = 0;

        if (ngx_rtmp_chain_reader_read(&reader, nalp, ctx->avc_nal_bytes)
            != NGX_OK)
        {
            break;
        }

        size = ngx_rtmp_r32(size);
        if (size <= 0) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "ngx_rtmp_codec_detect_cea: zero size nal");
            break;
        }

        if (ngx_rtmp_chain_reader_read(&reader, &nal_type, sizeof(nal_type))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "ngx_rtmp_codec_detect_cea: read nal type failed");
            break;
        }

        size--;

        ngx_rtmp_chain_reader_ep_init(&nal_reader, &reader);

        if (ngx_rtmp_chain_reader_skip(&reader, size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                "ngx_rtmp_codec_detect_cea: "
                "failed to skip nal, size: %uD", size);
#if (NGX_DEBUG)
            ngx_rtmp_codec_dump_header(s, "ngx_rtmp_codec_detect_cea in", in);
#endif
            break;
        }

        nal_type = (nal_type >> nal_type_shift) & nal_type_mask;
        if (nal_type != sei_type) {
            continue;
        }

        nal_reader.left = size;

        if (ngx_rtmp_codec_sei_detect_cea(s, &nal_reader)) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_rtmp_codec_parse_extended_header(ngx_rtmp_session_t *s, ngx_chain_t *in,
    ngx_uint_t packet_type)
{
    ngx_rtmp_codec_ctx_t  *ctx;

    if (packet_type > NGX_RTMP_PKT_TYPE_CODED_FRAMES_X) {
        /* TODO: handle metadata AMF here */
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_codec_parse_extended_header: "
            "metadata is not supported");
        return NGX_OK;
    }

    if (in->buf->last - in->buf->pos <= 4) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ngx_rtmp_codec_parse_extended_header: buffer size too small %ui",
            in->buf->last - in->buf->pos);
        return NGX_OK;
    }

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "ngx_rtmp_codec_parse_extended_header: codec_id: %ui, packet_type %ui",
            ctx->video_codec_id, packet_type);

    switch (ctx->video_codec_id) {

    case NGX_RTMP_CODEC_FOURCC_HEV1:
    case NGX_RTMP_CODEC_FOURCC_HVC1:
        if (packet_type == NGX_RTMP_PKT_TYPE_SEQUENCE_START) {
            if(ngx_rtmp_codec_parse_hevc_header(s, in) < 0) {
                return NGX_ERROR;
            }
        }

        break;

    default:
        ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ngx_rtmp_codec_parse_extended_header: "
            "unsupported codec fourcc: 0x%uxD (%4s) packet_type %ui",
            ctx->video_codec_id, &ctx->video_codec_id, packet_type);
        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_chain_reader_t             reader;
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_chain_t                       **header;
    ngx_uint_t                          packet_type;
    ngx_flag_t                          is_ext_header;
    uint32_t                            fourcc;
    uint8_t                             fmt;
    static ngx_uint_t                   sample_rates[] =
                                        { 5512, 11025, 22050, 44100 };

    if (h->type != NGX_RTMP_MSG_AUDIO && h->type != NGX_RTMP_MSG_VIDEO) {
        return NGX_OK;
    }

    if (!s->in_stream) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "codec: av with no stream context");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_rtmp_stream_set_ctx(s, ctx, ngx_rtmp_codec_module);

        ctx->video_captions_tries = NGX_RTMP_CODEC_CAPTION_TRIES;
    }

    /* save codec */
    if (in->buf->last - in->buf->pos < 1) {
        return NGX_OK;
    }

    fmt =  in->buf->pos[0];

    if (h->type == NGX_RTMP_MSG_AUDIO) {
        is_ext_header = 0;

        ctx->audio_codec_id = (fmt & 0xf0) >> 4;
        ctx->audio_channels = (fmt & 0x01) + 1;
        ctx->sample_size = (fmt & 0x02) ? 2 : 1;

        if (ctx->sample_rate == 0) {
            ctx->sample_rate = sample_rates[(fmt & 0x0c) >> 2];
        }

    } else {
        is_ext_header = (fmt & NGX_RTMP_EXT_HEADER_MASK);

        if (!is_ext_header) {
            ctx->video_codec_id = (fmt & 0x0f);

        } else {
            ngx_rtmp_chain_reader_init(&reader, in);

            /* frame info - 1 byte */
            if (ngx_rtmp_chain_reader_skip(&reader, 1) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                    "codec: av failed to skip frame info");
                return NGX_ERROR;
            }

            if (ngx_rtmp_chain_reader_read(&reader, &fourcc, sizeof(fourcc))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                    "codec: av failed to read fourcc");
                return NGX_ERROR;
            }

            ctx->video_codec_id = fourcc;
        }
    }

    /* save AVC/AAC header */
    if (in->buf->last - in->buf->pos < 3) {
        return NGX_OK;
    }

    /* no conf */
    if (!ngx_rtmp_is_codec_header(ctx->video_codec_id, in))
    {
        if(h->type != NGX_RTMP_MSG_VIDEO
            || ctx->video_captions_tries <= 0)
        {
            return NGX_OK;
        }

        switch (ctx->video_codec_id) {

        case NGX_RTMP_VIDEO_H264:
        case NGX_RTMP_CODEC_FOURCC_HVC1:
        case NGX_RTMP_CODEC_FOURCC_HEV1:
            if (ngx_rtmp_codec_detect_cea(s, in)) {
                ctx->video_captions = 1;
                ctx->video_captions_tries = 0;

            } else {
                ctx->video_captions_tries--;
            }

            break;

        default:
            ctx->video_captions_tries = 0;
        }

        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    header = NULL;

    if (is_ext_header) {
        packet_type = (fmt & 0x0f);

        if (ngx_rtmp_codec_parse_extended_header(s, in, packet_type)
            == NGX_OK)
        {
            header = &ctx->avc_header;
        }

    } else if (h->type == NGX_RTMP_MSG_AUDIO) {
        if (ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC) {
            header = &ctx->aac_header;
            ngx_rtmp_codec_parse_aac_header(s, in);
        }

    } else {
        if (ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            header = &ctx->avc_header;
            ngx_rtmp_codec_parse_avc_header(s, in);
        }
    }

    if (header == NULL) {
        return NGX_OK;
    }

    if (*header) {
        ngx_rtmp_free_shared_chain(cscf, *header);
    }

    *header = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    return NGX_OK;
}


static void
ngx_rtmp_codec_parse_aac_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_uint_t              idx;
    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;

    static ngx_uint_t      aac_sample_rates[] =
        { 96000, 88200, 64000, 48000,
          44100, 32000, 24000, 22050,
          16000, 12000, 11025,  8000,
           7350,     0,     0,     0 };

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "aac", in);
#endif

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    ngx_rtmp_bit_read(&br, 16);

    ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
    if (ctx->aac_profile == 31) {
        ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
    }

    idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
    if (idx == 15) {
        ctx->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);

    } else {
        ctx->sample_rate = aac_sample_rates[idx];
    }

    ctx->aac_chan_conf = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);

    if (ctx->aac_profile == 5 || ctx->aac_profile == 29) {

        if (ctx->aac_profile == 29) {
            ctx->aac_ps = 1;
        }

        ctx->aac_sbr = 1;

        idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
        if (idx == 15) {
            ctx->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);

        } else {
            ctx->sample_rate = aac_sample_rates[idx];
        }

        ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
        if (ctx->aac_profile == 31) {
            ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
        }
    }

    /* MPEG-4 Audio Specific Config

       5 bits: object type
       if (object type == 31) {
         6 bits + 32: object type
       }

       4 bits: frequency index
       if (frequency index == 15) {
         24 bits: frequency
       }

       4 bits: channel configuration

       if (object_type == 5) {
           4 bits: frequency index
           if (frequency index == 15) {
             24 bits: frequency
           }

           5 bits: object type
           if (object type == 31) {
             6 bits + 32: object type
           }
       }

       var bits: AOT Specific Config
     */

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: aac header profile=%ui, "
                   "sample_rate=%ui, chan_conf=%ui",
                   ctx->aac_profile, ctx->sample_rate, ctx->aac_chan_conf);
}


static void
ngx_rtmp_codec_avc_skip_scaling_list(ngx_rtmp_bit_reader_t *br,
    ngx_int_t size_of_scaling_list)
{
    ngx_int_t  last_scale = 8;
    ngx_int_t  next_scale = 8;
    ngx_int_t  delta_scale;
    ngx_int_t  j;

    for (j = 0; j < size_of_scaling_list; j++) {
        if (next_scale != 0) {
            delta_scale = ngx_rtmp_bit_read_golomb_signed(br);
            next_scale = (last_scale + delta_scale) & 0xff;
        }

        last_scale = (next_scale == 0) ? last_scale : next_scale;
    }
}


static void
ngx_rtmp_codec_parse_avc_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_uint_t              profile_idc, width, height, crop_left, crop_right,
                            crop_top, crop_bottom, frame_mbs_only, n, cf_idc,
                            num_ref_frames;
    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "avc", in);
#endif

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    ngx_rtmp_bit_read(&br, 48);

    ctx->avc_profile = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);
    ctx->avc_compat = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);
    ctx->avc_level = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);

    /* nal bytes */
    ctx->avc_nal_bytes = (ngx_uint_t) ((ngx_rtmp_bit_read_8(&br) & 0x03) + 1);

    /* nnals */
    if ((ngx_rtmp_bit_read_8(&br) & 0x1f) == 0) {
        return;
    }

    /* nal size */
    ngx_rtmp_bit_read(&br, 16);

    /* nal type */
    if ((ngx_rtmp_bit_read_8(&br) & 0x1f) != 7) {
        return;
    }

    /* SPS */

    /* profile idc */
    profile_idc = (ngx_uint_t) ngx_rtmp_bit_read(&br, 8);

    /* flags */
    ngx_rtmp_bit_read(&br, 8);

    /* level idc */
    ngx_rtmp_bit_read(&br, 8);

    /* SPS id */
    ngx_rtmp_bit_read_golomb(&br);

    if (profile_idc == 100 || profile_idc == 110 ||
        profile_idc == 122 || profile_idc == 244 || profile_idc == 44 ||
        profile_idc == 83 || profile_idc == 86 || profile_idc == 118)
    {
        /* chroma format idc */
        cf_idc = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

        if (cf_idc == 3) {

            /* separate color plane */
            ngx_rtmp_bit_read(&br, 1);
        }

        /* bit depth luma - 8 */
        ngx_rtmp_bit_read_golomb(&br);

        /* bit depth chroma - 8 */
        ngx_rtmp_bit_read_golomb(&br);

        /* qpprime y zero transform bypass */
        ngx_rtmp_bit_read(&br, 1);

        /* seq scaling matrix present */
        if (ngx_rtmp_bit_read(&br, 1)) {

            for (n = 0; n < (cf_idc != 3 ? 8u : 12u); n++) {

                /* seq scaling list present */
                if (ngx_rtmp_bit_read(&br, 1)) {
                    if (n < 6) {
                        ngx_rtmp_codec_avc_skip_scaling_list(&br, 16);

                    } else {
                        ngx_rtmp_codec_avc_skip_scaling_list(&br, 64);
                    }
                }
            }
        }
    }

    /* log2 max frame num */
    ngx_rtmp_bit_read_golomb(&br);

    /* pic order cnt type */
    switch (ngx_rtmp_bit_read_golomb(&br)) {
    case 0:

        /* max pic order cnt */
        ngx_rtmp_bit_read_golomb(&br);
        break;

    case 1:

        /* delta pic order alwys zero */
        ngx_rtmp_bit_read(&br, 1);

        /* offset for non-ref pic */
        ngx_rtmp_bit_read_golomb(&br);

        /* offset for top to bottom field */
        ngx_rtmp_bit_read_golomb(&br);

        /* num ref frames in pic order */
        num_ref_frames = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

        for (n = 0; n < num_ref_frames; n++) {

            /* offset for ref frame */
            ngx_rtmp_bit_read_golomb(&br);
        }
    }

    /* num ref frames */
    ctx->avc_ref_frames = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* gaps in frame num allowed */
    ngx_rtmp_bit_read(&br, 1);

    /* pic width in mbs - 1 */
    width = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* pic height in map units - 1 */
    height = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* frame mbs only flag */
    frame_mbs_only = (ngx_uint_t) ngx_rtmp_bit_read(&br, 1);

    if (!frame_mbs_only) {

        /* mbs adaprive frame field */
        ngx_rtmp_bit_read(&br, 1);
    }

    /* direct 8x8 inference flag */
    ngx_rtmp_bit_read(&br, 1);

    /* frame cropping */
    if (ngx_rtmp_bit_read(&br, 1)) {

        crop_left = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_right = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_top = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_bottom = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    } else {

        crop_left = 0;
        crop_right = 0;
        crop_top = 0;
        crop_bottom = 0;
    }

    ctx->width = (width + 1) * 16 - (crop_left + crop_right) * 2;
    ctx->height = (2 - frame_mbs_only) * (height + 1) * 16 -
                  (crop_top + crop_bottom) * 2;

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: avc header "
                   "profile=%ui, compat=%ui, level=%ui, "
                   "nal_bytes=%ui, ref_frames=%ui, width=%ui, height=%ui",
                   ctx->avc_profile, ctx->avc_compat, ctx->avc_level,
                   ctx->avc_nal_bytes, ctx->avc_ref_frames,
                   ctx->width, ctx->height);
}


static ngx_int_t
ngx_rtmp_codec_parse_hevc_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
#if (NGX_DEBUG)
    ngx_uint_t              size;
    ngx_uint_t              narrs;
    ngx_uint_t              nal_type;
    ngx_uint_t              i, j, nnal, nnall;
#endif

    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "ngx_rtmp_codec_parse_hevc_header in:", in);
#endif

    /* HEVCDecoderConfigurationRecord */
    /* http://ffmpeg.org/doxygen/trunk/hevc_8c_source.html#l00040 */

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    /* skip tag header and configurationVersion(1 byte) */
    ngx_rtmp_bit_read(&br, 48);

    /* unsigned int(2) general_profile_space; */
    /* unsigned int(1) general_tier_flag; */
    /* unsigned int(5) general_profile_idc; */
    ctx->avc_profile = (ngx_uint_t) (ngx_rtmp_bit_read_8(&br) & 0x1f);

    /* unsigned int(32) general_profile_compatibility_flags; */
    ctx->avc_compat = (ngx_uint_t) ngx_rtmp_bit_read_32(&br);
    /* unsigned int(48) general_constraint_indicator_flags; */
    ngx_rtmp_bit_read(&br, 48);
    /* unsigned int(8) general_level_idc; */
    ctx->avc_level = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);

    /* bit(4) reserved = ‘1111’b; */
    /* unsigned int(12) min_spatial_segmentation_idc; */
    /* bit(6) reserved = ‘111111’b; */
    /* unsigned int(2) parallelismType; */
    /* bit(6) reserved = ‘111111’b; */
    /* unsigned int(2) chroma_format_idc; */
    /* bit(5) reserved = ‘11111’b; */
    /* unsigned int(3) bit_depth_luma_minus8; */
    /* bit(5) reserved = ‘11111’b; */
    /* unsigned int(3) bit_depth_chroma_minus8; */
    /* bit(16) avgFrameRate; */
    /* bit(2) constantFrameRate; */
    /* bit(3) numTemporalLayers; */
    /* bit(1) temporalIdNested; */
    ngx_rtmp_bit_read(&br, 70);

    /* unsigned int(2) lengthSizeMinusOne; */
    ctx->avc_nal_bytes = (ngx_uint_t) ngx_rtmp_bit_read(&br, 2) + 1;

#if (NGX_DEBUG)
    /* unsigned int(8) numOfArrays; 04 */
    narrs = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "codec: hevc header narrs=%ui", narrs);

    /* parse vps sps pps .. */
    for (j = 0; j < narrs && !ngx_rtmp_bit_read_err(&br); j++) {
        /* bit(1) array_completeness; */
        nal_type = (ngx_uint_t) ngx_rtmp_bit_read_8(&br) & 0x3f;
        nnal = (ngx_uint_t) ngx_rtmp_bit_read_16(&br);

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "codec: hevc nal_type=%ui nnal=%ui", nal_type, nnal);

        for (i = 0; i < nnal && !ngx_rtmp_bit_read_err(&br); i++) {
            nnall = (ngx_uint_t) ngx_rtmp_bit_read_16(&br);
            ngx_rtmp_bit_read(&br, nnall * 8);

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "codec: hevc nnall=%ui",  nnall);
            /* vps: 32 sps : 33 pps : 34 */
        }
    }

    size = codec_config_hvcc_nal_units_get_size(s->connection->log, ctx, in);
    if (size <= 0) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "ngx_rtmp_codec_parse_hevc_header: "
            "codec_config_hvcc_nal_units_get_size failed");
        return NGX_ERROR;
    }
#endif

    if (ngx_rtmp_bit_read_err(&br)) {
        ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
            "codec: failed to parse hevc header");
        return NGX_ERROR;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "codec: hevc header "
        "profile=%ui, compat=%ui, level=%ui, nal_bytes=%ui, ref_frames=%ui, "
        "frame_rate=%.2f, width=%ui, height=%ui",
        ctx->avc_profile, ctx->avc_compat, ctx->avc_level, ctx->avc_nal_bytes,
        ctx->avc_ref_frames, ctx->frame_rate, ctx->width, ctx->height);

    return NGX_OK;
}


#if (NGX_DEBUG)
static void
ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *msg,
    ngx_chain_t *in)
{
    u_char  buf[257], *pp, *p;
    u_char  hex[] = "0123456789abcdef";

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, msg);

    for (p = in->buf->pos; p < in->buf->last; ) {
        for (pp = buf; p < in->buf->last && pp < buf + sizeof(buf) - 3; ++p) {
            *pp++ = hex[*p >> 4];
            *pp++ = hex[*p & 0x0f];
        }

        *pp = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "%s", buf);
   }
}
#endif


static ngx_int_t
ngx_rtmp_codec_reconstruct_meta(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_int_t                       rc;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id;
        double                      audio_data_rate;
        double                      audio_codec_id;
        u_char                      profile[32];
        u_char                      level[32];
    }                               v;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("Server"),
          "NGINX RTMP (github.com/arut/nginx-rtmp-module)", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayWidth"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayHeight"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videocodecid"),
          &v.video_codec_id, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiocodecid"),
          &v.audio_codec_id, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onMetaData", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx->meta) {
        ngx_rtmp_free_shared_chain(cscf, ctx->meta);
        ctx->meta = NULL;
    }

    v.width = ctx->width;
    v.height = ctx->height;
    v.duration = ctx->duration;
    v.frame_rate = ctx->frame_rate;
    v.video_data_rate = ctx->video_data_rate;
    v.video_codec_id = ctx->video_codec_id;
    v.audio_data_rate = ctx->audio_data_rate;
    v.audio_codec_id = ctx->audio_codec_id;
    ngx_memcpy(v.profile, ctx->profile, sizeof(ctx->profile));
    ngx_memcpy(v.level, ctx->level, sizeof(ctx->level));

    rc = ngx_rtmp_append_amf(s, &ctx->meta, NULL, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0]));
    if (rc != NGX_OK || ctx->meta == NULL) {
        return NGX_ERROR;
    }

    return ngx_rtmp_codec_prepare_meta(s, 0);
}


static ngx_int_t
ngx_rtmp_codec_copy_meta(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t      *ctx;
    ngx_rtmp_core_srv_conf_t  *cscf;

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx->meta) {
        ngx_rtmp_free_shared_chain(cscf, ctx->meta);
    }

    ctx->meta = ngx_rtmp_append_shared_bufs(cscf, NULL, in);

    if (ctx->meta == NULL) {
        return NGX_ERROR;
    }

    return ngx_rtmp_codec_prepare_meta(s, h->timestamp);
}


static ngx_int_t
ngx_rtmp_codec_prepare_meta(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    ngx_rtmp_header_t      h;
    ngx_rtmp_codec_ctx_t  *ctx;

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF;
    h.msid = s->in_msid;
    h.type = NGX_RTMP_MSG_AMF_META;
    h.timestamp = timestamp;
    ngx_rtmp_prepare_message(s, &h, NULL, ctx->meta);

    ctx->meta_version = ngx_rtmp_codec_get_next_version();

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_meta_data(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    ngx_rtmp_codec_app_conf_t      *cacf;
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_uint_t                      skip;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id_n;
        u_char                      video_codec_id_s[32];
        double                      audio_data_rate;
        double                      audio_codec_id_n;
        u_char                      audio_codec_id_s[32];
        u_char                      profile[32];
        u_char                      level[32];
    }                               v;

    static ngx_rtmp_amf_elt_t       in_video_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.video_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.video_codec_id_s, sizeof(v.video_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_audio_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.audio_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.audio_codec_id_s, sizeof(v.audio_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_inf[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT,
          ngx_string("videocodecid"),
          in_video_codec_id, sizeof(in_video_codec_id) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT,
          ngx_string("audiocodecid"),
          in_audio_codec_id, sizeof(in_audio_codec_id) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);

    if (!s->in_stream) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "codec: meta data with no stream context");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_stream_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_rtmp_stream_set_ctx(s, ctx, ngx_rtmp_codec_module);

        ctx->video_captions_tries = NGX_RTMP_CODEC_CAPTION_TRIES;
    }

    ngx_memzero(&v, sizeof(v));

    /* use -1 as a sign of unchanged data;
     * 0 is a valid value for uncompressed audio */
    v.audio_codec_id_n = -1;

    /* FFmpeg sends a string in front of actual metadata; ignore it */
    skip = !(in->buf->last > in->buf->pos
            && *in->buf->pos == NGX_RTMP_AMF_STRING);
    if (ngx_rtmp_receive_amf(s, in, in_elts + skip,
                sizeof(in_elts) / sizeof(in_elts[0]) - skip))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: error parsing data frame");
        return NGX_OK;
    }

    ctx->width = (ngx_uint_t) v.width;
    ctx->height = (ngx_uint_t) v.height;
    ctx->duration = (ngx_uint_t) v.duration;
    ctx->frame_rate = v.frame_rate;
    ctx->video_data_rate = (ngx_uint_t) v.video_data_rate;
    ctx->video_codec_id = (ngx_uint_t) v.video_codec_id_n;
    ctx->audio_data_rate = (ngx_uint_t) v.audio_data_rate;
    ctx->audio_codec_id = (v.audio_codec_id_n == -1
            ? 0 : v.audio_codec_id_n == 0
            ? NGX_RTMP_AUDIO_UNCOMPRESSED : (ngx_uint_t) v.audio_codec_id_n);
    ngx_memcpy(ctx->profile, v.profile, sizeof(v.profile));
    ngx_memcpy(ctx->level, v.level, sizeof(v.level));

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "codec: data frame: "
            "width=%ui height=%ui duration=%ui frame_rate=%ui "
            "video=%s (%ui) audio=%s (%ui)",
            ctx->width, ctx->height, ctx->duration,
            (ngx_uint_t) ctx->frame_rate,
            ngx_rtmp_get_video_codec_name(ctx->video_codec_id),
            ctx->video_codec_id,
            ngx_rtmp_get_audio_codec_name(ctx->audio_codec_id),
            ctx->audio_codec_id);

    switch (cacf->meta) {
        case NGX_RTMP_CODEC_META_ON:
            return ngx_rtmp_codec_reconstruct_meta(s);
        case NGX_RTMP_CODEC_META_COPY:
            return ngx_rtmp_codec_copy_meta(s, h, in);
    }

    /* NGX_RTMP_CODEC_META_OFF */

    return NGX_OK;
}


static void *
ngx_rtmp_codec_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_codec_app_conf_t  *cacf;

    cacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_codec_app_conf_t));
    if (cacf == NULL) {
        return NULL;
    }

    cacf->meta = NGX_CONF_UNSET_UINT;

    return cacf;
}


static char *
ngx_rtmp_codec_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_codec_app_conf_t *prev = parent;
    ngx_rtmp_codec_app_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->meta, prev->meta, NGX_RTMP_CODEC_META_ON);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_codec_disconnect;

    /* register metadata handler */
    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&ch->name, "@setDataFrame");
    ch->handler = ngx_rtmp_codec_meta_data;

    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&ch->name, "onMetaData");
    ch->handler = ngx_rtmp_codec_meta_data;


    return NGX_OK;
}

#if (NGX_DEBUG)

#define parse_be16(p)                                                        \
    ( ((uint16_t) ((u_char *) (p))[0] << 8) | (((u_char *) (p))[1]) )
#define parse_be32(p)                                                        \
    ( ((uint32_t) ((u_char *)(p))[0] << 24) | (((u_char *)(p))[1] << 16)     \
        | (((u_char *)(p))[2] << 8) | (((u_char *)(p))[3]) )

#define read_be16(p, v)  { v = parse_be16(&(p)); }
#define read_be32(p, v)  { v = parse_be32(&(p)); }

static size_t
codec_config_hvcc_nal_units_get_size(ngx_log_t *log, ngx_rtmp_codec_ctx_t *ctx,
    ngx_chain_t *in)
{
    size_t                    size;
    u_char                   *nalp;
    u_char                    type_count;
    u_char                    nal_unit_size;
    uint16_t                  count;
    uint32_t                  unit_size;
    ngx_rtmp_chain_reader_t   reader;

    ngx_rtmp_chain_reader_init(&reader, in);

    if (ngx_rtmp_chain_reader_skip(&reader, 5) < 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "codec_config_hvcc_nal_units_get_size: "
            "failed to skip to start of extra data");
        return 0;
    }

    if (ngx_rtmp_chain_reader_skip(&reader, HEVC_HVCC_HEADER_SIZE) < 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "codec_config_hvcc_nal_units_get_size: "
            "extra data size <= %uz too small", HEVC_HVCC_HEADER_SIZE);
        return 0;
    }

    if (ngx_rtmp_chain_reader_read(&reader, &type_count, 1) < 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "codec_config_hvcc_nal_units_get_size: "
            "failed to read %d bytes: type_count ", sizeof(type_count));
        return 0;
    }

    size = 0;
    nal_unit_size = sizeof(uint16_t);
    nalp = (u_char *) &unit_size + sizeof(unit_size) - nal_unit_size;

    for (; type_count > 0; type_count--)
    {
        if (ngx_rtmp_chain_reader_skip(&reader, 1) < 0) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "codec_config_hvcc_nal_units_get_size: failed to skip 1 byte");
            return 0;
        }

        if (ngx_rtmp_chain_reader_read(&reader, &count, sizeof(count)) < 0) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "codec_config_hvcc_nal_units_get_size: "
                "failed to read NAL count %uD", sizeof(count));
            return 0;
        }

        read_be16(count, count);

        for (; count > 0; count--) {

            unit_size = 0;
            if (ngx_rtmp_chain_reader_read(&reader, nalp, nal_unit_size) < 0) {
                ngx_log_error(NGX_LOG_NOTICE, log, 0,
                    "codec_config_hvcc_nal_units_get_size: "
                    "failed to read %uD bytes unit_size",
                    (uint32_t) sizeof(unit_size));
                return 0;
            }

            read_be32(unit_size, unit_size);

            if (ngx_rtmp_chain_reader_skip(&reader, unit_size) < 0) {
                ngx_log_error(NGX_LOG_NOTICE, log, 0,
                    "codec_config_hvcc_nal_units_get_size: "
                    "failed to skip NAL unit of size %uD", unit_size);
                return 0;
            }

            ngx_log_debug1(NGX_LOG_NOTICE, log, 0,
                "codec_config_hvcc_nal_units_get_size: "
                "skipped NAL unit of size %uD", unit_size);

            size += nal_unit_size + 1 + unit_size;
        }
    }

    return size;
}

#endif