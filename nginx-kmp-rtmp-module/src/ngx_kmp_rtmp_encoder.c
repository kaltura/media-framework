#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_kmp_rtmp_encoder.h"
#include "ngx_kmp_rtmp_amf.h"


#define NGX_RTMP_HEADER_0_SIZE        12
#define NGX_RTMP_HEADER_1_SIZE        8
#define NGX_RTMP_HEADER_2_SIZE        4
#define NGX_RTMP_HEADER_3_SIZE        1

#define NGX_RTMP_EXT_TIMESTAMP        0x00ffffff
#define NGX_RTMP_EXT_TIMESTAMP_SIZE   4

#define NGX_RTMP_DEFAULT_CHUNK_SIZE   128

#define NGX_RTMP_CSID_PROT_CTRL       2
#define NGX_RTMP_CSID_AMF_INI         3

#define NGX_RTMP_MSG_CHUNK_SIZE       1
#define NGX_RTMP_MSG_AUDIO            8
#define NGX_RTMP_MSG_VIDEO            9
#define NGX_RTMP_MSG_AMF_META         18
#define NGX_RTMP_MSG_AMF_CMD          20

/* video */
#define NGX_RTMP_AVC_HEADER_SIZE      5  /* frame / packet type, pts_delay */

#define NGX_RTMP_FRAME_TYPE_KEY       1
#define NGX_RTMP_FRAME_TYPE_INTER     2

#define NGX_RTMP_AVC_SEQUENCE_HEADER  0
#define NGX_RTMP_AVC_NALU             1

#define NGX_RTMP_EXT_HEADER_SIZE      5  /* (frame | packet type), fourcc */
#define NGX_RTMP_EXT_HEADER_SIZE_NALU 8  /*  + pts_delay */
#define NGX_RTMP_EXT_SEQUENCE_HEADER  0
#define NGX_RTMP_EXT_NALU             1

/* audio */
#define NGX_RTMP_AAC_HEADER_SIZE      2  /* sound_info + packet_type */

#define NGX_RTMP_SOUND_RATE_5_5_KHZ   0
#define NGX_RTMP_SOUND_RATE_11_KHZ    1
#define NGX_RTMP_SOUND_RATE_22_KHZ    2
#define NGX_RTMP_SOUND_RATE_44_KHZ    3

#define NGX_RTMP_SOUND_SIZE_8_BIT     0
#define NGX_RTMP_SOUND_SIZE_16_BIT    1

#define NGX_RTMP_SOUND_TYPE_MONO      0
#define NGX_RTMP_SOUND_TYPE_STEREO    1

#define NGX_RTMP_AAC_SEQUENCE_HEADER  0
#define NGX_RTMP_AAC_RAW              1


#define NGX_RTMP_FRAME_HEADER_MAX_SIZE  (NGX_RTMP_HEADER_0_SIZE              \
    + NGX_RTMP_EXT_TIMESTAMP_SIZE + NGX_RTMP_EXT_HEADER_SIZE_NALU)


#define ngx_kmp_rtmp_chunk_count(mlen, chunk_size)                           \
    (((mlen) + (chunk_size) - 1) / (chunk_size))


typedef struct {
    u_char                   format;
    u_char                   csid;
    uint32_t                 timestamp;
    uint32_t                 mlen;
    u_char                   type;
    uint32_t                 msid;
} ngx_kmp_rtmp_header_t;


typedef struct {
    ngx_kmp_rtmp_cmd_base_t  base;
    ngx_str_t                name;
} ngx_kmp_rtmp_cmd_stream_t;


typedef struct {
    ngx_kmp_rtmp_cmd_base_t  base;
    uint32_t                 stream_id;
} ngx_kmp_rtmp_cmd_stream_id_t;


static size_t  ngx_kmp_rtmp_header_size[] = {
    NGX_RTMP_HEADER_0_SIZE,
    NGX_RTMP_HEADER_1_SIZE,
    NGX_RTMP_HEADER_2_SIZE,
    NGX_RTMP_HEADER_3_SIZE,
};


static ngx_str_t  ngx_kmp_rtmp_cmd_connect =
    ngx_string("connect");
static ngx_str_t  ngx_kmp_rtmp_cmd_create_stream =
    ngx_string("createStream");
static ngx_str_t  ngx_kmp_rtmp_cmd_release_stream =
    ngx_string("releaseStream");
static ngx_str_t  ngx_kmp_rtmp_cmd_delete_stream =
    ngx_string("deleteStream");
static ngx_str_t  ngx_kmp_rtmp_cmd_publish =
    ngx_string("publish");
static ngx_str_t  ngx_kmp_rtmp_cmd_fcpublish =
    ngx_string("FCPublish");
static ngx_str_t  ngx_kmp_rtmp_cmd_fcunpublish =
    ngx_string("FCUnpublish");
static ngx_str_t  ngx_kmp_rtmp_cmd_set_data_frame =
    ngx_string("@setDataFrame");
static ngx_str_t  ngx_kmp_rtmp_cmd_on_metadata =
    ngx_string("@onMetaData");
static ngx_str_t  ngx_kmp_rtmp_cmd_onfi =
    ngx_string("onFI");

static ngx_str_t  ngx_kmp_rtmp_publish_type_live =
    ngx_string("live");


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_connect_obj[] = {

    { ngx_kmp_rtmp_amf_string,
      ngx_string("app"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, app),
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_string("flashVer"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, flash_ver),
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_string("swfUrl"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, swf_url),
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_string("tcUrl"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, tc_url),
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_string("pageUrl"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, page_url),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_connect[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_connect,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_connect_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_object,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      &ngx_kmp_rtmp_amf_connect_obj },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_fcpublish[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_fcpublish,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, name),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_fcunpublish[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_fcunpublish,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, name),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_create_stream[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_create_stream,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_base_t, tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_release_stream[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_release_stream,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, name),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_delete_stream[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_delete_stream,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_id_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_id_t, stream_id),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_publish[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_publish,
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, base.tx_id),
      NULL },

    { ngx_kmp_rtmp_amf_null,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_cmd_stream_t, name),
      NULL },

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_publish_type_live,
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_metadata_obj[] = {

    { ngx_kmp_rtmp_amf_uint16,
      ngx_string("width"),
      NGX_KMP_RTMP_AMF_VIDEO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_VIDEO].u.video.width),
      NULL },

    { ngx_kmp_rtmp_amf_uint16,
      ngx_string("height"),
      NGX_KMP_RTMP_AMF_VIDEO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_VIDEO].u.video.height),
      NULL },

    { ngx_kmp_rtmp_amf_bitrate,
      ngx_string("videodatarate"),
      NGX_KMP_RTMP_AMF_VIDEO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_VIDEO].bitrate),
      NULL },

    { ngx_kmp_rtmp_amf_rational,
      ngx_string("framerate"),
      NGX_KMP_RTMP_AMF_VIDEO,
      offsetof(ngx_kmp_rtmp_metadata_t,
        mi[KMP_MEDIA_VIDEO].u.video.frame_rate),
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_string("videocodecid"),
      NGX_KMP_RTMP_AMF_VIDEO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_VIDEO].codec_id),
      NULL },


    { ngx_kmp_rtmp_amf_bitrate,
      ngx_string("audiodatarate"),
      NGX_KMP_RTMP_AMF_AUDIO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_AUDIO].bitrate),
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_string("audiosamplerate"),
      NGX_KMP_RTMP_AMF_AUDIO,
      offsetof(ngx_kmp_rtmp_metadata_t,
        mi[KMP_MEDIA_AUDIO].u.audio.sample_rate),
      NULL },

    { ngx_kmp_rtmp_amf_uint16,
      ngx_string("audiosamplesize"),
      NGX_KMP_RTMP_AMF_AUDIO,
      offsetof(ngx_kmp_rtmp_metadata_t,
        mi[KMP_MEDIA_AUDIO].u.audio.bits_per_sample),
      NULL },

    { ngx_kmp_rtmp_amf_stereo,
      ngx_string("stereo"),
      NGX_KMP_RTMP_AMF_AUDIO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_AUDIO].u.audio.channels),
      NULL },

    { ngx_kmp_rtmp_amf_uint32,
      ngx_string("audiocodecid"),
      NGX_KMP_RTMP_AMF_AUDIO,
      offsetof(ngx_kmp_rtmp_metadata_t, mi[KMP_MEDIA_AUDIO].codec_id),
      (void *) KMP_CODEC_AUDIO_BASE },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_metadata[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_set_data_frame,
      NULL },

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_on_metadata,
      NULL },

    { ngx_kmp_rtmp_amf_mixed_array,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      &ngx_kmp_rtmp_amf_metadata_obj },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_onfi_obj[] = {

    { ngx_kmp_rtmp_amf_string,
      ngx_string("sd"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_onfi_t, date),
      NULL },

    { ngx_kmp_rtmp_amf_string,
      ngx_string("st"),
      NGX_KMP_RTMP_AMF_DEFAULT,
      offsetof(ngx_kmp_rtmp_onfi_t, time),
      NULL },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_kmp_rtmp_amf_field_t  ngx_kmp_rtmp_amf_onfi[] = {

    { ngx_kmp_rtmp_amf_fixed_string,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      (uintptr_t) &ngx_kmp_rtmp_cmd_onfi,
      NULL },

    { ngx_kmp_rtmp_amf_mixed_array,
      ngx_null_string,
      NGX_KMP_RTMP_AMF_DEFAULT,
      0,
      &ngx_kmp_rtmp_amf_onfi_obj },

      ngx_kmp_rtmp_amf_null_field
};


static ngx_inline u_char *
ngx_kmp_rtmp_encoder_write_header(u_char *p, ngx_kmp_rtmp_header_t *h)
{
    u_char  fmt = h->format;

    *p++ = (fmt << 6) | h->csid;
    if (fmt <= 2) {
        ngx_kmp_rtmp_amf_write_be24(p, h->timestamp);
        if (fmt <= 1) {
            ngx_kmp_rtmp_amf_write_be24(p, h->mlen);
            *p++ = h->type;
            if (fmt <= 0) {
                p = ngx_copy(p, &h->msid, sizeof(h->msid));
            }
        }
    }

    return p;
}


static u_char *
ngx_kmp_rtmp_encoder_add_chunk_headers(u_char *p, size_t mlen,
    size_t chunk_size, u_char csid)
{
    size_t       cur_chunk_size;
    u_char      *src;
    u_char      *dst;
    ngx_uint_t   i;
    ngx_uint_t   chunks;

    /* Note: assuming mlen > 0, otherwise chunks - 1 overflows */

    chunks = ngx_kmp_rtmp_chunk_count(mlen, chunk_size);
    cur_chunk_size = mlen - (chunks - 1) * chunk_size;

    for (i = chunks - 1; i > 0; i--) {

        src = p + i * chunk_size;
        dst = src + i * NGX_RTMP_HEADER_3_SIZE;

        ngx_memmove(dst, src, cur_chunk_size);
        dst[-1] = 0xc0 | csid;  /* format = 3 */

        cur_chunk_size = chunk_size;
    }

    return p + mlen + (chunks - 1) * NGX_RTMP_HEADER_3_SIZE;
}


static size_t
ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_field_t *fields,
    ngx_uint_t type, void *data, u_char fmt, size_t chunk_size)
{
    size_t  mlen;

    mlen = ngx_kmp_rtmp_amf(fields, NULL, type, data);

    return ngx_kmp_rtmp_header_size[fmt] + mlen
        + (ngx_kmp_rtmp_chunk_count(mlen, chunk_size) - 1)
        * NGX_RTMP_HEADER_3_SIZE;
}


static u_char *
ngx_kmp_rtmp_encoder_amf_write(u_char *p, ngx_kmp_rtmp_amf_field_t *fields,
    ngx_uint_t type, void *data, ngx_kmp_rtmp_header_t *h, size_t chunk_size)
{
    u_char  *body;
    u_char  *header;

    header = p;
    p += ngx_kmp_rtmp_header_size[h->format];

    body = p;
    p = (u_char *) ngx_kmp_rtmp_amf(fields, p, type, data);
    h->mlen = p - body;

    ngx_kmp_rtmp_encoder_write_header(header, h);

    return ngx_kmp_rtmp_encoder_add_chunk_headers(body, h->mlen, chunk_size,
        h->csid);
}


size_t
ngx_kmp_rtmp_encoder_connect_get_size(ngx_kmp_rtmp_connect_t *connect)
{
    size_t  size;

    /* connect */

    size = ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_connect,
        NGX_KMP_RTMP_AMF_DEFAULT, connect, 0, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    /* set chunk size */

    size += NGX_RTMP_HEADER_0_SIZE + sizeof(uint32_t);

    return size;
}


u_char *
ngx_kmp_rtmp_encoder_connect_write(u_char *p, ngx_kmp_rtmp_connect_t *connect,
    uint32_t chunk_size)
{
    ngx_kmp_rtmp_header_t  h;

    /* connect */

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_connect,
        NGX_KMP_RTMP_AMF_DEFAULT, connect, &h, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    /* set chunk size */

    h.csid = NGX_RTMP_CSID_PROT_CTRL;
    h.type = NGX_RTMP_MSG_CHUNK_SIZE;
    h.mlen = sizeof(chunk_size);

    p = ngx_kmp_rtmp_encoder_write_header(p, &h);

    ngx_kmp_rtmp_amf_write_be32(p, chunk_size);

    return p;
}


size_t
ngx_kmp_rtmp_encoder_stream_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name)
{
    uint32_t                   chunk_size;
    ngx_kmp_rtmp_cmd_stream_t  cmd;

    chunk_size = sc->chunk_size;
    cmd.name = *name;

    return ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_release_stream,
        NGX_KMP_RTMP_AMF_DEFAULT, &cmd, 1, chunk_size)
        + ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_fcpublish,
            NGX_KMP_RTMP_AMF_DEFAULT, &cmd, 1, chunk_size)
        + ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_create_stream,
            NGX_KMP_RTMP_AMF_DEFAULT, &cmd, 1, chunk_size)
        + ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_publish,
            NGX_KMP_RTMP_AMF_DEFAULT, &cmd, 0, chunk_size);
}


u_char *
ngx_kmp_rtmp_encoder_stream_write(u_char *p, ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name, uint32_t *tx_id)
{
    uint32_t                   chunk_size;
    ngx_kmp_rtmp_header_t      h;
    ngx_kmp_rtmp_cmd_stream_t  cmd;

    ngx_memzero(&h, sizeof(h));
    h.format = 1;
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    cmd.base.tx_id = *tx_id;
    cmd.name = *name;

    chunk_size = sc->chunk_size;

    cmd.base.tx_id++;
    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_release_stream,
        NGX_KMP_RTMP_AMF_DEFAULT, &cmd, &h, chunk_size);

    cmd.base.tx_id++;
    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_fcpublish,
        NGX_KMP_RTMP_AMF_DEFAULT, &cmd, &h, chunk_size);

    cmd.base.tx_id++;
    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_create_stream,
        NGX_KMP_RTMP_AMF_DEFAULT, &cmd, &h, chunk_size);

    h.format = 0;
    h.csid = sc->csid;
    h.msid = sc->msid;

    cmd.base.tx_id++;
    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_publish,
        NGX_KMP_RTMP_AMF_DEFAULT, &cmd, &h, chunk_size);

    *tx_id = cmd.base.tx_id;

    return p;
}


size_t
ngx_kmp_rtmp_encoder_unstream_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name)
{
    uint32_t                      chunk_size;
    ngx_kmp_rtmp_cmd_stream_t     fc_cmd;
    ngx_kmp_rtmp_cmd_stream_id_t  del_cmd;

    chunk_size = sc->chunk_size;
    fc_cmd.name = *name;

    return ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_fcunpublish,
            NGX_KMP_RTMP_AMF_DEFAULT, &fc_cmd, 1, chunk_size)
        + ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_delete_stream,
            NGX_KMP_RTMP_AMF_DEFAULT, &del_cmd, 1, chunk_size);
}


u_char *
ngx_kmp_rtmp_encoder_unstream_write(u_char *p, ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *name, uint32_t *tx_id)
{
    uint32_t                      chunk_size;
    ngx_kmp_rtmp_header_t         h;
    ngx_kmp_rtmp_cmd_stream_t     fc_cmd;
    ngx_kmp_rtmp_cmd_stream_id_t  del_cmd;

    ngx_memzero(&h, sizeof(h));
    h.format = 1;
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    chunk_size = sc->chunk_size;

    fc_cmd.base.tx_id = ++(*tx_id);
    fc_cmd.name = *name;

    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_fcunpublish,
        NGX_KMP_RTMP_AMF_DEFAULT, &fc_cmd, &h, chunk_size);

    del_cmd.base.tx_id = ++(*tx_id);
    del_cmd.stream_id = sc->msid;

    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_delete_stream,
        NGX_KMP_RTMP_AMF_DEFAULT, &del_cmd, &h, chunk_size);

    return p;
}


static ngx_uint_t
ngx_kmp_rtmp_encoder_metadata_get_type(ngx_kmp_rtmp_metadata_t *meta)
{
    ngx_uint_t  type;

    type = 0;

    if (meta->mi[KMP_MEDIA_VIDEO].codec_id != KMP_CODEC_INVALID) {
        type |= NGX_KMP_RTMP_AMF_VIDEO;
    }

    if (meta->mi[KMP_MEDIA_AUDIO].codec_id != KMP_CODEC_INVALID) {
        type |= NGX_KMP_RTMP_AMF_AUDIO;
    }

    return type;
}


size_t
ngx_kmp_rtmp_encoder_metadata_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_metadata_t *meta)
{
    return ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_metadata,
        ngx_kmp_rtmp_encoder_metadata_get_type(meta), meta, 0, sc->chunk_size);
}


u_char *
ngx_kmp_rtmp_encoder_metadata_write(u_char *p, ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_metadata_t *meta)
{
    ngx_kmp_rtmp_header_t  h;

    ngx_memzero(&h, sizeof(h));
    h.csid = sc->csid;
    h.type = NGX_RTMP_MSG_AMF_META;
    h.msid = sc->msid;

    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_metadata,
        ngx_kmp_rtmp_encoder_metadata_get_type(meta), meta, &h,
        sc->chunk_size);

    return p;
}


void
ngx_kmp_rtmp_encoder_update_media_info(ngx_kmp_rtmp_stream_ctx_t *sc,
    kmp_media_info_t *media_info)
{
    ngx_int_t  sound_rate;
    ngx_int_t  sound_size;
    ngx_int_t  sound_type;
    ngx_int_t  sound_format;

    if (media_info->media_type != KMP_MEDIA_AUDIO) {
        return;
    }

    sound_format = media_info->codec_id - KMP_CODEC_AUDIO_BASE;

    if (media_info->u.audio.sample_rate <= 8000) {
        sound_rate = NGX_RTMP_SOUND_RATE_5_5_KHZ;

    } else if (media_info->u.audio.sample_rate <= 16000) {
        sound_rate = NGX_RTMP_SOUND_RATE_11_KHZ;

    } else if (media_info->u.audio.sample_rate <= 32000) {
        sound_rate = NGX_RTMP_SOUND_RATE_22_KHZ;

    } else {
        sound_rate = NGX_RTMP_SOUND_RATE_44_KHZ;
    }

    switch (media_info->u.audio.bits_per_sample) {

    case 8:
        sound_size = NGX_RTMP_SOUND_SIZE_8_BIT;
        break;

    default:
        sound_size = NGX_RTMP_SOUND_SIZE_16_BIT;
        break;
    }

    switch (media_info->u.audio.channels) {

    case 1:
        sound_type = NGX_RTMP_SOUND_TYPE_MONO;
        break;

    default:
        sound_type = NGX_RTMP_SOUND_TYPE_STEREO;
        break;
    }

    sc->sound_info = (sound_format << 4)
        | (sound_rate << 2)
        | (sound_size << 1)
        | (sound_type);
}


static u_char *
ngx_kmp_rtmp_encoder_avc_header_write(u_char *p, u_char packet_type,
    u_char key_frame, uint32_t pts_delay)
{
    u_char  frame_type;

    frame_type = key_frame ? NGX_RTMP_FRAME_TYPE_KEY
        : NGX_RTMP_FRAME_TYPE_INTER;

    *p++ = (frame_type << 4) | KMP_CODEC_VIDEO_H264;
    *p++ = packet_type;
    ngx_kmp_rtmp_amf_write_be24(p, pts_delay);

    return p;
}


size_t
ngx_kmp_rtmp_encoder_avc_sequence_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *extra_data)
{
    size_t  mlen;

    mlen = NGX_RTMP_AVC_HEADER_SIZE + extra_data->len;

    return NGX_RTMP_HEADER_0_SIZE + mlen
        + (ngx_kmp_rtmp_chunk_count(mlen, sc->chunk_size) - 1)
        * NGX_RTMP_HEADER_3_SIZE;
}


u_char *
ngx_kmp_rtmp_encoder_avc_sequence_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data)
{
    u_char                 *body;
    ngx_kmp_rtmp_header_t   h;

    ngx_memzero(&h, sizeof(h));
    h.csid = sc->csid;
    h.mlen = NGX_RTMP_AVC_HEADER_SIZE + extra_data->len;
    h.type = NGX_RTMP_MSG_VIDEO;
    h.msid = sc->msid;

    p = ngx_kmp_rtmp_encoder_write_header(p, &h);

    body = p;
    p = ngx_kmp_rtmp_encoder_avc_header_write(p, NGX_RTMP_AVC_SEQUENCE_HEADER,
        1, 0);
    ngx_memcpy(p, extra_data->data, extra_data->len);

    return ngx_kmp_rtmp_encoder_add_chunk_headers(body, h.mlen, sc->chunk_size,
        h.csid);
}


static u_char *
ngx_kmp_rtmp_encoder_ext_header_write(u_char *p, u_char packet_type,
    u_char key_frame, uint32_t fourcc, uint32_t pts_delay)
{
    u_char  frame_type;

    frame_type = key_frame ? NGX_RTMP_FRAME_TYPE_KEY
        : NGX_RTMP_FRAME_TYPE_INTER;

    *p++ = 0x80 | (frame_type << 4) | packet_type;

    p = ngx_copy(p, &fourcc, sizeof(fourcc));

    if (packet_type == NGX_RTMP_EXT_NALU) {
        ngx_kmp_rtmp_amf_write_be24(p, pts_delay);
    }

    return p;
}


size_t
ngx_kmp_rtmp_encoder_ext_sequence_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *extra_data)
{
    size_t  mlen;

    mlen = NGX_RTMP_EXT_HEADER_SIZE + extra_data->len;

    return NGX_RTMP_HEADER_0_SIZE + mlen
        + (ngx_kmp_rtmp_chunk_count(mlen, sc->chunk_size) - 1)
        * NGX_RTMP_HEADER_3_SIZE;
}


u_char *
ngx_kmp_rtmp_encoder_ext_sequence_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, uint32_t fourcc, ngx_str_t *extra_data)
{
    u_char                 *body;
    ngx_kmp_rtmp_header_t   h;

    ngx_memzero(&h, sizeof(h));
    h.csid = sc->csid;
    h.mlen = NGX_RTMP_EXT_HEADER_SIZE + extra_data->len;
    h.type = NGX_RTMP_MSG_VIDEO;
    h.msid = sc->msid;

    p = ngx_kmp_rtmp_encoder_write_header(p, &h);

    body = p;
    p = ngx_kmp_rtmp_encoder_ext_header_write(p, NGX_RTMP_EXT_SEQUENCE_HEADER,
        1, fourcc, 0);
    ngx_memcpy(p, extra_data->data, extra_data->len);

    return ngx_kmp_rtmp_encoder_add_chunk_headers(body, h.mlen, sc->chunk_size,
        h.csid);
}


static u_char *
ngx_kmp_rtmp_encoder_aac_header_write(u_char *p, u_char sound_info,
    u_char packet_type)
{
    *p++ = sound_info;
    *p++ = packet_type;

    return p;
}


size_t
ngx_kmp_rtmp_encoder_aac_sequence_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_str_t *extra_data)
{
    size_t  mlen;

    mlen = NGX_RTMP_AAC_HEADER_SIZE + extra_data->len;

    return NGX_RTMP_HEADER_0_SIZE + mlen
        + (ngx_kmp_rtmp_chunk_count(mlen, sc->chunk_size) - 1)
        * NGX_RTMP_HEADER_3_SIZE;
}


u_char *
ngx_kmp_rtmp_encoder_aac_sequence_write(u_char *p,
    ngx_kmp_rtmp_stream_ctx_t *sc, ngx_str_t *extra_data)
{
    u_char                 *body;
    ngx_kmp_rtmp_header_t   h;

    ngx_memzero(&h, sizeof(h));
    h.csid = sc->csid;
    h.mlen = NGX_RTMP_AAC_HEADER_SIZE + extra_data->len;
    h.type = NGX_RTMP_MSG_AUDIO;
    h.msid = sc->msid;

    p = ngx_kmp_rtmp_encoder_write_header(p, &h);

    body = p;
    p = ngx_kmp_rtmp_encoder_aac_header_write(p, sc->sound_info,
        NGX_RTMP_AAC_SEQUENCE_HEADER);
    ngx_memcpy(p, extra_data->data, extra_data->len);

    return ngx_kmp_rtmp_encoder_add_chunk_headers(body, h.mlen, sc->chunk_size,
        h.csid);
}


size_t
ngx_kmp_rtmp_encoder_onfi_get_size(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_onfi_t *onfi)
{
    return ngx_kmp_rtmp_encoder_amf_get_size(ngx_kmp_rtmp_amf_onfi,
        NGX_KMP_RTMP_AMF_DEFAULT, onfi, 1, sc->chunk_size);
}


u_char *
ngx_kmp_rtmp_encoder_onfi_write(u_char *p, ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_onfi_t *onfi)
{
    ngx_kmp_rtmp_header_t  h;

    ngx_memzero(&h, sizeof(h));
    h.format = 1;
    h.csid = sc->csid;
    h.type = NGX_RTMP_MSG_AMF_META;
    h.msid = sc->msid;

    p = ngx_kmp_rtmp_encoder_amf_write(p, ngx_kmp_rtmp_amf_onfi,
        NGX_KMP_RTMP_AMF_DEFAULT, onfi, &h, sc->chunk_size);

    return p;
}


ngx_int_t
ngx_kmp_rtmp_encoder_frame_write(ngx_kmp_rtmp_stream_ctx_t *sc,
    ngx_kmp_rtmp_frame_t *frame, uint32_t codec_id,
    ngx_kmp_rtmp_write_pt write, void *data)
{
    size_t                  chunk_left;
    size_t                  header_size;
    u_char                 *p;
    u_char                  chunk_header;
    u_char                  buf[NGX_RTMP_FRAME_HEADER_MAX_SIZE];
    ngx_int_t               rc;
    ngx_buf_chain_t         chain;
    ngx_kmp_rtmp_header_t   h;

    p = buf;

    ngx_memzero(&h, sizeof(h));

    h.timestamp = frame->dts;

    if (sc->wrote_frame) {
        h.format = 1;
        h.timestamp -= sc->last_timestamp;
        p += NGX_RTMP_HEADER_1_SIZE;

    } else {
        sc->wrote_frame = 1;
        p += NGX_RTMP_HEADER_0_SIZE;
    }

    if (h.timestamp >= NGX_RTMP_EXT_TIMESTAMP) {
        ngx_kmp_rtmp_amf_write_be32(p, h.timestamp);
        h.timestamp = NGX_RTMP_EXT_TIMESTAMP;
    }

    /* TODO: add support for "vp09" and "av01" */
    switch (codec_id) {

    case KMP_CODEC_VIDEO_H264:
        header_size = NGX_RTMP_AVC_HEADER_SIZE;
        h.type = NGX_RTMP_MSG_VIDEO;

        p = ngx_kmp_rtmp_encoder_avc_header_write(p, NGX_RTMP_AVC_NALU,
            frame->flags & KMP_FRAME_FLAG_KEY, frame->pts_delay);
        break;

    case KMP_CODEC_VIDEO_H265:
        header_size = NGX_RTMP_EXT_HEADER_SIZE_NALU;
        h.type = NGX_RTMP_MSG_VIDEO;

        p = ngx_kmp_rtmp_encoder_ext_header_write(p, NGX_RTMP_EXT_NALU,
            frame->flags & KMP_FRAME_FLAG_KEY, NGX_RTMP_EXT_FOURCC_HVC1,
            frame->pts_delay);
        break;

    case KMP_CODEC_AUDIO_MP3:
        header_size = 1;
        h.type = NGX_RTMP_MSG_AUDIO;

        *p++ = sc->sound_info;
        break;

    case KMP_CODEC_AUDIO_AAC:
        header_size = NGX_RTMP_AAC_HEADER_SIZE;
        h.type = NGX_RTMP_MSG_AUDIO;

        p = ngx_kmp_rtmp_encoder_aac_header_write(p, sc->sound_info,
            NGX_RTMP_AAC_RAW);
        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, sc->log, 0,
            "ngx_kmp_rtmp_encoder_frame_write: invalid codec %uD", codec_id);
        return NGX_ERROR;
    }

    h.csid = sc->csid;
    h.msid = sc->msid;
    h.mlen = header_size + frame->size;

    ngx_kmp_rtmp_encoder_write_header(buf, &h);

    rc = write(data, buf, p - buf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, sc->log, 0,
            "ngx_kmp_rtmp_encoder_frame_write: write failed %i (1)", rc);
        return rc;
    }

    chunk_header = 0xc0 | h.csid;
    chunk_left = sc->chunk_size - header_size;
    chain = *frame->data;

    for ( ;; ) {

        if (chain.size > chunk_left) {
            rc = write(data, chain.data, chunk_left);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, sc->log, 0,
                    "ngx_kmp_rtmp_encoder_frame_write: "
                    "write failed %i (2)", rc);
                return rc;
            }

            chain.data += chunk_left;
            chain.size -= chunk_left;

            rc = write(data, &chunk_header, sizeof(chunk_header));
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, sc->log, 0,
                    "ngx_kmp_rtmp_encoder_frame_write: "
                    "write failed %i (3)", rc);
                return rc;
            }

            chunk_left = sc->chunk_size;
            continue;
        }

        rc = write(data, chain.data, chain.size);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, sc->log, 0,
                "ngx_kmp_rtmp_encoder_frame_write: write failed %i (4)", rc);
            return rc;
        }

        if (chain.next == NULL) {
            break;
        }

        chunk_left -= chain.size;
        chain = *chain.next;
    }

    sc->last_timestamp = frame->dts;

    return NGX_OK;
}
