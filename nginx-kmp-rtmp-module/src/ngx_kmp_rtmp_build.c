#include "ngx_kmp_rtmp_build.h"


#define HANDSHAKE_SIZE       (1 + 1536 + 1536) /* C0 + C1 + C2 messages */
#define SET_CHUNK_SIZE       4
#define FULL_HEADER_SIZE     12
#define PARTIAL_HEADER_SIZE  8
#define AMF_NUMBER_SIZE     (2 + 1 + 8)  /* key length + type + number value */
#define AMF_BOOLEAN_SIZE    (2 + 1 + 1)  /* key length + type + boolean value */
#define NGX_STREAM_KMP_RTMP_INVALID_MSID  0xffffffff
#define RTMP_TIMESCALE      1000
#define NGX_RTMP_KEY_FRAME      0x10
#define NGX_RTMP_INTER_FRAME    0x20


struct {
    u_char  key_type[1];
    u_char  key_length[2];
    u_char  connect_key[7];
    u_char  transaction_id_type[1];
    u_char  transaction_id_value[8];
    u_char  object_type[1];
    u_char  end_object[3];
} ngx_kmp_rtmp_build_connect_t;

struct {
    u_char  key_type[1];
    u_char  key_length[2];
    u_char  release_stream_key[13];
    u_char  transaction_id_type[1];
    u_char  transaction_id_value[8];
    u_char  null_type[1];
    u_char  stream_type[1];
    u_char  stream_size[2];
} ngx_kmp_rtmp_build_release_stream_t;

struct {
    u_char  key_type[1];
    u_char  key_length[2];
    u_char  fcpublish_key[9];
    u_char  transaction_id_type[1];
    u_char  transaction_id_value[8];
    u_char  null_type[1];
    u_char  stream_type[1];
    u_char  stream_size[2];
} ngx_kmp_rtmp_build_fcpublish_t;

struct {
    u_char  key_type[1];
    u_char  key_length[2];
    u_char  create_stream_key[12];
    u_char  transaction_id_type[1];
    u_char  transaction_id_value[8];
    u_char  null_type[1];
} ngx_kmp_rtmp_build_create_stream_t;

struct {
    u_char  key_type[1];
    u_char  key_length[2];
    u_char  publish_key[7];
    u_char  transaction_id_type[1];
    u_char  transaction_id_value[8];
    u_char  null_type[1];
    u_char  stream_type[1];
    u_char  stream_size[2];
    u_char  live_param[7];
} ngx_kmp_rtmp_build_publish_t;

struct {
    u_char  set_data_frame_type[1];
    u_char  set_data_frame_length[2];
    u_char  set_data_frame[13];
    u_char  on_meta_data_type[1];
    u_char  on_meta_data_length[2];
    u_char  on_meta_data[10];
    u_char  array_type[1];
    u_char  num_of_elem[4];
} ngx_kmp_rtmp_metadata_t;

typedef struct {
    ngx_str_t   app;
    ngx_str_t   flash_ver;
    ngx_str_t   tc_url;
} ngx_kmp_rtmp_connect_fields_t;

typedef struct ngx_kmp_rtmp_amf_field_s ngx_kmp_rtmp_amf_field_t;
typedef u_char *(*amf_write_pt)(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data);


struct ngx_kmp_rtmp_amf_field_s {
	ngx_str_t      key;
	ngx_uint_t     offset;
    amf_write_pt   func;
	uint32_t       data;
	size_t         size;
};


static u_char *ngx_kmp_rtmp_amf_obj_uint16 (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);
static u_char *ngx_kmp_rtmp_amf_obj_uint32 (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);
static u_char *ngx_kmp_rtmp_amf_obj_rational (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);
static u_char *ngx_kmp_rtmp_amf_obj_bitrate (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);
static u_char *ngx_kmp_rtmp_amf_obj_channels (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);
static u_char *ngx_kmp_rtmp_amf_obj_string (
    ngx_kmp_rtmp_amf_field_t *field, u_char *p, void *data);


static ngx_kmp_rtmp_amf_field_t ngx_kmp_rtmp_video_metadata_fields[] = {
    { ngx_string("width"),
      offsetof(kmp_media_info_t, u.video.width),
      ngx_kmp_rtmp_amf_obj_uint16,
      0,
      AMF_NUMBER_SIZE },
    { ngx_string("height"),
      offsetof(kmp_media_info_t, u.video.height),
      ngx_kmp_rtmp_amf_obj_uint16,
      0,
      AMF_NUMBER_SIZE },
   { ngx_string("videodatarate"),
      offsetof(kmp_media_info_t, bitrate),
      ngx_kmp_rtmp_amf_obj_bitrate,
      0,
      AMF_NUMBER_SIZE },
   { ngx_string("framerate"),
      offsetof(kmp_media_info_t, u.video.frame_rate),
      ngx_kmp_rtmp_amf_obj_rational,
      0,
      AMF_NUMBER_SIZE },
   { ngx_string("videocodecid"),
      offsetof(kmp_media_info_t, codec_id),
      ngx_kmp_rtmp_amf_obj_uint32,
      0,
      AMF_NUMBER_SIZE }
};

static ngx_kmp_rtmp_amf_field_t ngx_kmp_rtmp_audio_metadata_fields[] = {
    { ngx_string("audiodatarate"),
      offsetof(kmp_media_info_t, bitrate),
      ngx_kmp_rtmp_amf_obj_bitrate,
      0,
      AMF_NUMBER_SIZE },
    { ngx_string("audiosamplerate"),
      offsetof(kmp_media_info_t, u.audio.sample_rate),
      ngx_kmp_rtmp_amf_obj_uint32,
      0,
      AMF_NUMBER_SIZE },
    { ngx_string("audiosamplesize"),
      offsetof(kmp_media_info_t, u.audio.bits_per_sample),
      ngx_kmp_rtmp_amf_obj_uint16,
      0,
      AMF_NUMBER_SIZE },
   { ngx_string("stereo"),
      offsetof(kmp_media_info_t, u.audio.channels),
      ngx_kmp_rtmp_amf_obj_channels,
      0,
      AMF_BOOLEAN_SIZE },
   { ngx_string("audiocodecid"),
      offsetof(kmp_media_info_t, codec_id),
      ngx_kmp_rtmp_amf_obj_uint32,
      1000,
      AMF_NUMBER_SIZE }
};

static ngx_kmp_rtmp_amf_field_t ngx_kmp_rtmp_connect_fields[] = {
    { ngx_string("app"),
      offsetof(ngx_kmp_rtmp_connect_fields_t, app),
      ngx_kmp_rtmp_amf_obj_string,
      0,
      0 },

    { ngx_string("flashVer"),
      offsetof(ngx_kmp_rtmp_connect_fields_t, flash_ver),
      ngx_kmp_rtmp_amf_obj_string,
      0,
      0 },
    { ngx_string("tcUrl"),
      offsetof(ngx_kmp_rtmp_connect_fields_t, tc_url),
      ngx_kmp_rtmp_amf_obj_string,
      0,
      0 }
};



static ngx_chain_t *
ngx_kmp_rtmp_build_alloc_chain_buf(ngx_pool_t *pool, void *pos, void *last)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_rtmp_build_alloc_chain_buf: ngx_alloc_chain_link failed");
        return NULL;
    }

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_rtmp_build_alloc_chain_buf: ngx_calloc_buf failed");
        return NULL;
    }

    b->temporary = 1;
    b->start = b->pos = pos;
    b->end = b->last = last;
    cl->buf = b;
    cl->next = NULL;

    return cl;
}

ngx_chain_t *
ngx_kmp_rtmp_build_get_chain(ngx_stream_kmp_rtmp_upstream_t *upstream,
    ngx_pool_t *pool, void *pos, void *last)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = upstream->free;
    if (cl != NULL) {
        upstream->free = cl->next;
        b = cl->buf;
        b->start = b->pos = pos;
        b->end = b->last = last;

    } else {
        cl = ngx_kmp_rtmp_build_alloc_chain_buf(pool, pos, last);

        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_kmp_rtmp_build_get_chain: alloc chain buf failed");
            return NULL;
        }
    }

    cl->next = NULL;

    return cl;
}

static ngx_inline u_char *
ngx_kmp_rtmp_write_amf_key(u_char *p, ngx_str_t *key)
{
    write_be16(p, key->len);

    return ngx_copy(p, key->data, key->len);
}

static ngx_inline u_char *
ngx_kmp_rtmp_write_amf_number(u_char *p, double val)
{
    u_char  *v;

    v = (u_char*)&val + sizeof(double) - 1;
    *p++ = NGX_RTMP_AMF_NUMBER;
	*p++ = *v--;	*p++ = *v--;	*p++ = *v--;	*p++ = *v--;
	*p++ = *v--;	*p++ = *v--;	*p++ = *v--;	*p++ = *v--;

    return p;
}

static u_char *
ngx_kmp_rtmp_amf_obj_string(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    ngx_str_t  *val;

    //p = ngx_kmp_rtmp_write_amf_key(p, &field->key);
    /* set value type as string*/
    *p++ = NGX_RTMP_AMF_STRING;
    val = (ngx_str_t *)((u_char *)data + field->offset);
    /* set value length */
    write_be16(p, val->len);
    p = ngx_copy(p, val->data, val->len);

    return p;
}

static u_char *
ngx_kmp_rtmp_amf_obj_channels(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    uint8_t     val;
    uint16_t    channels;

    channels = *((uint16_t *)((u_char *)data + field->offset));
    val = channels == 2 ? 1 : 0;
    *p++ = NGX_RTMP_AMF_BOOLEAN;
    *p++ = val;

    return p;
}

static u_char *
ngx_kmp_rtmp_amf_obj_uint16(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    double      val;

    val = *((uint16_t *)((u_char *)data + field->offset));
    return ngx_kmp_rtmp_write_amf_number(p, val);
}

static u_char *
ngx_kmp_rtmp_amf_obj_uint32(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    double      val;

    val = *((uint32_t *)((u_char *)data + field->offset)) - field->data;
    return ngx_kmp_rtmp_write_amf_number(p, val);
}

static u_char *
ngx_kmp_rtmp_amf_obj_rational(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    double      val;

    val = ((double)(*((uint32_t *)((u_char *)data + field->offset)))) /
         ((double)*((uint32_t *)((u_char *)data + field->offset + 4)));

    return ngx_kmp_rtmp_write_amf_number(p, val);
}

static u_char *
ngx_kmp_rtmp_amf_obj_bitrate(ngx_kmp_rtmp_amf_field_t *field, u_char *p,
    void *data)
{
    double      val;

    val = *((uint32_t *)((u_char *)data + field->offset)) / 1000;
    return ngx_kmp_rtmp_write_amf_number(p, val);
}

static u_char *
ngx_kmp_rtmp_build_header(u_char *message, char csid,
    uint32_t timestamp, uint32_t length, char message_type,
    uint32_t msid)
{
    u_char  *p;

    p = message;
    /* set chunk stream id */
    *p++ = csid;
    /* set timestamp */
    write_be24(p, timestamp);
    /* set message length */
    write_be24(p, length);
    /* set message type */
    *p++ = message_type;
    /* set message stream id */
    if (msid != NGX_STREAM_KMP_RTMP_INVALID_MSID) {
        p = ngx_copy(p, &msid, 4);
    }

    return p;
}

static void
ngx_kmp_rtmp_set_message_size(u_char *message, uint32_t length)
{
    u_char  *p;

    p = message;
    /* set message length */
    write_be24(p, length);
}

static u_char *
ngx_kmp_rtmp_build_h264_header(u_char *message, u_char sequence,
    uint32_t delay, uint8_t key_frame)
{
    u_char  *p;

    p = message;
    /* set key frame and codec (h264) */
    if (key_frame) {
        *p++ = NGX_RTMP_KEY_FRAME | KMP_CODEC_VIDEO_H264;
        //*p++ = 0x17;
    } else {
        *p++ = NGX_RTMP_INTER_FRAME | KMP_CODEC_VIDEO_H264;
        //*p++ = 0x27;
    }
    /* set sequence */
    *p++ = sequence;
    /* set pts delay */
    write_be24(p, delay);

    return p;
}

static u_char *
ngx_kmp_rtmp_build_aac_header(u_char *message, uint8_t sequence)
{
    u_char  *p;

    p = message;
    /* set codec (AAC) */
    *p++ = 0xaf;
    /* set sequence */
    *p++ = sequence;

    return p;
}

static u_char *
ngx_kmp_rtmp_handshake(u_char *message)
{
    int        i;
    u_char    *p;
    uint32_t   uptime;

    p = message;

    *p++ = 0x03;
    uptime = htonl(ngx_current_msec);
    p = ngx_copy(p, &uptime, 4);
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x00;

    for (i = 1; i <= 3064; i++) {
        *p++ = (char)(rand() & 255);
    }

    return p;
}

static u_char *
ngx_kmp_rtmp_connect(u_char *message, ngx_str_t *app, ngx_str_t *tc_url,
    ngx_str_t *flash_ver)
{
    u_char     buf[2000];
    u_char    *p, *start_body;
    uint64_t   transaction_id = 0;

    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x03, 0, 0,
        0x14, 0);
    start_body = p;

    ngx_kmp_rtmp_amf_write_string(p, "connect");
    p = ngx_kmp_rtmp_write_amf_number(p, transaction_id);

    /* object type*/
    *p++ = NGX_RTMP_AMF_OBJECT;

    ngx_kmp_rtmp_connect_fields_t connect_field;
    connect_field.app = *app;
    connect_field.flash_ver = *flash_ver;
    connect_field.tc_url = *tc_url;

    for (int i = 0 ; i < (int)(
        sizeof(ngx_kmp_rtmp_connect_fields) /
        sizeof(ngx_kmp_rtmp_connect_fields[0])) ; i++)
    {
        ngx_kmp_rtmp_amf_field_t field = ngx_kmp_rtmp_connect_fields[i];
        p = ngx_kmp_rtmp_write_amf_key(p, &field.key);
        p = field.func(&field, p, &connect_field);
    }

    /* end object */
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = NGX_RTMP_AMF_END;
    ngx_kmp_rtmp_set_message_size(message + 4, (uint32_t)(p - start_body));

    while (p - start_body > 128) {
        size_t len = p - start_body - 128;
        ngx_memcpy(buf, start_body + 128, len);
        start_body = start_body + 128;
        *start_body++ = 0xc3;
        p++;
        ngx_memcpy(start_body, buf, len);
    }

    return p;
}

static u_char *
ngx_kmp_rtmp_set_chunk_size(u_char *message, ngx_uint_t chunk_size)
{
    u_char     *p;

    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x02, 0, 4, 0x01, 0);
    chunk_size = htonl(chunk_size);
    p = ngx_copy(p, &chunk_size, 4);

    return p;
}

static u_char *
ngx_kmp_rtmp_release_stream(u_char *message, ngx_str_t *stream_name)
{
    size_t     message_size;
    u_char    *p;
    uint64_t   transaction_id = 0;

    message_size  = sizeof(ngx_kmp_rtmp_build_release_stream_t) +
        stream_name->len;
    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x43, 0, message_size,
        0x14, NGX_STREAM_KMP_RTMP_INVALID_MSID);
    ngx_kmp_rtmp_amf_write_string(p, "releaseStream");
    p = ngx_kmp_rtmp_write_amf_number(p, transaction_id);
    /* null type */
    *p++ = NGX_RTMP_AMF_NULL;
    /* string type for stream name*/
    *p++ = NGX_RTMP_AMF_STRING;
    /* size for stream name*/
    write_be16(p, stream_name->len);
    p = ngx_copy(p, stream_name->data, stream_name->len);

    return p;
}

static u_char *
ngx_kmp_rtmp_fcpublish(u_char *message, ngx_str_t *stream_name)
{
    size_t     message_size;
    u_char    *p;
    uint64_t   transaction_id = 0;

    message_size  = sizeof(ngx_kmp_rtmp_build_fcpublish_t) + stream_name->len;
    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x43, 0, message_size,
        0x14, NGX_STREAM_KMP_RTMP_INVALID_MSID);
    ngx_kmp_rtmp_amf_write_string(p, "FCPublish");
    p = ngx_kmp_rtmp_write_amf_number(p, transaction_id);
    /* null type */
    *p++ = NGX_RTMP_AMF_NULL;
    /* string type for stream name*/
    *p++ = NGX_RTMP_AMF_STRING;
    /* size for stream name*/
    write_be16(p, stream_name->len);
    p = ngx_copy(p, stream_name->data, stream_name->len);

    return p;
}

static u_char *
ngx_kmp_rtmp_create_stream(u_char *message)
{
    size_t     message_size;
    u_char    *p;
    uint64_t   transaction_id = 0;

    message_size = sizeof(ngx_kmp_rtmp_build_create_stream_t);
    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x43, 0, message_size,
        0x14, NGX_STREAM_KMP_RTMP_INVALID_MSID);
    ngx_kmp_rtmp_amf_write_string(p, "createStream");
    /* transaction id number type*/
    p = ngx_kmp_rtmp_write_amf_number(p, transaction_id);
    /* null type */
    *p++ = NGX_RTMP_AMF_NULL;

    return p;
}

static u_char *
ngx_kmp_rtmp_publish(u_char *message, ngx_str_t *stream_name)
{
    size_t     message_size;
    u_char    *p;
    uint64_t   transaction_id = 0;

    message_size =  sizeof(ngx_kmp_rtmp_build_publish_t) + stream_name->len;
    p = message;
    p = ngx_kmp_rtmp_build_header(p, 0x04, 0, message_size , 0x14, 1);
    ngx_kmp_rtmp_amf_write_string(p, "publish");
    /* transaction id number type*/
    p = ngx_kmp_rtmp_write_amf_number(p, transaction_id);
    /* null type */
    *p++ = NGX_RTMP_AMF_NULL;
    /* string type for stream name*/
    *p++ = NGX_RTMP_AMF_STRING;
    /* size for stream name*/
    write_be16(p, stream_name->len);
    p = ngx_copy(p, stream_name->data, stream_name->len);
    ngx_kmp_rtmp_amf_write_string(p, "live");

    return p;
}

size_t
ngx_kmp_rtmp_handshake_init_get_size(ngx_str_t *app, ngx_str_t *tc_url, ngx_str_t *flash_ver) {
    size_t ret;

    ret =
        HANDSHAKE_SIZE  +
        sizeof(ngx_kmp_rtmp_build_connect_t) + app->len + tc_url->len +
            flash_ver->len + FULL_HEADER_SIZE +
        SET_CHUNK_SIZE + FULL_HEADER_SIZE;

    return ret;
}

void
ngx_kmp_rtmp_build_handshake_init(ngx_buf_t *b, ngx_str_t *host,
    ngx_str_t *app, ngx_str_t *tc_url, ngx_str_t *flash_ver,
    ngx_uint_t chunk_size)
{
    u_char       *p;

    p = b->last;

    p = ngx_kmp_rtmp_handshake(p);
    p = ngx_kmp_rtmp_connect(p, app, tc_url, flash_ver);
    p = ngx_kmp_rtmp_set_chunk_size(p, chunk_size);
    b->last = p;
}

size_t
ngx_kmp_rtmp_stream_init_get_size(ngx_str_t *stream_name) {
    size_t ret;

    ret = sizeof(ngx_kmp_rtmp_build_release_stream_t) + stream_name->len +
            PARTIAL_HEADER_SIZE +
            sizeof(ngx_kmp_rtmp_build_fcpublish_t) + stream_name->len +
            PARTIAL_HEADER_SIZE +
            sizeof(ngx_kmp_rtmp_build_create_stream_t) + PARTIAL_HEADER_SIZE +
            sizeof(ngx_kmp_rtmp_build_publish_t) + stream_name->len +
            FULL_HEADER_SIZE;

    return ret;
}

void
ngx_kmp_rtmp_build_stream_init(ngx_buf_t *b, ngx_str_t *stream_name)
{
    u_char       *p;

    p = b->last;

    p = ngx_kmp_rtmp_release_stream(p, stream_name);
    p = ngx_kmp_rtmp_fcpublish(p, stream_name);
    p = ngx_kmp_rtmp_create_stream(p);
    p = ngx_kmp_rtmp_publish(p, stream_name);

    b->last = p;
}

ngx_int_t
ngx_kmp_rtmp_build_rtmp(ngx_stream_kmp_rtmp_upstream_t *upstream,
    ngx_stream_kmp_rtmp_track_t *ctx, ngx_rtmp_kmp_frame_t *frame, ngx_uint_t chunk_size, uint32_t timescale)
{
    u_char       *p, *start, header_mask;
    size_t        copy, size, buf_size, left_data_size, offset = 0;
    size_t        current_chunk_size = 0, current_chunk_left = 0;
    int32_t       dts, delay, msid;
    ngx_pool_t   *pool = ctx->s->connection->pool;
    ngx_chain_t  *ch, *last = NULL, *first = NULL;

    start = p = ngx_buf_queue_get(&upstream->buf_queue);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_rtmp_build_rtmp: alloc message failed");
        return NGX_ERROR;
    }

    buf_size = upstream->buf_queue.used_size;
    dts = ngx_kmp_rtmp_rescale_time((frame->dts - ctx->last_timestamp),
        timescale, RTMP_TIMESCALE);
    ctx->last_timestamp = frame->dts;

    /* add the h264/aac header to the size of the message */
    size = frame->size + (ctx->media_type == 0 ? 5 : 2);

    if (ctx->no_msid) {
        header_mask = 0x40;
        msid = NGX_STREAM_KMP_RTMP_INVALID_MSID;
    } else {
        header_mask = 0x00;
        msid = 1;
    }

    switch (ctx->media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_kmp_rtmp_build_header(p,
            header_mask | 0x06, dts, size, NGX_RTMP_PACKET_VIDEO, msid);
        delay = ngx_kmp_rtmp_rescale_time((frame->pts), timescale,
            RTMP_TIMESCALE);
        p = ngx_kmp_rtmp_build_h264_header(p, 1,
            delay, frame->flags & 0x01);
        buf_size -= 5;
        offset += 5;
        current_chunk_size = 5;
        break;
    case KMP_MEDIA_AUDIO:
        p = ngx_kmp_rtmp_build_header(p,
            header_mask |  0x04, dts, size, NGX_RTMP_PACKET_AUDIO, msid);
        p = ngx_kmp_rtmp_build_aac_header(p, 1);
        buf_size -= 2;
        offset += 2;
        current_chunk_size = 2;
        break;
    }

    buf_size -= (!ctx->no_msid ? 12 : 8);
    offset += (!ctx->no_msid ? 12 : 8);
    left_data_size = frame->size;

    for ( ;; ) {
        copy = ngx_min(buf_size, left_data_size);
        if (current_chunk_size + copy > chunk_size) {
           if (copy == buf_size) {
                copy--;
                left_data_size++;

            }
            current_chunk_left = chunk_size - current_chunk_size;

            if (ngx_buf_chain_copy(&frame->data, p,
                current_chunk_left) == NULL)
            {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_rtmp_build_rtmp: copy data failed");
                return NGX_ERROR;
            }

            *(p++ + current_chunk_left) = 0xc6;

            if (ngx_buf_chain_copy(&frame->data, p + current_chunk_left,
                copy - current_chunk_left) == NULL)
            {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_rtmp_build_rtmp: copy data failed");
                return NGX_ERROR;
            }
            current_chunk_size = copy - current_chunk_left;
            copy++;
        } else {
            current_chunk_size += copy;

            if (ngx_buf_chain_copy(&frame->data, p,
                copy) == NULL)
            {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_rtmp_build_rtmp: copy data failed");
                return NGX_ERROR;
            }
        }

        ch = ngx_kmp_rtmp_build_get_chain(upstream, pool, start,
            start + copy + offset);

        if (last != NULL) {
            last->next = ch;
        } else {
            first = ch;
        }
        last = ch;
        offset = 0;

        if (buf_size >= left_data_size) {
            break;
        } else {
            left_data_size -= buf_size;
            start = p = ngx_buf_queue_get(&upstream->buf_queue);
            if (p == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_rtmp_build_rtmp: alloc message failed");
                return NGX_ERROR;
            }
            buf_size = upstream->buf_queue.used_size;
        }
    }

    ctx->no_msid = 1;

    *upstream->last = first;
    upstream->last = &last->next;

    return NGX_OK;
}

size_t
ngx_kmp_rtmp_meta_data_get_size(ngx_stream_kmp_rtmp_track_t *video_ctx,
    ngx_stream_kmp_rtmp_track_t *audio_ctx)
{
    size_t ret;

    ret = FULL_HEADER_SIZE + sizeof(ngx_kmp_rtmp_metadata_t);

    if (video_ctx != NULL) {
        for (int i = 0 ; i < (int) (
            sizeof(ngx_kmp_rtmp_video_metadata_fields) /
            sizeof(ngx_kmp_rtmp_video_metadata_fields[0])) ; i++)
        {
            ngx_kmp_rtmp_amf_field_t field =
                ngx_kmp_rtmp_video_metadata_fields[i];
            ret += field.key.len + field.size;
        }
        ret += FULL_HEADER_SIZE + video_ctx->media_info_data.len + 5;
    }

    if (audio_ctx != NULL) {
        for (int i = 0 ; i < (int) (
            sizeof(ngx_kmp_rtmp_audio_metadata_fields) /
            sizeof(ngx_kmp_rtmp_audio_metadata_fields[0])) ; i++)
        {
            ngx_kmp_rtmp_amf_field_t field =
                ngx_kmp_rtmp_audio_metadata_fields[i];
            ret += field.key.len + field.size;
        }
       ret += FULL_HEADER_SIZE + audio_ctx->media_info_data.len + 2;
    }

    return ret;
}

void
ngx_kmp_rtmp_build_meta_data(ngx_buf_t *b,
    ngx_stream_kmp_rtmp_track_t *video_ctx,
    ngx_stream_kmp_rtmp_track_t *audio_ctx)
{
    int           i;
    u_char       *p, *start, *tmp;
    uint32_t      nelem;

    start = p = b->last;

    p = ngx_kmp_rtmp_build_header(p, 0x04, 0, 0, 0x12, 1);
    tmp = p;
    ngx_kmp_rtmp_amf_write_string(p, "@setDataFrame");
    ngx_kmp_rtmp_amf_write_string(p, "onMetaData");
    *p++ = NGX_RTMP_AMF_MIXED_ARRAY;
    nelem = sizeof(ngx_kmp_rtmp_video_metadata_fields) /
        sizeof(ngx_kmp_rtmp_video_metadata_fields[0]) +
        sizeof(ngx_kmp_rtmp_audio_metadata_fields) /
        sizeof(ngx_kmp_rtmp_audio_metadata_fields[0]);

    write_be32(p, nelem);

    if (video_ctx != NULL) {
        for (i = 0 ; i < (int)(
            sizeof(ngx_kmp_rtmp_video_metadata_fields) /
            sizeof(ngx_kmp_rtmp_video_metadata_fields[0])) ; i++)
        {
            ngx_kmp_rtmp_amf_field_t field =
                ngx_kmp_rtmp_video_metadata_fields[i];
            p = ngx_kmp_rtmp_write_amf_key(p, &field.key);
            p = field.func(&field, p, &video_ctx->media_info);
        }
    }

    if (audio_ctx != NULL) {
        for (i = 0 ; i < (int)(
            sizeof(ngx_kmp_rtmp_audio_metadata_fields) /
            sizeof(ngx_kmp_rtmp_audio_metadata_fields[0])) ; i++)
        {
            ngx_kmp_rtmp_amf_field_t field =
                ngx_kmp_rtmp_audio_metadata_fields[i];
            p = ngx_kmp_rtmp_write_amf_key(p, &field.key);
            p = field.func(&field, p, &audio_ctx->media_info);
        }
    }

    ngx_kmp_rtmp_set_message_size(start + 4, p - tmp);

    /* add the h264/aac header to the size of the message */
    if (video_ctx != NULL) {
        p = ngx_kmp_rtmp_build_header(p, 0x06, 0, video_ctx->media_info_data.len + 5, 0x09,
            1);
        p = ngx_kmp_rtmp_build_h264_header(p, 0, 0, 1);
        p = ngx_copy(p, video_ctx->media_info_data.data,
            video_ctx->media_info_data.len);
    }

    if (audio_ctx != NULL) {
        p = ngx_kmp_rtmp_build_header(p, 0x04, 0, audio_ctx->media_info_data.len + 2, 0x08,
            1);
        p = ngx_kmp_rtmp_build_aac_header(p, 0);
        p = ngx_copy(p, audio_ctx->media_info_data.data,
            audio_ctx->media_info_data.len);
    }

    b->last = p;
}
