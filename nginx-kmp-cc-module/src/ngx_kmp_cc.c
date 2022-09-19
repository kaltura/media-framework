#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_kmp_out_track_internal.h>
#include "ngx_buf_chain_reader.h"

#include "ngx_kmp_cc.h"

#include "media/cea708.h"
#include "media/eia608.h"


#define NGX_KMP_CC_608_BASE          0     /* CC1 = 0 .. CC4 = 3 */
#define NGX_KMP_CC_708_BASE          4     /* SERVICE1 = 4 .. SERVICE63 = 66 */

#define NGX_KMP_CC_PACKET_MAX_COUNT  0x1f  /* cc_count is 5 bits */

#define NGX_KMP_CC_SERVICE_INPUT_ID_PREFIX    "kmp-cc://"
#define NGX_KMP_CC_SERVICE_TRACK_INFO_HEADER  "\"input_type\":\"cc\",\"cc\":"

#define NGX_KMP_CC_AVC_NAL_SEI               6
#define NGX_KMP_CC_SEI_USER_DATA_REGISTERED  4

#define NGX_KMP_CC_ATOM_HEADER_SIZE    8

#define NGX_KMP_CC_SERVICE_ID_SIZE     (sizeof("service63") - 1)

#define NGX_KMP_CC_ISO8601_DATE_LEN    (sizeof("yyyy-mm-dd") - 1)

#define NGX_KMP_CC_ERR_INTERNAL_ERROR  "internal_error"
#define NGX_KMP_CC_ERR_ALLOC_FAILED    "alloc_failed"
#define NGX_KMP_CC_ERR_WRITE_FAILED    "write_failed"
#define NGX_KMP_CC_ERR_PACKET_LIMIT    "packet_limit_reached"
#define NGX_KMP_CC_ERR_BAD_MEDIA_INFO  "bad_media_info"
#define NGX_KMP_CC_ERR_BAD_JSON        "bad_publish_json"


#define ngx_copy_str(dst, src)         ngx_copy(dst, (src).data, (src).len)

#define ngx_kmp_cc_rescale_time(time, cur_scale, new_scale)                  \
    ((((uint64_t) (time)) * (new_scale) + (cur_scale) / 2) / (cur_scale))

#define ngx_kmp_cc_write_be32(p, dw) {                                       \
        *(p)++ = ((dw) >> 24) & 0xff;                                        \
        *(p)++ = ((dw) >> 16) & 0xff;                                        \
        *(p)++ = ((dw) >> 8) & 0xff;                                         \
        *(p)++ = (dw) & 0xff;                                                \
    }


typedef enum {
    cc_state_idle,
    cc_state_started,
    cc_state_wrote_header,
} ngx_kmp_cc_state_e;


typedef struct {
    u_char                       version;
    u_char                       profile;
    u_char                       compatibility;
    u_char                       level;
    u_char                       nula_length_size;
} ngx_kmp_cc_avcc_config_t;


typedef struct {
    ngx_queue_t                  queue;
    int64_t                      pts;
    ngx_uint_t                   cc_count;
    u_char                       data[NGX_KMP_CC_PACKET_MAX_COUNT * 3];
} ngx_kmp_cc_packet_t;


typedef void (*ngx_kmp_cc_parse_pt)(void *ctx, vlc_tick_t tick,
    u_char *data, size_t size);

typedef struct {
    ngx_rbtree_node_t            node;        /* must be first */
    ngx_queue_t                  queue;
    ngx_json_str_t               id;
    u_char                       id_buf[NGX_KMP_CC_SERVICE_ID_SIZE];

    ngx_kmp_cc_ctx_t            *ctx;
    ngx_kmp_out_track_t         *out;

    ngx_kmp_cc_parse_pt          decode;
    void                        *decode_ctx;

    ngx_kmp_cc_state_e           state;
    ngx_kmp_out_track_marker_t   vttc;
    ngx_kmp_out_track_marker_t   payl;
    u_char                       buf[128];
    size_t                       buf_used;

    ngx_fd_t                     dump_fd;

    ngx_uint_t                   received_bytes;
} ngx_kmp_cc_service_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  queue;
} ngx_kmp_cc_services_t;


struct ngx_kmp_cc_ctx_s {
    ngx_pool_t                  *pool;
    ngx_log_t                   *log;
    ngx_kmp_cc_conf_t            conf;
    ngx_kmp_cc_input_t           input;
    ngx_kmp_out_track_conf_t    *oconf;
    char                        *error;

    ngx_kmp_cc_services_t        services;

    uint32_t                     timescale;
    uint32_t                     avc_nal_bytes;

    int64_t                      pts;
    int64_t                      max_pts;
    int64_t                      last_created;
    u_char                      *min_used;

    ngx_uint_t                   packets_left;
    ngx_queue_t                  pending;   /* ngx_kmp_cc_packet_t */
    ngx_queue_t                  free;      /* ngx_kmp_cc_packet_t */

    ngx_int_t                    c608_channel[2];  /* per field */
    cea708_demux_t              *c708_demux;

    ngx_uint_t                   pending_packets;
    ngx_uint_t                   received_bytes;
    ngx_uint_t                   received_packets;

    unsigned                     output_all:1;
};


static ngx_int_t ngx_kmp_cc_708_demux_create(ngx_kmp_cc_ctx_t *ctx);


#include "ngx_kmp_cc_json.h"


/* user_data_registered_itu_t_t35 */
static u_char ngx_kmp_cc_sei_payload_header[] = {
    0xb5,   /* itu_t_t35_country_code   */
    0x00,   /* Itu_t_t35_provider_code  */
    0x31,
    0x47,   /* ATSC_user_identifier ('GA94') */
    0x41,
    0x39,
    0x34,
    0x03,   /* ATSC1_data_user_data_type_code */
};


static ngx_fd_t
ngx_kmp_cc_service_open_dump_file(ngx_kmp_cc_service_t *svc)
{
    ngx_fd_t           fd;
    ngx_str_t          name;
    ngx_str_t          folder;
    ngx_kmp_cc_ctx_t  *ctx;

    ctx = svc->ctx;
    folder = ctx->conf.dump_folder;

    if (folder.len == 0) {
        return NGX_INVALID_FILE;
    }

    name.len = folder.len + sizeof("/ngx_live_cc_dump____.dat")
        + NGX_KMP_CC_ISO8601_DATE_LEN + ctx->input.channel_id.s.len
        + ctx->input.track_id.s.len + svc->id.s.len;
    name.data = ngx_alloc(name.len, ctx->log);
    if (name.data == NULL) {
        return NGX_INVALID_FILE;
    }

    ngx_sprintf(name.data, "%V/ngx_live_cc_dump_%*s_%V_%V_%V.dat%Z",
        &folder, NGX_KMP_CC_ISO8601_DATE_LEN, ngx_cached_http_log_iso8601.data,
        &ctx->input.channel_id.s, &ctx->input.track_id.s, &svc->id.s);

    fd = ngx_open_file((char *) name.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
        NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
            "ngx_kmp_cc_service_open_dump_file: "
            ngx_open_file_n " \"%s\" failed", name.data);
        ngx_free(name.data);
        return NGX_INVALID_FILE;
    }

    ngx_free(name.data);
    return fd;
}


static ngx_kmp_cc_service_t *
ngx_kmp_cc_service_get(ngx_kmp_cc_ctx_t *ctx, uint32_t id)
{
    ngx_rbtree_t       *rbtree;
    ngx_rbtree_node_t  *node, *sentinel;

    rbtree = &ctx->services.rbtree;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (id < node->key) {
            node = node->left;
            continue;
        }

        if (id > node->key) {
            node = node->right;
            continue;
        }

        return (ngx_kmp_cc_service_t *) node;
    }

    return NULL;
}


static ngx_kmp_cc_service_t *
ngx_kmp_cc_service_create(ngx_kmp_cc_ctx_t *ctx, ngx_int_t id)
{
    u_char                *p;
    ngx_kmp_cc_service_t  *svc;

    svc = ngx_pcalloc(ctx->pool, sizeof(*svc));
    if (svc == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_cc_service_create: alloc failed");
        ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
        return NULL;
    }

    svc->node.key = id;
    svc->ctx = ctx;

    p = svc->id_buf;

    svc->id.s.data = p;
    if (id < NGX_KMP_CC_708_BASE) {
        *p++ = 'c';
        *p++ = 'c';
        *p++ = '1' + id - NGX_KMP_CC_608_BASE;

    } else {
        p = ngx_sprintf(p, "service%i", id - NGX_KMP_CC_708_BASE + 1);
    }

    svc->id.s.len = p - svc->id_buf;

    ngx_rbtree_insert(&ctx->services.rbtree, &svc->node);
    ngx_queue_insert_tail(&ctx->services.queue, &svc->queue);

    svc->dump_fd = ngx_kmp_cc_service_open_dump_file(svc);

    return svc;
}


static void
ngx_kmp_cc_service_close(ngx_kmp_cc_service_t *svc, char *reason)
{
    if (svc->decode_ctx != NULL) {
        if (svc->node.key < NGX_KMP_CC_708_BASE) {
            Eia608Release(svc->decode_ctx);

        } else {
            CEA708_Decoder_Release(svc->decode_ctx);
        }
    }

    if (svc->out != NULL) {
        ngx_kmp_out_track_detach(svc->out, reason);
    }

    if (svc->dump_fd != NGX_INVALID_FILE) {
        ngx_close_file(svc->dump_fd);
    }
}


static ngx_int_t
ngx_kmp_cc_service_track_create(ngx_kmp_cc_service_t *svc,
    ngx_json_key_value_t *json, ngx_pool_t *temp_pool)
{
    u_char               *p;
    size_t                json_size;
    size_t                input_id_size;
    ngx_int_t             rc;
    ngx_kmp_cc_ctx_t     *ctx;
    ngx_kmp_out_track_t  *track;

    ctx = svc->ctx;

    track = ngx_kmp_out_track_create(ctx->oconf, KMP_MEDIA_SUBTITLE);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_cc_service_track_create: create track failed");
        ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
        return NGX_ABORT;
    }

    input_id_size = sizeof(NGX_KMP_CC_SERVICE_INPUT_ID_PREFIX) - 1
        + ctx->input.channel_id.s.len + ctx->input.track_id.s.len
        + svc->id.s.len + sizeof("//") - 1;

    json_size = sizeof(NGX_KMP_CC_SERVICE_TRACK_INFO_HEADER) - 1
        + ngx_kmp_cc_service_publish_json_get_size(svc);

    p = ngx_pnalloc(track->pool, input_id_size + json_size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_cc_service_track_create: alloc failed");
        ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
        return NGX_ABORT;
    }

    track->input_id.data = p;
    p = ngx_copy_fix(p, NGX_KMP_CC_SERVICE_INPUT_ID_PREFIX);
    p = ngx_copy_str(p, ctx->input.channel_id.s);
    *p++ = '/';
    p = ngx_copy_str(p, ctx->input.track_id.s);
    *p++ = '/';
    p = ngx_copy_str(p, svc->id.s);
    track->input_id.len = p - track->input_id.data;

    track->json_info.data = p;
    p = ngx_copy_fix(p, NGX_KMP_CC_SERVICE_TRACK_INFO_HEADER);
    p = ngx_kmp_cc_service_publish_json_write(p, svc);
    track->json_info.len = p - track->json_info.data;

    track->media_info.codec_id = KMP_CODEC_SUBTITLE_WEBVTT;
    ngx_str_set(&track->extra_data, "WEBVTT");

    rc = ngx_kmp_out_track_write_media_info(track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_cc_service_track_create: write media info failed");
        ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
        return NGX_ABORT;
    }

    switch (json->value.type) {

    case NGX_JSON_NULL:
        rc = ngx_kmp_out_track_publish(track);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_kmp_cc_service_track_create: publish failed");
            ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
            return NGX_ABORT;
        }

        break;

    case NGX_JSON_OBJECT:
        rc = ngx_kmp_out_track_publish_json(track, &json->value.v.obj,
            temp_pool);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_kmp_cc_service_track_create: publish json failed");
            ctx->error = NGX_KMP_CC_ERR_BAD_JSON;
            return NGX_ERROR;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_service_track_create: "
            "invalid element type %d for key \"%V\"",
            json->value.type, &json->key);
        ctx->error = NGX_KMP_CC_ERR_BAD_JSON;
        return NGX_ERROR;
    }

    svc->out = track;

    return NGX_OK;
}


static void
ngx_kmp_cc_service_frame_start(void *data)
{
    ngx_kmp_cc_ctx_t      *ctx;
    ngx_kmp_cc_service_t  *svc;

    svc = data;
    ctx = svc->ctx;

    if (ctx->error) {
        return;
    }

    if (svc->state != cc_state_idle) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_cc_service_frame_start: invalid state %d", svc->state);
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    svc->state = cc_state_started;
}


static void
ngx_kmp_cc_service_frame_add_setting(void *data, ngx_str_t *str)
{
    ngx_kmp_cc_ctx_t      *ctx;
    ngx_kmp_cc_service_t  *svc;

    svc = data;
    ctx = svc->ctx;

    if (ctx->error) {
        return;
    }

    if (svc->state != cc_state_started) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_cc_service_frame_add_setting: "
            "invalid state %d", svc->state);
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    if (str->len + 1 > sizeof(svc->buf) - svc->buf_used) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_service_frame_add_setting: "
            "not enough room for setting %V", str);
        return;
    }

    if (svc->buf_used > 0) {
        svc->buf[svc->buf_used++] = ' ';
    }

    ngx_memcpy(svc->buf + svc->buf_used, str->data, str->len);
    svc->buf_used += str->len;
}


static ngx_int_t
ngx_kmp_cc_service_write_settings(ngx_kmp_cc_service_t *svc)
{
    size_t   size;
    u_char  *p;
    u_char   header[NGX_KMP_CC_ATOM_HEADER_SIZE];

    size = sizeof(header) + svc->buf_used;

    p = header;

    ngx_kmp_cc_write_be32(p, size);
    *p++ = 's';  *p++ = 't';  *p++ = 't';  *p++ = 'g';

    if (ngx_kmp_out_track_write_frame_data(svc->out, header, sizeof(header))
        != NGX_OK
        || ngx_kmp_out_track_write_frame_data(svc->out, svc->buf,
            svc->buf_used) != NGX_OK)
    {
        svc->ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_cc_service_frame_write(void *data, void *buf, size_t len)
{
    size_t                 size;
    u_char                *p;
    u_char                 header[NGX_KMP_CC_ATOM_HEADER_SIZE];
    ngx_kmp_cc_ctx_t      *ctx;
    ngx_kmp_cc_service_t  *svc;

    svc = data;
    ctx = svc->ctx;

    if (ctx->error) {
        return;
    }

    switch (svc->state) {

    case cc_state_started:

        if (ngx_kmp_out_track_write_frame_start(svc->out) != NGX_OK) {
            ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
            break;
        }

        ngx_kmp_out_track_write_marker_start(svc->out, &svc->vttc);

        ngx_memzero(header, sizeof(header));

        if (ngx_kmp_out_track_write_frame_data(svc->out, header,
            sizeof(header)) != NGX_OK)
        {
            ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
            break;
        }

        if (svc->buf_used > 0) {
            if (ngx_kmp_cc_service_write_settings(svc) != NGX_OK) {
                return;
            }
        }

        ngx_kmp_out_track_write_marker_start(svc->out, &svc->payl);

        svc->buf_used = NGX_KMP_CC_ATOM_HEADER_SIZE;
        ngx_memzero(svc->buf, svc->buf_used);

        svc->state = cc_state_wrote_header;

        /* fall through */

    case cc_state_wrote_header:

        p = buf;

        while (len > 0) {
            size = sizeof(svc->buf) - svc->buf_used;
            if (size >= len) {
                ngx_memcpy(svc->buf + svc->buf_used, p, len);
                svc->buf_used += len;
                break;
            }

            ngx_memcpy(svc->buf + svc->buf_used, p, size);

            if (ngx_kmp_out_track_write_frame_data(svc->out, svc->buf,
                sizeof(svc->buf)) != NGX_OK)
            {
                ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
                break;
            }

            svc->buf_used = 0;

            p += size;
            len -= size;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_cc_service_frame_write: invalid state %d", svc->state);
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }
}


static void
ngx_kmp_cc_service_frame_end(void *data, vlc_tick_t start, vlc_tick_t end)
{
    size_t                 size;
    u_char                *p;
    u_char                 header[NGX_KMP_CC_ATOM_HEADER_SIZE];
    int64_t                dts, pts;
    ngx_kmp_cc_ctx_t      *ctx;
    kmp_frame_packet_t     frame;
    ngx_kmp_cc_service_t  *svc;

    svc = data;
    ctx = svc->ctx;

    if (ctx->error) {
        return;
    }

    switch (svc->state) {

    case cc_state_started:
        /* empty frame - ignore */
        goto done;

    case cc_state_wrote_header:
        break;

    default:
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_cc_service_frame_end: invalid state %d", svc->state);
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    if (svc->buf_used > 0) {
        if (ngx_kmp_out_track_write_frame_data(svc->out, svc->buf,
            svc->buf_used) != NGX_OK)
        {
            ctx->error = NGX_KMP_CC_ERR_WRITE_FAILED;
            return;
        }

        svc->buf_used = 0;
    }

    /* close payl */

    size = ngx_kmp_out_track_marker_get_size(svc->out, &svc->payl);

    p = header;

    ngx_kmp_cc_write_be32(p, size);
    *p++ = 'p';  *p++ = 'a';  *p++ = 'y';  *p++ = 'l';

    if (ngx_kmp_out_track_write_marker_end(svc->out, &svc->payl,
        header, sizeof(header)) != NGX_OK)
    {
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    /* close vttc */

    size = ngx_kmp_out_track_marker_get_size(svc->out, &svc->vttc);

    p = header;

    ngx_kmp_cc_write_be32(p, size);
    *p++ = 'v';  *p++ = 't';  *p++ = 't';  *p++ = 'c';

    if (ngx_kmp_out_track_write_marker_end(svc->out, &svc->vttc,
        header, sizeof(header)) != NGX_OK)
    {
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    /* close frame */

    dts = ngx_kmp_cc_rescale_time(start, CLOCK_FREQ, ctx->timescale);
    pts = ngx_kmp_cc_rescale_time(end, CLOCK_FREQ, ctx->timescale);

    ngx_memzero(&frame, sizeof(frame));
    frame.header.packet_type = KMP_PACKET_FRAME;
    frame.header.header_size = sizeof(frame);

    frame.f.dts = dts;
    frame.f.pts_delay = pts - dts;
    frame.f.created = ctx->last_created - frame.f.pts_delay;

    if (ngx_kmp_out_track_write_frame_end(svc->out, &frame) != NGX_OK) {
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return;
    }

    svc->out->stats.last_timestamp = dts;

done:

    svc->state = cc_state_idle;
}


static subtitle_handler_t  ngx_kmp_cc_service_handler = {
    ngx_kmp_cc_service_frame_start,
    ngx_kmp_cc_service_frame_add_setting,
    ngx_kmp_cc_service_frame_write,
    ngx_kmp_cc_service_frame_end,
};


static ngx_int_t
ngx_kmp_cc_service_decoder_init(ngx_kmp_cc_service_t *svc)
{
    ngx_int_t          rc;
    ngx_int_t          id;
    ngx_kmp_cc_ctx_t  *ctx;

    ctx = svc->ctx;
    id = svc->node.key;

    if (id < NGX_KMP_CC_708_BASE) {
        id -= NGX_KMP_CC_608_BASE;

        svc->decode_ctx = Eia608New(ctx->log, id, svc,
            &ngx_kmp_cc_service_handler);
        if (svc->decode_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "ngx_kmp_cc_service_decoder_init: new eia608 decoder failed");
            ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
            return NGX_ABORT;
        }

        svc->decode = Eia608Parse;

    } else {
        rc = ngx_kmp_cc_708_demux_create(ctx);
        if (rc != NGX_OK) {
            return rc;
        }

        id -= NGX_KMP_CC_708_BASE;

        svc->decode_ctx = CEA708_Decoder_New(ctx->log, id, svc,
            &ngx_kmp_cc_service_handler);
        if (svc->decode_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "ngx_kmp_cc_service_decoder_init: new cea708 decoder failed");
            ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
            return NGX_ABORT;
        }

        svc->decode = CEA708_Decoder_Push;
    }

    return NGX_OK;
}


static ngx_kmp_cc_service_t *
ngx_kmp_cc_service_get_or_create(ngx_kmp_cc_ctx_t *ctx, uint32_t id)
{
    ngx_int_t              rc;
    ngx_kmp_cc_service_t  *svc;
    ngx_json_key_value_t   json;

    svc = ngx_kmp_cc_service_get(ctx, id);
    if (svc != NULL) {
        return svc;
    }

    svc = ngx_kmp_cc_service_create(ctx, id);
    if (svc == NULL) {
        return NULL;
    }

    if (!ctx->output_all) {
        return svc;
    }

    json.value.type = NGX_JSON_NULL;

    rc = ngx_kmp_cc_service_track_create(svc, &json, NULL);
    if (rc != NGX_OK) {
        return NULL;
    }

    rc = ngx_kmp_cc_service_decoder_init(svc);
    if (rc != NGX_OK) {
        return NULL;
    }

    return svc;
}


static void
ngx_kmp_cc_service_push(ngx_kmp_cc_service_t *svc, vlc_tick_t tick,
    u_char *buf, size_t size)
{
    svc->received_bytes += size;

    if (svc->dump_fd != NGX_INVALID_FILE) {
        if (ngx_write_fd(svc->dump_fd, buf, size) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, svc->ctx->log, ngx_errno,
                "ngx_kmp_cc_service_push: dump file write failed");
            ngx_close_file(svc->dump_fd);
            svc->dump_fd = NGX_INVALID_FILE;
        }
    }

    if (svc->decode_ctx != NULL) {
        svc->decode(svc->decode_ctx, tick, buf, size);
    }
}


static void
ngx_kmp_cc_parse_608_channel(ngx_int_t *channel, u_char d[2])
{
    static const int  p4[16] = {
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0
    };

    int  d1;

    if (p4[d[0] & 0xf] == p4[d[0] >> 4] || p4[d[1] & 0xf] == p4[d[1] >> 4]) {
        /* invalid parity */
        *channel = -1;
        return;
    }

    d1 = d[0] & 0x7f;
    if (d1 >= 0x10 && d1 <= 0x1f) {
        *channel = ((d1 & 0x08) != 0);

    } else if (d1 < 0x10) {
        *channel = 2;
    }
}


static ngx_kmp_cc_packet_t *
ngx_kmp_cc_packet_alloc(ngx_kmp_cc_ctx_t *ctx)
{
    ngx_queue_t          *q;
    ngx_kmp_cc_packet_t  *pkt;

    q = ngx_queue_head(&ctx->free);
    if (q != ngx_queue_sentinel(&ctx->free)) {
        pkt = ngx_queue_data(q, ngx_kmp_cc_packet_t, queue);
        ngx_queue_remove(q);
        return pkt;
    }

    if (ctx->packets_left <= 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_packet_alloc: packet limit reached");
        ctx->error = NGX_KMP_CC_ERR_PACKET_LIMIT;
        return NULL;
    }

    pkt = ngx_palloc(ctx->pool, sizeof(*pkt));
    if (pkt == NULL) {
        ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
        return NULL;
    }

    ctx->packets_left--;

    return pkt;
}


static void
ngx_kmp_cc_packet_free(ngx_kmp_cc_ctx_t *ctx, ngx_kmp_cc_packet_t *pkt)
{
    ngx_queue_insert_tail(&ctx->free, &pkt->queue);
}


static ngx_int_t
ngx_kmp_cc_packet_push(ngx_kmp_cc_ctx_t *ctx, ngx_kmp_cc_packet_t *pkt)
{
    u_char                *p, *end;
    u_char                 cc_valid;
    u_char                 cc_type;
    ngx_int_t             *channelp;
    ngx_uint_t             field;
    ngx_uint_t             channel;
    vlc_tick_t             tick;
    ngx_kmp_cc_service_t  *svc;

    tick = ngx_kmp_cc_rescale_time(pkt->pts, ctx->timescale, CLOCK_FREQ);

    p = pkt->data;
    for (end = p + pkt->cc_count * 3; p < end; p += 3) {

        cc_valid = p[0] & 0x04;
        if (!cc_valid) {
            continue;
        }

        cc_type = p[0] & 0x03;

        if (cc_type < 2) {

            /* 608 */

            if ((p[1] & 0x7f) == 0 && (p[2] & 0x7f) == 0) {
                continue;
            }

            field = cc_type;
            channelp = &ctx->c608_channel[field];

            ngx_kmp_cc_parse_608_channel(channelp, p + 1);

            if (*channelp < 0 || *channelp > 1) {
                continue;
            }

            channel = (field << 1) | (*channelp);

            svc = ngx_kmp_cc_service_get_or_create(ctx,
                NGX_KMP_CC_608_BASE + channel);
            if (svc == NULL) {
                return NGX_ERROR;
            }

            ngx_kmp_cc_service_push(svc, tick, p + 1, 2);

        } else {

            /* 708 */

            if (ctx->c708_demux == NULL) {
                if (!ctx->output_all) {
                    continue;
                }

                if (ngx_kmp_cc_708_demux_create(ctx) != NGX_OK) {
                    break;
                }
            }

            CEA708_DTVCC_Demuxer_Push(ctx->c708_demux, tick, p);
        }
    }

    return ctx->error ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
ngx_kmp_cc_packet_push_all(ngx_kmp_cc_ctx_t *ctx)
{
    ngx_queue_t          *q;
    ngx_kmp_cc_packet_t  *pkt;

    for ( ;; ) {
        q = ngx_queue_head(&ctx->pending);
        if (q == ngx_queue_sentinel(&ctx->pending)) {
            break;
        }

        pkt = ngx_queue_data(q, ngx_kmp_cc_packet_t, queue);

        if (ngx_kmp_cc_packet_push(ctx, pkt) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_queue_remove(q);
        ngx_kmp_cc_packet_free(ctx, pkt);
    }

    ctx->pending_packets = 0;

    return NGX_OK;
}


static void
ngx_kmp_cc_packet_insert(ngx_kmp_cc_ctx_t *ctx, ngx_kmp_cc_packet_t *pkt)
{
    ngx_queue_t          *q;
    ngx_kmp_cc_packet_t  *cur;

    /* inserting in ascending pts order */

    q = ngx_queue_last(&ctx->pending);
    for ( ;; ) {
        if (q == ngx_queue_sentinel(&ctx->pending)) {
            break;
        }

        cur = ngx_queue_data(q, ngx_kmp_cc_packet_t, queue);
        if (pkt->pts >= cur->pts) {
            break;
        }

        q = ngx_queue_prev(q);
    }

    ngx_queue_insert_after(q, &pkt->queue);

    ctx->pending_packets++;
}


/* udr = user data registered */
static ngx_int_t
ngx_kmp_cc_process_udr_sei(ngx_kmp_cc_ctx_t *ctx,
    ngx_buf_chain_reader_ep_t *reader)
{
    u_char                b;
    u_char                buf[sizeof(ngx_kmp_cc_sei_payload_header)];
    size_t                size;
    ngx_uint_t            cc_count;
    ngx_kmp_cc_packet_t  *pkt;

    if (ngx_buf_chain_reader_ep_read(reader, buf, sizeof(buf)) != NGX_OK
        || ngx_memcmp(buf, ngx_kmp_cc_sei_payload_header, sizeof(buf)) != 0)
    {
        return NGX_OK;
    }

    if (ngx_buf_chain_reader_ep_read(reader, &b, sizeof(b)) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_process_udr_sei: read user_data_type failed");
        return NGX_DECLINED;
    }

    /* process_cc_data_flag */

    if (!(b & 0x40)) {
        return NGX_OK;
    }

    cc_count = b & 0x1f;
    if (cc_count <= 0) {
        return NGX_OK;
    }

    /* em_data */

    if (ngx_buf_chain_reader_ep_read(reader, &b, sizeof(b)) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_process_udr_sei: read em_data failed");
        return NGX_DECLINED;
    }

    if (b != 0xff) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_process_udr_sei: unexpected em_data value 0x%uxD",
            (uint32_t) b);
        return NGX_DECLINED;
    }

    pkt = ngx_kmp_cc_packet_alloc(ctx);
    if (pkt == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_cc_process_udr_sei: alloc failed");
        return NGX_ABORT;
    }

    size = cc_count * 3;

    if (ngx_buf_chain_reader_ep_read(reader, pkt->data, size) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_process_udr_sei: read cc_data_pkt failed");
        ngx_kmp_cc_packet_free(ctx, pkt);
        return NGX_DECLINED;
    }

    pkt->cc_count = cc_count;
    pkt->pts = ctx->pts;

    ngx_kmp_cc_packet_insert(ctx, pkt);

    ctx->received_bytes += size;
    ctx->received_packets++;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_cc_process_sei_nal(ngx_kmp_cc_ctx_t *ctx,
    ngx_buf_chain_reader_ep_t *reader)
{
    u_char                     b;
    uint32_t                   payload_type;
    uint32_t                   payload_size;
    ngx_int_t                  rc;
    ngx_buf_chain_reader_ep_t  payload;

    while (reader->left >= 2) {

        payload_type = 0;
        do {
            if (ngx_buf_chain_reader_ep_read(reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                    "ngx_kmp_cc_process_sei_nal: read payload type failed");
                return NGX_DECLINED;
            }

            payload_type += b;
        } while (b == 0xff);

        payload_size = 0;
        do {
            if (ngx_buf_chain_reader_ep_read(reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                    "ngx_kmp_cc_process_sei_nal: read payload size failed");
                return NGX_DECLINED;
            }

            payload_size += b;
        } while (b == 0xff);

        payload = *reader;

        if (ngx_buf_chain_reader_ep_skip(reader, payload_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "ngx_kmp_cc_process_sei_nal: skip payload failed");
            return NGX_DECLINED;
        }

        if (payload_type != NGX_KMP_CC_SEI_USER_DATA_REGISTERED) {
            continue;
        }

        payload.left = payload_size;

        rc = ngx_kmp_cc_process_udr_sei(ctx, &payload);
        if (rc != NGX_OK && rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_cc_process_frame(ngx_kmp_cc_ctx_t *ctx, ngx_buf_chain_t *in)
{
    u_char                      nal_type;
    u_char                     *nalp;
    uint32_t                    size;
    ngx_int_t                   rc;
    ngx_buf_chain_t             reader;
    ngx_buf_chain_reader_ep_t   nal_reader;

    if (!ctx->avc_nal_bytes) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_cc_process_frame: avc_nal_bytes not set");
        return NGX_DECLINED;
    }

    reader = *in;

    nalp = (u_char *) &size + sizeof(size) - ctx->avc_nal_bytes;

    for ( ;; ) {

        /* nal unit */
        size = 0;

        if (ngx_buf_chain_reader_read(&reader, nalp, ctx->avc_nal_bytes)
            != NGX_OK)
        {
            break;
        }

        size = htonl(size);
        if (size <= 0) {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "ngx_kmp_cc_process_frame: zero size nal");
            return NGX_DECLINED;
        }

        if (ngx_buf_chain_reader_read(&reader, &nal_type, sizeof(nal_type))
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "ngx_kmp_cc_process_frame: read nal type failed");
            return NGX_DECLINED;
        }

        size--;

        ngx_buf_chain_reader_ep_init(&nal_reader, &reader);

        if (ngx_buf_chain_reader_skip(&reader, size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "ngx_kmp_cc_process_frame: "
                "failed to skip nal, size: %uD", size);
            return NGX_DECLINED;
        }

        if ((nal_type & 0x1f) != NGX_KMP_CC_AVC_NAL_SEI) {
            continue;
        }

        nal_reader.left = size;

        rc = ngx_kmp_cc_process_sei_nal(ctx, &nal_reader);
        if (rc != NGX_OK && rc != NGX_DECLINED) {
            return rc;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_cc_add_frame(ngx_kmp_cc_ctx_t *ctx, ngx_kmp_in_evt_frame_t *evt)
{
    ngx_int_t     rc;
    kmp_frame_t  *frame;

    frame = evt->frame;

    ctx->pts = frame->dts + frame->pts_delay;
    ctx->last_created = frame->created;

    if ((frame->flags & KMP_FRAME_FLAG_KEY) || ctx->pts > ctx->max_pts) {

        if (ngx_kmp_cc_packet_push_all(ctx) != NGX_OK) {
            return NGX_ABORT;
        }

        ctx->max_pts = ctx->pts;
        ctx->min_used = evt->data_head->data;
    }

    rc = ngx_kmp_cc_process_frame(ctx, evt->data_head);
    if (rc != NGX_OK && rc != NGX_DECLINED) {
        return rc;
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_cc_add_media_info(ngx_kmp_cc_ctx_t *ctx,
    ngx_kmp_in_evt_media_info_t *evt)
{
    kmp_media_info_t          *media_info;
    ngx_kmp_cc_avcc_config_t   avcc;

    media_info = evt->media_info;

    if (media_info->media_type != KMP_MEDIA_VIDEO) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_add_media_info: invalid media type %uD",
            media_info->media_type);
        ctx->error = NGX_KMP_CC_ERR_BAD_MEDIA_INFO;
        return NGX_ERROR;
    }

    if (media_info->codec_id != KMP_CODEC_VIDEO_H264) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_add_media_info: unsupported codec id %uD",
            media_info->codec_id);
        ctx->error = NGX_KMP_CC_ERR_BAD_MEDIA_INFO;
        return NGX_ERROR;
    }

    if (evt->extra_data_size < sizeof(avcc)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_add_media_info: invalid extra data size %uD",
            evt->extra_data_size);
        ctx->error = NGX_KMP_CC_ERR_BAD_MEDIA_INFO;
        return NGX_ERROR;
    }

    if (ngx_buf_chain_copy(&evt->extra_data, &avcc, sizeof(avcc)) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_cc_add_media_info: copy failed");
        ctx->error = NGX_KMP_CC_ERR_INTERNAL_ERROR;
        return NGX_ABORT;
    }

    ctx->avc_nal_bytes = (avcc.nula_length_size & 0x3) + 1;
    ctx->timescale = media_info->timescale;

    return NGX_OK;
}


void
ngx_kmp_cc_end_stream(ngx_kmp_cc_ctx_t *ctx)
{
    (void) ngx_kmp_cc_packet_push_all(ctx);
}


u_char *
ngx_kmp_cc_get_min_used(ngx_kmp_cc_ctx_t *ctx)
{
    return ctx->min_used;
}


static void
ngx_kmp_cc_708_demux_handler(void *data, uint8_t i_sid, vlc_tick_t tick,
    uint8_t *p_data, size_t i_data)
{
    ngx_kmp_cc_ctx_t      *ctx;
    ngx_kmp_cc_service_t  *svc;

    ctx = data;

    svc = ngx_kmp_cc_service_get_or_create(ctx,
        NGX_KMP_CC_708_BASE + i_sid - 1);
    if (svc == NULL) {
        return;
    }

    ngx_kmp_cc_service_push(svc, tick, p_data, i_data);
}


static ngx_int_t
ngx_kmp_cc_708_demux_create(ngx_kmp_cc_ctx_t *ctx)
{
    if (ctx->c708_demux != NULL) {
        return NGX_OK;
    }

    ctx->c708_demux = CEA708_DTVCC_Demuxer_New(ctx->log, ctx,
        ngx_kmp_cc_708_demux_handler);
    if (ctx->c708_demux == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_708_demux_create: new cea708 demux failed");
        ctx->error = NGX_KMP_CC_ERR_ALLOC_FAILED;
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_cc_service_parse_id(ngx_str_t *id)
{
    u_char     *p;
    ngx_int_t   num;

    switch (id->len) {

    case 3:
        /* cc1 - cc4 */
        p = id->data;
        if (p[0] != 'c' || p[1] != 'c' || p[2] < '1' || p[2] > '4') {
            return NGX_ERROR;
        }

        return NGX_KMP_CC_608_BASE + p[2] - '1';

    case 8:
    case 9:
        /* service1 - service63 */
        p = id->data;
        if (ngx_strncmp(p, "service", 7) != 0) {
            return NGX_ERROR;
        }

        p += 7;
        if (p[0] == '0') {      /* do not allow service01 */
            return NGX_ERROR;
        }

        num = ngx_atoi(p, id->len - 7);
        if (num < 1 || num > 63) {
            return NGX_ERROR;
        }

        return NGX_KMP_CC_708_BASE + num - 1;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_kmp_cc_service_from_json(ngx_kmp_cc_ctx_t *ctx, ngx_json_key_value_t *json,
    ngx_pool_t *temp_pool)
{
    ngx_int_t              id;
    ngx_int_t              rc;
    ngx_kmp_cc_service_t  *svc;

    id = ngx_kmp_cc_service_parse_id(&json->key);
    if (id == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_service_from_json: "
            "invalid service id \"%V\"", &json->key);
        ctx->error = NGX_KMP_CC_ERR_BAD_JSON;
        return NGX_ERROR;
    }

    if (ngx_kmp_cc_service_get(ctx, id) != NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_cc_service_from_json: "
            "duplicate service id \"%V\"", &json->key);
        ctx->error = NGX_KMP_CC_ERR_BAD_JSON;
        return NGX_ERROR;
    }

    svc = ngx_kmp_cc_service_create(ctx, id);
    if (svc == NULL) {
        return NGX_ABORT;
    }

    rc = ngx_kmp_cc_service_track_create(svc, json, temp_pool);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_kmp_cc_service_decoder_init(svc);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_cc_create(ngx_pool_t *pool, ngx_pool_t *temp_pool,
    ngx_kmp_cc_conf_t *conf, ngx_kmp_cc_input_t *input, ngx_json_value_t *json,
    ngx_kmp_out_track_conf_t *oconf, ngx_kmp_cc_ctx_t **pctx)
{
    ngx_int_t              rc;
    ngx_kmp_cc_ctx_t      *ctx;
    ngx_json_object_t     *obj;
    ngx_json_key_value_t  *cur;
    ngx_json_key_value_t  *last;

    switch (json->type) {

    case NGX_JSON_NULL:
        obj = NULL;
        break;

    case NGX_JSON_OBJECT:
        obj = &json->v.obj;
        if (obj->nelts <= 0) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_kmp_cc_create: object is empty");
            return NGX_ERROR;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_kmp_cc_create: invalid json type %d, expected object/null",
            json->type);
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_cc_create: alloc failed");
        return NGX_ABORT;
    }

    ctx->pool = pool;
    ctx->log = pool->log;
    ctx->conf = *conf;
    ctx->input = *input;
    ctx->oconf = oconf;

    ctx->packets_left = conf->max_pending_packets;
    ngx_queue_init(&ctx->pending);
    ngx_queue_init(&ctx->free);

    ngx_rbtree_init(&ctx->services.rbtree, &ctx->services.sentinel,
        ngx_rbtree_insert_value);
    ngx_queue_init(&ctx->services.queue);

    ngx_memset(ctx->c608_channel, 0xff, sizeof(ctx->c608_channel));

    if (json->type == NGX_JSON_OBJECT) {
        cur = obj->elts;

        for (last = cur + obj->nelts; cur < last; cur++) {

            if (cur->key.len == 1 && cur->key.data[0] == '*'
                && cur->value.type == NGX_JSON_NULL)
            {
                ctx->output_all = 1;
                continue;
            }

            rc = ngx_kmp_cc_service_from_json(ctx, cur, temp_pool);
            if (rc != NGX_OK) {
                ngx_kmp_cc_close(ctx, "create_failed");
                return rc;
            }
        }

    } else {
        ctx->output_all = 1;
    }

    *pctx = ctx;

    return NGX_OK;
}


void
ngx_kmp_cc_close(ngx_kmp_cc_ctx_t *ctx, char *reason)
{
    ngx_queue_t           *q;
    ngx_kmp_cc_service_t  *svc;

    if (ctx->error) {
        reason = ctx->error;
    }

    for (q = ngx_queue_head(&ctx->services.queue);
        q != ngx_queue_sentinel(&ctx->services.queue);
        q = ngx_queue_next(q))
    {
        svc = ngx_queue_data(q, ngx_kmp_cc_service_t, queue);

        ngx_kmp_cc_service_close(svc, reason);
    }

    if (ctx->c708_demux != NULL) {
        CEA708_DTVCC_Demuxer_Release(ctx->c708_demux);
    }
}
