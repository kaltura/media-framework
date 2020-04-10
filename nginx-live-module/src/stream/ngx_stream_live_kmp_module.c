#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_live_kmp.h>
#include "../ngx_live.h"
#include "../ngx_live_input_bufs.h"
#include "../ngx_live_segmenter.h"
#include "../ngx_live_media_info.h"


#define NGX_STREAM_ISO8601_DATE_LEN          (sizeof("yyyy-mm-dd") - 1)
#define NGX_STREAM_REQUEST_TIME_OUT          408


typedef struct {
    ngx_msec_t                read_timeout;
    ngx_msec_t                send_timeout;
    ngx_str_t                 dump_folder;
} ngx_stream_live_kmp_srv_conf_t;


typedef struct {
    ngx_pool_cleanup_t        cln;
    ngx_stream_session_t     *s;
    ngx_log_t                *log;
    ngx_live_track_t         *track;
    ngx_live_channel_t       *channel;
    u_char                    remote_addr_buf[NGX_SOCKADDR_STRLEN];

    ngx_buf_t                 active_buf;
    kmp_packet_header_t       packet_header;
    u_char                   *packet_header_pos;
    uint32_t                  packet_left;
    ngx_buf_chain_t          *packet_data_first;
    ngx_buf_chain_t          *packet_data_last;

    kmp_ack_frames_packet_t   ack_packet;
    u_char                   *ack_packet_pos;
    uint64_t                  acked_frame_id;

    ngx_fd_t                  dump_fd;

    unsigned                  got_media_info:1;
    unsigned                  wait_key:1;
} ngx_stream_live_kmp_ctx_t;


static void *ngx_stream_live_kmp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_live_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_live_kmp(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_live_kmp_commands[] = {

    { ngx_string("live_kmp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_live_kmp,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("live_kmp_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, read_timeout),
      NULL },

    { ngx_string("live_kmp_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("live_kmp_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, dump_folder),
      NULL },

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_live_kmp_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_live_kmp_create_srv_conf,      /* create server configuration */
    ngx_stream_live_kmp_merge_srv_conf        /* merge server configuration */
};

ngx_module_t  ngx_stream_live_kmp_module = {
    NGX_MODULE_V1,
    &ngx_stream_live_kmp_module_ctx,          /* module context */
    ngx_stream_live_kmp_commands,             /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (nginx_version < 1013006)
static size_t
ngx_strnlen(u_char *p, size_t n)
{
    size_t  i;

    for (i = 0; i < n; i++) {

        if (p[i] == '\0') {
            return i;
        }
    }

    return n;
}
#endif

static void
ngx_stream_live_kmp_free(void *data)
{
    ngx_stream_live_kmp_ctx_t  *ctx;

    ctx = data;

    if (ctx->dump_fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->dump_fd);
    }

    if (ctx->packet_data_last != NULL) {
        ctx->packet_data_last->next = NULL;

        ngx_live_channel_buf_chain_free_list(ctx->channel,
            ctx->packet_data_first, ctx->packet_data_last);
    }

    /* detach from track */
    ngx_memzero(&ctx->track->input, sizeof(ctx->track->input));
}

static void
ngx_stream_live_kmp_disconnect(ngx_live_track_t *track, ngx_uint_t rc)
{
    ngx_stream_finalize_session(track->input.data, rc);
}

static ngx_int_t
ngx_stream_live_kmp_recv(ngx_stream_session_t *s, ngx_buf_t *b)
{
    ngx_connection_t  *c = s->connection;
    ssize_t            n;

    n = c->recv(c, b->last, b->end - b->last);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_live_kmp_recv: recv failed");
        return NGX_STREAM_OK;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_stream_live_kmp_recv: client closed connection");
        return NGX_STREAM_OK;
    }

    b->last += n;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_live_kmp_media_info(ngx_stream_live_kmp_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_buf_chain_t   *data = ctx->packet_data_first;
    kmp_media_info_t   media_info;
    kmp_media_info_t  *media_info_ptr;

    if (ctx->packet_header.header_size < sizeof(kmp_media_info_packet_t)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_media_info: invalid header size %uD",
            ctx->packet_header.header_size);
        return NGX_STREAM_BAD_REQUEST;
    }

    media_info_ptr = ngx_buf_chain_read(&data, &media_info,
        sizeof(media_info));
    if (media_info_ptr == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_stream_live_kmp_media_info: read header failed");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    if (ctx->packet_header.header_size > sizeof(kmp_media_info_packet_t)) {

        if (ngx_buf_chain_skip(&data, ctx->packet_header.header_size -
            sizeof(kmp_media_info_packet_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_stream_live_kmp_media_info: skip failed");
            return NGX_STREAM_INTERNAL_SERVER_ERROR;
        }
    }

    if (media_info_ptr->media_type == KMP_MEDIA_AUDIO) {
        media_info_ptr->u.audio.padding = 0;
    }

    rc = ngx_live_add_media_info(ctx->track, media_info_ptr, data,
        ctx->packet_header.data_size);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_ABORT:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_media_info: push returned abort");
        ngx_live_channel_finalize(ctx->channel);
        return NGX_STREAM_INTERNAL_SERVER_ERROR;

    default:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_media_info: push failed");
        return NGX_STREAM_BAD_REQUEST;
    }

    ctx->got_media_info = 1;
    ctx->wait_key = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_stream_live_kmp_frame(ngx_stream_live_kmp_ctx_t *ctx)
{
    ngx_int_t         rc;
    kmp_frame_t       frame;
    kmp_frame_t      *frame_ptr;
    ngx_buf_chain_t  *cur;
    ngx_buf_chain_t  *data = ctx->packet_data_first;

    /* get the frame metadata */
    if (ctx->packet_header.header_size < sizeof(kmp_frame_packet_t)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_frame: invalid header size %uD",
            ctx->packet_header.header_size);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (!ctx->got_media_info) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_frame: no media info, skipping frame");
        return NGX_OK;
    }

    if (ctx->packet_header.data_size == 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_frame: skipping empty frame");
        return NGX_OK;
    }

    frame_ptr = ngx_buf_chain_read(&data, &frame, sizeof(frame));
    if (frame_ptr == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_stream_live_kmp_frame: read header failed");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_STREAM, &ctx->track->log, 0,
        "ngx_stream_live_kmp_frame: track: %V, created: %L, size: %uD, "
        "dts: %L, flags: 0x%uxD, ptsDelay: %uD",
        &ctx->track->sn.str, frame_ptr->created, ctx->packet_header.data_size,
        frame_ptr->dts, frame_ptr->flags, frame_ptr->pts_delay);

    if (ctx->wait_key) {

        /* ignore frames that arrive before the first key */
        if (ctx->track->media_type == KMP_MEDIA_VIDEO &&
            (frame_ptr->flags & KMP_FRAME_FLAG_KEY) == 0)
        {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_live_kmp_frame: "
                "skipping non-key frame, created: %L, dts: %L",
                frame_ptr->created, frame_ptr->dts);
            return NGX_OK;
        }

        ctx->wait_key = 0;
    }

    if (ctx->packet_header.header_size > sizeof(kmp_frame_packet_t)) {

        if (ngx_buf_chain_skip(&data, ctx->packet_header.header_size -
            sizeof(kmp_frame_packet_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_stream_live_kmp_frame: skip failed");
            return NGX_STREAM_INTERNAL_SERVER_ERROR;
        }
    }

    /* add the frame */
    frame_ptr->flags &= KMP_FRAME_FLAG_MASK;

    rc = ngx_live_add_frame(ctx->track, frame_ptr, data, ctx->packet_data_last,
        ctx->packet_header.data_size);
    switch (rc) {

    case NGX_DONE:
        return NGX_OK;

    case NGX_OK:
        break;

    case NGX_ABORT:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_frame: add frame returned abort");
        ngx_live_channel_finalize(ctx->channel);
        return NGX_STREAM_INTERNAL_SERVER_ERROR;

    default:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_frame: add frame failed");
        return NGX_STREAM_BAD_REQUEST;
    }

    /* ownership of data .. packet_data_last chains passed to add handler */
    if (ctx->packet_data_first != data) {
        for (cur = ctx->packet_data_first; cur->next != data; cur = cur->next);

        cur->next = NULL;

        ctx->packet_data_last = cur;

    } else {
        ctx->packet_data_last = NULL;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_live_kmp_process_buffer(ngx_stream_live_kmp_ctx_t *ctx)
{
    size_t            size;
    size_t            buf_left;
    size_t            header_left;
    ngx_int_t         rc;
    ngx_buf_t        *b = &ctx->active_buf;
    ngx_buf_chain_t  *part;

    while (b->pos < b->last) {

        if (ctx->packet_left <= 0) {

            /* read packet header */
            header_left = (u_char *) &ctx->packet_header +
                sizeof(ctx->packet_header) - ctx->packet_header_pos;

            buf_left = b->last - b->pos;

            if (buf_left < header_left) {
                ctx->packet_header_pos = ngx_copy(ctx->packet_header_pos,
                    b->pos, buf_left);
                b->pos = b->last;
                break;
            }

            ngx_memcpy(ctx->packet_header_pos, b->pos, header_left);
            b->pos += header_left;

            ctx->packet_header_pos = (u_char *) &ctx->packet_header;

            /* validate the packet header */
            switch (ctx->packet_header.packet_type) {

            case KMP_PACKET_CONNECT:
            case KMP_PACKET_MEDIA_INFO:
            case KMP_PACKET_FRAME:
            case KMP_PACKET_END_OF_STREAM:
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_stream_live_kmp_process_buffer: "
                    "unknown kmp packet 0x%uxD",
                    ctx->packet_header.packet_type);
                return NGX_STREAM_BAD_REQUEST;
            }

            if (ctx->packet_header.header_size < sizeof(ctx->packet_header) ||
                ctx->packet_header.header_size > KMP_MAX_HEADER_SIZE) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_stream_live_kmp_process_buffer: "
                    "invalid header size %uD", ctx->packet_header.header_size);
                return NGX_STREAM_BAD_REQUEST;
            }

            if (ctx->packet_header.data_size > KMP_MAX_DATA_SIZE) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_stream_live_kmp_process_buffer: "
                    "invalid data size %uD", ctx->packet_header.data_size);
                return NGX_STREAM_BAD_REQUEST;
            }

            ctx->packet_left = ctx->packet_header.header_size +
                ctx->packet_header.data_size - sizeof(ctx->packet_header);
        }

        size = ngx_min(b->last - b->pos, ctx->packet_left);

        if (size > 0) {

            /* link packet data */
            if (ctx->packet_data_last != NULL &&
                ctx->packet_data_last->data + ctx->packet_data_last->size
                == b->pos)
            {
                ctx->packet_data_last->size += size;

            } else {

                part = ngx_live_channel_buf_chain_alloc(ctx->channel);
                if (part == NULL) {
                    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                        "ngx_stream_live_kmp_process_buffer: "
                        "alloc chain failed");
                    ngx_live_channel_finalize(ctx->channel);
                    return NGX_STREAM_INTERNAL_SERVER_ERROR;
                }

                part->data = b->pos;
                part->size = size;

                if (ctx->packet_data_last != NULL) {
                    ctx->packet_data_last->next = part;

                } else {
                    ctx->packet_data_first = part;
                }

                ctx->packet_data_last = part;
            }

            b->pos += size;
            ctx->packet_left -= size;
        }

        if (ctx->packet_left > 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                "ngx_stream_live_kmp_process_buffer: packet left: %uD",
                ctx->packet_left);
            break;
        }

        /* terminate the data chain */
        if (ctx->packet_data_last != NULL) {
            ctx->packet_data_last->next = NULL;

        } else {
            ctx->packet_data_first = NULL;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
            "ngx_stream_live_kmp_process_buffer: "
            "packet_type: 0x%uxD, header: %uD, data: %uD",
            ctx->packet_header.packet_type, ctx->packet_header.header_size,
            ctx->packet_header.data_size);

        switch (ctx->packet_header.packet_type) {

        case KMP_PACKET_CONNECT:
            break;

        case KMP_PACKET_MEDIA_INFO:
            rc = ngx_stream_live_kmp_media_info(ctx);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_stream_live_kmp_process_buffer: "
                    "handle media info failed %i", rc);
                return rc;
            }
            break;

        case KMP_PACKET_FRAME:
            rc = ngx_stream_live_kmp_frame(ctx);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_stream_live_kmp_process_buffer: "
                    "handle frame failed %i", rc);
                return rc;
            }
            break;

        case KMP_PACKET_END_OF_STREAM:
            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                "ngx_stream_live_kmp_process_buffer: "
                "got end of stream");
            ngx_live_end_of_stream(ctx->track);
            return NGX_STREAM_OK;

        default:
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_stream_live_kmp_process_buffer: "
                "unknown kmp packet 0x%uxD", ctx->packet_header.packet_type);
            return NGX_STREAM_BAD_REQUEST;
        }

        if (ctx->packet_data_last != NULL) {
            ngx_live_channel_buf_chain_free_list(ctx->channel,
                ctx->packet_data_first, ctx->packet_data_last);

            ctx->packet_data_last = NULL;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_live_kmp_read_packets(ngx_stream_live_kmp_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_stream_session_t  *s = ctx->s;

    for ( ;; ) {

        b = &ctx->active_buf;
        if (b->last >= b->end) {

            rc = ngx_live_input_bufs_get(ctx->track, b);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_stream_live_kmp_read_packets: failed to get buffer");
                ngx_live_channel_finalize(ctx->channel);
                return NGX_STREAM_INTERNAL_SERVER_ERROR;
            }
        }

        rc = ngx_stream_live_kmp_recv(s, b);
        if (rc != NGX_OK) {

            if (rc != NGX_AGAIN) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_stream_live_kmp_read_packets: recv failed");
            }
            return rc;
        }

        ctx->track->input.received_bytes += b->last - b->pos;

        if (ctx->dump_fd != NGX_INVALID_FILE) {
            if (ngx_write_fd(ctx->dump_fd, b->pos, b->last - b->pos)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
                    "ngx_stream_live_kmp_read_packets: "
                    "dump file write failed");
                ngx_close_file(ctx->dump_fd);
                ctx->dump_fd = NGX_INVALID_FILE;
            }
        }

        rc = ngx_stream_live_kmp_process_buffer(ctx);
        if (rc != NGX_OK) {
            return rc;
        }
    }
}

static void
ngx_stream_live_kmp_dummy_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, wev->log, 0,
        "ngx_stream_live_kmp_dummy_handler: called");
}

static void
ngx_stream_live_kmp_write_handler(ngx_event_t *wev)
{
    ssize_t                          n, size;
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_live_kmp_ctx_t       *ctx;
    ngx_stream_live_kmp_srv_conf_t  *lscf;

    c = wev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
        "ngx_stream_live_kmp_write_handler: called");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, NGX_ETIMEDOUT,
            "ngx_stream_live_kmp_write_handler: timed out");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    for ( ;; ) {

        size = (u_char *) &ctx->ack_packet + sizeof(ctx->ack_packet) -
            ctx->ack_packet_pos;

        n = ngx_send(c, ctx->ack_packet_pos, size);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_live_kmp_write_handler: send failed");
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return;
        }

        if (n > 0) {

            if (n < size) {
                ctx->ack_packet_pos += n;
                break;
            }

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            if (ctx->ack_packet.frame_id != ctx->acked_frame_id) {
                /* got another ack while sending */
                ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                    "ngx_stream_live_kmp_write_handler: sending ack %uL",
                    ctx->acked_frame_id);
                ctx->ack_packet.frame_id = ctx->acked_frame_id;
                ctx->ack_packet_pos = (u_char *) &ctx->ack_packet;
                continue;
            }

            wev->handler = ngx_stream_live_kmp_dummy_handler;
        }

        break;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_write_handler: "
            "handle write event failed");
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }

    if (!wev->timer_set && wev->handler != ngx_stream_live_kmp_dummy_handler) {
        lscf = ngx_stream_get_module_srv_conf(s,
            ngx_stream_live_kmp_module);

        ngx_add_timer(wev, lscf->send_timeout);
    }
}

static void
ngx_stream_live_kmp_ack_frames(ngx_live_track_t *track, ngx_uint_t count)
{
    ngx_event_t                *wev;
    ngx_stream_session_t       *s = track->input.data;
    ngx_stream_live_kmp_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    ctx->acked_frame_id += count;

    s = ctx->s;
    wev = s->connection->write;
    if (wev->handler != ngx_stream_live_kmp_dummy_handler) {
        /* busy sending some other ack */
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "ngx_stream_live_kmp_ack_frames: sending ack %uL",
        ctx->acked_frame_id);
    ctx->ack_packet.frame_id = ctx->acked_frame_id;
    ctx->ack_packet_pos = (u_char *) &ctx->ack_packet;
    wev->handler = ngx_stream_live_kmp_write_handler;

    ngx_stream_live_kmp_write_handler(wev);
}

static ngx_fd_t
ngx_stream_live_kmp_open_dump_file(ngx_stream_session_t *s)
{
    ngx_fd_t                         fd;
    ngx_str_t                        name;
    ngx_stream_live_kmp_srv_conf_t  *lscf;

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_live_kmp_module);

    if (lscf->dump_folder.len == 0) {
        return NGX_INVALID_FILE;
    }

    name.len = lscf->dump_folder.len + sizeof("/ngx_live_kmp_dump___.dat") +
        NGX_STREAM_ISO8601_DATE_LEN + NGX_INT64_LEN + NGX_ATOMIC_T_LEN;
    name.data = ngx_alloc(name.len, s->connection->log);
    if (name.data == NULL) {
        return NGX_INVALID_FILE;
    }

    ngx_sprintf(name.data, "%V/ngx_live_kmp_dump_%*s_%P_%uA.dat%Z",
        &lscf->dump_folder, NGX_STREAM_ISO8601_DATE_LEN,
        ngx_cached_http_log_iso8601.data, ngx_pid, s->connection->number);

    fd = ngx_open_file((char *) name.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
        NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
            "ngx_stream_live_kmp_open_dump_file: "
            ngx_open_file_n " \"%s\" failed", name.data);
        ngx_free(name.data);
        return NGX_INVALID_FILE;
    }

    ngx_free(name.data);
    return fd;
}

static u_char *
ngx_stream_live_kmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_live_channel_t         *channel;
    ngx_stream_session_t       *s;
    ngx_stream_live_kmp_ctx_t  *ctx;

    s = log->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    p = buf;

    if (ctx != NULL) {
        channel = ctx->channel;

        p = ngx_snprintf(buf, len, ", nsi: %uD, track: %V, channel: %V",
            channel->next_segment_index, &ctx->track->sn.str,
            &channel->sn.str);
        len -= p - buf;
        buf = p;
    }

    return p;
}

static ngx_int_t
ngx_stream_live_kmp_read_header(ngx_event_t *rev)
{
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_str_t                   track_id;
    ngx_str_t                   channel_id;
    ngx_connection_t           *c;
    ngx_live_track_t           *track;
    ngx_live_channel_t         *channel;
    ngx_stream_session_t       *s;
    kmp_connect_packet_t       *header;
    ngx_stream_live_kmp_ctx_t  *ctx;

    c = rev->data;
    s = c->data;
    c = s->connection;

    /* read connect packet */
    b = c->buffer;
    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, sizeof(kmp_connect_packet_t));
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_stream_live_kmp_read_header: create buf failed");
            return NGX_STREAM_INTERNAL_SERVER_ERROR;
        }

        c->buffer = b;
    }

    rc = ngx_stream_live_kmp_recv(s, b);
    if (rc != NGX_OK) {

        if (rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_stream_live_kmp_read_header: recv failed");
        }

        return rc;
    }

    if (b->last - b->pos < (ssize_t) sizeof(*header)) {
        return NGX_AGAIN;
    }

    /* validate connect packet */
    header = (void *) b->pos;
    if (header->header.packet_type != KMP_PACKET_CONNECT) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: invalid packet type 0x%uxD",
            header->header.packet_type);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (header->header.header_size < sizeof(*header) ||
        header->header.header_size > KMP_MAX_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: invalid header size %uD",
            header->header.header_size);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (header->header.data_size > KMP_MAX_DATA_SIZE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: invalid data size %uD",
            header->header.data_size);
        return NGX_STREAM_BAD_REQUEST;
    }

    /* get the channel */
    channel_id.data = header->channel_id;
    channel_id.len = ngx_strnlen(channel_id.data, sizeof(header->channel_id));

    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: unknown channel \"%V\"",
            &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    /* get the track */
    track_id.data = header->track_id;
    track_id.len = ngx_strnlen(track_id.data, sizeof(header->track_id));
    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (track->type == ngx_live_track_type_filler) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: "
            "track \"%V\" in channel \"%V\" is a filler track",
            &track_id, &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (track->input.data != NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_header: "
            "track \"%V\" in channel \"%V\" already connected to %uA",
            &track_id, &channel_id, track->input.connection);
        return NGX_STREAM_BAD_REQUEST;
    }

    /* allocate context */
    ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_live_kmp_read_header: alloc ctx failed");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    /* initialize the context */
    ctx->cln.data = ctx;
    ctx->cln.handler = ngx_stream_live_kmp_free;

    ctx->cln.next = c->pool->cleanup;
    c->pool->cleanup = &ctx->cln;

    ctx->s = s;
    ctx->track = track;
    ctx->channel = track->channel;
    ctx->log = c->log;

    ctx->packet_header_pos = (u_char *) &ctx->packet_header;
    ctx->packet_left = header->header.header_size + header->header.data_size -
        sizeof(*header);
    ctx->packet_header.packet_type = KMP_PACKET_CONNECT;

    ctx->ack_packet.header.packet_type = KMP_PACKET_ACK_FRAMES;
    ctx->ack_packet.header.header_size = sizeof(ctx->ack_packet);
    ctx->acked_frame_id = header->initial_frame_id;

    ctx->dump_fd = ngx_stream_live_kmp_open_dump_file(s);
    if (ctx->dump_fd != NGX_INVALID_FILE) {
        if (ngx_write_fd(ctx->dump_fd, b->pos, b->last - b->pos)
            == NGX_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                "ngx_stream_live_kmp_read_header: dump file write failed");
            ngx_close_file(ctx->dump_fd);
            ctx->dump_fd = NGX_INVALID_FILE;
        }
    }

    /* attach to track */
    track->input.ack_frames = ngx_stream_live_kmp_ack_frames;
    track->input.disconnect = ngx_stream_live_kmp_disconnect;
    track->input.data = s;

    track->input.connection = c->number;
    track->input.start_msec = ngx_current_msec;
    track->input.received_bytes = sizeof(*header);

    /* get the address name with port */
    track->input.remote_addr.data = ctx->remote_addr_buf;
    track->input.remote_addr.len = ngx_sock_ntop(c->sockaddr,
        c->socklen, ctx->remote_addr_buf,
        NGX_SOCKADDR_STRLEN, 1);
    if (track->input.remote_addr.len == 0) {
        track->input.remote_addr = c->addr_text;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_live_kmp_module);

    rc = ngx_live_core_track_event(track, NGX_LIVE_EVENT_TRACK_CONNECT, NULL);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_live_kmp_read_header: failed to send connect event");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "ngx_stream_live_kmp_read_header: connected, initial frame id: %uL",
        ctx->acked_frame_id);

    return NGX_OK;
}

static void
ngx_stream_live_kmp_read_handler(ngx_event_t *rev)
{
    ngx_int_t                        rc;
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_live_kmp_ctx_t       *ctx;
    ngx_stream_live_kmp_srv_conf_t  *lscf;

    c = rev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_stream_live_kmp_read_handler: shutdown timeout");

        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
            "ngx_stream_live_kmp_read_handler: timed out");

        ngx_stream_finalize_session(s, NGX_STREAM_REQUEST_TIME_OUT);
        return;
    }

    if (ctx == NULL) {

        rc = ngx_stream_live_kmp_read_header(rev);
        if (rc != NGX_OK) {

            if (rc == NGX_AGAIN) {
                goto again;
            }

            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_stream_live_kmp_read_handler: read header failed %i", rc);
            ngx_stream_finalize_session(s, rc);
            return;
        }

        ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);
    }

    rc = ngx_stream_live_kmp_read_packets(ctx);
    if (rc == NGX_AGAIN) {
        goto again;
    }

    if (rc != NGX_STREAM_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_live_kmp_read_handler: read packets failed %i", rc);
    }
    ngx_stream_finalize_session(s, rc);
    return;

again:

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_stream_live_kmp_read_handler: handle read event failed");
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_live_kmp_module);

    if (lscf->read_timeout) {
        ngx_add_timer(rev, lscf->read_timeout);
    }
}


static void
ngx_stream_live_kmp_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c;

    c = s->connection;

    s->log_handler = ngx_stream_live_kmp_log_error;

    c->read->handler = ngx_stream_live_kmp_read_handler;
    c->write->handler = ngx_stream_live_kmp_dummy_handler;

    ngx_stream_live_kmp_read_handler(c->read);
}

static void *
ngx_stream_live_kmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_live_kmp_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_live_kmp_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_stream_live_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_live_kmp_srv_conf_t  *prev = parent;
    ngx_stream_live_kmp_srv_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 20 * 1000);

    ngx_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 10 * 1000);

    ngx_conf_merge_str_value(conf->dump_folder, prev->dump_folder, "");

    return NGX_CONF_OK;
}

static char *
ngx_stream_live_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_stream_live_kmp_handler;

    return NGX_CONF_OK;
}
