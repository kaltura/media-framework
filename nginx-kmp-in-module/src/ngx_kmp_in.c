#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_md5.h>
#include "ngx_kmp_in.h"

#include "ngx_kmp_in_json.h"


#define NGX_KMP_IN_OK                        200
#define NGX_KMP_IN_BAD_REQUEST               400
#define NGX_KMP_IN_REQUEST_TIME_OUT          408
#define NGX_KMP_IN_INTERNAL_SERVER_ERROR     500

#define NGX_KMP_IN_ISO8601_DATE_LEN          (sizeof("yyyy-mm-dd") - 1)


#if (nginx_version < 1013006)
size_t
ngx_kmp_in_strnlen(u_char *p, size_t n)
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


void
ngx_kmp_in_update_latency_stats(ngx_uint_t timescale,
    ngx_kmp_in_stats_latency_t *stats, int64_t from)
{
    int64_t      now;
    uint64_t     latency;
    ngx_time_t  *tp;

    tp = ngx_timeofday();
    now = (int64_t) tp->sec * timescale +
        (int64_t) tp->msec * timescale / 1000;

    if (now < from) {
        return;
    }

    latency = now - from;

    if (stats->min > latency || stats->count <= 0) {
        stats->min = latency;
    }

    if (stats->max < latency) {
        stats->max = latency;
    }

    stats->count++;
    stats->sum += latency;
}


ngx_int_t
ngx_kmp_in_parse_json_chain(ngx_pool_t *pool, ngx_buf_chain_t *chain,
    size_t size, ngx_json_value_t *json)
{
    u_char     *p, *str;
    u_char      error[128];
    ngx_int_t   rc;

    p = ngx_pnalloc(pool, size + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_json_parse_chain: alloc failed");
        return NGX_ABORT;
    }

    str = p;

    p = ngx_buf_chain_copy(&chain, p, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_json_parse_chain: copy failed");
        return NGX_ABORT;
    }

    *p = '\0';

    rc = ngx_json_parse(pool, str, json, error, sizeof(error));
    if (rc != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_parse_chain: parse failed %i, %s", rc, error);
        return rc == NGX_JSON_BAD_DATA ? NGX_ERROR : NGX_ABORT;
    }

    return NGX_OK;
}


static void
ngx_kmp_in_chain_md5_hex(u_char dst[32], ngx_buf_chain_t *chain)
{
    u_char     hash[16];
    ngx_md5_t  md5;

    ngx_md5_init(&md5);

    for (; chain; chain = chain->next) {
        ngx_md5_update(&md5, chain->data, chain->size);
    }

    ngx_md5_final(hash, &md5);
    ngx_hex_dump(dst, hash, sizeof(hash));
}


static void
ngx_kmp_in_cleanup(void *data)
{
    ngx_kmp_in_ctx_t  *ctx;

    ctx = data;

    if (ctx->dump_fd != NGX_INVALID_FILE) {
        ngx_close_file(ctx->dump_fd);
    }

    if (ctx->packet_data_last != NULL) {
        ctx->packet_data_last->next = NULL;

        ctx->free_chain_list(ctx->data, ctx->packet_data_first,
            ctx->packet_data_last);
    }

    /* detach from track */
    if (ctx->disconnected != NULL) {
        ctx->disconnected(ctx);
    }
}


static ngx_inline ngx_int_t
ngx_kmp_in_recv(ngx_connection_t *c, ngx_buf_t *b)
{
    ssize_t  n;

    n = c->recv(c, b->last, b->end - b->last);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_in_recv: recv failed");
        return NGX_KMP_IN_OK;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_kmp_in_recv: client closed connection");
        return NGX_KMP_IN_OK;
    }

    b->last += n;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_in_connect_data(ngx_kmp_in_ctx_t *ctx)
{
    ngx_int_t                       rc;
    ngx_buf_chain_t                *data;
    ngx_kmp_in_evt_connect_data_t   evt;

    if (ctx->connect_data == NULL) {
        return NGX_OK;
    }

    data = ctx->packet_data_first;

    if (ctx->packet_header.header_size > sizeof(kmp_connect_packet_t)) {

        if (ngx_buf_chain_skip(&data, ctx->packet_header.header_size -
            sizeof(kmp_connect_packet_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_kmp_in_connect_data: skip failed");
            return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
        }
    }

    evt.header = (void *) ctx->connection->buffer->pos;
    evt.data = data;

    rc = ctx->connect_data(ctx, &evt);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_ABORT:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_connect_data: connect_data handler returned abort");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;

    default:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_connect_data: connect_data handler failed");
        return NGX_KMP_IN_BAD_REQUEST;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_in_media_info(ngx_kmp_in_ctx_t *ctx)
{
    ngx_int_t                     rc;
    ngx_buf_chain_t              *data = ctx->packet_data_first;
    kmp_media_info_t              media_info;
    ngx_kmp_in_evt_media_info_t   evt;

    if (ctx->packet_header.header_size < sizeof(kmp_media_info_packet_t)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_in_media_info: invalid header size %uD",
            ctx->packet_header.header_size);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    if (ngx_buf_chain_copy(&data, &media_info, sizeof(media_info)) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_in_media_info: read header failed");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
    }

    if (media_info.timescale <= 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_in_media_info: invalid timescale %uD",
            media_info.timescale);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    if (ctx->packet_header.header_size > sizeof(kmp_media_info_packet_t)) {

        if (ngx_buf_chain_skip(&data, ctx->packet_header.header_size -
            sizeof(kmp_media_info_packet_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_kmp_in_media_info: skip failed");
            return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
        }
    }

    evt.media_info = &media_info;
    evt.extra_data = data;
    evt.extra_data_size = ctx->packet_header.data_size;

    rc = ctx->media_info(ctx->data, &evt);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_ABORT:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_media_info: add media info returned abort");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;

    default:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_media_info: add media info failed");
        return NGX_KMP_IN_BAD_REQUEST;
    }

    ctx->timescale = media_info.timescale;
    ctx->wait_key = media_info.media_type == KMP_MEDIA_VIDEO;
    return NGX_OK;
}


static ngx_int_t
ngx_kmp_in_frame(ngx_kmp_in_ctx_t *ctx)
{
    u_char                   data_md5[32];
    uint64_t                 frame_id;
    ngx_int_t                rc;
    kmp_frame_t              frame;
    ngx_buf_chain_t         *cur;
    ngx_buf_chain_t         *data;
    ngx_kmp_in_evt_frame_t   evt;

    /* get the frame metadata */
    if (ctx->packet_header.header_size < sizeof(kmp_frame_packet_t)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_kmp_in_frame: invalid header size %uD",
            ctx->packet_header.header_size);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    frame_id = ctx->cur_frame_id;

    if (ctx->skip_left > 0) {
        ctx->skip_left--;
        ctx->skipped.duplicate++;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
            "ngx_kmp_in_frame: skipping frame, cur: %uL, left: %uL",
            frame_id, ctx->skip_left);

        if (ctx->skip_left <= 0 && ctx->skip_wait_key) {
            ctx->wait_key = 0;
        }

        goto done;
    }

    if (ctx->timescale <= 0) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_in_frame: no media info, skipping frame");
        ctx->skipped.no_media_info++;
        goto done;
    }

    if (ctx->packet_header.data_size == 0) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
            "ngx_kmp_in_frame: skipping empty frame");
        ctx->skipped.empty++;
        goto done;
    }

    data = ctx->packet_data_first;
    if (ngx_buf_chain_copy(&data, &frame, sizeof(frame)) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_kmp_in_frame: read header failed");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
    }

    if (ctx->wait_key) {

        /* ignore frames that arrive before the first key */
        if (!(frame.flags & KMP_FRAME_FLAG_KEY)) {
            ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                "ngx_kmp_in_frame: "
                "skipping non-key frame, created: %L, dts: %L",
                frame.created, frame.dts);
            ctx->skipped.no_key++;
            goto done;
        }

        ctx->wait_key = 0;
    }

    if (ctx->packet_header.header_size > sizeof(kmp_frame_packet_t)) {

        if (ngx_buf_chain_skip(&data, ctx->packet_header.header_size -
            sizeof(kmp_frame_packet_t)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_kmp_in_frame: skip failed");
            return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
        }
    }

    if (ctx->conf.log_frames) {
        ngx_kmp_in_chain_md5_hex(data_md5, data);

        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "ngx_kmp_in_frame: id: %uL, created: %L, dts: %L, "
            "flags: 0x%uxD, ptsDelay: %uD, size: %uD, md5: %*s",
            frame_id, frame.created, frame.dts, frame.flags,
            frame.pts_delay, ctx->packet_header.data_size,
            (size_t) sizeof(data_md5), data_md5);

    } else {
        ngx_log_debug7(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
            "ngx_kmp_in_frame: track: %V, id: %uL, created: %L, "
            "size: %uD, dts: %L, flags: 0x%uxD, ptsDelay: %uD",
            &ctx->track_id, frame_id, frame.created,
            ctx->packet_header.data_size, frame.dts, frame.flags,
            frame.pts_delay);
    }

    /* update latency stats */
    ngx_kmp_in_update_latency_stats(ctx->timescale, &ctx->latency,
        frame.created);

    /* add the frame */
    frame.flags &= KMP_FRAME_FLAG_MASK;

    evt.frame_id = frame_id;
    evt.frame = &frame;

    evt.data_head = data;
    evt.data_tail = ctx->packet_data_last;
    evt.size = ctx->packet_header.data_size;

    rc = ctx->frame(ctx->data, &evt);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DONE:
        goto done;

    case NGX_ABORT:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_frame: add frame returned abort");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;

    default:
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_frame: add frame failed");
        return NGX_KMP_IN_BAD_REQUEST;
    }

    /* ownership of data .. packet_data_last chains passed to add handler */
    if (ctx->packet_data_first != data) {
        for (cur = ctx->packet_data_first; cur->next != data; cur = cur->next);

        cur->next = NULL;

        ctx->packet_data_last = cur;

    } else {
        ctx->packet_data_last = NULL;
    }

done:

    ctx->cur_frame_id++;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_in_process_buffer(ngx_kmp_in_ctx_t *ctx)
{
    size_t            size;
    size_t            buf_left;
    size_t            header_left;
    uint32_t          packet_type;
    ngx_int_t         rc;
    ngx_buf_t        *b;
    ngx_buf_chain_t  *part;

    b = &ctx->active_buf;

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
            packet_type = ctx->packet_header.packet_type;

            switch (packet_type) {

            case KMP_PACKET_CONNECT:
            case KMP_PACKET_MEDIA_INFO:
            case KMP_PACKET_FRAME:
            case KMP_PACKET_END_OF_STREAM:
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_kmp_in_process_buffer: "
                    "unknown kmp packet 0x%uxD", packet_type);
                return NGX_KMP_IN_BAD_REQUEST;
            }

            if (ctx->packet_header.header_size < sizeof(ctx->packet_header)
                || ctx->packet_header.header_size > KMP_MAX_HEADER_SIZE)
            {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_kmp_in_process_buffer: "
                    "invalid header size %uD, type: %*s",
                    ctx->packet_header.header_size,
                    (size_t) sizeof(packet_type), &packet_type);
                return NGX_KMP_IN_BAD_REQUEST;
            }

            if (ctx->packet_header.data_size > KMP_MAX_DATA_SIZE) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_kmp_in_process_buffer: "
                    "invalid data size %uD, type: %*s",
                    ctx->packet_header.data_size,
                    (size_t) sizeof(packet_type), &packet_type);
                return NGX_KMP_IN_BAD_REQUEST;
            }

            ctx->packet_left = ctx->packet_header.header_size +
                ctx->packet_header.data_size - sizeof(ctx->packet_header);
        }

        size = ngx_min(b->last - b->pos, ctx->packet_left);

        if (size > 0) {

            /* link packet data */
            if (ctx->packet_data_last != NULL
                && ctx->packet_data_last->data + ctx->packet_data_last->size
                == b->pos)
            {
                ctx->packet_data_last->size += size;

            } else {

                part = ctx->alloc_chain(ctx->data);
                if (part == NULL) {
                    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                        "ngx_kmp_in_process_buffer: alloc chain failed");
                    return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
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
                "ngx_kmp_in_process_buffer: packet left: %uD",
                ctx->packet_left);
            break;
        }

        /* terminate the data chain */
        if (ctx->packet_data_last != NULL) {
            ctx->packet_data_last->next = NULL;

        } else {
            ctx->packet_data_first = NULL;
        }

        packet_type = ctx->packet_header.packet_type;

        ngx_log_debug3(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
            "ngx_kmp_in_process_buffer: "
            "packet_type: 0x%uxD, header: %uD, data: %uD",
            packet_type, ctx->packet_header.header_size,
            ctx->packet_header.data_size);

        switch (packet_type) {

        case KMP_PACKET_CONNECT:
            rc = ngx_kmp_in_connect_data(ctx);
            break;

        case KMP_PACKET_MEDIA_INFO:
            rc = ngx_kmp_in_media_info(ctx);
            break;

        case KMP_PACKET_FRAME:
            rc = ngx_kmp_in_frame(ctx);
            break;

        case KMP_PACKET_END_OF_STREAM:
            ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                "ngx_kmp_in_process_buffer: "
                "got end of stream");
            ctx->end_stream(ctx->data);
            return NGX_KMP_IN_OK;

        default:
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                "ngx_kmp_in_process_buffer: "
                "unknown kmp packet 0x%uxD", packet_type);
            return NGX_KMP_IN_BAD_REQUEST;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_kmp_in_process_buffer: "
                "handler failed %i, type: %*s",
                rc, (size_t) sizeof(packet_type), &packet_type);
            return rc;
        }

        if (ctx->packet_data_last != NULL) {
            ctx->free_chain_list(ctx->data, ctx->packet_data_first,
                ctx->packet_data_last);

            ctx->packet_data_last = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_in_read_packets(ngx_kmp_in_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = ctx->connection;

    for ( ;; ) {

        b = &ctx->active_buf;
        if (b->last >= b->end) {

            rc = ctx->get_input_buf(ctx->data, b);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_in_read_packets: failed to get buffer");
                return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
            }
        }

        rc = ngx_kmp_in_recv(c, b);
        if (rc != NGX_OK) {

            if (rc != NGX_AGAIN) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                    "ngx_kmp_in_read_packets: recv failed");
            }

            return rc;
        }

        ctx->received_bytes += b->last - b->pos;

        if (ctx->dump_fd != NGX_INVALID_FILE) {
            if (ngx_write_fd(ctx->dump_fd, b->pos, b->last - b->pos)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
                    "ngx_kmp_in_read_packets: dump file write failed");
                ngx_close_file(ctx->dump_fd);
                ctx->dump_fd = NGX_INVALID_FILE;
            }
        }

        rc = ngx_kmp_in_process_buffer(ctx);
        if (rc != NGX_OK) {
            return rc;
        }
    }
}


ngx_int_t
ngx_kmp_in_write_handler(ngx_kmp_in_ctx_t *ctx)
{
    ssize_t            n, size;
    ngx_event_t       *wev;
    ngx_connection_t  *c;

    c = ctx->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
        "ngx_kmp_in_write_handler: called, writing: %uD",
        (uint32_t) ctx->writing);

    if (!ctx->writing) {
        return NGX_OK;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, NGX_ETIMEDOUT,
            "ngx_kmp_in_write_handler: timed out");
        return NGX_KMP_IN_OK;
    }

    for ( ;; ) {

        size = (u_char *) &ctx->ack_packet + sizeof(ctx->ack_packet) -
            ctx->ack_packet_pos;

        n = ngx_send(c, ctx->ack_packet_pos, size);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_kmp_in_write_handler: send failed");
            return NGX_KMP_IN_OK;
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
                    "ngx_kmp_in_write_handler: sending ack %uL",
                    ctx->acked_frame_id);
                ctx->ack_packet.frame_id = ctx->acked_frame_id;
                ctx->ack_packet_pos = (u_char *) &ctx->ack_packet;
                continue;
            }

            ctx->writing = 0;
        }

        break;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_kmp_in_write_handler: "
            "handle write event failed");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
    }

    if (!wev->timer_set && ctx->writing) {
        ngx_add_timer(wev, ctx->conf.send_timeout);
    }

    return NGX_OK;
}


void
ngx_kmp_in_ack_frames(ngx_kmp_in_ctx_t *ctx, uint64_t next_frame_id)
{
    ngx_event_t  *wev;

    if (next_frame_id <= ctx->acked_frame_id) {
        return;
    }

    ctx->acked_frame_id = next_frame_id;

    if (ctx->writing) {
        /* busy sending some other ack */
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "ngx_kmp_in_ack_frames: sending ack %uL", ctx->acked_frame_id);

    ctx->ack_packet.frame_id = ctx->acked_frame_id;
    ctx->ack_packet_pos = (u_char *) &ctx->ack_packet;
    ctx->writing = 1;

    wev = ctx->connection->write;
    ngx_post_event(wev, &ngx_posted_events);
}


static ngx_int_t
ngx_kmp_in_read_header(ngx_kmp_in_ctx_t *ctx)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_uint_t                   level;
    ngx_connection_t            *c;
    kmp_connect_packet_t        *header;
    ngx_kmp_in_evt_connected_t   evt;

    c = ctx->connection;

    /* read connect packet */
    b = c->buffer;
    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, sizeof(kmp_connect_packet_t));
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_kmp_in_read_header: create buf failed");
            return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
        }

        c->buffer = b;
    }

    rc = ngx_kmp_in_recv(c, b);
    if (rc != NGX_OK) {

        if (rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_kmp_in_read_header: recv failed");
        }

        return rc;
    }

    if (b->last - b->pos < (ssize_t) sizeof(*header)) {
        return NGX_AGAIN;
    }

    ctx->received_bytes = sizeof(*header);

    if (ctx->dump_fd != NGX_INVALID_FILE) {
        if (ngx_write_fd(ctx->dump_fd, b->pos, b->last - b->pos)
            == NGX_ERROR)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                "ngx_kmp_in_read_header: dump file write failed");
            ngx_close_file(ctx->dump_fd);
            ctx->dump_fd = NGX_INVALID_FILE;
        }
    }

    /* validate connect packet */
    header = (void *) b->pos;
    if (header->header.packet_type != KMP_PACKET_CONNECT) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_kmp_in_read_header: invalid packet type 0x%uxD",
            header->header.packet_type);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    if (header->header.header_size < sizeof(*header)
        || header->header.header_size > KMP_MAX_HEADER_SIZE)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_kmp_in_read_header: invalid header size %uD",
            header->header.header_size);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    if (header->header.data_size > KMP_MAX_DATA_SIZE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_kmp_in_read_header: invalid data size %uD",
            header->header.data_size);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    if (header->initial_frame_id >= KMP_INVALID_FRAME_ID) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_kmp_in_read_header: invalid initial frame id %uL",
            header->initial_frame_id);
        return NGX_KMP_IN_BAD_REQUEST;
    }

    /* send connected event */
    ngx_memzero(&evt, sizeof(evt));
    evt.header = header;

    rc = ctx->connected(ctx, &evt);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_in_read_header: event handler failed");
        return rc;
    }

    /* initialize parser */
    ctx->packet_header_pos = (u_char *) &ctx->packet_header;
    ctx->packet_left = header->header.header_size + header->header.data_size
        - sizeof(*header);
    ctx->packet_header = header->header;

    ctx->skip_left = evt.skip_count;
    ctx->skip_wait_key = evt.skip_wait_key;
    ctx->header_read = 1;

    if (ctx->packet_left <= 0) {
        rc = ngx_kmp_in_connect_data(ctx);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_kmp_in_read_header: "
                "handle connect data failed %i", rc);
            return rc;
        }
    }

    /* initialize sender */
    ctx->ack_packet.header.packet_type = KMP_PACKET_ACK_FRAMES;
    ctx->ack_packet.header.header_size = sizeof(ctx->ack_packet);
    ctx->cur_frame_id = header->initial_frame_id;
    ctx->acked_frame_id = header->initial_frame_id;

    level = evt.skip_count > 0 ? NGX_LOG_NOTICE : NGX_LOG_INFO;

    ngx_log_error(level, c->log, 0,
        "ngx_kmp_in_read_header: "
        "connected, initial_frame_id: %uL, skip: %uL, skip_wait_key: %uD",
        ctx->acked_frame_id, evt.skip_count, (uint32_t) evt.skip_wait_key);

    return NGX_OK;
}


ngx_int_t
ngx_kmp_in_read_handler(ngx_kmp_in_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = ctx->connection;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "ngx_kmp_in_read_handler: shutdown timeout");

        return NGX_KMP_IN_OK;
    }

    rev = c->read;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
            "ngx_kmp_in_read_handler: timed out");

        return NGX_KMP_IN_REQUEST_TIME_OUT;
    }

    if (!ctx->header_read) {
        rc = ngx_kmp_in_read_header(ctx);
        if (rc != NGX_OK) {

            if (rc == NGX_AGAIN) {
                goto again;
            }

            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_kmp_in_read_handler: read header failed %i", rc);
            return rc;
        }
    }

    rc = ngx_kmp_in_read_packets(ctx);
    if (rc == NGX_AGAIN) {
        goto again;
    }

    if (rc != NGX_KMP_IN_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_in_read_handler: read packets failed %i", rc);
    }

    return rc;

again:

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_kmp_in_read_handler: handle read event failed");
        return NGX_KMP_IN_INTERNAL_SERVER_ERROR;
    }

    if (ctx->conf.read_timeout) {
        ngx_add_timer(rev, ctx->conf.read_timeout);
    }

    return NGX_OK;
}


static ngx_fd_t
ngx_kmp_in_open_dump_file(ngx_kmp_in_ctx_t *ctx)
{
    ngx_fd_t            fd;
    ngx_str_t           name;
    ngx_kmp_in_conf_t  *conf;

    conf = &ctx->conf;
    if (conf->dump_folder.len == 0) {
        return NGX_INVALID_FILE;
    }

    name.len = conf->dump_folder.len + sizeof("/ngx_live_kmp_dump___.dat") +
        NGX_KMP_IN_ISO8601_DATE_LEN + NGX_INT64_LEN + NGX_ATOMIC_T_LEN;
    name.data = ngx_alloc(name.len, ctx->connection->log);
    if (name.data == NULL) {
        return NGX_INVALID_FILE;
    }

    ngx_sprintf(name.data, "%V/ngx_live_kmp_dump_%*s_%P_%uA.dat%Z",
        &conf->dump_folder, NGX_KMP_IN_ISO8601_DATE_LEN,
        ngx_cached_http_log_iso8601.data, ngx_pid, ctx->connection->number);

    fd = ngx_open_file((char *) name.data, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE,
        NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ctx->connection->log, ngx_errno,
            "ngx_kmp_in_open_dump_file: "
            ngx_open_file_n " \"%s\" failed", name.data);
        ngx_free(name.data);
        return NGX_INVALID_FILE;
    }

    ngx_free(name.data);
    return fd;
}


ngx_kmp_in_ctx_t *
ngx_kmp_in_create(ngx_connection_t *c, ngx_kmp_in_conf_t *conf)
{
    ngx_kmp_in_ctx_t    *ctx;
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(c->pool, sizeof(*ctx));
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_kmp_in_create: alloc failed");
        return NULL;
    }

    ctx = cln->data;

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->conf = *conf;
    ctx->connection = c;
    ctx->log = c->log;
    ctx->start_sec = ngx_time();

    /* get the address name with port */
    ctx->remote_addr.s.data = ctx->remote_addr_buf;
    ctx->remote_addr.s.len = ngx_sock_ntop(c->sockaddr,
        c->socklen, ctx->remote_addr_buf,
        NGX_SOCKADDR_STRLEN, 1);
    if (ctx->remote_addr.s.len == 0) {
        ctx->remote_addr.s = c->addr_text;
    }

    ngx_json_str_set_escape(&ctx->remote_addr);

    ctx->dump_fd = ngx_kmp_in_open_dump_file(ctx);

    cln->handler = ngx_kmp_in_cleanup;

    return ctx;
}


void
ngx_kmp_in_init_conf(ngx_kmp_in_conf_t *conf)
{
    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->log_frames = NGX_CONF_UNSET;
}


void
ngx_kmp_in_merge_conf(ngx_kmp_in_conf_t *prev, ngx_kmp_in_conf_t *conf)
{
    ngx_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 20 * 1000);

    ngx_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 10 * 1000);

    ngx_conf_merge_str_value(conf->dump_folder, prev->dump_folder, "");

    ngx_conf_merge_value(conf->log_frames, prev->log_frames, 0);
}
