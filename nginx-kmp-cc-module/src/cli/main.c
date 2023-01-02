#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_live_kmp.h>
#include <ngx_kmp_out_track_internal.h>
#include "../ngx_kmp_cc.h"

#include "../media/eia608.h"
#include "../media/cea708.h"


/* nginx stubs */

volatile ngx_cycle_t  *ngx_cycle;


void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
}

#if !(NGX_WIN32)
void
ngx_debug_point(void)
{
    ngx_abort();
}
#else
#define STDOUT_FILENO  1
#endif


static ngx_int_t
ngx_read_file_data(char *file, u_char **data, size_t *size)
{
    ssize_t          n;
    ngx_fd_t         fd;
    ngx_file_info_t  fi;

    fd = ngx_open_file(file, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    *size = (size_t) ngx_file_size(&fi);

    *data = ngx_alloc(*size, ngx_cycle->log);
    if (*data == NULL) {
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, *data, *size);
    if (n == -1) {
        return NGX_ERROR;
    }

    if ((size_t) n != *size) {
        return NGX_ERROR;
    }

    ngx_close_file(fd);

    return NGX_OK;
}


/* kmp_out_track create stubs */

ngx_kmp_out_track_t *
ngx_kmp_out_track_create(ngx_kmp_out_track_conf_t *conf,
    ngx_uint_t media_type)
{
    ngx_kmp_out_track_t  *track;

    track = ngx_alloc(sizeof(*track), ngx_cycle->log);

    track->pool = ngx_cycle->pool;

    return track;
}


ngx_int_t
ngx_kmp_out_track_write_media_info(ngx_kmp_out_track_t *track)
{
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_publish(ngx_kmp_out_track_t *track)
{
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_publish_json(ngx_kmp_out_track_t *track,
    ngx_json_object_t *obj, ngx_pool_t *temp_pool)
{
    return NGX_OK;
}


void
ngx_kmp_out_track_write_marker_start(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker)
{
}


ngx_int_t
ngx_kmp_out_track_write_marker_end(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker, void *data, size_t size)
{
    ngx_write_fd(STDOUT_FILENO, data, size);
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_write_frame_start(ngx_kmp_out_track_t *track)
{
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_write_frame_data(ngx_kmp_out_track_t *track, u_char *data,
    size_t size)
{
    ngx_write_fd(STDOUT_FILENO, data, size);
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_write_frame_end(ngx_kmp_out_track_t *track,
    kmp_frame_packet_t *frame)
{
    ngx_write_fd(STDOUT_FILENO, frame, sizeof(*frame));
    return NGX_OK;
}


void
ngx_kmp_out_track_detach(ngx_kmp_out_track_t *track, char *reason)
{
}


size_t
ngx_kmp_out_track_json_get_size(ngx_kmp_out_track_t *obj)
{
    return 0;
}


u_char *
ngx_kmp_out_track_json_write(u_char *p, ngx_kmp_out_track_t *obj)
{
    return p;
}


/* kmp parsing */

static void
handle_kmp_media_info(ngx_kmp_cc_ctx_t *ctx, kmp_packet_header_t *header,
    u_char *base)
{
    ngx_buf_chain_t               extra_data;
    kmp_media_info_t             *media_info;
    ngx_kmp_in_evt_media_info_t   evt;

    if (header->header_size != sizeof(*header) + sizeof(*media_info)) {
        return;
    }

    media_info = &evt.media_info;

    ngx_memcpy(media_info, base, sizeof(*media_info));
    base += sizeof(*media_info);

    if (media_info->timescale <= 0) {
        return;
    }

    extra_data.data = base;
    extra_data.size = header->data_size;
    extra_data.next = NULL;

    evt.extra_data = &extra_data;
    evt.extra_data_size = header->data_size;

    ngx_kmp_cc_add_media_info(ctx, &evt);
}


static void
handle_kmp_frame(ngx_kmp_cc_ctx_t *ctx, kmp_packet_header_t *header,
    u_char *base)
{
    kmp_frame_t             *frame;
    ngx_buf_chain_t          frame_data;
    ngx_kmp_in_evt_frame_t   evt;

    if (header->header_size != sizeof(*header) + sizeof(*frame)
        || header->data_size == 0)
    {
        return;
    }

    frame = &evt.frame;

    ngx_memcpy(frame, base, sizeof(*frame));
    base += sizeof(*frame);

    frame_data.data = base;
    frame_data.size = header->data_size;
    frame_data.next = NULL;

    evt.frame_id = 0;
    evt.size = header->data_size;
    evt.data_head = &frame_data;
    evt.data_tail = &frame_data;

    ngx_kmp_cc_add_frame(ctx, &evt);
}


static void
handle_kmp_packets(ngx_kmp_cc_ctx_t *ctx, u_char *base, size_t size)
{
    size_t               total_size;
    kmp_packet_header_t  header;

    while (size >= sizeof(header)) {
        ngx_memcpy(&header, base, sizeof(header));

        if (header.header_size < sizeof(header)
            || header.header_size > KMP_MAX_HEADER_SIZE)
        {
            return;
        }

        if (header.data_size > KMP_MAX_DATA_SIZE) {
            return;
        }

        total_size = header.header_size + header.data_size;
        if (size < total_size) {
            return;
        }

        switch (header.packet_type) {

        case KMP_PACKET_MEDIA_INFO:
            handle_kmp_media_info(ctx, &header, base + sizeof(header));
            break;

        case KMP_PACKET_FRAME:
            handle_kmp_frame(ctx, &header, base + sizeof(header));
            break;
        }

        base += total_size;
        size -= total_size;
    }
}


static int
parse_cc_kmp(u_char *data, size_t size)
{
    ngx_kmp_cc_ctx_t    *ctx;
    ngx_json_value_t     null_json;
    ngx_kmp_cc_conf_t    conf;
    ngx_kmp_cc_input_t   input;

    null_json.type = NGX_JSON_NULL;

    ngx_memzero(&conf, sizeof(conf));
    conf.max_pending_packets = 128;

    ngx_memzero(&input, sizeof(input));

    if (ngx_kmp_cc_create(ngx_cycle->pool, NULL, &conf, &input, &null_json,
        NULL, &ctx) != NGX_OK)
    {
        return 1;
    }

    handle_kmp_packets(ctx, data, size);

    ngx_kmp_cc_close(ctx, "");

    return 0;
}


/* 608 / 708 processing */

static enum {
    cc_start,
    cc_settings,
    cc_write,
    cc_end,
} cc_state;


static void cc_handler_start(void *priv)
{
    cc_state = cc_start;
}


static void cc_handler_add_setting(void *priv, ngx_str_t *str)
{
    if (cc_state == cc_start) {
        cc_state = cc_settings;

    } else {
        ngx_write_fd(STDOUT_FILENO, " ", 1);
    }

    ngx_write_fd(STDOUT_FILENO, str->data, str->len);
}


static void cc_handler_write(void *priv, void *buf, size_t len)
{
    if (cc_state == cc_settings) {
        ngx_write_fd(STDOUT_FILENO, "\n", 1);
    }

    cc_state = cc_write;

    ngx_write_fd(STDOUT_FILENO, buf, len);
}


static void cc_handler_end(void *priv, vlc_tick_t start, vlc_tick_t end)
{
    ngx_write_fd(STDOUT_FILENO, "\n\n", 2);

    cc_state = cc_end;
}


static subtitle_handler_t  cc_handler = {
    cc_handler_start,
    cc_handler_add_setting,
    cc_handler_write,
    cc_handler_end,
};


static int
parse_cc_608(u_char *data, size_t size)
{
    u_char      *p, *end;
    eia608_t    *ctx;
    vlc_tick_t   tick;

    ctx = Eia608New(ngx_cycle->log, 0, NULL, &cc_handler);
    if (ctx == NULL) {
        return 1;
    }

    tick = 0;

    for (p = data, end = data + size; p + 1 < end; p += 2) {
        Eia608Parse(ctx, tick++, p, 2);
    }

    Eia608Release(ctx);

    return 0;
}


static int
parse_cc_708(u_char *data, size_t size)
{
    cea708_t  *ctx;

    ctx = CEA708_Decoder_New(ngx_cycle->log, 0, NULL, &cc_handler);
    if (ctx == NULL) {
        return 1;
    }

    CEA708_Decoder_Push(ctx, 0, data, size);

    CEA708_Decoder_Release(ctx);

    return 0;
}


/* main */

int ngx_cdecl
main(int argc, char *const *argv)
{
    char         *format;
    size_t        size;
    u_char       *data;
    ngx_log_t     log;
    ngx_cycle_t   cycle;

    if (argc < 2) {
        return 1;
    }

    ngx_memzero(&cycle, sizeof(cycle));

    ngx_memzero(&log, sizeof(log));
    cycle.log = &log;

    ngx_time_update();

    cycle.pool = ngx_create_pool(1024, &log);
    if (cycle.pool == NULL) {
        return 1;
    }

    ngx_cycle = &cycle;

    if (ngx_read_file_data(argv[1], &data, &size) != NGX_OK) {
        return 1;
    }

    if (argc > 2) {
        format = argv[2];

        if (strcmp(format, "608") == 0) {
            return parse_cc_608(data, size);

        } else if (strcmp(format, "708") == 0) {
            return parse_cc_708(data, size);
        }
    }

    return parse_cc_kmp(data, size);
}
