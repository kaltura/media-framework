#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_live_kmp.h>

#include "ngx_ts_bit_stream.h"
#include "ngx_ts_opus.h"


#define NGX_TS_TIMESCALE         90000
#define NGX_TS_OPUS_SAMPLE_RATE  48000


static uint64_t  ngx_ts_opus_channel_layouts[] = {
    KMP_CH_LAYOUT_MONO,
    KMP_CH_LAYOUT_STEREO,
    KMP_CH_LAYOUT_SURROUND,
    KMP_CH_LAYOUT_QUAD,
    KMP_CH_LAYOUT_5POINT0_BACK,
    KMP_CH_LAYOUT_5POINT1_BACK,
    KMP_CH_LAYOUT_5POINT1|KMP_CH_BACK_CENTER,
    KMP_CH_LAYOUT_7POINT1,
};


static u_char  ngx_ts_opus_streams[] = {
    1, 1, 1, 2, 2, 3, 4, 4, 5,
};


static u_char  ngx_ts_opus_coupled_streams[] = {
    1, 0, 1, 1, 2, 2, 2, 3, 3
};


static u_char  ngx_ts_opus_channel_map[][8] = {
    { 0 },
    { 0, 1 },
    { 0, 2, 1 },
    { 0, 1, 2, 3 },
    { 0, 4, 1, 2, 3 },
    { 0, 4, 1, 2, 3, 5 },
    { 0, 4, 1, 2, 3, 5, 6 },
    { 0, 6, 1, 2, 3, 4, 5, 7 },
};


static uint32_t  ngx_ts_opus_frame_duration[] = {   /* 1/10 msec */
    100, 200, 400, 600,
    100, 200, 400, 600,
    100, 200, 400, 600,
    100, 200,
    100, 200,
    25, 50, 100, 200,
    25, 50, 100, 200,
    25, 50, 100, 200,
    25, 50, 100, 200,
};


ngx_int_t
ngx_ts_opus_get_channel_conf(ngx_log_t *log, ngx_str_t *es_info)
{
    u_char  *p, *end;
    u_char   tag, len;
    u_char   channel_conf;

    p = es_info->data;
    end = es_info->data + es_info->len;

    while (end - p >= 2) {
        tag = *p++;
        len = *p++;

        if (len > end - p) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_get_channel_conf: "
                "truncated descriptor, tag: 0x%uxD, len: %uD",
                (uint32_t) tag, (uint32_t) len);
            return NGX_ERROR;
        }

        switch (tag) {

        case 0x7f:  /* dvb extension */

            if (len < 2) {
                break;
            }

            if (p[0] != 0x80) { /* user defined */
                break;
            }

            channel_conf = p[1];
            if (channel_conf > 8) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_ts_opus_get_channel_conf: "
                    "unsupported channel config %uD", (uint32_t) channel_conf);
                return NGX_ERROR;
            }

            return channel_conf;
        }

        p += len;
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
        "ngx_ts_opus_get_channel_conf: missing channel config");
    return NGX_ERROR;
}


ngx_int_t
ngx_ts_opus_parse(u_char channel_conf, uint16_t pre_skip,
    ngx_ts_opus_params_t *params, ngx_str_t *extra_data)
{
    u_char  *p;
    u_char   channels;
    u_char   mapping_family;

    if (channel_conf > 8) {
        return NGX_ERROR;
    }

    channels = channel_conf ? channel_conf : 2;
    mapping_family = channel_conf ? (channels > 2) : 255;

    params->channels = channels;
    params->channel_layout = ngx_ts_opus_channel_layouts[channels - 1];
    params->sample_rate = NGX_TS_OPUS_SAMPLE_RATE;

    /* write the extra data (dOps box) */

    p = extra_data->data;

    *p++ = 0;                   /* version */
    *p++ = channels;
    ngx_ts_write_be16(p, pre_skip);
    ngx_ts_write_be32(p, NGX_TS_OPUS_SAMPLE_RATE);
    ngx_ts_write_be16(p, 0);    /* output gain */
    *p++ = mapping_family;

    if (mapping_family) {
        *p++ = ngx_ts_opus_streams[channel_conf];
        *p++ = ngx_ts_opus_coupled_streams[channel_conf];
        p = ngx_copy(p, ngx_ts_opus_channel_map[channels - 1], channels);
    }

    extra_data->len = p - extra_data->data;

    return NGX_OK;
}


static uint32_t
ngx_ts_opus_get_duration(ngx_ts_chain_reader_t *reader)
{
    u_char    toc, frames;
    uint32_t  frame_duration, duration;

    if (ngx_ts_chain_reader_read(reader, &toc, sizeof(toc)) != NGX_OK) {
        return 0;
    }

    switch (toc & 0x03) {

    case 1:
    case 2:
        frames = 2;
        break;

    case 3:
        if (ngx_ts_chain_reader_read(reader, &frames, sizeof(frames))
            != NGX_OK)
        {
            return 0;
        }

        frames &= 63;
        break;

    default:    /* 0 */
        frames = 1;
        break;
    }

    frame_duration = ngx_ts_opus_frame_duration[toc >> 3];

    duration = frames * frame_duration;
    if (duration > 1200) {
        return 0;
    }

    return duration * NGX_TS_TIMESCALE / 10000;
}


ngx_int_t
ngx_ts_opus_read_control_header(ngx_log_t *log, ngx_ts_chain_reader_t *reader,
    ngx_ts_opus_packet_header_t *hdr)
{
    u_char                 b;
    u_char                 buf[2];
    u_char                 flags;
    ngx_ts_chain_reader_t  save;

    if (ngx_ts_chain_reader_read(reader, &buf, 2) != NGX_OK) {
        return NGX_DONE;
    }

    /* control_header_prefix */

    if (buf[0] != 0x7f || (buf[1] & 0xe0) != 0xe0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_opus_read_control_header: invalid control_header_prefix");
        return NGX_ERROR;
    }

    flags = buf[1];

    /* payload_size */

    hdr->size = 0;

    for ( ;; ) {
        if (ngx_ts_chain_reader_read(reader, &b, sizeof(b)) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_read_control_header: read payload_size failed");
            return NGX_ERROR;
        }

        hdr->size += b;

        if (b != 0xff) {
            break;
        }
    }

    /* start_trim_flag */

    if (flags & 0x10) {
        if (ngx_ts_chain_reader_read(reader, &buf, 2) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_read_control_header: read start_trim failed");
            return NGX_ERROR;
        }

        hdr->start_trim = ((buf[0] << 8) | buf[1]) & 0x1fff;

    } else {
        hdr->start_trim = 0;
    }

    /* end_trim_flag */

    if (flags & 0x08) {
        if (ngx_ts_chain_reader_skip(reader, 2) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_read_control_header: read end_trim failed");
            return NGX_ERROR;
        }
    }

    /* control_extension_flag */

    if (flags & 0x04) {
        if (ngx_ts_chain_reader_read(reader, &b, sizeof(b)) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_read_control_header: "
                "read control_extension_length failed");
            return NGX_ERROR;
        }

        if (ngx_ts_chain_reader_skip(reader, b) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_opus_read_control_header: read reserved failed");
            return NGX_ERROR;
        }
    }

    save = *reader;

    hdr->duration = ngx_ts_opus_get_duration(reader);
    if (hdr->duration <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_opus_read_control_header: failed to get packet duration");
        return NGX_ERROR;
    }

    *reader = save;

    return NGX_OK;
}
