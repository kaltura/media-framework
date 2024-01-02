#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_kmp.h>
#include "ngx_ts_bit_stream.h"
#include "ngx_ts_ac3.h"


#define NGX_TS_AC3_HEADER_SIZE  7


static uint32_t  ngx_ts_ac3_sample_rates[] = {
    48000, 44100, 32000, 0
};


static uint16_t  ngx_ts_ac3_bitrates[] = {
    32, 40, 48, 56, 64, 80, 96, 112,
    128, 160, 192, 224, 256, 320, 384, 448,
    512, 576, 640
};


static u_char    ngx_ts_ac3_channels[] = {
    2, 1, 2, 3, 3, 4, 4, 5
};


static uint16_t  ngx_ts_ac3_channel_layouts[] = {
    KMP_CH_LAYOUT_STEREO,
    KMP_CH_LAYOUT_MONO,
    KMP_CH_LAYOUT_STEREO,
    KMP_CH_LAYOUT_SURROUND,
    KMP_CH_LAYOUT_2_1,
    KMP_CH_LAYOUT_4POINT0,
    KMP_CH_LAYOUT_2_2,
    KMP_CH_LAYOUT_5POINT0
};


static u_char    ngx_ts_ac3_eac3_blocks[] = {
    1, 2, 3, 6
};


static ngx_int_t
ngx_ts_ac3_parse(ngx_log_t *log, ngx_ts_bit_stream_t *br,
    ngx_ts_ac3_params_t *params, ngx_str_t *extra_data)
{
    u_char               lfe_on;
    u_char               sr_shift;
    u_char               bitstream_id;
    u_char               channel_mode;
    u_char               bit_rate_code;
    u_char               bitstream_mode;
    u_char               frame_size_code;
    u_char               sample_rate_code;
    uint32_t             sample_rate;
    ngx_ts_bit_stream_t  bw;

    /* parse */

    ngx_ts_bit_stream_read(br, 16);                         /* crc1 */

    sample_rate_code = ngx_ts_bit_stream_read(br, 2);       /* fscod */
    sample_rate = ngx_ts_ac3_sample_rates[sample_rate_code];
    if (sample_rate == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_parse: invalid sample rate code");
        return NGX_ERROR;
    }

    frame_size_code = ngx_ts_bit_stream_read(br, 6);        /* frmsizecod */

    bit_rate_code = frame_size_code >> 1;
    if (bit_rate_code >= sizeof(ngx_ts_ac3_bitrates)
        / sizeof(ngx_ts_ac3_bitrates[0]))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_parse: invalid frame size code %uD",
            (uint32_t) frame_size_code);
        return NGX_ERROR;
    }

    bitstream_id = ngx_ts_bit_stream_read(br, 5);           /* bsid */
    bitstream_mode = ngx_ts_bit_stream_read(br, 3);         /* bsmod */
    channel_mode = ngx_ts_bit_stream_read(br, 3);           /* acmod */

    if ((channel_mode & 0x1) && channel_mode != 0x1) {
        ngx_ts_bit_stream_read(br, 2);                      /* cmixlev */
    }

    if (channel_mode & 0x4) {
        ngx_ts_bit_stream_read(br, 2);                      /* surmixlev */
    }

    if (channel_mode == 0x2) {
        ngx_ts_bit_stream_read(br, 2);                      /* dsurmod */
    }

    lfe_on = ngx_ts_bit_stream_read_one(br);                /* lfeon */

    if (br->err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_parse: input stream overflow");
        return NGX_ERROR;
    }

    /* set the params */

    sr_shift = bitstream_id > 8 ? bitstream_id - 8 : 0;

    params->bitrate = (ngx_ts_ac3_bitrates[bit_rate_code] * 1000) >> sr_shift;
    params->channels = ngx_ts_ac3_channels[channel_mode] + lfe_on;
    params->bits_per_sample = 16;
    params->sample_rate = sample_rate >> sr_shift;

    params->channel_layout = ngx_ts_ac3_channel_layouts[channel_mode];
    if (lfe_on) {
        params->channel_layout |= KMP_CH_LOW_FREQUENCY;
    }

    /* write the extra data (dac3 box) */

    ngx_ts_bit_stream_init(&bw, extra_data->data, extra_data->len);

    ngx_ts_bit_stream_write(&bw, 2, sample_rate_code);      /* fscod */
    ngx_ts_bit_stream_write(&bw, 5, bitstream_id);          /* bsid */
    ngx_ts_bit_stream_write(&bw, 3, bitstream_mode);        /* bsmod */
    ngx_ts_bit_stream_write(&bw, 3, channel_mode);          /* acmod */
    ngx_ts_bit_stream_write_one(&bw, lfe_on);               /* lfeon */
    ngx_ts_bit_stream_write(&bw, 5, bit_rate_code);         /* bit_rate_code */
    ngx_ts_bit_stream_write(&bw, 5, 0);                     /* reserved */

    if (bw.err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_parse: output stream overflow");
        return NGX_ERROR;
    }

    extra_data->len = ngx_ts_bit_stream_size(&bw, extra_data->data);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_ec3_parse(ngx_log_t *log, ngx_ts_bit_stream_t *br,
    ngx_ts_ac3_params_t *params, ngx_str_t *extra_data)
{
    u_char               frame_type;
    u_char               sample_rate_code;
    u_char               sample_rate_code2;
    u_char               num_blocks_code;
    u_char               channel_mode;
    u_char               lfe_on;
    u_char               bitstream_id;
    uint16_t             data_rate;
    uint16_t             frame_size;
    uint32_t             num_blocks;
    ngx_ts_bit_stream_t  bw;

    /* parse */

    frame_type = ngx_ts_bit_stream_read(br, 2);             /* strmtyp */
    if (frame_type == 0x3) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ec3_parse: invalid frame type");
        return NGX_ERROR;
    }

    ngx_ts_bit_stream_read(br, 3);  /* substreamid */

    frame_size = (ngx_ts_bit_stream_read(br, 11) + 1) << 1; /* frmsiz */
    if (frame_size < NGX_TS_AC3_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ec3_parse: invalid frame size %uD", (uint32_t) frame_size);
        return NGX_ERROR;
    }

    sample_rate_code = ngx_ts_bit_stream_read(br, 2);       /* fscod */
    if (sample_rate_code == 0x3) {
        sample_rate_code2 = ngx_ts_bit_stream_read(br, 2);  /* fscod2 */
        if (sample_rate_code2 == 0x3) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_ec3_parse: invalid sample rate code");
            return NGX_ERROR;
        }

        params->sample_rate = ngx_ts_ac3_sample_rates[sample_rate_code2] / 2;

        num_blocks = 6;

    } else {
        params->sample_rate = ngx_ts_ac3_sample_rates[sample_rate_code];

        num_blocks_code = ngx_ts_bit_stream_read(br, 2);    /* numblkscod */
        num_blocks = ngx_ts_ac3_eac3_blocks[num_blocks_code];
    }

    channel_mode = ngx_ts_bit_stream_read(br, 3);           /* acmod */
    lfe_on = ngx_ts_bit_stream_read_one(br);                /* lfeon */
    bitstream_id = ngx_ts_bit_stream_read(br, 5);           /* bsid */

    if (br->err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ec3_parse: input stream overflow");
        return NGX_ERROR;
    }

    /* set the params */

    params->bitrate = 8 * frame_size * params->sample_rate
        / (num_blocks * 256);
    params->channels = ngx_ts_ac3_channels[channel_mode] + lfe_on;
    params->bits_per_sample = 16;

    params->channel_layout = ngx_ts_ac3_channel_layouts[channel_mode];
    if (lfe_on) {
        params->channel_layout |= KMP_CH_LOW_FREQUENCY;
    }

    /* write the extra data (dec3 box) */

    ngx_ts_bit_stream_init(&bw, extra_data->data, extra_data->len);

    data_rate = params->bitrate / 1000;
    ngx_ts_bit_stream_write(&bw, 13, data_rate);            /* data_rate */

    /* Note: supporting only one independent stream */
    ngx_ts_bit_stream_write(&bw, 3, 0);                     /* num_ind_sub */
    ngx_ts_bit_stream_write(&bw, 2, sample_rate_code);      /* fscod */
    ngx_ts_bit_stream_write(&bw, 5, bitstream_id);          /* bsid */
    ngx_ts_bit_stream_write_one(&bw, 0);                    /* reserved */
    ngx_ts_bit_stream_write_one(&bw, 0);                    /* asvc */
    ngx_ts_bit_stream_write(&bw, 3, 0);                     /* bsmod */
    ngx_ts_bit_stream_write(&bw, 3, channel_mode);          /* acmod */
    ngx_ts_bit_stream_write_one(&bw, lfe_on);               /* lfeon */
    ngx_ts_bit_stream_write(&bw, 3, 0);                     /* reserved */

    /* Note: dependent streams are not supported */
    ngx_ts_bit_stream_write(&bw, 4, 0);                     /* num_dep_sub */
    ngx_ts_bit_stream_write_one(&bw, 0);                    /* reserved */

    if (bw.err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ec3_parse: output stream overflow");
        return NGX_ERROR;
    }

    extra_data->len = ngx_ts_bit_stream_size(&bw, extra_data->data);

    return NGX_OK;
}


ngx_int_t
ngx_ts_ac3_ec3_parse(ngx_log_t *log, ngx_chain_t *cl,
    ngx_ts_ac3_params_t *params, ngx_str_t *extra_data)
{
    u_char               *p;
    u_char                bsid;
    size_t                size;
    ngx_buf_t            *buf;
    ngx_ts_bit_stream_t   br;

    buf = cl->buf;
    p = buf->pos;

    size = buf->last - p;
    if (size < NGX_TS_AC3_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_ec3_parse: size %uz too small for header", size);
        return NGX_ERROR;
    }

    if (p[0] != 0x0b || p[1] != 0x77) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_ec3_parse: invalid syncword");
        return NGX_ERROR;
    }

    bsid = p[5] >> 3;
    if (bsid > 16) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_ac3_ec3_parse: invalid bsid %uD", (uint32_t) bsid);
        return NGX_ERROR;
    }

    ngx_memzero(extra_data->data, extra_data->len);

    ngx_ts_bit_stream_init(&br, buf->pos + 2, buf->last - buf->pos - 2);

    if (bsid <= 10) {
        return ngx_ts_ac3_parse(log, &br, params, extra_data);

    } else {
        return ngx_ts_ec3_parse(log, &br, params, extra_data);
    }
}
