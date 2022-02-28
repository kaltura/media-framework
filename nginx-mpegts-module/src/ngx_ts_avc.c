
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_avc.h"


typedef struct {
    u_char                     *pos;
    u_char                     *last;
    ngx_uint_t                  shift;
    ngx_uint_t                  err;  /* unsigned  err:1; */
    const char                 *name;
    ngx_log_t                  *log;
} ngx_ts_avc_reader_t;


typedef struct {
    ngx_chain_t                *cl;
    ngx_buf_t                  *buf;
    u_char                     *pos;
} ngx_ts_avc_chain_reader_t;

typedef struct {
    ngx_ts_avc_chain_reader_t   base;
    uint32_t                    last_three;
    size_t                      left;
} ngx_ts_avc_chain_reader_ep_t;


static void ngx_ts_avc_init_reader(ngx_ts_avc_reader_t *br, u_char *buf,
    size_t len, ngx_log_t *log);
static uint64_t ngx_ts_avc_read(ngx_ts_avc_reader_t *br, ngx_uint_t bits);
static uint64_t ngx_ts_avc_read_golomb(ngx_ts_avc_reader_t *br);


/* user_data_registered_itu_t_t35 */
static u_char  ngx_ts_avc_cea_header[] = {
    0xb5,    /* itu_t_t35_country_code   */
    0x00,    /* Itu_t_t35_provider_code  */
    0x31,
    0x47,    /* user_identifier ('GA94') */
    0x41,
    0x39,
    0x34,
};


static void
ngx_ts_avc_init_reader(ngx_ts_avc_reader_t *br, u_char *buf, size_t len,
    ngx_log_t *log)
{
    ngx_memzero(br, sizeof(ngx_ts_avc_reader_t));

    br->pos = buf;
    br->last = buf + len;
    br->log = log;
}


static uint64_t
ngx_ts_avc_read(ngx_ts_avc_reader_t *br, ngx_uint_t bits)
{
    uint64_t    v;
    ngx_uint_t  k, n;

    if (br->err) {
        return 0;
    }

    v = 0;
    n = bits;

    while (n) {
        if (br->pos == br->last) {
            br->err = 1;
            break;
        }

        k = ngx_min(8 - br->shift, n);

        /*
         * [-------------|||||||||--------------]
         *    br->shift      k
         */

        v = (v << k) | (*br->pos & (0xff >> br->shift)) >> (8 - br->shift - k);

        n -= k;
        br->shift += k;

        if (br->shift == 8) {
            br->shift = 0;
            br->pos++;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, br->log, 0,
                   "ts avc %s[%uL]:%uL", br->name, bits, v);

    return v;
}


static uint64_t
ngx_ts_avc_read_golomb(ngx_ts_avc_reader_t *br)
{
    /*
     * ISO/IEC 14496-10:2004(E)
     * 9.1 Parsing process for Exp-Golomb codes, p. 159
     */

    uint64_t    v;
    ngx_uint_t  n;

    if (br->err) {
        return 0;
    }

    n = 0;

    while (ngx_ts_avc_read(br, 1) == 0) {
        if (br->err) {
            return 0;
        }

        n++;
    }

    v = ((uint64_t) 1 << n) - 1 + ngx_ts_avc_read(br, n);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, br->log, 0, "ts avc %s:%uL",
                   br->name, v);

    return v;
}


static int64_t
ngx_ts_avc_read_golomb_signed(ngx_ts_avc_reader_t *br)
{
    int64_t  value;

    value = ngx_ts_avc_read_golomb(br);
    if (value > 0) {
        if (value & 1) {        /* positive */
            value = (value + 1) / 2;

        } else {
            value = -(value / 2);
        }
    }

    return value;
}


static void
ngx_ts_avc_skip_scaling_list(ngx_ts_avc_reader_t *br,
    ngx_int_t size_of_scaling_list)
{
    ngx_int_t  last_scale = 8;
    ngx_int_t  next_scale = 8;
    ngx_int_t  delta_scale;
    ngx_int_t  j;

    for (j = 0; j < size_of_scaling_list; j++) {
        if (next_scale != 0) {
            delta_scale = ngx_ts_avc_read_golomb_signed(br);
            next_scale = (last_scale + delta_scale) & 0xff;
        }

        last_scale = (next_scale == 0) ? last_scale : next_scale;
    }
}


ngx_int_t
ngx_ts_avc_decode_params(ngx_ts_avc_params_t *avc, ngx_ts_stream_t *ts,
    u_char *sps, size_t sps_len, u_char *pps, size_t pps_len)
{
    /*
     * ISO/IEC 14496-10:2004(E)
     * 7.3.2.1 Sequence parameter set RBSP syntax, p. 31
     */

    ngx_uint_t            type, n, i;
    ngx_ts_avc_reader_t   br;

    /* ignore PPS so far */

    ngx_ts_avc_init_reader(&br, sps, sps_len, ts->log);

    br.name = "nalu_type";
    type = ngx_ts_avc_read(&br, 8);
    if ((type & 0x1f) != 7) {
        goto failed;
    }

    br.name = "profile_idc";
    avc->profile_idc = ngx_ts_avc_read(&br, 8);

    br.name = "constraints";
    avc->constraints = ngx_ts_avc_read(&br, 8);

    br.name = "level_idc";
    avc->level_idc = ngx_ts_avc_read(&br, 8);

    br.name = "seq_parameter_set_id";
    avc->sps_id = ngx_ts_avc_read_golomb(&br);

    if (avc->profile_idc == 100
        || avc->profile_idc == 110
        || avc->profile_idc == 122
        || avc->profile_idc == 244
        || avc->profile_idc == 44
        || avc->profile_idc == 83
        || avc->profile_idc == 86
        || avc->profile_idc == 118
        || avc->profile_idc == 128
        || avc->profile_idc == 138
        || avc->profile_idc == 139
        || avc->profile_idc == 134)
    {
        br.name = "chroma_format_idc";
        avc->chroma_format_idc = ngx_ts_avc_read_golomb(&br);

        if (avc->chroma_format_idc == 3) {
            br.name =
                     "residual_colour_transform_flagseparate_colour_plane_flag";
            avc->residual_colour_transform_flagseparate_colour_plane_flag =
                                                        ngx_ts_avc_read(&br, 1);
        }

        br.name = "bit_depth_luma_minus8";
        avc->bit_depth_luma = ngx_ts_avc_read_golomb(&br) + 8;

        br.name = "bit_depth_chroma_minus8";
        avc->bit_depth_chroma = ngx_ts_avc_read_golomb(&br) + 8;

        br.name = "qpprime_y_zero_transform_bypass_flag";
        avc->qpprime_y_zero_transform_bypass_flag = ngx_ts_avc_read(&br, 1);

        br.name = "seq_scaling_matrix_present_flag";
        avc->seq_scaling_matrix_present_flag = ngx_ts_avc_read(&br, 1);

        if (avc->seq_scaling_matrix_present_flag) {
            n = (avc->chroma_format_idc != 3) ? 8 : 12;

            for (i = 0; i < n; i++) {
                br.name = "seq_scaling_list_present_flag[i]";
                if (ngx_ts_avc_read(&br, 1)) {
                    if (i < 6) {
                        ngx_ts_avc_skip_scaling_list(&br, 16);

                    } else {
                        ngx_ts_avc_skip_scaling_list(&br, 64);
                    }
                }
            }
        }
    }

    br.name = "log2_max_frame_num_minus4";
    avc->max_frame_num = (1 << (ngx_ts_avc_read_golomb(&br) + 4));

    br.name = "pic_order_cnt_type";
    avc->pic_order_cnt_type = ngx_ts_avc_read_golomb(&br);

    if (avc->pic_order_cnt_type == 0) {
        br.name = "log2_max_pic_order_cnt_lsb_minus4";
        avc->max_pic_order_cnt_lsb = (1 << (ngx_ts_avc_read_golomb(&br) + 4));

    } else if (avc->pic_order_cnt_type == 1) {
        br.name = "delta_pic_order_always_zero_flag";
        avc->delta_pic_order_always_zero_flag = ngx_ts_avc_read(&br, 1);

        br.name = "offset_for_non_ref_pic";
        avc->offset_for_non_ref_pic = ngx_ts_avc_read_golomb(&br);

        br.name = "offset_for_top_to_bottom_field";
        avc->offset_for_top_to_bottom_field = ngx_ts_avc_read_golomb(&br);

        br.name = "num_ref_frames_in_pic_order_cnt_cycle";
        n = ngx_ts_avc_read_golomb(&br);

        for (i = 0; i < n; i++) {
            br.name = "offset_for_ref_frame[i]";
            (void) ngx_ts_avc_read_golomb(&br);
        }
    }

    br.name = "num_ref_frames";
    avc->num_ref_frames = ngx_ts_avc_read_golomb(&br);

    br.name = "gaps_in_frame_num_value_allowed_flag";
    avc->gaps_in_frame_num_value_allowed_flag = ngx_ts_avc_read(&br, 1);

    br.name = "pic_width_in_mbs_minus1";
    avc->pic_width_in_mbs = ngx_ts_avc_read_golomb(&br) + 1;

    br.name = "pic_height_in_map_units_minus1";
    avc->pic_height_in_map_units = ngx_ts_avc_read_golomb(&br) + 1;

    br.name = "frame_mbs_only_flag";
    avc->frame_mbs_only_flag = ngx_ts_avc_read(&br, 1);

    if (!avc->frame_mbs_only_flag) {
        br.name = "mb_adaptive_frame_field_flag";
        avc->mb_adaptive_frame_field_flag = ngx_ts_avc_read(&br, 1);
    }

    br.name = "direct_8x8_inference_flag";
    avc->direct_8x8_inference_flag = ngx_ts_avc_read(&br, 1);

    br.name = "frame_cropping_flag";
    avc->frame_cropping_flag = ngx_ts_avc_read(&br, 1);

    if (avc->frame_cropping_flag) {
        br.name = "frame_crop_left_offset";
        avc->frame_crop_left_offset = ngx_ts_avc_read_golomb(&br);

        br.name = "frame_crop_right_offset";
        avc->frame_crop_right_offset = ngx_ts_avc_read_golomb(&br);

        br.name = "frame_crop_top_offset";
        avc->frame_crop_top_offset = ngx_ts_avc_read_golomb(&br);

        br.name = "frame_crop_bottom_offset";
        avc->frame_crop_bottom_offset = ngx_ts_avc_read_golomb(&br);
    }

    if (br.err) {
        goto failed;
    }

    avc->width =
            avc->pic_width_in_mbs * 16
            - (avc->frame_crop_left_offset + avc->frame_crop_right_offset) * 2;

    avc->height =
            (2 - avc->frame_mbs_only_flag) * avc->pic_height_in_map_units * 16
            - (avc->frame_crop_top_offset + avc->frame_crop_bottom_offset) * 2;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts avc width:%ui, height:%ui", avc->width, avc->height);

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, ts->log, 0,
                  "failed to parse AVC parameters");

    return NGX_ERROR;
}


static ngx_int_t
ngx_ts_avc_chain_reader_ep_read(ngx_ts_avc_chain_reader_ep_t *reader,
    u_char *dst, size_t size)
{
    u_char   b;
    u_char  *dst_end;

    if (size > reader->left) {
        return NGX_ERROR;
    }
    reader->left -= size;

    dst_end = dst + size;
    while (dst < dst_end) {

        for ( ;; ) {

            if (reader->base.pos < reader->base.buf->last) {
                b = *reader->base.pos++;
                break;
            }

            if (reader->base.cl->next == NULL) {
                return NGX_ERROR;
            }

            reader->base.cl = reader->base.cl->next;
            reader->base.buf = reader->base.cl->buf;
            reader->base.pos = reader->base.buf->pos;
        }

        reader->last_three = ((reader->last_three << 8) | b) & 0xffffff;
        if (reader->last_three == 3) {
            if (reader->left <= 0) {
                return NGX_ERROR;
            }
            reader->left--;
            continue;
        }

        *dst++ = b;
    }

    return NGX_OK;
}

ngx_int_t
ngx_ts_avc_chain_reader_ep_skip(ngx_ts_avc_chain_reader_ep_t *reader,
    size_t size)
{
    u_char  b;

    if (size > reader->left) {
        return NGX_ERROR;
    }
    reader->left -= size;

    while (size > 0) {

        for ( ;; ) {

            if (reader->base.pos < reader->base.buf->last) {
                b = *reader->base.pos++;
                break;
            }

            if (reader->base.cl->next == NULL) {
                return NGX_ERROR;
            }

            reader->base.cl = reader->base.cl->next;
            reader->base.buf = reader->base.cl->buf;
            reader->base.pos = reader->base.buf->pos;
        }


        reader->last_three = ((reader->last_three << 8) | b) & 0xffffff;
        if (reader->last_three == 3) {
            if (reader->left <= 0) {
                return NGX_ERROR;
            }
            reader->left--;
            continue;
        }

        size--;
    }

    return NGX_OK;
}


ngx_flag_t
ngx_ts_avc_sei_detect_cea(ngx_log_t *log, ngx_chain_t *in, u_char *pos,
    size_t size)
{
    u_char                        b;
    u_char                        buf[sizeof(ngx_ts_avc_cea_header)];
    uint32_t                      payload_type;
    uint32_t                      payload_size;
    ngx_ts_avc_chain_reader_ep_t  payload;
    ngx_ts_avc_chain_reader_ep_t  reader;

    reader.base.cl = in;
    reader.base.buf = in->buf;
    reader.base.pos = pos;
    reader.left = size;
    reader.last_three = 1;

    if (ngx_ts_avc_chain_reader_ep_skip(&reader, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "ngx_ts_avc_sei_detect_cea: skip nal type failed");
        return 0;
    }

    while (reader.left >= 2 + sizeof(buf)) {

        payload_type = 0;
        do {
            if (ngx_ts_avc_chain_reader_ep_read(&reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "ngx_ts_avc_sei_detect_cea: read payload type failed");
                return 0;
            }

            payload_type += b;
        } while (b == 0xff);

        payload_size = 0;
        do {
            if (ngx_ts_avc_chain_reader_ep_read(&reader, &b, sizeof(b))
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "ngx_ts_avc_sei_detect_cea: read payload size failed");
                return 0;
            }

            payload_size += b;
        } while (b == 0xff);

        payload = reader;

        if (ngx_ts_avc_chain_reader_ep_skip(&reader, payload_size) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "ngx_ts_avc_sei_detect_cea: skip payload failed");
            return 0;
        }

        if (payload_type != 4) {    /* user data registered */
            continue;
        }

        payload.left = payload_size;

        if (ngx_ts_avc_chain_reader_ep_read(&payload, buf, sizeof(buf))
            != NGX_OK)
        {
            continue;
        }

        if (ngx_memcmp(buf, ngx_ts_avc_cea_header, sizeof(buf)) == 0) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                "ngx_ts_avc_detect_cea: cea captions detected");
            return 1;
        }
    }

    return 0;
}
