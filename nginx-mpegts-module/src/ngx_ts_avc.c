
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_avc.h"
#include "ngx_ts_heavc.h"


static void
ngx_ts_avc_skip_scaling_list(ngx_ts_heavc_reader_t *br,
    ngx_int_t size_of_scaling_list)
{
    ngx_int_t  last_scale = 8;
    ngx_int_t  next_scale = 8;
    ngx_int_t  delta_scale;
    ngx_int_t  j;

    for (j = 0; j < size_of_scaling_list; j++) {
        if (next_scale != 0) {
            delta_scale = ngx_ts_heavc_read_se(br, "delta_scale");
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

    ngx_uint_t              type, n, i;
    ngx_ts_heavc_reader_t   br;

    /* ignore PPS so far */
    ngx_memzero(avc, sizeof(ngx_ts_avc_params_t));

    ngx_ts_heavc_init_reader(&br, sps, sps_len, ts->log, "avc");

    type = ngx_ts_heavc_read_u(&br, 8, "nalu_type");
    if ((type & 0x1f) != NGX_TS_AVC_NAL_SPS) {
        goto failed;
    }

    avc->profile_idc = ngx_ts_heavc_read_u(&br, 8, "profile_idc");

    avc->constraints = ngx_ts_heavc_read_u(&br, 8, "constraints");

    avc->level_idc = ngx_ts_heavc_read_u(&br, 8, "level_idc");

    avc->sps_id = ngx_ts_heavc_read_ue(&br, "seq_parameter_set_id");

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
        avc->chroma_format_idc = ngx_ts_heavc_read_ue(&br, "chroma_format_idc");

        if (avc->chroma_format_idc == 3) {
            avc->residual_colour_transform_flagseparate_colour_plane_flag =
                ngx_ts_heavc_read_u1(&br,
                   "residual_colour_transform_flagseparate_colour_plane_flag");
        }

        avc->bit_depth_luma = ngx_ts_heavc_read_ue(&br, "bit_depth_luma_minus8")
            + 8;

        avc->bit_depth_chroma = ngx_ts_heavc_read_ue(&br,
            "bit_depth_chroma_minus8") + 8;

        avc->qpprime_y_zero_transform_bypass_flag = ngx_ts_heavc_read_u1(&br,
            "qpprime_y_zero_transform_bypass_flag");

        avc->seq_scaling_matrix_present_flag = ngx_ts_heavc_read_u1(&br,
            "seq_scaling_matrix_present_flag");

        if (avc->seq_scaling_matrix_present_flag) {
            n = (avc->chroma_format_idc != 3) ? 8 : 12;

            for (i = 0; i < n; i++) {
                if (ngx_ts_heavc_read_u1(&br,
                    "seq_scaling_list_present_flag[i]"))
                {
                    if (i < 6) {
                        ngx_ts_avc_skip_scaling_list(&br, 16);

                    } else {
                        ngx_ts_avc_skip_scaling_list(&br, 64);
                    }
                }
            }
        }
    }

    avc->max_frame_num = (1 << (ngx_ts_heavc_read_ue(&br,
        "log2_max_frame_num_minus4") + 4));

    avc->pic_order_cnt_type = ngx_ts_heavc_read_ue(&br, "pic_order_cnt_type");

    if (avc->pic_order_cnt_type == 0) {
        avc->max_pic_order_cnt_lsb = (1 << (ngx_ts_heavc_read_ue(&br,
            "log2_max_pic_order_cnt_lsb_minus4") + 4));

    } else if (avc->pic_order_cnt_type == 1) {
        avc->delta_pic_order_always_zero_flag = ngx_ts_heavc_read_u1(&br,
            "delta_pic_order_always_zero_flag");

        avc->offset_for_non_ref_pic = ngx_ts_heavc_read_ue(&br,
            "offset_for_non_ref_pic");

        avc->offset_for_top_to_bottom_field = ngx_ts_heavc_read_ue(&br,
            "offset_for_top_to_bottom_field");

        n = ngx_ts_heavc_read_ue(&br, "num_ref_frames_in_pic_order_cnt_cycle");

        for (i = 0; i < n; i++) {
            (void) ngx_ts_heavc_read_ue(&br, "offset_for_ref_frame[i]");
        }
    }

    avc->num_ref_frames = ngx_ts_heavc_read_ue(&br, "num_ref_frames");

    avc->gaps_in_frame_num_value_allowed_flag = ngx_ts_heavc_read_u1(&br,
        "gaps_in_frame_num_value_allowed_flag");

    avc->pic_width_in_mbs = ngx_ts_heavc_read_ue(&br,
        "pic_width_in_mbs_minus1") + 1;

    avc->pic_height_in_map_units = ngx_ts_heavc_read_ue(&br,
        "pic_height_in_map_units_minus1") + 1;

    avc->frame_mbs_only_flag = ngx_ts_heavc_read_u1(&br,
        "frame_mbs_only_flag");

    if (!avc->frame_mbs_only_flag) {
        avc->mb_adaptive_frame_field_flag = ngx_ts_heavc_read_u1(&br,
            "mb_adaptive_frame_field_flag");
    }

    avc->direct_8x8_inference_flag = ngx_ts_heavc_read_u1(&br,
        "direct_8x8_inference_flag");

    avc->frame_cropping_flag = ngx_ts_heavc_read_u1(&br,
        "frame_cropping_flag");

    if (avc->frame_cropping_flag) {
        avc->frame_crop_left_offset = ngx_ts_heavc_read_ue(&br,
            "frame_crop_left_offset");

        avc->frame_crop_right_offset = ngx_ts_heavc_read_ue(&br,
            "frame_crop_right_offset");

        avc->frame_crop_top_offset = ngx_ts_heavc_read_ue(&br,
            "frame_crop_top_offset");

        avc->frame_crop_bottom_offset = ngx_ts_heavc_read_ue(&br,
            "frame_crop_bottom_offset");
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


ngx_int_t
ngx_ts_avc_get_ps_id(ngx_buf_t *b, ngx_log_t *log, uint32_t *idp)
{
    u_char                 type;
    size_t                 size;
    uint32_t               id;
    ngx_ts_heavc_reader_t  br;

    size = b->last - b->pos;
    if (size < 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_avc_get_ps_id: invalid buffer size %uz", size);
        return NGX_ERROR;
    }

    ngx_ts_heavc_init_reader(&br, b->pos + 1, size - 1, log, "avc");

    type = *b->pos & 0x1f;
    switch (type) {

    case NGX_TS_AVC_NAL_SPS:
        ngx_ts_heavc_skip_u(&br, 8, "profile_idc");
        ngx_ts_heavc_skip_u(&br, 8, "constraints");
        ngx_ts_heavc_skip_u(&br, 8, "level_idc");

        id = ngx_ts_heavc_read_ue(&br, "seq_parameter_set_id");
        break;

    case NGX_TS_AVC_NAL_PPS:
        id = ngx_ts_heavc_read_ue(&br, "pic_parameter_set_id");
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_avc_get_ps_id: invalid nalu type %uD", (uint32_t) type);
        return NGX_ERROR;
    }

    if (br.err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_avc_get_ps_id: stream overflow");
        return NGX_ERROR;
    }

    *idp = (type << 16) | id;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
        "ngx_ts_avc_get_ps_id: 0x%uxD", *idp);

    return NGX_OK;
}
