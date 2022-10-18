#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_hevc.h"
#include "ngx_ts_heavc.h"


#define HEVC_NALU_HEADER_SIZE             2
#define HEVC_EXTENDED_SAR                 255
#define HEVC_MAX_SHORT_TERM_REF_PIC_SETS  64
#define HEVC_MAX_SPATIAL_SEGMENTATION     (1 << 12)
#define HEVC_HVCC_HEADER_SIZE             22


#define ngx_ts_hevc_get_nal_type(pc)  (((*pc) >> 1) & 0x3f)

#define ngx_ts_hevc_write_be16(p, w) {                                       \
        *(p)++ = ((w) >> 8) & 0xff;                                          \
        *(p)++ =  (w) & 0xff;                                                \
    }

#define ngx_ts_hevc_write_be32(p, dw) {                                      \
        *(p)++ = ((dw) >> 24) & 0xff;                                        \
        *(p)++ = ((dw) >> 16) & 0xff;                                        \
        *(p)++ = ((dw) >> 8) & 0xff;                                         \
        *(p)++ =  (dw) & 0xff;                                               \
    }


typedef struct {

    /* hvcc fields */

    u_char    general_profile_space;
    u_char    general_tier_flag;
    u_char    general_profile_idc;
    uint32_t  general_profile_compatibility_flags;
    uint64_t  general_constraint_indicator_flags;
    u_char    general_level_idc;
    uint16_t  min_spatial_segmentation_idc;
    u_char    parallelism_type;
    u_char    chroma_format_idc;
    u_char    bit_depth_luma_minus8;
    u_char    bit_depth_chroma_minus8;
    u_char    num_temporal_layers;
    u_char    sps_temporal_id_nesting_flag;

    /* resolution fields */

    uint32_t  pic_width_in_luma_samples;
    uint32_t  pic_height_in_luma_samples;
    uint32_t  conf_win_left_offset;
    uint32_t  conf_win_right_offset;
    uint32_t  conf_win_top_offset;
    uint32_t  conf_win_bottom_offset;
    unsigned  separate_colour_plane_flag:1;
} ngx_ts_hevc_ctx_t;


/* profile tier level */
typedef struct {
    u_char    profile_space;
    u_char    tier_flag;
    u_char    profile_idc;
    uint32_t  profile_compatibility_flags;
    uint64_t  constraint_indicator_flags;
    u_char    level_idc;
} ngx_ts_hevc_ptl_t;


static void
ngx_ts_hevc_update_ptl(ngx_ts_hevc_ctx_t *ctx, ngx_ts_hevc_ptl_t *ptl)
{
    ctx->general_profile_space = ptl->profile_space;

    if (ctx->general_tier_flag < ptl->tier_flag) {
        ctx->general_tier_flag = ptl->tier_flag;
        ctx->general_level_idc = ptl->level_idc;

    } else {
        ctx->general_level_idc = ngx_max(ctx->general_level_idc,
            ptl->level_idc);
    }

    ctx->general_profile_idc = ngx_max(ctx->general_profile_idc,
        ptl->profile_idc);

    ctx->general_profile_compatibility_flags &=
        ptl->profile_compatibility_flags;

    ctx->general_constraint_indicator_flags &=
        ptl->constraint_indicator_flags;
}


static void
ngx_ts_hevc_parse_ptl(ngx_ts_heavc_reader_t *br, ngx_ts_hevc_ctx_t *ctx,
    ngx_uint_t max_sub_layers_minus1)
{
    uint32_t           sub_layer_profile_present_flags;
    uint32_t           sub_layer_level_present_flags;
    ngx_uint_t         i;
    ngx_ts_hevc_ptl_t  general_ptl;

    general_ptl.profile_space = ngx_ts_heavc_read_u(br, 2,
        "general_profile_space");
    general_ptl.tier_flag = ngx_ts_heavc_read_u1(br,
        "general_tier_flag");
    general_ptl.profile_idc = ngx_ts_heavc_read_u(br, 5,
        "general_profile_idc");
    general_ptl.profile_compatibility_flags = ngx_ts_heavc_read_u(br, 32,
        "general_profile_compatibility_flag");
    general_ptl.constraint_indicator_flags = ngx_ts_heavc_read_u(br, 48,
        "general_progressive_source_flag...");
    general_ptl.level_idc = ngx_ts_heavc_read_u(br, 8, "general_level_idc");

    if (ctx != NULL) {
        ngx_ts_hevc_update_ptl(ctx, &general_ptl);
    }

    sub_layer_profile_present_flags = 0;
    sub_layer_level_present_flags = 0;

    for (i = 0; i < max_sub_layers_minus1; i++) {
        sub_layer_profile_present_flags |= ngx_ts_heavc_read_u1(br,
            "sub_layer_profile_present_flag") << i;
        sub_layer_level_present_flags |= ngx_ts_heavc_read_u1(br,
            "sub_layer_level_present_flag") << i;
    }

    if (max_sub_layers_minus1 > 0) {
        for (i = max_sub_layers_minus1; i < 8; i++) {
            ngx_ts_heavc_skip_u(br, 2, "reserved_zero_2bits");
        }
    }

    for (i = 0; i < max_sub_layers_minus1; i++) {
        if (sub_layer_profile_present_flags & (1 << i)) {
            ngx_ts_heavc_skip_u(br, 40, "sub_layer_profile_space...");
            ngx_ts_heavc_skip_u(br, 48, "sub_layer_progressive_source_flag...");
        }

        if (sub_layer_level_present_flags & (1 << i)) {
            ngx_ts_heavc_skip_u(br, 8, "sub_layer_level_idc");
        }
    }
}


static ngx_int_t
ngx_ts_hevc_hvcc_parse_vps(ngx_ts_heavc_reader_t *br, ngx_ts_hevc_ctx_t *ctx)
{
    ngx_uint_t  vps_max_sub_layers_minus1;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, br->log, 0, "--- ts hevc vps ---");

    ngx_ts_heavc_skip_u(br, 12, "vps_video_parameter_set_id...");

    vps_max_sub_layers_minus1 = ngx_ts_heavc_read_u(br, 3,
        "vps_max_sub_layers_minus1");

    ctx->num_temporal_layers = ngx_max(ctx->num_temporal_layers,
        vps_max_sub_layers_minus1 + 1);

    ngx_ts_heavc_skip_u(br, 17, "vps_temporal_id_nesting_flag...");

    ngx_ts_hevc_parse_ptl(br, ctx, vps_max_sub_layers_minus1);

    return NGX_OK;
}


static void
ngx_ts_hevc_skip_sub_layer_hrd_params(ngx_ts_heavc_reader_t *br,
    ngx_uint_t cpb_cnt_minus1, u_char sub_pic_hrd_params_present_flag)
{
    ngx_uint_t  i;

    for (i = 0; i <= cpb_cnt_minus1; i++) {
        ngx_ts_heavc_read_ue(br, "bit_rate_value_minus1");
        ngx_ts_heavc_read_ue(br, "cpb_size_value_minus1");

        if (sub_pic_hrd_params_present_flag) {
            ngx_ts_heavc_read_ue(br, "cpb_size_du_value_minus1");
            ngx_ts_heavc_read_ue(br, "bit_rate_du_value_minus1");
        }

        ngx_ts_heavc_skip_u1(br, "cbr_flag");
    }
}


static ngx_int_t
ngx_ts_hevc_skip_hrd_params(ngx_ts_heavc_reader_t *br,
    u_char common_inf_present_flag, ngx_uint_t max_sub_layers_minus1)
{
    u_char      low_delay_hrd_flag;
    u_char      fixed_pic_rate_within_cvs_flag;
    u_char      fixed_pic_rate_general_flag;
    u_char      nal_hrd_parameters_present_flag;
    u_char      vcl_hrd_parameters_present_flag;
    u_char      sub_pic_hrd_params_present_flag;
    ngx_uint_t  i;
    ngx_uint_t  cpb_cnt_minus1;

    nal_hrd_parameters_present_flag = 0;
    vcl_hrd_parameters_present_flag = 0;
    sub_pic_hrd_params_present_flag = 0;

    if (common_inf_present_flag) {
        nal_hrd_parameters_present_flag = ngx_ts_heavc_read_u1(br,
            "nal_hrd_parameters_present_flag");
        vcl_hrd_parameters_present_flag = ngx_ts_heavc_read_u1(br,
            "vcl_hrd_parameters_present_flag");

        if (nal_hrd_parameters_present_flag
            || vcl_hrd_parameters_present_flag)
        {
            sub_pic_hrd_params_present_flag = ngx_ts_heavc_read_u1(br,
                "sub_pic_hrd_params_present_flag");

            if (sub_pic_hrd_params_present_flag) {
                ngx_ts_heavc_skip_u(br, 19, "tick_divisor_minus2...");
            }

            ngx_ts_heavc_skip_u(br, 8, "bit_rate_scale...");

            if (sub_pic_hrd_params_present_flag) {
                ngx_ts_heavc_skip_u(br, 4, "cpb_size_du_scale");
            }

            ngx_ts_heavc_skip_u(br, 15,
                "initial_cpb_removal_delay_length_minus1...");
        }
    }

    for (i = 0; i <= max_sub_layers_minus1; i++) {
        fixed_pic_rate_general_flag = ngx_ts_heavc_read_u1(br,
            "fixed_pic_rate_general_flag");

        fixed_pic_rate_within_cvs_flag = 0;
        if (!fixed_pic_rate_general_flag) {
            fixed_pic_rate_within_cvs_flag = ngx_ts_heavc_read_u1(br,
                "fixed_pic_rate_within_cvs_flag");
        }

        low_delay_hrd_flag = 0;
        if (fixed_pic_rate_within_cvs_flag) {
            ngx_ts_heavc_read_ue(br, "elemental_duration_in_tc_minus1");

        } else {
            low_delay_hrd_flag = ngx_ts_heavc_read_u1(br,
                "low_delay_hrd_flag");
        }

        cpb_cnt_minus1 = 0;
        if (!low_delay_hrd_flag) {
            cpb_cnt_minus1 = ngx_ts_heavc_read_ue(br, "cpb_cnt_minus1");
            if (cpb_cnt_minus1 > 31) {
                ngx_log_error(NGX_LOG_ERR, br->log, 0,
                    "ngx_ts_hevc_skip_hrd_params: "
                    "cpb_cnt_minus1 %ui too big", cpb_cnt_minus1);
                return NGX_ERROR;
            }
        }

        if (nal_hrd_parameters_present_flag) {
            ngx_ts_hevc_skip_sub_layer_hrd_params(br, cpb_cnt_minus1,
                sub_pic_hrd_params_present_flag);
        }

        if (vcl_hrd_parameters_present_flag) {
            ngx_ts_hevc_skip_sub_layer_hrd_params(br, cpb_cnt_minus1,
                sub_pic_hrd_params_present_flag);
        }
    }

    return NGX_OK;
}


static void
ngx_ts_hevc_hvcc_parse_vui(ngx_ts_heavc_reader_t *br, ngx_ts_hevc_ctx_t *ctx,
    ngx_uint_t max_sub_layers_minus1)
{
    ngx_uint_t  min_spatial_segmentation_idc;

    if (ngx_ts_heavc_read_u1(br, "aspect_ratio_info_present_flag")) {
        if (ngx_ts_heavc_read_u(br, 8, "aspect_ratio_idc")
            == HEVC_EXTENDED_SAR)
        {
            ngx_ts_heavc_skip_u(br, 32, "sar_width...");
        }
    }

    if (ngx_ts_heavc_read_u1(br, "overscan_info_present_flag")) {
        ngx_ts_heavc_skip_u1(br, "overscan_appropriate_flag");
    }

    if (ngx_ts_heavc_read_u1(br, "video_signal_type_present_flag")) {
        ngx_ts_heavc_skip_u(br, 4, "video_format...");

        if (ngx_ts_heavc_read_u1(br, "colour_description_present_flag")) {
            ngx_ts_heavc_skip_u(br, 24, "colour_primaries...");
        }
    }

    if (ngx_ts_heavc_read_u1(br, "chroma_loc_info_present_flag")) {
        ngx_ts_heavc_read_ue(br, "chroma_sample_loc_type_top_field");
        ngx_ts_heavc_read_ue(br, "chroma_sample_loc_type_bottom_field");
    }

    ngx_ts_heavc_skip_u(br, 3, "neutral_chroma_indication_flag...");

    if (ngx_ts_heavc_read_u1(br, "default_display_window_flag")) {
        ngx_ts_heavc_read_ue(br, "def_disp_win_left_offset");
        ngx_ts_heavc_read_ue(br, "def_disp_win_right_offset");
        ngx_ts_heavc_read_ue(br, "def_disp_win_top_offset");
        ngx_ts_heavc_read_ue(br, "def_disp_win_bottom_offset");
    }

    if (ngx_ts_heavc_read_u1(br, "vui_timing_info_present_flag")) {
        ngx_ts_heavc_skip_u(br, 32, "vps_num_units_in_tick");
        ngx_ts_heavc_skip_u(br, 32, "vps_time_scale");

        if (ngx_ts_heavc_read_u1(br, "vps_poc_proportional_to_timing_flag")) {
            ngx_ts_heavc_read_ue(br, "vps_num_ticks_poc_diff_one_minus1");
        }

        if (ngx_ts_heavc_read_u1(br, "vui_hrd_parameters_present_flag")) {
            ngx_ts_hevc_skip_hrd_params(br, 1, max_sub_layers_minus1);
        }
    }

    if (ngx_ts_heavc_read_u1(br, "bitstream_restriction_flag")) {
        ngx_ts_heavc_skip_u(br, 3, "tiles_fixed_structure_flag...");

        min_spatial_segmentation_idc = ngx_ts_heavc_read_ue(br,
            "min_spatial_segmentation_idc");

        ctx->min_spatial_segmentation_idc = ngx_min(
            ctx->min_spatial_segmentation_idc,
            min_spatial_segmentation_idc);

        ngx_ts_heavc_read_ue(br, "max_bytes_per_pic_denom");
        ngx_ts_heavc_read_ue(br, "max_bits_per_min_cu_denom");
        ngx_ts_heavc_read_ue(br, "log2_max_mv_length_horizontal");
        ngx_ts_heavc_read_ue(br, "log2_max_mv_length_vertical");
    }
}


static void
ngx_ts_hevc_skip_scaling_list_data(ngx_ts_heavc_reader_t *br)
{
    ngx_int_t  i;
    ngx_int_t  size_id;
    ngx_int_t  coef_num;
    ngx_int_t  matrix_id;

    for (size_id = 0; size_id < 4; size_id++) {
        for (matrix_id = 0; matrix_id < (size_id == 3 ? 2 : 6); matrix_id++) {

            if (!ngx_ts_heavc_read_u1(br, "scaling_list_pred_mode_flag")) {
                ngx_ts_heavc_read_ue(br, "scaling_list_pred_matrix_id_delta");

            } else {
                coef_num = ngx_min(64, 1 << (4 + (size_id << 1)));

                if (size_id > 1) {
                    ngx_ts_heavc_read_se(br, "scaling_list_dc_coef_minus8");
                }

                for (i = 0; i < coef_num; i++) {
                    ngx_ts_heavc_read_se(br, "scaling_list_delta_coef");
                }
            }
        }
    }
}


static ngx_int_t
ngx_ts_hevc_parse_rps(ngx_ts_heavc_reader_t *br, ngx_uint_t rps_idx,
    ngx_uint_t num_rps, ngx_uint_t *num_delta_pocs)
{
    u_char      use_delta_flag;
    u_char      used_by_curr_pic_flag;
    ngx_uint_t  i;
    ngx_uint_t  num_negative_pics;
    ngx_uint_t  num_positive_pics;

    if (rps_idx && ngx_ts_heavc_read_u1(br,
        "inter_ref_pic_set_prediction_flag"))
    {
        if (rps_idx >= num_rps) {
            ngx_log_error(NGX_LOG_ALERT, br->log, 0,
                "ngx_ts_hevc_parse_rps: "
                "rps index %ui larger than rps count %ui", rps_idx, num_rps);
            return NGX_ERROR;
        }

        ngx_ts_heavc_skip_u1(br, "delta_rps_sign");
        ngx_ts_heavc_read_ue(br, "abs_delta_rps_minus1");

        num_delta_pocs[rps_idx] = 0;

        for (i = 0; i <= num_delta_pocs[rps_idx - 1]; i++) {
            used_by_curr_pic_flag = ngx_ts_heavc_read_u1(br,
                "used_by_curr_pic_flag");

            use_delta_flag = 0;
            if (!used_by_curr_pic_flag) {
                use_delta_flag = ngx_ts_heavc_read_u1(br, "use_delta_flag");
            }

            if (used_by_curr_pic_flag || use_delta_flag) {
                num_delta_pocs[rps_idx]++;
            }
        }

    } else {
        num_negative_pics = ngx_ts_heavc_read_ue(br, "num_negative_pics");
        num_positive_pics = ngx_ts_heavc_read_ue(br, "num_positive_pics");

        num_delta_pocs[rps_idx] = num_negative_pics + num_positive_pics;

        for (i = 0; i < num_negative_pics; i++) {
            ngx_ts_heavc_read_ue(br, "delta_poc_s0_minus1");
            ngx_ts_heavc_skip_u1(br, "used_by_curr_pic_s0_flag");

            if (br->err) {
                ngx_log_error(NGX_LOG_ERR, br->log, 0,
                    "ngx_ts_hevc_parse_rps: stream overflow (1)");
                return NGX_ERROR;
            }
        }

        for (i = 0; i < num_positive_pics; i++) {
            ngx_ts_heavc_read_ue(br, "delta_poc_s1_minus1");
            ngx_ts_heavc_skip_u1(br, "used_by_curr_pic_s1_flag");

            if (br->err) {
                ngx_log_error(NGX_LOG_ERR, br->log, 0,
                    "ngx_ts_hevc_parse_rps: stream overflow (2)");
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hevc_hvcc_parse_sps(ngx_ts_heavc_reader_t *br, ngx_ts_hevc_ctx_t *ctx)
{
    ngx_uint_t  i;
    ngx_uint_t  len;
    ngx_uint_t  sps_max_sub_layers_minus1;
    ngx_uint_t  num_long_term_ref_pics_sps;
    ngx_uint_t  num_short_term_ref_pic_sets;
    ngx_uint_t  log2_max_pic_order_cnt_lsb_minus4;
    ngx_uint_t  num_delta_pocs[HEVC_MAX_SHORT_TERM_REF_PIC_SETS];

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, br->log, 0, "--- ts hevc sps ---");

    ngx_ts_heavc_skip_u(br, 4, "sps_video_parameter_set_id");

    sps_max_sub_layers_minus1 = ngx_ts_heavc_read_u(br, 3,
        "sps_max_sub_layers_minus1");

    ctx->num_temporal_layers = ngx_max(ctx->num_temporal_layers,
        sps_max_sub_layers_minus1 + 1);

    ctx->sps_temporal_id_nesting_flag = ngx_ts_heavc_read_u1(br,
        "sps_temporal_id_nesting_flag");

    ngx_ts_hevc_parse_ptl(br, ctx, sps_max_sub_layers_minus1);

    ngx_ts_heavc_read_ue(br, "sps_seq_parameter_set_id");

    ctx->chroma_format_idc = ngx_ts_heavc_read_ue(br, "chroma_format_idc");

    if (ctx->chroma_format_idc == 3) {
        ctx->separate_colour_plane_flag = ngx_ts_heavc_read_u1(br,
            "separate_colour_plane_flag");
    }

    ctx->pic_width_in_luma_samples = ngx_ts_heavc_read_ue(br,
        "pic_width_in_luma_samples");
    ctx->pic_height_in_luma_samples = ngx_ts_heavc_read_ue(br,
        "pic_height_in_luma_samples");

    if (ngx_ts_heavc_read_u1(br, "conformance_window_flag")) {
        ctx->conf_win_left_offset = ngx_ts_heavc_read_ue(br,
            "conf_win_left_offset");
        ctx->conf_win_right_offset = ngx_ts_heavc_read_ue(br,
            "conf_win_right_offset");
        ctx->conf_win_top_offset = ngx_ts_heavc_read_ue(br,
            "conf_win_top_offset");
        ctx->conf_win_bottom_offset = ngx_ts_heavc_read_ue(br,
            "conf_win_bottom_offset");
    }

    ctx->bit_depth_luma_minus8 = ngx_ts_heavc_read_ue(br,
        "bit_depth_luma_minus8");
    ctx->bit_depth_chroma_minus8 = ngx_ts_heavc_read_ue(br,
        "bit_depth_chroma_minus8");
    log2_max_pic_order_cnt_lsb_minus4 = ngx_ts_heavc_read_ue(br,
        "log2_max_pic_order_cnt_lsb_minus4");

    i = ngx_ts_heavc_read_u1(br, "sps_sub_layer_ordering_info_present_flag")
        ? 0 : sps_max_sub_layers_minus1;
    for (; i <= sps_max_sub_layers_minus1; i++) {
        ngx_ts_heavc_read_ue(br, "sps_max_dec_pic_buffering_minus1");
        ngx_ts_heavc_read_ue(br, "sps_max_num_reorder_pics");
        ngx_ts_heavc_read_ue(br, "sps_max_latency_increase_plus1");
    }

    ngx_ts_heavc_read_ue(br, "log2_min_luma_coding_block_size_minus3");
    ngx_ts_heavc_read_ue(br, "log2_diff_max_min_luma_coding_block_size");
    ngx_ts_heavc_read_ue(br, "log2_min_luma_transform_block_size_minus2");
    ngx_ts_heavc_read_ue(br, "log2_diff_max_min_luma_transform_block_size");
    ngx_ts_heavc_read_ue(br, "max_transform_hierarchy_depth_inter");
    ngx_ts_heavc_read_ue(br, "max_transform_hierarchy_depth_intra");

    if (ngx_ts_heavc_read_u1(br, "scaling_list_enabled_flag") &&
        ngx_ts_heavc_read_u1(br, "sps_scaling_list_data_present_flag"))
    {
        ngx_ts_hevc_skip_scaling_list_data(br);
    }

    ngx_ts_heavc_skip_u(br, 2, "amp_enabled_flag...");

    if (ngx_ts_heavc_read_u1(br, "pcm_enabled_flag")) {
        ngx_ts_heavc_skip_u(br, 8, "pcm_sample_bit_depth_luma_minus1...");
        ngx_ts_heavc_read_ue(br, "log2_min_pcm_luma_coding_block_size_minus3");
        ngx_ts_heavc_read_ue(br,
            "log2_diff_max_min_pcm_luma_coding_block_size");
        ngx_ts_heavc_skip_u1(br, "pcm_loop_filter_disabled_flag");
    }

    num_short_term_ref_pic_sets = ngx_ts_heavc_read_ue(br,
        "num_short_term_ref_pic_sets");
    if (num_short_term_ref_pic_sets > HEVC_MAX_SHORT_TERM_REF_PIC_SETS) {
        ngx_log_error(NGX_LOG_ERR, br->log, 0,
            "ngx_ts_hevc_hvcc_parse_sps: "
            "num_short_term_ref_pic_sets %ui too big",
            num_short_term_ref_pic_sets);
        return NGX_ERROR;
    }

    for (i = 0; i < num_short_term_ref_pic_sets; i++) {
        if (ngx_ts_hevc_parse_rps(br, i, num_short_term_ref_pic_sets,
            num_delta_pocs) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_ts_heavc_read_u1(br, "long_term_ref_pics_present_flag")) {
        num_long_term_ref_pics_sps = ngx_ts_heavc_read_ue(br,
            "num_long_term_ref_pics_sps");
        if (num_long_term_ref_pics_sps > 31) {
            ngx_log_error(NGX_LOG_ERR, br->log, 0,
                "ngx_ts_hevc_hvcc_parse_sps: "
                "num_long_term_ref_pics_sps %ui too big",
                num_long_term_ref_pics_sps);
            return NGX_ERROR;
        }

        for (i = 0; i < num_long_term_ref_pics_sps; i++) {
            len = ngx_min(log2_max_pic_order_cnt_lsb_minus4 + 4, 16);
            ngx_ts_heavc_skip_u(br, len, "lt_ref_pic_poc_lsb_sps");
            ngx_ts_heavc_skip_u1(br, "used_by_curr_pic_lt_sps_flag");
        }
    }

    ngx_ts_heavc_skip_u(br, 2, "sps_temporal_mvp_enabled_flag...");

    if (ngx_ts_heavc_read_u1(br, "vui_parameters_present_flag")) {
        ngx_ts_hevc_hvcc_parse_vui(br, ctx, sps_max_sub_layers_minus1);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hevc_hvcc_parse_pps(ngx_ts_heavc_reader_t *br, ngx_ts_hevc_ctx_t *ctx)
{
    u_char  tiles_enabled_flag;
    u_char  entropy_coding_sync_enabled_flag;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, br->log, 0, "--- ts hevc pps ---");

    ngx_ts_heavc_read_ue(br, "pps_pic_parameter_set_id");
    ngx_ts_heavc_read_ue(br, "pps_seq_parameter_set_id");

    ngx_ts_heavc_skip_u(br, 7, "dependent_slice_segments_enabled_flag...");

    ngx_ts_heavc_read_ue(br, "num_ref_idx_l0_default_active_minus1");
    ngx_ts_heavc_read_ue(br, "num_ref_idx_l1_default_active_minus1");
    ngx_ts_heavc_read_se(br, "init_qp_minus26");

    ngx_ts_heavc_skip_u(br, 2, "constrained_intra_pred_flag...");

    if (ngx_ts_heavc_read_u1(br, "cu_qp_delta_enabled_flag")) {
        ngx_ts_heavc_read_ue(br, "diff_cu_qp_delta_depth");
    }

    ngx_ts_heavc_read_se(br, "pps_cb_qp_offset");
    ngx_ts_heavc_read_se(br, "pps_cr_qp_offset");

    ngx_ts_heavc_skip_u(br, 4, "pps_slice_chroma_qp_offsets_present_flag...");

    tiles_enabled_flag = ngx_ts_heavc_read_u1(br, "tiles_enabled_flag");
    entropy_coding_sync_enabled_flag = ngx_ts_heavc_read_u1(br,
        "entropy_coding_sync_enabled_flag");

    if (entropy_coding_sync_enabled_flag && tiles_enabled_flag) {
        ctx->parallelism_type = 0;

    } else if (entropy_coding_sync_enabled_flag) {
        ctx->parallelism_type = 3;

    } else if (tiles_enabled_flag) {
        ctx->parallelism_type = 2;

    } else {
        ctx->parallelism_type = 1;
    }

    return NGX_OK;
}


static void
ngx_ts_hevc_init_ctx(ngx_ts_hevc_ctx_t *ctx)
{
    ngx_memzero(ctx, sizeof(*ctx));

    ctx->general_profile_compatibility_flags = 0xffffffff;
    ctx->general_constraint_indicator_flags  = 0xffffffffffff;

    ctx->min_spatial_segmentation_idc = USHRT_MAX;
}


static ngx_int_t
ngx_ts_hevc_parse_nalus(ngx_ts_hevc_ctx_t *ctx, ngx_log_t *log,
    ngx_ts_hevc_nalu_array_t *nalus)
{
    u_char                  type;
    size_t                  size;
    ngx_int_t               rc;
    ngx_buf_t              *cur;
    ngx_uint_t              i;
    ngx_ts_heavc_reader_t   br;

    for (i = 0; i < nalus->nelts; i++) {
        cur = &nalus->elts[i];

        size = cur->last - cur->pos;
        if (size < HEVC_NALU_HEADER_SIZE) {
            continue;
        }

        ngx_ts_heavc_init_reader(&br, cur->pos + HEVC_NALU_HEADER_SIZE,
            size - HEVC_NALU_HEADER_SIZE, log, "hevc");

        type = ngx_ts_hevc_get_nal_type(cur->pos);
        switch (type) {

        case NGX_TS_HEVC_NAL_VPS:
            rc = ngx_ts_hevc_hvcc_parse_vps(&br, ctx);
            break;

        case NGX_TS_HEVC_NAL_SPS:
            rc = ngx_ts_hevc_hvcc_parse_sps(&br, ctx);
            break;

        case NGX_TS_HEVC_NAL_PPS:
            rc = ngx_ts_hevc_hvcc_parse_pps(&br, ctx);
            break;

        default:
            rc = NGX_OK;
            break;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        if (br.err) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_ts_hevc_parse_nalus: "
                "nal %uD stream overflow", (uint32_t) type);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static u_char *
ngx_ts_hevc_hvcc_write_header(u_char *p, ngx_ts_hevc_ctx_t *ctx)
{
    u_char    constant_frame_rate;
    u_char    configuration_version;
    u_char    length_size_minus_one;
    uint16_t  avg_frame_rate;

    configuration_version = 1;
    avg_frame_rate = 0;
    constant_frame_rate = 0;
    length_size_minus_one = 3;

    if (ctx->min_spatial_segmentation_idc > HEVC_MAX_SPATIAL_SEGMENTATION) {
        ctx->min_spatial_segmentation_idc = 0;
    }

    if (!ctx->min_spatial_segmentation_idc) {
        ctx->parallelism_type = 0;
    }

    *p++ = configuration_version;

    *p++ = ctx->general_profile_space << 6
        | ctx->general_tier_flag << 5
        | ctx->general_profile_idc;

    ngx_ts_hevc_write_be32(p, ctx->general_profile_compatibility_flags);

    ngx_ts_hevc_write_be32(p, ctx->general_constraint_indicator_flags >> 16);
    ngx_ts_hevc_write_be16(p, ctx->general_constraint_indicator_flags);

    *p++ = ctx->general_level_idc;

    ngx_ts_hevc_write_be16(p, 0xf000 | ctx->min_spatial_segmentation_idc);

    *p++ = 0xfc | ctx->parallelism_type;

    *p++ = 0xfc | ctx->chroma_format_idc;

    *p++ = 0xf8 | ctx->bit_depth_luma_minus8;

    *p++ = 0xf8 | ctx->bit_depth_chroma_minus8;

    ngx_ts_hevc_write_be16(p, avg_frame_rate);

    *p++ = constant_frame_rate << 6
        | ctx->num_temporal_layers << 3
        | ctx->sps_temporal_id_nesting_flag  << 2
        | length_size_minus_one;

    return p;
}


static u_char *
ngx_ts_hevc_hvcc_write_nalus(u_char *p, ngx_ts_hevc_nalu_array_t *nalus)
{
    u_char       type;
    u_char      *num_of_arrays;
    u_char      *pnum_nalus;
    size_t       size;
    uint64_t     seen_types;
    ngx_buf_t   *b;
    ngx_uint_t   i, j;
    ngx_uint_t   num_nalus;

    num_of_arrays = p;
    *p++ = 0;

    seen_types = 0;

    for (i = 0; i < nalus->nelts; i++) {
        b = &nalus->elts[i];

        type = ngx_ts_hevc_get_nal_type(b->pos);
        if (seen_types & (1ULL << type)) {
            continue;
        }

        seen_types |= (1ULL << type);

        *p++ = 0x80 | type;     /* array_completeness */

        num_nalus = 0;
        pnum_nalus = p;
        p += 2;

        for (j = i; j < nalus->nelts; j++) {
            b = &nalus->elts[j];
            if (ngx_ts_hevc_get_nal_type(b->pos) != type) {
                continue;
            }

            size = b->last - b->pos;

            ngx_ts_hevc_write_be16(p, size);

            p = ngx_copy(p, b->pos, size);

            num_nalus++;
        }

        ngx_ts_hevc_write_be16(pnum_nalus, num_nalus);

        (*num_of_arrays)++;
    }

    return p;
}


size_t
ngx_ts_hevc_hvcc_get_size(ngx_ts_hevc_nalu_array_t *nalus)
{
    size_t       size;
    u_char       type;
    uint64_t     seen_types;
    ngx_buf_t   *b;
    ngx_uint_t   i;

    seen_types = 0;
    size = HEVC_HVCC_HEADER_SIZE + 1;   /* 1 = num_of_arrays */

    for (i = 0; i < nalus->nelts; i++) {
        b = &nalus->elts[i];

        size += 2 + (b->last - b->pos);

        type = ngx_ts_hevc_get_nal_type(b->pos);
        if (seen_types & (1ULL << type)) {
            continue;
        }

        seen_types |= 1ULL << type;
        size += 1 + 2;      /* 1 = type, 2 = num_nalus */
    }

    return size;
}


static ngx_int_t
ngx_ts_hevc_init_params(ngx_ts_hevc_ctx_t *ctx, ngx_log_t *log,
    ngx_ts_hevc_params_t *params)
{
    uint32_t  sub_width_c, sub_height_c;
    uint32_t  clipped_width, clipped_height;

    static u_char  sub_width_c_table[] =  { 1, 2, 2, 1 };
    static u_char  sub_height_c_table[] = { 1, 2, 1, 1 };

    ngx_memzero(params, sizeof(*params));

    if (!ctx->separate_colour_plane_flag && ctx->chroma_format_idc < 4) {
        sub_width_c = sub_width_c_table[ctx->chroma_format_idc];
        sub_height_c = sub_height_c_table[ctx->chroma_format_idc];

    } else {
        sub_width_c = sub_height_c = 1;
    }

    clipped_width = (ctx->conf_win_left_offset + ctx->conf_win_right_offset)
        * sub_width_c;
    clipped_height = (ctx->conf_win_top_offset + ctx->conf_win_bottom_offset)
        * sub_height_c;

    if (clipped_width >= ctx->pic_width_in_luma_samples) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_hevc_init_params: "
            "clipped_width %uD larger than width %uD",
            clipped_width, ctx->pic_width_in_luma_samples);
        return NGX_ERROR;
    }

    if (clipped_height >= ctx->pic_height_in_luma_samples) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_hevc_init_params: "
            "clipped_height %uD larger than height %uD",
            clipped_height, ctx->pic_height_in_luma_samples);
        return NGX_ERROR;
    }

    params->width = ctx->pic_width_in_luma_samples - clipped_width;
    params->height = ctx->pic_height_in_luma_samples - clipped_height;

    return NGX_OK;
}


u_char *
ngx_ts_hevc_hvcc_write(u_char *p, ngx_log_t *log,
    ngx_ts_hevc_nalu_array_t *nalus, ngx_ts_hevc_params_t *params)
{
    ngx_ts_hevc_ctx_t  ctx;

    ngx_ts_hevc_init_ctx(&ctx);

    if (ngx_ts_hevc_parse_nalus(&ctx, log, nalus) != NGX_OK) {
        return NULL;
    }

    if (ngx_ts_hevc_init_params(&ctx, log, params) != NGX_OK) {
        return NULL;
    }

    p = ngx_ts_hevc_hvcc_write_header(p, &ctx);

    p = ngx_ts_hevc_hvcc_write_nalus(p, nalus);

    return p;
}


ngx_int_t
ngx_ts_hevc_get_ps_id(ngx_buf_t *b, ngx_log_t *log, uint32_t *idp)
{
    u_char                 type;
    size_t                 size;
    uint32_t               id;
    ngx_uint_t             sps_max_sub_layers_minus1;
    ngx_ts_heavc_reader_t  br;

    size = b->last - b->pos;
    if (size < HEVC_NALU_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_hevc_get_ps_id: invalid buffer size %uz", size);
        return NGX_ERROR;
    }

    ngx_ts_heavc_init_reader(&br, b->pos + HEVC_NALU_HEADER_SIZE,
        size - HEVC_NALU_HEADER_SIZE, log, "hevc");

    type = ngx_ts_hevc_get_nal_type(b->pos);
    switch (type) {

    case NGX_TS_HEVC_NAL_VPS:
        id = ngx_ts_heavc_read_u(&br, 4, "vps_video_parameter_set_id");
        break;

    case NGX_TS_HEVC_NAL_SPS:
        ngx_ts_heavc_skip_u(&br, 4, "sps_video_parameter_set_id");

        sps_max_sub_layers_minus1 = ngx_ts_heavc_read_u(&br, 3,
            "sps_max_sub_layers_minus1");

        ngx_ts_heavc_skip_u1(&br, "sps_temporal_id_nesting_flag");

        ngx_ts_hevc_parse_ptl(&br, NULL, sps_max_sub_layers_minus1);

        id = ngx_ts_heavc_read_ue(&br, "sps_seq_parameter_set_id");
        break;

    case NGX_TS_HEVC_NAL_PPS:
        id = ngx_ts_heavc_read_ue(&br, "pps_pic_parameter_set_id");
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_hevc_get_ps_id: invalid nalu type %uD", (uint32_t) type);
        return NGX_ERROR;
    }

    if (br.err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_ts_hevc_get_ps_id: stream overflow");
        return NGX_ERROR;
    }

    *idp = (type << 16) | id;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
        "ngx_ts_hevc_get_ps_id: 0x%uxD", *idp);

    return NGX_OK;
}
