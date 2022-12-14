#ifndef __AVC_DEFS_H__
#define __AVC_DEFS_H__

// NAL unit types
enum {
    AVC_NAL_SLICE           = 1,
    AVC_NAL_DPA             = 2,
    AVC_NAL_DPB             = 3,
    AVC_NAL_DPC             = 4,
    AVC_NAL_IDR_SLICE       = 5,
    AVC_NAL_SEI             = 6,
    AVC_NAL_SPS             = 7,
    AVC_NAL_PPS             = 8,
    AVC_NAL_AUD             = 9,
    AVC_NAL_END_SEQUENCE    = 10,
    AVC_NAL_END_STREAM      = 11,
    AVC_NAL_FILLER_DATA     = 12,
    AVC_NAL_SPS_EXT         = 13,
    AVC_NAL_AUXILIARY_SLICE = 19,
};

enum {
    HEVC_NAL_TRAIL_N = 0,
    HEVC_NAL_TRAIL_R = 1,
    HEVC_NAL_TSA_N = 2,
    HEVC_NAL_TSA_R = 3,
    HEVC_NAL_STSA_N = 4,
    HEVC_NAL_STSA_R = 5,
    HEVC_NAL_RADL_N = 6,
    HEVC_NAL_RADL_R = 7,
    HEVC_NAL_RASL_N = 8,
    HEVC_NAL_RASL_R = 9,
    HEVC_NAL_BLA_W_LP = 16,
    HEVC_NAL_BLA_W_RADL = 17,
    HEVC_NAL_BLA_N_LP = 18,
    HEVC_NAL_IDR_W_RADL = 19,
    HEVC_NAL_IDR_N_LP = 20,
    HEVC_NAL_CRA_NUT = 21,
    HEVC_NAL_RSV_IRAP_VCL22 = 22,
    HEVC_NAL_RSV_IRAP_VCL23 = 23,
    HEVC_NAL_VPS_NUT = 32,
    HEVC_NAL_SPS_NUT = 33,
    HEVC_NAL_PPS_NUT = 34,
    HEVC_NAL_AUD_NUT = 35,
    HEVC_NAL_EOS_NUT = 36,
    HEVC_NAL_EOB_NUT = 37,
    HEVC_NAL_FD_NUT = 38,
    HEVC_NAL_PREFIX_SEI_NUT = 39,
    HEVC_NAL_SUFFIX_SEI_NUT = 40,
};

#endif // __AVC_DEFS_H__
