#ifndef __MEDIA_FORMAT_H__
#define __MEDIA_FORMAT_H__

// includes
#include "codec_config.h"
#include "frames_source.h"

// macros
#define rescale_time(time, cur_scale, new_scale) ((((uint64_t)(time)) * (new_scale) + (cur_scale) / 2) / (cur_scale))
#define rescale_time_neg(time, cur_scale, new_scale) ((time) >= 0 ? rescale_time(time, cur_scale, new_scale) : -rescale_time(-(time), cur_scale, new_scale))

#define media_null_bitrate_estimator(est) {                                 \
        (est).k1.num = 1;                                                   \
        (est).k1.den = 1;                                                   \
        (est).k2 = 0;                                                       \
        (est).k3 = 0;                                                       \
    }

#define media_bitrate_estimate(est, bitrate, segment_duration) \
    (uint64_t)(bitrate) * (est).k1.num / (est).k1.den + (uint64_t)(est).k2 * 1000 / (segment_duration) + (est).k3

// constants
#define MAX_CODEC_NAME_SIZE (64)

#define VOD_ENC_KEY_SIZE     (16)
#define VOD_ENC_IV_SIZE      (16)
#define VOD_ENC_KID_SIZE     (16)
#define VOD_ENC_SYS_ID_SIZE  (16)

#define VOD_CODEC_FLAG(name) (1 << (VOD_CODEC_ID_##name - 1))

#define vod_codec_in_mask(codec_id, mask) (((mask) & (1 << ((codec_id) - 1))) != 0)

// enums
enum {
    VOD_CODEC_ID_INVALID,

    // video
    VOD_CODEC_ID_VIDEO,
    VOD_CODEC_ID_AVC = VOD_CODEC_ID_VIDEO,
    VOD_CODEC_ID_HEVC,
    VOD_CODEC_ID_VP8,
    VOD_CODEC_ID_VP9,
    VOD_CODEC_ID_AV1,

    // audio
    VOD_CODEC_ID_AUDIO,
    VOD_CODEC_ID_AAC = VOD_CODEC_ID_AUDIO,
    VOD_CODEC_ID_AC3,
    VOD_CODEC_ID_EAC3,
    VOD_CODEC_ID_MP3,
    VOD_CODEC_ID_DTS,
    VOD_CODEC_ID_VORBIS,
    VOD_CODEC_ID_OPUS,
    VOD_CODEC_ID_VOLUME_MAP,

    // captions
    VOD_CODEC_ID_SUBTITLE,
    VOD_CODEC_ID_WEBVTT = VOD_CODEC_ID_SUBTITLE,
    VOD_CODEC_ID_TTML,

    VOD_CODEC_ID_COUNT
};

typedef struct {
    uint16_t width;
    uint16_t height;
    uint32_t nal_packet_size_length;
    uint8_t transfer_characteristics;
    uint8_t cea_captions;
    uint32_t frame_rate_num;
    uint32_t frame_rate_denom;
} video_media_info_t;

typedef struct {
    uint8_t object_type_id;
    uint16_t channels;
    uint64_t channel_layout;
    uint16_t bits_per_sample;
    uint32_t sample_rate;
    mp4a_config_t codec_config;
} audio_media_info_t;

typedef struct media_info_s {
    uint32_t media_type;
    uint32_t format;
    uint32_t timescale;
    uint32_t bitrate;
    uint32_t avg_bitrate;
    uint32_t codec_id;
    vod_str_t codec_name;
    vod_str_t extra_data;
    vod_str_t parsed_extra_data;
    union {
        video_media_info_t video;
        audio_media_info_t audio;
    } u;
} media_info_t;


typedef struct {
    u_char id[VOD_ENC_SYS_ID_SIZE];
    vod_str_t data;
    vod_str_t base64_data;
} media_enc_sys_t;

typedef struct {
    u_char key[VOD_ENC_KEY_SIZE];
    u_char iv[VOD_ENC_IV_SIZE];
    u_char key_id[VOD_ENC_KID_SIZE];
    vod_array_t systems;    /* media_enc_sys_t */
    void* ctx;
    unsigned has_key_id:1;
} media_enc_t;


typedef struct {
    media_info_t* media_info;
    media_enc_t* enc;

    vod_list_t frames;        // input_frame_t
    vod_uint_t frame_count;
    int64_t start_dts;

    frames_source_t* frames_source;
    void* frames_source_context;
} media_segment_track_t;

typedef struct {
    uint32_t segment_index;
    uint32_t duration;
    int64_t start;
    media_segment_track_t* tracks;
    media_segment_track_t* tracks_end;
    uint32_t track_count;
    vod_str_t metadata;
} media_segment_t;

typedef struct {
    media_info_t* media_info;
    media_enc_t* enc;
    vod_str_t stsd_atom;
} media_init_segment_track_t;

typedef struct {
    media_init_segment_track_t* first;
    media_init_segment_track_t* last;
    uint32_t count;
    vod_str_t lang;
} media_init_segment_t;

typedef struct {
    uint32_t num;
    uint32_t den;
} media_rational_t;

/* final_bitrate = k1 * net_bitrate + k2 / segment_duration + k3 */
typedef struct {
    media_rational_t k1;
    uint32_t k2;
    uint32_t k3;
} media_bitrate_estimator_t;


size_t media_segment_track_get_total_size(media_segment_track_t* track);

#endif //__MEDIA_FORMAT_H__
