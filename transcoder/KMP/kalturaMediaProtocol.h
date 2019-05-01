#ifndef _LIVE_PROTOCOL_H_INCLUDED_
#define _LIVE_PROTOCOL_H_INCLUDED_

enum {
    LIVE_CODEC_ID_VIDEO_JPEG = 1,
    LIVE_CODEC_ID_VIDEO_SORENSON_H263 = 2,
    LIVE_CODEC_ID_VIDEO_SCREEN = 3,
    LIVE_CODEC_ID_VIDEO_ON2_VP6 = 4,
    LIVE_CODEC_ID_VIDEO_ON2_VP6_ALPHA = 5,
    LIVE_CODEC_ID_VIDEO_SCREEN2 = 6,
    LIVE_CODEC_ID_VIDEO_H264 = 7,
    
    LIVE_CODEC_ID_AUDIO_UNCOMPRESSED = 1016,
    LIVE_CODEC_ID_AUDIO_ADPCM = 1001,
    LIVE_CODEC_ID_AUDIO_MP3 = 1002,
    LIVE_CODEC_ID_AUDIO_LINEAR_LE = 1003,
    LIVE_CODEC_ID_AUDIO_NELLY16 = 1004,
    LIVE_CODEC_ID_AUDIO_NELLY8 = 1005,
    LIVE_CODEC_ID_AUDIO_NELLY = 1006,
    LIVE_CODEC_ID_AUDIO_G711A = 1007,
    LIVE_CODEC_ID_AUDIO_G711U = 1008,
    LIVE_CODEC_ID_AUDIO_AAC = 1010,
    LIVE_CODEC_ID_AUDIO_SPEEX = 1011,
    LIVE_CODEC_ID_AUDIO_MP3_8 = 1014,
    LIVE_CODEC_ID_AUDIO_DEVSPEC = 1015,
};

typedef struct {
    uint16_t den,num;
} rational_t;

typedef struct {
    uint16_t channels;
    uint16_t bits_per_sample;
    uint32_t sample_rate;
} live_audio_media_info_t;

typedef struct {
    uint16_t width;
    uint16_t height;
    rational_t frame_rate;        // currently rounded by nginx-rtmp, will need a patch to avoid it
} live_video_media_info_t;

typedef struct {
    uint32_t media_type;    // 0 = video, 1 = audio
    uint32_t codec_id;        // currently rtmp enum
    uint32_t timescale;        // currently hardcoded to 90k, maybe for audio we should use the sample rate
    uint32_t bitrate;        // bps    (rtmp module returns in kbps, will multiply by 1000)
    union {
        live_video_media_info_t video;
        live_audio_media_info_t audio;
    } u;
} live_media_info_t;

typedef struct {
    uint64_t created;
    uint64_t dts;
    uint32_t flags;
    uint32_t pts_delay;
} frame_info_t;

#define FRAME_FLAG_KEY (0x01)

#define PACKET_TYPE_CONNECT (1)
#define PACKET_TYPE_MEDIA_INFO (2)
#define PACKET_TYPE_FRAME (3)
#define PACKET_TYPE_EOS (4)

#define MAX_SET_ID (32)
#define MAX_TRACK_ID (32)


enum {
    LIVE_MEDIA_TYPE_VIDEO,
    LIVE_MEDIA_TYPE_AUDIO,
    LIVE_MEDIA_TYPE_COUNT,
};

typedef struct {
    uint32_t packet_type;
    uint32_t header_size;
    uint32_t data_size;
    uint32_t reserved;
} packet_header_t;

typedef struct {
    packet_header_t header;
    u_char set_id[MAX_SET_ID];
    u_char track_id[MAX_TRACK_ID];
} connect_header_t;

typedef struct {
    packet_header_t header;
    live_media_info_t m;
} media_info_packet_t;

typedef struct {
    packet_header_t header;
    frame_info_t f;
} frame_packet_t;

#endif /* _LIVE_PROTOCOL_H_INCLUDED_ */
