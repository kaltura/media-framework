#ifndef _NGX_LIVE_KMP_H_INCLUDED_
#define _NGX_LIVE_KMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* constants */
#define KMP_MAX_CHANNEL_ID_LEN  (32)
#define KMP_MAX_TRACK_ID_LEN    (32)

#define KMP_MAX_HEADER_SIZE     (64 * 1024)
#define KMP_MAX_DATA_SIZE       (16 * 1024 * 1024)

#define KMP_FRAME_FLAG_KEY      (0x01)
#define KMP_FRAME_FLAG_MASK     (KMP_FRAME_FLAG_KEY)

#define KMP_MEDIA_TYPE_MASK     ((1 << KMP_MEDIA_COUNT) - 1)

/* matches ffmpeg AV_CH_XXX */
#define KMP_CH_FRONT_LEFT               0x00000001
#define KMP_CH_FRONT_RIGHT              0x00000002
#define KMP_CH_FRONT_CENTER             0x00000004
#define KMP_CH_LOW_FREQUENCY            0x00000008
#define KMP_CH_BACK_LEFT                0x00000010
#define KMP_CH_BACK_RIGHT               0x00000020
#define KMP_CH_FRONT_LEFT_OF_CENTER     0x00000040
#define KMP_CH_FRONT_RIGHT_OF_CENTER    0x00000080
#define KMP_CH_BACK_CENTER              0x00000100
#define KMP_CH_SIDE_LEFT                0x00000200
#define KMP_CH_SIDE_RIGHT               0x00000400
#define KMP_CH_TOP_CENTER               0x00000800
#define KMP_CH_TOP_FRONT_LEFT           0x00001000
#define KMP_CH_TOP_FRONT_CENTER         0x00002000
#define KMP_CH_TOP_FRONT_RIGHT          0x00004000
#define KMP_CH_TOP_BACK_LEFT            0x00008000
#define KMP_CH_TOP_BACK_CENTER          0x00010000
#define KMP_CH_TOP_BACK_RIGHT           0x00020000
#define KMP_CH_WIDE_LEFT                0x0000000080000000ULL
#define KMP_CH_WIDE_RIGHT               0x0000000100000000ULL
#define KMP_CH_SURROUND_DIRECT_LEFT     0x0000000200000000ULL
#define KMP_CH_SURROUND_DIRECT_RIGHT    0x0000000400000000ULL
#define KMP_CH_LOW_FREQUENCY_2          0x0000000800000000ULL

#define KMP_CH_LAYOUT_MONO      (KMP_CH_FRONT_CENTER)
#define KMP_CH_LAYOUT_STEREO    (KMP_CH_FRONT_LEFT|KMP_CH_FRONT_RIGHT)

/* enums */
enum {
    /* client -> server */
    KMP_PACKET_CONNECT              = 0x74636e63,   /* cnct */
    KMP_PACKET_MEDIA_INFO           = 0x666e696d,   /* minf */
    KMP_PACKET_FRAME                = 0x6d617266,   /* fram */
    KMP_PACKET_END_OF_STREAM        = 0x74736f65,   /* eost */

    /* server -> client */
    KMP_PACKET_ACK_FRAMES           = 0x666b6361,   /* ackf */
};

enum {
    KMP_MEDIA_VIDEO,
    KMP_MEDIA_AUDIO,
    KMP_MEDIA_COUNT,
};

enum {
    /* aligns with NGX_RTMP_VIDEO_XXX */
    KMP_CODEC_VIDEO_JPEG            = 1,
    KMP_CODEC_VIDEO_SORENSON_H263   = 2,
    KMP_CODEC_VIDEO_SCREEN          = 3,
    KMP_CODEC_VIDEO_ON2_VP6         = 4,
    KMP_CODEC_VIDEO_ON2_VP6_ALPHA   = 5,
    KMP_CODEC_VIDEO_SCREEN2         = 6,
    KMP_CODEC_VIDEO_H264            = 7,

    /* NGX_RTMP_AUDIO_XXX + 1000 */
    KMP_CODEC_AUDIO_UNCOMPRESSED    = 1016,
    KMP_CODEC_AUDIO_ADPCM           = 1001,
    KMP_CODEC_AUDIO_MP3             = 1002,
    KMP_CODEC_AUDIO_LINEAR_LE       = 1003,
    KMP_CODEC_AUDIO_NELLY16         = 1004,
    KMP_CODEC_AUDIO_NELLY8          = 1005,
    KMP_CODEC_AUDIO_NELLY           = 1006,
    KMP_CODEC_AUDIO_G711A           = 1007,
    KMP_CODEC_AUDIO_G711U           = 1008,
    KMP_CODEC_AUDIO_AAC             = 1010,
    KMP_CODEC_AUDIO_SPEEX           = 1011,
    KMP_CODEC_AUDIO_MP3_8           = 1014,
    KMP_CODEC_AUDIO_DEVSPEC         = 1015,
};


/* basic types */
typedef struct {
    uint32_t                num;
    uint32_t                denom;
} kmp_rational_t;

typedef struct {
    uint16_t                channels;
    uint16_t                bits_per_sample;
    uint32_t                sample_rate;
    uint64_t                channel_layout;
} kmp_audio_media_info_t;

typedef struct {
    uint16_t                width;
    uint16_t                height;
    kmp_rational_t          frame_rate;
    uint32_t                cea_captions;
} kmp_video_media_info_t;

typedef union {
    kmp_video_media_info_t  video;
    kmp_audio_media_info_t  audio;
} kmp_media_info_union_t;

typedef struct {
    uint32_t                media_type;
    uint32_t                codec_id;
    uint32_t                timescale;     /* currently hardcoded to 90k */
    uint32_t                bitrate;       /* bps */
    kmp_media_info_union_t  u;
} kmp_media_info_t;

typedef struct {
    int64_t                 created;
    int64_t                 dts;
    uint32_t                flags;
    int32_t                 pts_delay;
} kmp_frame_t;

/* packets */
typedef struct {
    uint32_t                packet_type;
    uint32_t                header_size;
    uint32_t                data_size;
    uint32_t                reserved;
} kmp_packet_header_t;

typedef struct {
    kmp_packet_header_t     header;
    u_char                  channel_id[KMP_MAX_CHANNEL_ID_LEN];
    u_char                  track_id[KMP_MAX_TRACK_ID_LEN];
    uint64_t                initial_frame_id;
    uint32_t                initial_offset;
    uint32_t                padding;
} kmp_connect_packet_t;

typedef struct {
    kmp_packet_header_t     header;
    kmp_media_info_t        m;
} kmp_media_info_packet_t;

typedef struct {
    kmp_packet_header_t     header;
    kmp_frame_t             f;
} kmp_frame_packet_t;

typedef struct {
    kmp_packet_header_t     header;
    uint64_t                frame_id;
    uint32_t                offset;
    uint32_t                padding;
} kmp_ack_frames_packet_t;

#endif /* _NGX_LIVE_KMP_H_INCLUDED_ */
