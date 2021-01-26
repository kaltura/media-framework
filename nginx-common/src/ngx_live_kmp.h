#ifndef _NGX_LIVE_KMP_H_INCLUDED_
#define _NGX_LIVE_KMP_H_INCLUDED_


/* constants */
#define KMP_MAX_CHANNEL_ID_LEN  (32)
#define KMP_MAX_TRACK_ID_LEN    (32)

#define KMP_MAX_HEADER_SIZE     (64 * 1024)
#define KMP_MAX_DATA_SIZE       (16 * 1024 * 1024)

#define KMP_FRAME_FLAG_KEY      (0x01)
#define KMP_FRAME_FLAG_MASK     (KMP_FRAME_FLAG_KEY)

/* matches ffmpeg AV_CH_XXX */
#define KMP_CH_FRONT_LEFT       0x00000001
#define KMP_CH_FRONT_RIGHT      0x00000002
#define KMP_CH_FRONT_CENTER     0x00000004

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
    uint32_t             num;
    uint32_t             denom;
} kmp_rational_t;

typedef struct {
    uint16_t             channels;
    uint16_t             bits_per_sample;
    uint32_t             sample_rate;
    uint64_t             channel_layout;
} kmp_audio_media_info_t;

typedef struct {
    uint16_t             width;
    uint16_t             height;
    kmp_rational_t       frame_rate;
    uint32_t             cea_captions;
} kmp_video_media_info_t;

typedef struct kmp_media_info_s kmp_media_info_t;

struct kmp_media_info_s {
    uint32_t             media_type;
    uint32_t             codec_id;
    uint32_t             timescale;     /* currently hardcoded to 90k */
    uint32_t             bitrate;       /* bps */
    union {
        kmp_video_media_info_t  video;
        kmp_audio_media_info_t  audio;
    } u;
};

typedef struct {
    int64_t              created;
    int64_t              dts;
    uint32_t             flags;
    uint32_t             pts_delay;
} kmp_frame_t;

/* packets */
typedef struct {
    uint32_t             packet_type;
    uint32_t             header_size;
    uint32_t             data_size;
    uint32_t             reserved;
} kmp_packet_header_t;

typedef struct {
    kmp_packet_header_t  header;
    u_char               channel_id[KMP_MAX_CHANNEL_ID_LEN];
    u_char               track_id[KMP_MAX_TRACK_ID_LEN];
    uint64_t             initial_frame_id;
    uint32_t             initial_offset;
    uint32_t             padding;
} kmp_connect_packet_t;

typedef struct {
    kmp_packet_header_t  header;
    kmp_media_info_t     m;
} kmp_media_info_packet_t;

typedef struct {
    kmp_packet_header_t  header;
    kmp_frame_t          f;
} kmp_frame_packet_t;

typedef struct {
    kmp_packet_header_t  header;
    uint64_t             frame_id;
    uint32_t             offset;
    uint32_t             padding;
} kmp_ack_frames_packet_t;

#endif /* _NGX_LIVE_KMP_H_INCLUDED_ */
