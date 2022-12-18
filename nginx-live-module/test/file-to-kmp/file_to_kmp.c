#include <libavutil/intreadwrite.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <getopt.h>
#include <sys/types.h>
#include "../../../nginx-common/src/ngx_live_kmp.h"


#define OUTPUT_TIMESCALE  90000


enum {
    EXIT_ERROR = 2,
};


typedef struct {
    size_t    len;
    u_char   *data;
} str_t;


typedef struct {
    int64_t   base_created;
    int       annex_b;
} kmp_write_frame_ctx_t;


static char *  program_name;
static int     show_help = 0;

static char const           short_options[] = "s:c:";
static struct option const  long_options[] =
{
    {"stream", required_argument, NULL, 's'},
    {"created", required_argument, NULL, 'c'},
    {"help", no_argument, &show_help, 1},
    {0, 0, 0, 0}
};

/* utils */
static void
verror(int errnum, const char *message, va_list args)
{
    char const  *s;

    fflush(stdout);

    fprintf(stderr, "%s: ", program_name);
    vfprintf(stderr, message, args);
    if (errnum) {
        s = strerror(errnum);
        fprintf(stderr, ": %s", s);
    }
    putc('\n', stderr);
    fflush(stderr);
}


static void
error(int errnum, const char *message, ...)
{
    va_list  args;

    va_start(args, message);
    verror(errnum, message, args);
    va_end(args);
}


/* ffmpeg */
enum {
    // 7.4.2.1.1: seq_parameter_set_id is in [0, 31].
    H264_MAX_SPS_COUNT = 32,
    // 7.4.2.2: pic_parameter_set_id is in [0, 255].
    H264_MAX_PPS_COUNT = 256,
};

static const uint8_t *
ff_avc_find_startcode_internal(const uint8_t *p, const uint8_t *end)
{
    const uint8_t *a = p + 4 - ((intptr_t) p & 3);

    for (end -= 3; p < a && p < end; p++) {
        if (p[0] == 0 && p[1] == 0 && p[2] == 1)
            return p;
    }

    for (end -= 3; p < end; p += 4) {
        uint32_t x = *(const uint32_t *) p;
        //      if ((x - 0x01000100) & (~x) & 0x80008000) // little endian
        //      if ((x - 0x00010001) & (~x) & 0x00800080) // big endian
        if ((x - 0x01010101) & (~x) & 0x80808080) { // generic
            if (p[1] == 0) {
                if (p[0] == 0 && p[2] == 1)
                    return p;
                if (p[2] == 0 && p[3] == 1)
                    return p + 1;
            }
            if (p[3] == 0) {
                if (p[2] == 0 && p[4] == 1)
                    return p + 2;
                if (p[4] == 0 && p[5] == 1)
                    return p + 3;
            }
        }
    }

    for (end += 3; p < end; p++) {
        if (p[0] == 0 && p[1] == 0 && p[2] == 1)
            return p;
    }

    return end + 3;
}


static const uint8_t *
ff_avc_find_startcode(const uint8_t *p, const uint8_t *end) {
    const uint8_t *out = ff_avc_find_startcode_internal(p, end);
    if (p < out && out < end && !out[-1]) out--;
    return out;
}


static int
ff_avc_parse_nal_units(AVIOContext *pb, const uint8_t *buf_in, int size)
{
    const uint8_t *p = buf_in;
    const uint8_t *end = p + size;
    const uint8_t *nal_start, *nal_end;

    size = 0;
    nal_start = ff_avc_find_startcode(p, end);
    for ( ;; ) {
        while (nal_start < end && !*(nal_start++));
        if (nal_start == end)
            break;

        nal_end = ff_avc_find_startcode(nal_start, end);
        avio_wb32(pb, nal_end - nal_start);
        avio_write(pb, nal_start, nal_end - nal_start);
        size += 4 + nal_end - nal_start;
        nal_start = nal_end;
    }
    return size;
}


static int
ff_avc_parse_nal_units_buf(const uint8_t *buf_in, uint8_t **buf, int *size)
{
    AVIOContext *pb;
    int ret = avio_open_dyn_buf(&pb);
    if (ret < 0)
        return ret;

    ff_avc_parse_nal_units(pb, buf_in, *size);

    av_freep(buf);
    *size = avio_close_dyn_buf(pb, buf);
    return 0;
}


static int
ff_isom_write_avcc(AVIOContext *pb, const uint8_t *data, int len)
{
    AVIOContext *sps_pb = NULL, *pps_pb = NULL;
    uint8_t *buf = NULL, *end, *start = NULL;
    uint8_t *sps = NULL, *pps = NULL;
    uint32_t sps_size = 0, pps_size = 0;
    int ret, nb_sps = 0, nb_pps = 0;

    if (len <= 6)
        return AVERROR_INVALIDDATA;

    /* check for H.264 start code */
    if (AV_RB32(data) != 0x00000001 &&
        AV_RB24(data) != 0x000001) {
        avio_write(pb, data, len);
        return 0;
    }

    ret = ff_avc_parse_nal_units_buf(data, &buf, &len);
    if (ret < 0)
        return ret;
    start = buf;
    end = buf + len;

    ret = avio_open_dyn_buf(&sps_pb);
    if (ret < 0)
        goto fail;
    ret = avio_open_dyn_buf(&pps_pb);
    if (ret < 0)
        goto fail;

    /* look for sps and pps */
    while (end - buf > 4) {
        uint32_t size;
        uint8_t nal_type;
        size = FFMIN(AV_RB32(buf), end - buf - 4);
        buf += 4;
        nal_type = buf[0] & 0x1f;

        if (nal_type == 7) { /* SPS */
            nb_sps++;
            if (size > UINT16_MAX || nb_sps >= H264_MAX_SPS_COUNT) {
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            avio_wb16(sps_pb, size);
            avio_write(sps_pb, buf, size);

        } else if (nal_type == 8) { /* PPS */
            nb_pps++;
            if (size > UINT16_MAX || nb_pps >= H264_MAX_PPS_COUNT) {
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            avio_wb16(pps_pb, size);
            avio_write(pps_pb, buf, size);
        }

        buf += size;
    }
    sps_size = avio_close_dyn_buf(sps_pb, &sps);
    pps_size = avio_close_dyn_buf(pps_pb, &pps);

    if (sps_size < 6 || !pps_size) {
        ret = AVERROR_INVALIDDATA;
        goto fail;
    }

    avio_w8(pb, 1); /* version */
    avio_w8(pb, sps[3]); /* profile */
    avio_w8(pb, sps[4]); /* profile compat */
    avio_w8(pb, sps[5]); /* level */
    avio_w8(pb, 0xff); /* 6 bits reserved (111111) + 2 bits nal size length - 1 (11) */
    avio_w8(pb, 0xe0 | nb_sps); /* 3 bits reserved (111) + 5 bits number of sps */

    avio_write(pb, sps, sps_size);
    avio_w8(pb, nb_pps); /* number of pps */
    avio_write(pb, pps, pps_size);

fail:
    if (!sps)
        avio_close_dyn_buf(sps_pb, &sps);
    if (!pps)
        avio_close_dyn_buf(pps_pb, &pps);
    av_free(sps);
    av_free(pps);
    av_free(start);

    return ret;
}


/* ffmpeg extension */
static int
ff_avc_parse_nal_units_size(const uint8_t *buf_in, int size)
{
    AVIOContext  *pb;
    u_char        buf[128];
    int           ret;

    pb = avio_alloc_context(buf, sizeof(buf), AVIO_FLAG_WRITE, NULL, NULL,
        NULL, NULL);
    if (pb == NULL) {
        error(0, "avio_alloc_context failed");
        return -1;
    }

    ret = ff_avc_parse_nal_units(pb, buf_in, size);

    avio_context_free(&pb);

    return ret;
}


/* kmp */
static uint32_t
kmp_get_audio_codec(int codec_id)
{
    switch (codec_id) {
    case AV_CODEC_ID_AAC:
        return KMP_CODEC_AUDIO_AAC;
    case AV_CODEC_ID_MP3:
        return KMP_CODEC_AUDIO_MP3;
    default:
        return 0;
    }
}


static uint32_t
kmp_get_video_codec(int codec_id)
{
    switch (codec_id) {
    case AV_CODEC_ID_FLV1:
        return KMP_CODEC_VIDEO_SORENSON_H263;
    case AV_CODEC_ID_FLASHSV:
        return KMP_CODEC_VIDEO_SCREEN;
    case AV_CODEC_ID_FLASHSV2:
        return KMP_CODEC_VIDEO_SCREEN2;
    case AV_CODEC_ID_VP6F:
        return KMP_CODEC_VIDEO_ON2_VP6;
    case AV_CODEC_ID_VP6A:
        return KMP_CODEC_VIDEO_ON2_VP6_ALPHA;
    case AV_CODEC_ID_H264:
        return KMP_CODEC_VIDEO_H264;
    default:
        return 0;
    }
}


static int
kmp_get_mediainfo(AVStream *stream, kmp_media_info_t *media_info,
    str_t *extra_data, int *annex_b)
{
    uint8_t            *tmp;
    AVIOContext        *extra;
    AVCodecParameters  *codecpar;

    codecpar = stream->codecpar;

    *annex_b = 0;

    extra_data->data = NULL;
    extra_data->len = codecpar->extradata_size;

    media_info->bitrate = (uint32_t) codecpar->bit_rate;
    media_info->timescale = OUTPUT_TIMESCALE;

    switch (codecpar->codec_type) {

    case AVMEDIA_TYPE_VIDEO:
        media_info->media_type = KMP_MEDIA_VIDEO;
        media_info->codec_id = kmp_get_video_codec(codecpar->codec_id);
        if (media_info->codec_id == 0) {
            error(0, "failed to get video codec %d", codecpar->codec_id);
            return -1;
        }

        media_info->u.video.width = codecpar->width;
        media_info->u.video.height = codecpar->height;
        media_info->u.video.frame_rate.denom = stream->avg_frame_rate.den;
        media_info->u.video.frame_rate.num = stream->avg_frame_rate.num;
        media_info->u.video.cea_captions = 0;

        if (media_info->codec_id == KMP_CODEC_VIDEO_H264 &&
            codecpar->extradata_size > 6 &&
            (AV_RB32(codecpar->extradata) == 0x00000001 ||
            AV_RB24(codecpar->extradata) == 0x000001))
        {
            /* convert to mp4 header */
            if (avio_open_dyn_buf(&extra) < 0) {
                error(0, "failed to allocate dynamic buf");
                return -1;
            }

            if (ff_isom_write_avcc(extra, codecpar->extradata,
                codecpar->extradata_size) < 0)
            {
                error(0, "failed to write avcC");
                avio_close_dyn_buf(extra, &tmp);
                av_free(tmp);
                return -1;
            }

            extra_data->len = avio_close_dyn_buf(extra, &extra_data->data);
            *annex_b = 1;
        }

        break;

    case AVMEDIA_TYPE_AUDIO:
        media_info->media_type = KMP_MEDIA_AUDIO;
        media_info->codec_id = kmp_get_audio_codec(codecpar->codec_id);
        if (media_info->codec_id == 0) {
            error(0, "failed to get audio codec %d", codecpar->codec_id);
            return -1;
        }
        media_info->u.audio.bits_per_sample = codecpar->bits_per_coded_sample;
        media_info->u.audio.sample_rate = codecpar->sample_rate;

#if LIBAVUTIL_VERSION_INT >= AV_VERSION_INT(57, 23, 100)
        media_info->u.audio.channels = codecpar->ch_layout.nb_channels;
        media_info->u.audio.channel_layout = codecpar->ch_layout.u.mask;
#else
        media_info->u.audio.channels = codecpar->channels;
        media_info->u.audio.channel_layout = codecpar->channel_layout;
#endif
        break;

    default:
        error(0, "unknown codec type %d", codecpar->codec_type);
        return -1;
    }

    if (extra_data->data == NULL && extra_data->len > 0) {
        extra_data->data = av_memdup(codecpar->extradata, extra_data->len);
        if (extra_data->data == NULL) {
            error(0, "failed to copy extra data");
            return -1;
        }
    }

    return 0;
}


static int
kmp_write_media_info(AVIOContext *pb, AVStream *stream, int *annex_b)
{
    str_t                    extra_data;
    kmp_media_info_packet_t  mi;

    if (kmp_get_mediainfo(stream, &mi.m, &extra_data, annex_b) < 0) {
        return -1;
    }

    mi.header.packet_type = KMP_PACKET_MEDIA_INFO;
    mi.header.header_size = sizeof(mi);
    mi.header.data_size = extra_data.len;
    mi.header.reserved = 0;
    avio_write(pb, (u_char *) &mi, sizeof(mi));
    avio_write(pb, extra_data.data, extra_data.len);
    av_free(extra_data.data);

    if (pb->error) {
        error(0, "failed to write media info");
        return -1;
    }

    return 0;
}


static int
kmp_write_frame(AVIOContext *pb, AVPacket *packet, kmp_write_frame_ctx_t *ctx)
{
    kmp_frame_packet_t  frame;

    frame.header.packet_type = KMP_PACKET_FRAME;
    frame.header.header_size = sizeof(frame);
    frame.header.data_size = ctx->annex_b ?
        ff_avc_parse_nal_units_size(packet->data, packet->size) : packet->size;
    frame.header.reserved = 0;

    if (AV_NOPTS_VALUE != packet->pts) {
        frame.f.pts_delay = (uint32_t) (packet->pts - packet->dts);

    } else {
        frame.f.pts_delay = 0;
    }
    frame.f.dts = packet->dts;
    frame.f.created = ctx->base_created + packet->dts;
    frame.f.flags = ((packet->flags & AV_PKT_FLAG_KEY) == AV_PKT_FLAG_KEY) ?
        KMP_FRAME_FLAG_KEY : 0;

    avio_write(pb, (u_char *) &frame, sizeof(frame));
    if (ctx->annex_b) {
        ff_avc_parse_nal_units(pb, packet->data, packet->size);

    } else {
        avio_write(pb, packet->data, packet->size);
    }

    if (pb->error) {
        error(0, "failed to write frame");
        return -1;
    }

    return 0;
}


static int64_t
kmp_get_time()
{
    struct timespec  spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    return (int64_t) spec.tv_sec * OUTPUT_TIMESCALE +
        (int64_t) spec.tv_nsec * OUTPUT_TIMESCALE / 1000000000;
}


static void
usage(int status)
{
    if (status != 0) {
        fprintf(stderr, "Usage: %s [OPTION]... INPUT OUTPUT\n", program_name);
        fprintf(stderr, "Try '%s --help' for more information.\n",
            program_name);

    } else {
        printf ("Usage: %s [OPTION]... INPUT OUTPUT\n", program_name);

        printf("\
Repackages the given input track to KMP protocol.\n\
The input can be any file format supported by libavformat.\n\
Output can be a file name or /dev/stdout for stdout\n");

        printf("\
\n\
      --help                display this help text and exit\n\
  -s, --stream              the index of the track in the input file.\n\
                            the default is 0.\n\
  -c, --created             the base KMP 'created' value, in 90kHz.\n\
                            the default behavior is to use the system clock.\n\
");
    }

    exit(status);
}

int
main(int argc, char **argv)
{
    int                     opt;
    int                     ret;
    int                     stream_id;
    int                     status = 1;
    char                   *input_file;
    char                   *output_file;
    AVPacket               *pkt = NULL;
    AVStream               *stream;
    AVRational              output_timebase = { 1, OUTPUT_TIMESCALE };
    AVIOContext            *pb = NULL;
    AVFormatContext        *fmt_ctx = NULL;
    kmp_write_frame_ctx_t   ctx;

    program_name = argv[0];

    /* parse the command line */
    stream_id = 0;
    ctx.base_created = kmp_get_time();

    for ( ;; ) {

        opt = getopt_long(argc, (char **) argv, short_options, long_options,
            NULL);
        if (opt == -1) {
            break;
        }

        switch (opt) {

        case 's':
            stream_id = atoi(optarg);
            break;

        case 'c':
            ctx.base_created = atoll(optarg);
            break;

        case 0:
            /* long options */
            break;

        default:
            usage(EXIT_ERROR);
            break;
        }
    }

    if (show_help || optind == argc) {
        usage(EXIT_SUCCESS);
    }

    if (optind + 2 != argc) {
        usage(EXIT_ERROR);
    }

    input_file = argv[optind];
    output_file = argv[optind + 1];

    /* open input file */
    ret = avformat_open_input(&fmt_ctx, input_file, NULL, NULL);
    if (ret < 0) {
        error(0, "could not open source file %s, err: %d", input_file, ret);
        goto done;
    }

    ret = avformat_find_stream_info(fmt_ctx, NULL);
    if (ret < 0) {
        error(0, "could not find stream information, err: %d", ret);
        goto done;
    }

    if (stream_id >= (int) fmt_ctx->nb_streams) {
        error(0, "stream id %d too large", stream_id);
        goto done;
    }

    stream = fmt_ctx->streams[stream_id];

    /* open output file */
    ret = avio_open2(&pb, output_file, AVIO_FLAG_WRITE, NULL, NULL);
    if (ret < 0) {
        error(0, "failed to open output file %s, err: %d", output_file, ret);
        goto done;
    }

    /* write media info */
    if (kmp_write_media_info(pb, stream, &ctx.annex_b) < 0) {
        goto done;
    }

    /* write frames */
    for ( ;; ) {
        pkt = av_packet_alloc();
        if (pkt == NULL) {
            error(0, "failed to alloc packet");
            goto done;
        }

        if (av_read_frame(fmt_ctx, pkt) < 0) {
            break;
        }

        if (pkt->stream_index == stream->index) {
            av_packet_rescale_ts(pkt, stream->time_base, output_timebase);

            if (kmp_write_frame(pb, pkt, &ctx) < 0) {
                goto done;
            }
        }

        av_packet_free(&pkt);
    }

    avio_flush(pb);
    if (pb->error) {
        error(0, "flush failed");
        goto done;
    }
    status = 0;

done:

    av_packet_free(&pkt);

    avio_close(pb);

    avformat_close_input(&fmt_ctx);

    return status;
}
