#include "mp4_init_segment.h"
#include "mp4_write_stream.h"
#include "mp4_defs.h"
#include "../read_stream.h"


#define DRM_KID_SIZE vod_member_size(tenc_atom_t, default_kid)

#define STSD_STPP_EXTRA_DATA                                                 \
    "http://www.smpte-ra.org/schemas/2052-1/2013/smpte-tt "                  \
    "http://www.w3.org/ns/ttml "                                             \
    "http://www.w3.org/ns/ttml#metadata "                                    \
    "http://www.w3.org/ns/ttml#parameter "                                   \
    "http://www.w3.org/ns/ttml#styling "                                     \
    "urn:ebu:tt:metadata urn:ebu:tt:style\0\0"


// macros
#define mp4_rescale_millis(millis, timescale) (millis * ((timescale) / 1000))
#define mp4_esds_atom_size(extra_data_len) (ATOM_HEADER_SIZE + 29 + extra_data_len)
#define mp4_copy_atom(p, raw_atom) vod_copy(p, (raw_atom).ptr, (raw_atom).size)

// typedefs
typedef struct {
    uint32_t media_type;
    uint32_t scheme_type;
    bool_t has_clear_lead;
    u_char* default_kid;
    u_char* iv;
    stsd_entry_header_t* original_stsd_entry;
    uint32_t original_stsd_entry_size;
    uint32_t original_stsd_entry_format;
    size_t tenc_atom_size;
    size_t schi_atom_size;
    size_t schm_atom_size;
    size_t frma_atom_size;
    size_t sinf_atom_size;
    size_t encrypted_stsd_entry_size;
    size_t stsd_atom_size;
} stsd_writer_context_t;

// init mp4 atoms
typedef struct {
    size_t stsd_size;
    size_t stbl_size;
    size_t minf_size;
    size_t mdia_size;
    size_t trak_size;
} track_sizes_t;

typedef struct {
    size_t moov_atom_size;
    size_t mvex_atom_size;
    size_t total_size;
    size_t track_count;
    track_sizes_t track_sizes[1];
} init_mp4_sizes_t;

typedef struct {
    u_char version[1];
    u_char flags[3];
    u_char track_id[4];
    u_char default_sample_description_index[4];
    u_char default_sample_duration[4];
    u_char default_sample_size[4];
    u_char default_sample_flags[4];
} trex_atom_t;

// fixed atoms

static const u_char ftyp_atom[] = {
    0x00, 0x00, 0x00, 0x1c,        // atom size
    0x66, 0x74, 0x79, 0x70,        // ftyp
    0x69, 0x73, 0x6f, 0x35,        // major brand
    0x00, 0x00, 0x00, 0x01,        // minor version
    0x69, 0x73, 0x6f, 0x35,        // compatible brand
    0x64, 0x61, 0x73, 0x68,        // compatible brand
    0x6d, 0x73, 0x69, 0x78,        // compatible brand
};
static const u_char hdlr_video_atom[] = {
    0x00, 0x00, 0x00, 0x2d,        // size
    0x68, 0x64, 0x6c, 0x72,        // hdlr
    0x00, 0x00, 0x00, 0x00,        // version + flags
    0x00, 0x00, 0x00, 0x00,        // pre defined
    0x76, 0x69, 0x64, 0x65,        // handler type = vide
    0x00, 0x00, 0x00, 0x00,        // reserved1
    0x00, 0x00, 0x00, 0x00,        // reserved2
    0x00, 0x00, 0x00, 0x00,        // reserved3
    0x56, 0x69, 0x64, 0x65,        // VideoHandler\0
    0x6f, 0x48, 0x61, 0x6e,
    0x64, 0x6c, 0x65, 0x72,
    0x00
};

static const u_char hdlr_audio_atom[] = {
    0x00, 0x00, 0x00, 0x2d,        // size
    0x68, 0x64, 0x6c, 0x72,        // hdlr
    0x00, 0x00, 0x00, 0x00,        // version + flags
    0x00, 0x00, 0x00, 0x00,        // pre defined
    0x73, 0x6f, 0x75, 0x6e,        // handler type = soun
    0x00, 0x00, 0x00, 0x00,        // reserved1
    0x00, 0x00, 0x00, 0x00,        // reserved2
    0x00, 0x00, 0x00, 0x00,        // reserved3
    0x53, 0x6f, 0x75, 0x6e,        // name = SoundHandler\0
    0x64, 0x48, 0x61, 0x6e,
    0x64, 0x6c, 0x65, 0x72,
    0x00
};

static const u_char hdlr_subtitle_wvtt_atom[] = {
    0x00, 0x00, 0x00, 0x25,        // size
    0x68, 0x64, 0x6c, 0x72,        // hdlr
    0x00, 0x00, 0x00, 0x00,        // version + flags
    0x00, 0x00, 0x00, 0x00,        // pre defined
    0x74, 0x65, 0x78, 0x74,        // handler type = text
    0x00, 0x00, 0x00, 0x00,        // reserved1
    0x00, 0x00, 0x00, 0x00,        // reserved2
    0x00, 0x00, 0x00, 0x00,        // reserved3
    0x73, 0x75, 0x62, 0x74,        // name = subt\0
    0x00
};

static const u_char hdlr_subtitle_stpp_atom[] = {
    0x00, 0x00, 0x00, 0x25,        // size
    0x68, 0x64, 0x6c, 0x72,        // hdlr
    0x00, 0x00, 0x00, 0x00,        // version + flags
    0x00, 0x00, 0x00, 0x00,        // pre defined
    0x73, 0x75, 0x62, 0x74,        // handler type = subt
    0x00, 0x00, 0x00, 0x00,        // reserved1
    0x00, 0x00, 0x00, 0x00,        // reserved2
    0x00, 0x00, 0x00, 0x00,        // reserved3
    0x73, 0x75, 0x62, 0x74,        // name = subt\0
    0x00
};

static const u_char dinf_atom[] = {
    0x00, 0x00, 0x00, 0x24,        // atom size
    0x64, 0x69, 0x6e, 0x66,        // dinf
    0x00, 0x00, 0x00, 0x1c,        // atom size
    0x64, 0x72, 0x65, 0x66,        // dref
    0x00, 0x00, 0x00, 0x00,        // version + flags
    0x00, 0x00, 0x00, 0x01,        // entry count
    0x00, 0x00, 0x00, 0x0c,        // atom size
    0x75, 0x72, 0x6c, 0x20,        // url
    0x00, 0x00, 0x00, 0x01,        // version + flags
};

static const u_char vmhd_atom[] = {
    0x00, 0x00, 0x00, 0x14,        // atom size
    0x76, 0x6d, 0x68, 0x64,        // vmhd
    0x00, 0x00, 0x00, 0x01,        // version & flags
    0x00, 0x00, 0x00, 0x00,        // reserved
    0x00, 0x00, 0x00, 0x00,        // reserved
};

static const u_char smhd_atom[] = {
    0x00, 0x00, 0x00, 0x10,        // atom size
    0x73, 0x6d, 0x68, 0x64,        // smhd
    0x00, 0x00, 0x00, 0x00,        // version & flags
    0x00, 0x00, 0x00, 0x00,        // reserved
};

static const u_char sthd_atom[] = {
    0x00, 0x00, 0x00, 0x0C,        // atom size
    0x73, 0x74, 0x68, 0x64,        // sthd
    0x00, 0x00, 0x00, 0x00,        // version & flags
};


static const u_char fixed_stbl_atoms[] = {
    0x00, 0x00, 0x00, 0x10,        // atom size
    0x73, 0x74, 0x74, 0x73,        // stts
    0x00, 0x00, 0x00, 0x00,        // version
    0x00, 0x00, 0x00, 0x00,        // entry count
    0x00, 0x00, 0x00, 0x10,        // atom size
    0x73, 0x74, 0x73, 0x63,        // stsc
    0x00, 0x00, 0x00, 0x00,        // version
    0x00, 0x00, 0x00, 0x00,        // entry count
    0x00, 0x00, 0x00, 0x14,        // atom size
    0x73, 0x74, 0x73, 0x7a,        // stsz
    0x00, 0x00, 0x00, 0x00,        // version
    0x00, 0x00, 0x00, 0x00,        // uniform size
    0x00, 0x00, 0x00, 0x00,        // entry count
    0x00, 0x00, 0x00, 0x10,        // atom size
    0x73, 0x74, 0x63, 0x6f,        // stco
    0x00, 0x00, 0x00, 0x00,        // version
    0x00, 0x00, 0x00, 0x00,        // entry count
};


static void
mp4_init_segment_get_track_sizes(
    media_init_segment_track_t* cur_track,
    atom_writer_t* stsd_atom_writer,
    track_sizes_t* result)
{
    media_info_t* media_info;
    size_t tkhd_atom_size;
    size_t mdhd_atom_size;
    size_t hdlr_atom_size = 0;

    if (stsd_atom_writer != NULL && stsd_atom_writer->write != NULL)
    {
        result->stsd_size = stsd_atom_writer->atom_size;
    }
    else
    {
        result->stsd_size = cur_track->stsd_atom.len;
    }

    tkhd_atom_size = ATOM_HEADER_SIZE + sizeof(tkhd_atom_t);
    mdhd_atom_size = ATOM_HEADER_SIZE + sizeof(mdhd_atom_t);

    result->stbl_size = ATOM_HEADER_SIZE + result->stsd_size + sizeof(fixed_stbl_atoms);
    result->minf_size = ATOM_HEADER_SIZE + sizeof(dinf_atom) + result->stbl_size;

    media_info = cur_track->media_info;
    switch (media_info->media_type)
    {
    case MEDIA_TYPE_VIDEO:
        result->minf_size += sizeof(vmhd_atom);
        hdlr_atom_size = sizeof(hdlr_video_atom);
        break;

    case MEDIA_TYPE_AUDIO:
        result->minf_size += sizeof(smhd_atom);
        hdlr_atom_size = sizeof(hdlr_audio_atom);
        break;

    case MEDIA_TYPE_SUBTITLE:
        result->minf_size += sizeof(sthd_atom);
        switch (media_info->codec_id)
        {
        case VOD_CODEC_ID_WEBVTT:
            hdlr_atom_size = sizeof(hdlr_subtitle_wvtt_atom);
            break;

        default: // VOD_CODEC_ID_TTML
            hdlr_atom_size = sizeof(hdlr_subtitle_stpp_atom);
            break;
        }
    }

    result->mdia_size = ATOM_HEADER_SIZE + mdhd_atom_size + hdlr_atom_size + result->minf_size;
    result->trak_size = ATOM_HEADER_SIZE + tkhd_atom_size + result->mdia_size;
}


static u_char*
mp4_init_segment_write_trex_atom(u_char* p, uint32_t track_id)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(trex_atom_t);

    write_atom_header(p, atom_size, 't', 'r', 'e', 'x');
    write_be32(p, 0);            // version + flags
    write_be32(p, track_id);    // track id
    write_be32(p, 1);            // default sample description index
    write_be32(p, 0);            // default sample duration
    write_be32(p, 0);            // default sample size
    write_be32(p, 0);            // default sample size
    return p;
}


static u_char*
mp4_init_segment_write_matrix(u_char* p, int16_t a, int16_t b, int16_t c,
    int16_t d, int16_t tx, int16_t ty)
{
    write_be32(p, a << 16);  // 16.16 format
    write_be32(p, b << 16);  // 16.16 format
    write_be32(p, 0);        // u in 2.30 format
    write_be32(p, c << 16);  // 16.16 format
    write_be32(p, d << 16);  // 16.16 format
    write_be32(p, 0);        // v in 2.30 format
    write_be32(p, tx << 16); // 16.16 format
    write_be32(p, ty << 16); // 16.16 format
    write_be32(p, 1 << 30);  // w in 2.30 format
    return p;
}


static u_char*
mp4_init_segment_write_mvhd_constants(u_char* p)
{
    write_be32(p, 0x00010000);    // preferred rate, 1.0
    write_be16(p, 0x0100);        // volume, full
    write_be16(p, 0);            // reserved
    write_be32(p, 0);            // reserved
    write_be32(p, 0);            // reserved
    p = mp4_init_segment_write_matrix(p, 1, 0, 0, 1, 0, 0);    // matrix
    write_be32(p, 0);            // reserved (preview time)
    write_be32(p, 0);            // reserved (preview duration)
    write_be32(p, 0);            // reserved (poster time)
    write_be32(p, 0);            // reserved (selection time)
    write_be32(p, 0);            // reserved (selection duration)
    write_be32(p, 0);            // reserved (current time)
    return p;
}


static u_char*
mp4_init_segment_write_mvhd_atom(u_char* p, uint32_t timescale, uint32_t duration)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(mvhd_atom_t);

    write_atom_header(p, atom_size, 'm', 'v', 'h', 'd');
    write_be32(p, 0);            // version + flags
    write_be32(p, 0);            // creation time
    write_be32(p, 0);            // modification time
    write_be32(p, timescale);    // timescale
    write_be32(p, duration);    // duration
    p = mp4_init_segment_write_mvhd_constants(p);
    write_be32(p, 0xffffffff);    // next track id
    return p;
}


static u_char*
mp4_init_segment_write_mvhd64_atom(u_char* p, uint32_t timescale, uint64_t duration)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(mvhd64_atom_t);

    write_atom_header(p, atom_size, 'm', 'v', 'h', 'd');
    write_be32(p, 0x01000000);    // version + flags
    write_be64(p, 0LL);            // creation time
    write_be64(p, 0LL);            // modification time
    write_be32(p, timescale);    // timescale
    write_be64(p, duration);    // duration
    p = mp4_init_segment_write_mvhd_constants(p);
    write_be32(p, 0xffffffff);    // next track id
    return p;
}


static u_char*
mp4_init_segment_write_tkhd_trailer(
    u_char* p,
    uint32_t media_type,
    uint16_t width,
    uint16_t height)
{
    write_be32(p, 0);                // reserved
    write_be32(p, 0);                // reserved
    write_be32(p, 0);                // layer / alternate group
    write_be16(p, media_type == MEDIA_TYPE_AUDIO ? 0x0100 : 0);        // volume
    write_be16(p, 0);                // reserved
    p = mp4_init_segment_write_matrix(p, 1, 0, 0, 1, 0, 0);    // matrix
    if (media_type == MEDIA_TYPE_VIDEO)
    {
        write_be32(p, width << 16);        // width
        write_be32(p, height << 16);    // height
    }
    else
    {
        write_be32(p, 0);            // width
        write_be32(p, 0);            // height
    }
    return p;
}


static u_char*
mp4_init_segment_write_tkhd_atom(
    u_char* p,
    uint32_t track_id,
    uint32_t duration,
    uint32_t media_type,
    uint16_t width,
    uint16_t height)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(tkhd_atom_t);

    write_atom_header(p, atom_size, 't', 'k', 'h', 'd');
    write_be32(p, 0x00000003);        // version + flags
    write_be32(p, 0);                // creation time
    write_be32(p, 0);                // modification time
    write_be32(p, track_id);        // track id
    write_be32(p, 0);                // reserved
    write_be32(p, duration);        // duration
    return mp4_init_segment_write_tkhd_trailer(p, media_type, width, height);
}


static u_char*
mp4_init_segment_write_tkhd64_atom(
    u_char* p,
    uint32_t track_id,
    uint64_t duration,
    uint32_t media_type,
    uint16_t width,
    uint16_t height)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(tkhd64_atom_t);

    write_atom_header(p, atom_size, 't', 'k', 'h', 'd');
    write_be32(p, 0x01000003);        // version + flags
    write_be64(p, 0LL);                // creation time
    write_be64(p, 0LL);                // modification time
    write_be32(p, track_id);        // track id
    write_be32(p, 0);                // reserved
    write_be64(p, duration);        // duration
    return mp4_init_segment_write_tkhd_trailer(p, media_type, width, height);
}


static u_char*
mp4_init_segment_write_mdhd_atom(u_char* p, uint32_t timescale, uint32_t duration)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(mdhd_atom_t);

    write_atom_header(p, atom_size, 'm', 'd', 'h', 'd');
    write_be32(p, 0);                // version + flags
    write_be32(p, 0);                // creation time
    write_be32(p, 0);                // modification time
    write_be32(p, timescale);        // timescale
    write_be32(p, duration);         // duration
    write_be16(p, 0x55c4);           // language (und)
    write_be16(p, 0);                // reserved
    return p;
}


static u_char*
mp4_init_segment_write_mdhd64_atom(u_char* p, uint32_t timescale, uint64_t duration)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(mdhd64_atom_t);

    write_atom_header(p, atom_size, 'm', 'd', 'h', 'd');
    write_be32(p, 0x01000000);       // version + flags
    write_be64(p, 0LL);              // creation time
    write_be64(p, 0LL);              // modification time
    write_be32(p, timescale);        // timescale
    write_be64(p, duration);         // duration
    write_be16(p, 0x55c4);           // language (und)
    write_be16(p, 0);                // reserved
    return p;
}


static u_char*
mp4_init_segment_write_avcc_atom(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + media_info->extra_data.len;

    write_atom_header(p, atom_size, 'a', 'v', 'c', 'C');
    p = vod_copy(p, media_info->extra_data.data, media_info->extra_data.len);
    return p;
}


static u_char*
mp4_init_segment_write_stsd_video_entry(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sample_entry_t) + sizeof(stsd_video_t) +
        ATOM_HEADER_SIZE + media_info->extra_data.len;

    write_atom_header(p, atom_size, 'a', 'v', 'c', '1');

    // sample_entry_t
    write_be32(p, 0);        // reserved
    write_be16(p, 0);        // reserved
    write_be16(p, 1);        // data reference index

    // stsd_video_t
    write_be16(p, 0);        // pre defined
    write_be16(p, 0);        // reserved
    write_be32(p, 0);        // pre defined
    write_be32(p, 0);        // pre defined
    write_be32(p, 0);        // pre defined
    write_be16(p, media_info->u.video.width);
    write_be16(p, media_info->u.video.height);
    write_be32(p, 0x00480000);    // horiz res (72 DPI)
    write_be32(p, 0x00480000);    // vert res (72 DPI)
    write_be32(p, 0);        // reserved
    write_be16(p, 1);        // frame count
    vod_memzero(p, 32);        // compressor name
    p += 32;
    write_be16(p, 0x18);    // depth
    write_be16(p, 0xffff);    // pre defined

    p = mp4_init_segment_write_avcc_atom(p, media_info);

    return p;
}


static u_char*
mp4_init_segment_write_esds_atom(u_char* p, media_info_t* media_info)
{
    size_t extra_data_len = media_info->extra_data.len;
    size_t atom_size = mp4_esds_atom_size(extra_data_len);

    write_atom_header(p, atom_size, 'e', 's', 'd', 's');
    write_be32(p, 0);                            // version + flags

    *p++ = MP4ESDescrTag;                        // tag
    *p++ = 3 + 3 * sizeof(descr_header_t) +        // len
        sizeof(config_descr_t) + extra_data_len + 1;
    write_be16(p, 0);                            // track id
    *p++ = 0;                                    // flags

    *p++ = MP4DecConfigDescrTag;                // tag
    *p++ = sizeof(config_descr_t) +                // len
        sizeof(descr_header_t) + extra_data_len;
    *p++ = media_info->u.audio.object_type_id;
    *p++ = 0x15;                                // stream type
    write_be24(p, 0);                            // buffer size
    write_be32(p, media_info->bitrate);    // max bitrate
    write_be32(p, media_info->bitrate);    // avg bitrate

    *p++ = MP4DecSpecificDescrTag;                // tag
    *p++ = extra_data_len;                        // len
    p = vod_copy(p, media_info->extra_data.data, extra_data_len);

    *p++ = MP4SLDescrTag;                        // tag
    *p++ = 1;                                    // len
    *p++ = 2;

    return p;
}


static u_char*
mp4_init_segment_write_stsd_audio_entry(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sample_entry_t) + sizeof(stsd_audio_t) +
        mp4_esds_atom_size(media_info->extra_data.len);

    write_atom_header(p, atom_size, 'm', 'p', '4', 'a');

    // sample_entry_t
    write_be32(p, 0);        // reserved
    write_be16(p, 0);        // reserved
    write_be16(p, 1);        // data reference index

    // stsd_audio_t
    write_be32(p, 0);        // reserved
    write_be32(p, 0);        // reserved
    write_be16(p, media_info->u.audio.channels);
    write_be16(p, media_info->u.audio.bits_per_sample);
    write_be16(p, 0);        // pre defined
    write_be16(p, 0);        // reserved
    write_be16(p, media_info->u.audio.sample_rate);
    write_be16(p, 0);

    p = mp4_init_segment_write_esds_atom(p, media_info);

    return p;
}


static u_char*
mp4_init_segment_write_vttc_atom(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + media_info->extra_data.len;

    write_atom_header(p, atom_size, 'v', 't', 't', 'C');
    p = vod_copy(p, media_info->extra_data.data, media_info->extra_data.len);
    return p;
}


static u_char*
mp4_init_segment_write_stsd_wvtt_entry(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sample_entry_t) +
        ATOM_HEADER_SIZE + media_info->extra_data.len;

    write_atom_header(p, atom_size, 'w', 'v', 't', 't');

    // sample_entry_t
    write_be32(p, 0);        // reserved
    write_be16(p, 0);        // reserved
    write_be16(p, 1);        // data reference index

    p = mp4_init_segment_write_vttc_atom(p, media_info);

    return p;
}


static u_char*
mp4_init_segment_write_stsd_stpp_entry(u_char* p, media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(sample_entry_t) +
        sizeof(STSD_STPP_EXTRA_DATA);

    write_atom_header(p, atom_size, 's', 't', 'p', 'p');

    // sample_entry_t
    write_be32(p, 0);        // reserved
    write_be16(p, 0);        // reserved
    write_be16(p, 1);        // data reference index

    p = vod_copy(p, STSD_STPP_EXTRA_DATA, sizeof(STSD_STPP_EXTRA_DATA));

    return p;
}



static size_t
mp4_init_segment_get_stsd_atom_size(media_info_t* media_info)
{
    size_t atom_size = ATOM_HEADER_SIZE + sizeof(stsd_atom_t);

    switch (media_info->media_type)
    {
    case MEDIA_TYPE_VIDEO:
        atom_size += ATOM_HEADER_SIZE + sizeof(sample_entry_t) + sizeof(stsd_video_t) +
            ATOM_HEADER_SIZE + media_info->extra_data.len;
        break;

    case MEDIA_TYPE_AUDIO:
        atom_size += ATOM_HEADER_SIZE + sizeof(sample_entry_t) + sizeof(stsd_audio_t) +
            mp4_esds_atom_size(media_info->extra_data.len);
        break;

    case MEDIA_TYPE_SUBTITLE:
        switch (media_info->codec_id)
        {
        case VOD_CODEC_ID_WEBVTT:
            atom_size += ATOM_HEADER_SIZE + sizeof(sample_entry_t) +
                ATOM_HEADER_SIZE + media_info->extra_data.len;
            break;

        default: // VOD_CODEC_ID_TTML
            atom_size += ATOM_HEADER_SIZE + sizeof(sample_entry_t) +
                sizeof(STSD_STPP_EXTRA_DATA);
            break;
        }
        break;
    }

    return atom_size;
}


static u_char*
mp4_init_segment_write_stsd_atom(u_char* p, size_t atom_size, media_info_t* media_info)
{
    write_atom_header(p, atom_size, 's', 't', 's', 'd');
    write_be32(p, 0);                // version + flags
    write_be32(p, 1);                // entries
    switch (media_info->media_type)
    {
    case MEDIA_TYPE_VIDEO:
        p = mp4_init_segment_write_stsd_video_entry(p, media_info);
        break;

    case MEDIA_TYPE_AUDIO:
        p = mp4_init_segment_write_stsd_audio_entry(p, media_info);
        break;

    case MEDIA_TYPE_SUBTITLE:
        switch (media_info->codec_id)
        {
        case VOD_CODEC_ID_WEBVTT:
            p = mp4_init_segment_write_stsd_wvtt_entry(p, media_info);
            break;

        default: // VOD_CODEC_ID_TTML
            p = mp4_init_segment_write_stsd_stpp_entry(p, media_info);
            break;
        }
        break;
    }
    return p;
}


static void
mp4_init_segment_calc_size(
    media_init_segment_t* segment,
    atom_writer_t* extra_moov_atoms_writer,
    atom_writer_t* stsd_atom_writers,
    init_mp4_sizes_t* result)
{
    track_sizes_t* track_sizes;
    uint32_t i;

    result->mvex_atom_size = ATOM_HEADER_SIZE +
        (ATOM_HEADER_SIZE + sizeof(trex_atom_t)) * segment->count;

    result->moov_atom_size = ATOM_HEADER_SIZE + result->mvex_atom_size;

    result->moov_atom_size += ATOM_HEADER_SIZE + sizeof(mvhd_atom_t);

    if (extra_moov_atoms_writer != NULL)
    {
        result->moov_atom_size += extra_moov_atoms_writer->atom_size;
    }

    for (i = 0; i < segment->count; i++)
    {
        track_sizes = &result->track_sizes[i];

        mp4_init_segment_get_track_sizes(
            &segment->first[i],
            stsd_atom_writers != NULL ? &stsd_atom_writers[i] : NULL,
            track_sizes);

        result->moov_atom_size += track_sizes->trak_size;
    }

    result->total_size = sizeof(ftyp_atom) + result->moov_atom_size;
}


static u_char*
mp4_init_segment_write(
    u_char* p,
    request_context_t* request_context,
    media_init_segment_t* segment,
    init_mp4_sizes_t* sizes,
    atom_writer_t* extra_moov_atoms_writer,
    atom_writer_t* stsd_atom_writers)
{
    media_init_segment_track_t* cur_track;
    track_sizes_t* track_sizes;
    media_info_t* media_info;
    uint32_t timescale = segment->first->media_info->timescale;
    uint64_t duration = 0;
    uint32_t i;

    // ftyp
    p = vod_copy(p, ftyp_atom, sizeof(ftyp_atom));

    // moov
    write_atom_header(p, sizes->moov_atom_size, 'm', 'o', 'o', 'v');

    // moov.mvhd
    if (duration > UINT_MAX)
    {
        p = mp4_init_segment_write_mvhd64_atom(p, timescale, duration);
    }
    else
    {
        p = mp4_init_segment_write_mvhd_atom(p, timescale, duration);
    }

    // moov.mvex
    write_atom_header(p, sizes->mvex_atom_size, 'm', 'v', 'e', 'x');

    for (i = 0; i < segment->count; i++)
    {
        // moov.mvex.trex
        p = mp4_init_segment_write_trex_atom(p, i + 1);
    }

    for (i = 0; i < segment->count; i++)
    {
        cur_track = &segment->first[i];
        track_sizes = &sizes->track_sizes[i];
        media_info = cur_track->media_info;

        // moov.trak
        write_atom_header(p, track_sizes->trak_size, 't', 'r', 'a', 'k');

        // moov.trak.tkhd
        if (duration > UINT_MAX)
        {
            p = mp4_init_segment_write_tkhd64_atom(
                p,
                i + 1,
                duration,
                media_info->media_type,
                media_info->u.video.width,
                media_info->u.video.height);
        }
        else
        {
            p = mp4_init_segment_write_tkhd_atom(
                p,
                i + 1,
                duration,
                media_info->media_type,
                media_info->u.video.width,
                media_info->u.video.height);
        }

        // moov.trak.mdia
        write_atom_header(p, track_sizes->mdia_size, 'm', 'd', 'i', 'a');

        // moov.trak.mdia.mdhd
        if (duration > UINT_MAX)
        {
            p = mp4_init_segment_write_mdhd64_atom(p, timescale, duration);
        }
        else
        {
            p = mp4_init_segment_write_mdhd_atom(p, timescale, duration);
        }

        // moov.trak.mdia.hdlr
        switch (media_info->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            p = vod_copy(p, hdlr_video_atom, sizeof(hdlr_video_atom));
            break;

        case MEDIA_TYPE_AUDIO:
            p = vod_copy(p, hdlr_audio_atom, sizeof(hdlr_audio_atom));
            break;

        case MEDIA_TYPE_SUBTITLE:
            switch (media_info->codec_id)
            {
            case VOD_CODEC_ID_WEBVTT:
                p = vod_copy(p, hdlr_subtitle_wvtt_atom, sizeof(hdlr_subtitle_wvtt_atom));
                break;

            default: // VOD_CODEC_ID_TTML
                p = vod_copy(p, hdlr_subtitle_stpp_atom, sizeof(hdlr_subtitle_stpp_atom));
                break;
            }
            break;
        }

        // moov.trak.mdia.minf
        write_atom_header(p, track_sizes->minf_size, 'm', 'i', 'n', 'f');
        switch (media_info->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            p = vod_copy(p, vmhd_atom, sizeof(vmhd_atom));
            break;

        case MEDIA_TYPE_AUDIO:
            p = vod_copy(p, smhd_atom, sizeof(smhd_atom));
            break;

        case MEDIA_TYPE_SUBTITLE:
            p = vod_copy(p, sthd_atom, sizeof(sthd_atom));
            break;
        }
        p = vod_copy(p, dinf_atom, sizeof(dinf_atom));

        // moov.trak.mdia.minf.stbl
        write_atom_header(p, track_sizes->stbl_size, 's', 't', 'b', 'l');
        if (stsd_atom_writers != NULL && stsd_atom_writers[i].write != NULL)
        {
            p = stsd_atom_writers[i].write(stsd_atom_writers[i].context, p);
        }
        else
        {
            p = vod_copy(p, cur_track->stsd_atom.data, cur_track->stsd_atom.len);
        }
        p = vod_copy(p, fixed_stbl_atoms, sizeof(fixed_stbl_atoms));
    }

    // moov.xxx
    if (extra_moov_atoms_writer != NULL)
    {
        p = extra_moov_atoms_writer->write(extra_moov_atoms_writer->context, p);
    }

    return p;
}


static vod_status_t
mp4_init_segment_build_stsd_atom(
    request_context_t* request_context,
    media_init_segment_track_t* track)
{
    size_t atom_size;
    u_char* p;

    atom_size = mp4_init_segment_get_stsd_atom_size(track->media_info);
    p = vod_alloc(request_context->pool, atom_size);
    if (p == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_init_segment_build_stsd_atom: vod_alloc failed (1)");
        return VOD_ALLOC_FAILED;
    }

    track->stsd_atom.data = p;
    track->stsd_atom.len =
        mp4_init_segment_write_stsd_atom(p, atom_size, track->media_info) - p;

    if (track->stsd_atom.len > atom_size)
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_init_segment_build_stsd_atom: stsd length %uL greater than allocated length %uz",
            track->stsd_atom.len, atom_size);
        return VOD_UNEXPECTED;
    }

    return VOD_OK;
}

vod_status_t
mp4_init_segment_build(
    request_context_t* request_context,
    media_init_segment_t* segment,
    bool_t size_only,
    atom_writer_t* extra_moov_atoms_writer,
    atom_writer_t* stsd_atom_writers,
    vod_str_t* result)
{
    media_init_segment_track_t* first_track = segment->first;
    media_init_segment_track_t* last_track = segment->last;
    media_init_segment_track_t* cur_track;
    init_mp4_sizes_t* sizes;
    vod_status_t rc;
    u_char* p;

    // create an stsd atom if needed
    for (cur_track = first_track; cur_track < last_track; cur_track++)
    {
        if (cur_track->stsd_atom.len != 0)
        {
            continue;
        }

        rc = mp4_init_segment_build_stsd_atom(request_context, cur_track);
        if (rc != VOD_OK)
        {
            return rc;
        }
    }

    // get the result size
    sizes = vod_alloc(request_context->pool, sizeof(*sizes) +
        sizeof(sizes->track_sizes[0]) * (segment->count - 1));
    if (sizes == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_init_segment_build: vod_alloc failed (1)");
        return VOD_ALLOC_FAILED;
    }

    mp4_init_segment_calc_size(
        segment,
        extra_moov_atoms_writer,
        stsd_atom_writers,
        sizes);

    // head request optimization
    if (size_only)
    {
        result->len = sizes->total_size;
        return VOD_OK;
    }

    // allocate the buffer
    result->data = vod_alloc(request_context->pool, sizes->total_size);
    if (result->data == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_init_segment_build: vod_alloc failed (2)");
        return VOD_ALLOC_FAILED;
    }

    // write the init mp4
    p = mp4_init_segment_write(
        result->data,
        request_context,
        segment,
        sizes,
        extra_moov_atoms_writer,
        stsd_atom_writers);

    result->len = p - result->data;

    if (result->len != sizes->total_size)
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_init_segment_build: result length %uz different than allocated length %uz",
            result->len, sizes->total_size);
        return VOD_UNEXPECTED;
    }

    return VOD_OK;
}

// encryption
#if (VOD_HAVE_OPENSSL_EVP)
#include "../aes_defs.h"

static vod_status_t
mp4_init_segment_init_encrypted_stsd_writer(
    request_context_t* request_context,
    media_init_segment_track_t* track,
    stsd_writer_context_t* result)
{
    vod_str_t* original_stsd = &track->stsd_atom;
    vod_status_t rc;

    // create an stsd atom if needed
    if (original_stsd->len == 0)
    {
        rc = mp4_init_segment_build_stsd_atom(request_context, track);
        if (rc != VOD_OK)
        {
            return rc;
        }
    }

    if (original_stsd->len < ATOM_HEADER_SIZE + sizeof(stsd_atom_t) + sizeof(stsd_entry_header_t))
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_init_segment_init_encrypted_stsd_writer: invalid stsd size %uL", original_stsd->len);
        return VOD_BAD_DATA;
    }

    result->media_type = track->media_info->media_type;
    result->original_stsd_entry = (stsd_entry_header_t*)(original_stsd->data + ATOM_HEADER_SIZE + sizeof(stsd_atom_t));
    result->original_stsd_entry_size = parse_be32(result->original_stsd_entry->size);
    result->original_stsd_entry_format = parse_be32(result->original_stsd_entry->format);

    if (result->original_stsd_entry_size < sizeof(stsd_entry_header_t) ||
        result->original_stsd_entry_size > original_stsd->len - ATOM_HEADER_SIZE -
            sizeof(stsd_atom_t))
    {
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_init_segment_init_encrypted_stsd_writer: invalid stsd entry size %uD", result->original_stsd_entry_size);
        return VOD_BAD_DATA;
    }

    if (result->iv != NULL)
    {
        result->tenc_atom_size = ATOM_HEADER_SIZE + sizeof(tenc_v1_atom_t);
    }
    else
    {
        result->tenc_atom_size = ATOM_HEADER_SIZE + sizeof(tenc_atom_t);
    }
    result->schi_atom_size = ATOM_HEADER_SIZE + result->tenc_atom_size;
    result->schm_atom_size = ATOM_HEADER_SIZE + sizeof(schm_atom_t);
    result->frma_atom_size = ATOM_HEADER_SIZE + sizeof(frma_atom_t);
    result->sinf_atom_size = ATOM_HEADER_SIZE +
        result->frma_atom_size +
        result->schm_atom_size +
        result->schi_atom_size;
    result->encrypted_stsd_entry_size = result->original_stsd_entry_size + result->sinf_atom_size;
    result->stsd_atom_size = ATOM_HEADER_SIZE + sizeof(stsd_atom_t) + result->encrypted_stsd_entry_size;
    if (result->has_clear_lead)
    {
        result->stsd_atom_size += result->original_stsd_entry_size;
    }

    return VOD_OK;
}


static u_char*
mp4_init_segment_write_encrypted_stsd(void* ctx, u_char* p)
{
    stsd_writer_context_t* context = (stsd_writer_context_t*)ctx;
    u_char format_by_media_type[MEDIA_TYPE_COUNT] = { 'v', 'a' };

    // stsd
    write_atom_header(p, context->stsd_atom_size, 's', 't', 's', 'd');
    write_be32(p, 0);                                // version + flags
    write_be32(p, context->has_clear_lead ? 2 : 1);    // entries

                                                    // stsd encrypted entry
    write_be32(p, context->encrypted_stsd_entry_size);        // size
    write_atom_name(p, 'e', 'n', 'c', format_by_media_type[context->media_type]);    // format
    p = vod_copy(p, context->original_stsd_entry + 1, context->original_stsd_entry_size - sizeof(stsd_entry_header_t));

    // sinf
    write_atom_header(p, context->sinf_atom_size, 's', 'i', 'n', 'f');

    // sinf.frma
    write_atom_header(p, context->frma_atom_size, 'f', 'r', 'm', 'a');
    write_be32(p, context->original_stsd_entry_format);

    // sinf.schm
    write_atom_header(p, context->schm_atom_size, 's', 'c', 'h', 'm');
    write_be32(p, 0);                            // version + flags
    write_be32(p, context->scheme_type);        // scheme type
    write_be32(p, 0x10000);                        // scheme version

                                                // sinf.schi
    write_atom_header(p, context->schi_atom_size, 's', 'c', 'h', 'i');

    // sinf.schi.tenc
    write_atom_header(p, context->tenc_atom_size, 't', 'e', 'n', 'c');
    if (context->iv != NULL)
    {
        write_be32(p, 0x01000000);                // version + flags
    }
    else
    {
        write_be32(p, 0);                        // version + flags
    }

    switch (context->scheme_type)
    {
    case SCHEME_TYPE_CENC:
        write_be32(p, 0x108);                    // default is encrypted, iv size = 8
        break;

    case SCHEME_TYPE_CBCS:
        switch (context->media_type)
        {
        case MEDIA_TYPE_VIDEO:
            write_be32(p, 0x190100);                    // default is encrypted, 1/9 crypt/skip ratio
            break;

        case MEDIA_TYPE_AUDIO:
            write_be32(p, 0x000100);                    // default is encrypted
            break;
        }
        break;
    }

    if (context->default_kid != NULL)
    {
        p = vod_copy(p, context->default_kid, DRM_KID_SIZE);    // default key id
    }
    else
    {
        vod_memzero(p, DRM_KID_SIZE);
        p += DRM_KID_SIZE;
    }

    if (context->iv != NULL)
    {
        *p++ = AES_BLOCK_SIZE;                            // default constant iv size
        p = vod_copy(p, context->iv, AES_BLOCK_SIZE);    // default constant iv
    }

    // clear entry
    if (context->has_clear_lead)
    {
        p = vod_copy(p, context->original_stsd_entry, context->original_stsd_entry_size);
    }

    return p;
}

vod_status_t
mp4_init_segment_get_encrypted_stsd_writers(
    request_context_t* request_context,
    media_init_segment_t* segment,
    uint32_t scheme_type,
    bool_t has_clear_lead,
    atom_writer_t** result)
{
    media_init_segment_track_t* cur_track;
    stsd_writer_context_t* stsd_writer_context;
    atom_writer_t* stsd_atom_writer;
    vod_status_t rc;
    media_enc_t* enc;
    uint32_t i;

    // allocate the context
    stsd_atom_writer = vod_alloc(request_context->pool,
        (sizeof(*stsd_atom_writer) + sizeof(*stsd_writer_context)) * segment->count);
    if (stsd_atom_writer == NULL)
    {
        vod_log_debug0(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_init_segment_get_encrypted_stsd_writers: vod_alloc failed");
        return VOD_ALLOC_FAILED;
    }

    *result = stsd_atom_writer;

    stsd_writer_context = (void*)(stsd_atom_writer + segment->count);

    for (i = 0;
        i < segment->count;
        i++, stsd_writer_context++, stsd_atom_writer++)
    {
        cur_track = &segment->first[i];
        enc = cur_track->enc;
        if (enc == NULL) // subtitles
        {
            vod_memzero(stsd_atom_writer, sizeof(*stsd_atom_writer));
            continue;
        }

        // build the stsd writer for the current track
        stsd_writer_context->scheme_type = scheme_type;
        stsd_writer_context->has_clear_lead = has_clear_lead;
        if (enc->has_key_id)
        {
            stsd_writer_context->default_kid = enc->key_id;
        }
        else
        {
            stsd_writer_context->default_kid = NULL;
        }
        stsd_writer_context->iv = scheme_type == SCHEME_TYPE_CBCS ? enc->iv : NULL;

        rc = mp4_init_segment_init_encrypted_stsd_writer(
            request_context,
            cur_track,
            stsd_writer_context);
        if (rc != VOD_OK)
        {
            vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
                "mp4_init_segment_get_encrypted_stsd_writers: mp4_init_segment_init_encrypted_stsd_writer failed %i", rc);
            return rc;
        }

        stsd_atom_writer->atom_size = stsd_writer_context->stsd_atom_size;
        stsd_atom_writer->write = mp4_init_segment_write_encrypted_stsd;
        stsd_atom_writer->context = stsd_writer_context;
    }

    return VOD_OK;
}
#endif // VOD_HAVE_OPENSSL_EVP
