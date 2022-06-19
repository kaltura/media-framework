#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_utils.h"
#include "ngx_http_pckg_fmp4.h"
#include "ngx_pckg_adapt_set.h"

#if (NGX_HAVE_OPENSSL_EVP)
#include "media/mp4/mp4_dash_encrypt.h"
#include "media/mp4/mp4_cenc_encrypt.h"
#endif


static ngx_int_t ngx_http_pckg_mpd_preconfiguration(ngx_conf_t *cf);

static void *ngx_http_pckg_mpd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pckg_mpd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);


#define MPD_DATE_TIME_FORMAT  "%04d-%02d-%02dT%02d:%02d:%02dZ"

#define MPD_DATE_TIME_LEN     (sizeof("2010-01-01T00:00:00Z") - 1)

#define mpd_date_time_params(tm)                                            \
    (tm).ngx_tm_year, (tm).ngx_tm_mon, (tm).ngx_tm_mday,                    \
    (tm).ngx_tm_hour, (tm).ngx_tm_min, (tm).ngx_tm_sec


#define MPD_HEADER1                                                         \
    "<?xml version=\"1.0\"?>\n"                                             \
    "<MPD\n"                                                                \
    "    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"         \
    "    xmlns=\"urn:mpeg:dash:schema:mpd:2011\"\n"                         \
    "    xsi:schemaLocation=\"urn:mpeg:dash:schema:mpd:2011 "               \
        "http://standards.iso.org/ittf/PubliclyAvailableStandards"          \
        "/MPEG-DASH_schema_files/DASH-MPD.xsd\"\n"                          \
    "    profiles=\"%V\"\n"                                                 \
    "    type=\"dynamic\"\n"                                                \
    "    availabilityStartTime=\"" MPD_DATE_TIME_FORMAT "\"\n"              \
    "    publishTime=\"" MPD_DATE_TIME_FORMAT "\"\n"

#define MPD_MIN_UPDATE_PERIOD                                               \
    "    minimumUpdatePeriod=\"PT%uD.%03uDS\"\n"

#define MPD_MEDIA_PRES_DURATION                                             \
    "    mediaPresentationDuration=\"PT%uD.%03uDS\"\n"

#define MPD_HEADER2                                                         \
    "    minBufferTime=\"PT%uD.%03uDS\"\n"                                  \
    "    timeShiftBufferDepth=\"PT%uD.%03uDS\"\n"                           \
    "    suggestedPresentationDelay=\"PT%uD.%03uDS\">\n"

#define MPD_PERIOD_HEADER_START                                             \
    "  <Period id=\"%uD\" start=\"PT%uD.%03uDS\">\n"

#define MPD_PERIOD_HEADER_START_DURATION                                    \
    "  <Period id=\"%uD\" start=\"PT%uD.%03uDS\" duration=\"PT%uD.%03uDS\">\n"

#define MPD_ADAPTATION_HEADER_VIDEO                                         \
    "    <AdaptationSet\n"                                                  \
    "        id=\"%uD\"\n"                                                  \
    "        maxWidth=\"%uD\"\n"                                            \
    "        maxHeight=\"%uD\"\n"                                           \
    "        maxFrameRate=\"%uD/%uD\"\n"                                    \
    "        segmentAlignment=\"true\">\n"

#define MPD_ACCESSIBILITY_CEA_608                                           \
    "      <Accessibility schemeIdUri=\"urn:scte:dash:cc:cea-608:2015\"/>\n"

#define MPD_REPRESENTATION_VIDEO                                            \
    "      <Representation\n"                                               \
    "          id=\"s%V-v\"\n"                                              \
    "          bandwidth=\"%uD\"\n"                                         \
    "          width=\"%uD\"\n"                                             \
    "          height=\"%uD\"\n"                                            \
    "          sar=\"1:1\"\n"                                               \
    "          frameRate=\"%uD/%uD\"\n"                                     \
    "          mimeType=\"%V\"\n"                                           \
    "          codecs=\"%V\"\n"                                             \
    "          startWithSAP=\"1\"/>\n"

#define MPD_ADAPTATION_HEADER_AUDIO                                         \
    "    <AdaptationSet\n"                                                  \
    "        id=\"%uD\"\n"                                                  \
    "        segmentAlignment=\"true\">\n"

#define MPD_ADAPTATION_HEADER_AUDIO_LANG                                    \
    "    <AdaptationSet\n"                                                  \
    "        id=\"%uD\"\n"                                                  \
    "        lang=\"%V\"\n"                                                 \
    "        segmentAlignment=\"true\">\n"

#define MPD_ADAPTATION_LABEL                                                \
    "      <Label>%V</Label>\n"

#define MPD_AUDIO_CHANNEL_CONFIG                                            \
    "      <AudioChannelConfiguration\n"                                    \
    "          schemeIdUri=\"urn:mpeg:dash:23003:3:"                        \
                                "audio_channel_configuration:2011\"\n"      \
    "          value=\"%uD\"/>\n"

#define MPD_AUDIO_CHANNEL_CONFIG_EAC3                                       \
    "      <AudioChannelConfiguration\n"                                    \
    "          schemeIdUri=\"tag:dolby.com,2014:dash:"                      \
                                "audio_channel_configuration:2011\"\n"      \
    "          value=\"%uxD\"/>\n"

#define MPD_REPRESENTATION_AUDIO                                            \
    "      <Representation\n"                                               \
    "          id=\"s%V-a\"\n"                                              \
    "          bandwidth=\"%uD\"\n"                                         \
    "          audioSamplingRate=\"%uD\"\n"                                 \
    "          mimeType=\"%V\"\n"                                           \
    "          codecs=\"%V\"\n"                                             \
    "          startWithSAP=\"1\"/>\n"

#define MPD_SEGMENT_TEMPLATE_HEADER                                         \
    "      <SegmentTemplate\n"                                              \
    "          timescale=\"%uD\"\n"                                         \
    "          media=\"%V-$Number$-$RepresentationID$%V\"\n"                \
    "          initialization=\"%V-%uD-$RepresentationID$%V\"\n"            \
    "          startNumber=\"%uD\">\n"                                      \
    "        <SegmentTimeline>\n"

#define MPD_SEGMENT_REPEAT_TIME                                             \
    "          <S t=\"%uL\" d=\"%uD\" r=\"%uD\"/>\n"

#define MPD_SEGMENT_TIME                                                    \
    "          <S t=\"%uL\" d=\"%uD\"/>\n"

#define MPD_SEGMENT_REPEAT                                                  \
    "          <S d=\"%uD\" r=\"%uD\"/>\n"

#define MPD_SEGMENT                                                         \
    "          <S d=\"%uD\"/>\n"

#define MPD_SEGMENT_TEMPLATE_FOOTER                                         \
    "        </SegmentTimeline>\n"                                          \
    "      </SegmentTemplate>\n"

#define MPD_ADAPTATION_FOOTER                                               \
    "    </AdaptationSet>\n"

#define MPD_PERIOD_FOOTER                                                   \
    "  </Period>\n"

#define MPD_UTC_TIMING                                                      \
    "  <UTCTiming\n"                                                        \
    "      schemeIdUri=\"urn:mpeg:dash:utc:direct:2014\"\n"                 \
    "      value=\"" MPD_DATE_TIME_FORMAT "\"/>\n"

#define MPD_FOOTER                                                          \
    "</MPD>\n"


#define MPD_CONT_PROT_CENC                                                  \
    "      <ContentProtection "                                             \
    "schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\" value=\"cenc\"/>\n"

#define MPD_CONT_PROT_CENC_SYS_ID                                           \
    "      <ContentProtection xmlns:cenc=\"urn:mpeg:cenc:2013\" "           \
    "schemeIdUri=\"urn:uuid:"

#define MPD_CONT_PROT_CENC_KEY_ID                                           \
    "\" cenc:default_KID=\""

#define MPD_CONT_PROT_CENC_PSSH                                             \
    "\">\n"                                                                 \
    "        <cenc:pssh>"

#define MPD_CONT_PROT_CENC_FOOTER                                           \
    "</cenc:pssh>\n"                                                        \
    "      </ContentProtection>\n"

#define MPD_CONT_PROT_PLAYREADY_SYS_ID                                      \
    "      <ContentProtection xmlns:cenc=\"urn:mpeg:cenc:2013\" "           \
    "xmlns:mspr=\"urn:microsoft:playready\" schemeIdUri=\"urn:uuid:"

#define MPD_CONT_PROT_PLAYREADY_KEY_ID                                      \
    "\" value=\"2.0\" cenc:default_KID=\""

#define MPD_CONT_PROT_PLAYREADY_PSSH                                        \
    "\">\n"                                                                 \
    "        <mspr:pro>"

#define MPD_CONT_PROT_PLAYREADY_FOOTER                                      \
    "</mspr:pro>\n"                                                         \
    "      </ContentProtection>\n"

#define mpd_is_playready_sys_id(id)                                         \
    (ngx_memcmp(id, ngx_http_pckg_mpd_playready_sys_id,                     \
        sizeof(ngx_http_pckg_mpd_playready_sys_id)) == 0)


typedef struct {
    ngx_http_complex_value_t  *profiles;
    ngx_uint_t                 pres_delay_segments;
}  ngx_http_pckg_mpd_loc_conf_t;


typedef struct {
    uint32_t                   max_width;
    uint32_t                   max_height;
    uint32_t                   max_frame_rate_num;
    uint32_t                   max_frame_rate_denom;
    unsigned                   cea_captions:1;
} ngx_http_pckg_mpd_video_params_t;


static ngx_command_t  ngx_http_pckg_mpd_commands[] = {

    { ngx_string("pckg_mpd_profiles"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_mpd_loc_conf_t, profiles),
      NULL },

    { ngx_string("pckg_mpd_pres_delay_segments"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pckg_mpd_loc_conf_t, pres_delay_segments),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pckg_mpd_module_ctx = {
    ngx_http_pckg_mpd_preconfiguration, /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_pckg_mpd_create_loc_conf,  /* create location configuration */
    ngx_http_pckg_mpd_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_pckg_mpd_module = {
    NGX_MODULE_V1,
    &ngx_http_pckg_mpd_module_ctx,      /* module context */
    ngx_http_pckg_mpd_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_pckg_mpd_ext = ngx_string(".mpd");

static ngx_str_t  ngx_http_pckg_mpd_content_type =
    ngx_string("application/dash+xml");


#if (NGX_HAVE_OPENSSL_EVP)

static u_char     ngx_http_pckg_mpd_playready_sys_id[] = {
    0x9a, 0x04, 0xf0, 0x79, 0x98, 0x40, 0x42, 0x86,
    0xab, 0x92, 0xe6, 0x5b, 0xe0, 0x88, 0x5f, 0x95
};

static size_t
ngx_http_pckg_mpd_cont_prot_get_size(ngx_pckg_track_t *track)
{
    size_t            size;
    ngx_uint_t        i, n;
    media_enc_t      *enc = track->enc;
    media_enc_sys_t  *sys, *elts;

    if (enc == NULL) {
        return 0;
    }

    n = enc->systems.nelts;
    elts = enc->systems.elts;

    size = sizeof(MPD_CONT_PROT_CENC) - 1;
    for (i = 0; i < n; i++) {
        sys = &elts[i];

        if (mpd_is_playready_sys_id(sys->id)) {
            size += sizeof(MPD_CONT_PROT_PLAYREADY_SYS_ID) - 1
                + VOD_GUID_LENGTH
                + sizeof(MPD_CONT_PROT_PLAYREADY_KEY_ID) - 1
                + VOD_GUID_LENGTH
                + sizeof(MPD_CONT_PROT_PLAYREADY_PSSH) - 1
                + sys->base64_data.len
                + sizeof(MPD_CONT_PROT_PLAYREADY_FOOTER) - 1;

        } else {
            size += sizeof(MPD_CONT_PROT_CENC_SYS_ID) - 1
                + VOD_GUID_LENGTH
                + sizeof(MPD_CONT_PROT_CENC_KEY_ID) - 1
                + VOD_GUID_LENGTH
                + sizeof(MPD_CONT_PROT_CENC_PSSH) - 1
                + mp4_dash_encrypt_base64_pssh_get_size(sys)
                + sizeof(MPD_CONT_PROT_CENC_FOOTER) - 1;
        }
    }

    return size;
}

static u_char *
ngx_http_pckg_mpd_cont_prot_write(u_char *p, ngx_pckg_track_t *track)
{
    ngx_uint_t        i, n;
    media_enc_t      *enc = track->enc;
    media_enc_sys_t  *sys, *elts;

    if (enc == NULL) {
        return p;
    }

    n = enc->systems.nelts;
    elts = enc->systems.elts;

    p = ngx_copy_fix(p, MPD_CONT_PROT_CENC);
    for (i = 0; i < n; i++) {
        sys = &elts[i];
        if (mpd_is_playready_sys_id(sys->id)) {
            p = ngx_copy_fix(p, MPD_CONT_PROT_PLAYREADY_SYS_ID);
            p = mp4_cenc_encrypt_write_guid(p, sys->id);
            p = ngx_copy_fix(p, MPD_CONT_PROT_PLAYREADY_KEY_ID);
            p = mp4_cenc_encrypt_write_guid(p, enc->key_id);
            p = ngx_copy_fix(p, MPD_CONT_PROT_PLAYREADY_PSSH);
            p = ngx_copy(p, sys->base64_data.data, sys->base64_data.len);
            p = ngx_copy_fix(p, MPD_CONT_PROT_PLAYREADY_FOOTER);

        } else {
            p = ngx_copy_fix(p, MPD_CONT_PROT_CENC_SYS_ID);
            p = mp4_cenc_encrypt_write_guid(p, sys->id);
            p = ngx_copy_fix(p, MPD_CONT_PROT_CENC_KEY_ID);
            p = mp4_cenc_encrypt_write_guid(p, enc->key_id);
            p = ngx_copy_fix(p, MPD_CONT_PROT_CENC_PSSH);
            p = mp4_dash_encrypt_base64_pssh_write(p, sys);
            p = ngx_copy_fix(p, MPD_CONT_PROT_CENC_FOOTER);
        }
    }

    return p;
}

#else

static size_t
ngx_http_pckg_mpd_cont_prot_get_size(ngx_pckg_track_t *track)
{
    return 0;
}

static u_char *
ngx_http_pckg_mpd_cont_prot_write(u_char *p, ngx_pckg_track_t *track)
{
    return p;
}

#endif


static ngx_http_pckg_container_t *
ngx_http_pckg_mpd_get_container(uint32_t codec_id)
{
    return &ngx_http_pckg_fmp4_container;
}


static int64_t
ngx_http_pckg_mpd_get_segment_time(ngx_pckg_timeline_t *timeline,
    ngx_uint_t end_offset)
{
    int64_t                     time;
    ngx_uint_t                  i, j;
    ngx_pckg_period_t          *periods, *period;
    ngx_ksmp_segment_repeat_t  *elt;

    time = 0;   /* suppress warning */

    periods = timeline->periods.elts;
    for (i = timeline->periods.nelts; i > 0; i--) {
        period = &periods[i - 1];
        time = period->header->time + period->duration;

        for (j = period->nelts; j > 0; j--) {
            elt = &period->elts[j - 1];
            if (elt->count >= end_offset) {
                return time - end_offset * elt->duration;
            }

            time -= (int64_t) elt->count * elt->duration;
            end_offset -= elt->count;
        }
    }

    return time;
}


static uint32_t
ngx_http_pckg_mpd_get_eac3_channel_config(media_info_t *media_info)
{
    uint64_t  cur;
    uint32_t  result = 0;
    uint32_t  i;

    static uint64_t  channel_layout_map[] = {
        KMP_CH_FRONT_LEFT,
        KMP_CH_FRONT_CENTER,
        KMP_CH_FRONT_RIGHT,
        KMP_CH_SIDE_LEFT,
        KMP_CH_SIDE_RIGHT,
        KMP_CH_FRONT_LEFT_OF_CENTER | KMP_CH_FRONT_RIGHT_OF_CENTER,
        KMP_CH_BACK_LEFT | KMP_CH_BACK_RIGHT,
        KMP_CH_BACK_CENTER,
        KMP_CH_TOP_CENTER,
        KMP_CH_SURROUND_DIRECT_LEFT | KMP_CH_SURROUND_DIRECT_RIGHT,
        KMP_CH_WIDE_LEFT | KMP_CH_WIDE_RIGHT,
        KMP_CH_TOP_FRONT_LEFT | KMP_CH_TOP_FRONT_RIGHT,
        KMP_CH_TOP_FRONT_CENTER,
        KMP_CH_TOP_BACK_LEFT | KMP_CH_TOP_BACK_RIGHT,
        KMP_CH_LOW_FREQUENCY_2,
        KMP_CH_LOW_FREQUENCY,
    };

    for (i = 0; i < vod_array_entries(channel_layout_map); i++) {
        cur = channel_layout_map[i];
        if ((media_info->u.audio.channel_layout & cur) == cur) {
            result |= 1 << (15 - i);
        }
    }

    return result;
}


static size_t
ngx_http_pckg_seg_tmpl_get_size(ngx_pckg_period_t *period,
    ngx_http_pckg_container_t *container)
{
    return sizeof(MPD_SEGMENT_TEMPLATE_HEADER) - 1 + NGX_INT32_LEN * 3
        + ngx_http_pckg_prefix_seg.len + container->seg_file_ext->len +
        + ngx_http_pckg_prefix_init_seg.len + container->init_file_ext->len
        + sizeof(MPD_SEGMENT_REPEAT_TIME) - 1 + NGX_INT32_LEN * 2
        + NGX_INT64_LEN
        + (period->nelts - 1) * (sizeof(MPD_SEGMENT_REPEAT) - 1
            + NGX_INT32_LEN * 2)
        + sizeof(MPD_SEGMENT_TEMPLATE_FOOTER) - 1;
}


static u_char *
ngx_http_pckg_seg_tmpl_write(u_char *p, ngx_pckg_period_t *period,
    ngx_http_pckg_container_t *container)
{
    int64_t                     shift;
    int64_t                     start_time;
    int64_t                     initial_time;
    uint32_t                    init_index;
    uint32_t                    start_number;
    ngx_uint_t                  i;
    ngx_pckg_channel_t         *channel;
    ngx_pckg_timeline_t        *timeline;
    ngx_ksmp_segment_repeat_t  *elt;

    timeline = period->timeline;
    channel = timeline->channel;

    start_number = period->header->segment_index + 1;

    if ((void *) period == timeline->periods.elts) {
        initial_time = timeline->header->first_period_initial_time;
        start_time = period->header->time;

        shift = start_time - initial_time;
        init_index = timeline->header->first_period_initial_segment_index + 1;

    } else {
        shift = 0;
        init_index = start_number;
    }

    p = ngx_sprintf(p, MPD_SEGMENT_TEMPLATE_HEADER,
        channel->header->timescale,
        &ngx_http_pckg_prefix_seg,
        container->seg_file_ext,
        &ngx_http_pckg_prefix_init_seg,
        init_index,
        container->init_file_ext,
        start_number);

    elt = period->elts;

    if (shift > 0) {
        if (elt->count > 1) {
            p = ngx_sprintf(p, MPD_SEGMENT_REPEAT_TIME,
                shift, elt->duration, elt->count - 1);

        } else {
            p = ngx_sprintf(p, MPD_SEGMENT_TIME, shift, elt->duration);
        }

    } else {
        if (elt->count > 1) {
            p = ngx_sprintf(p, MPD_SEGMENT_REPEAT,
                elt->duration, elt->count - 1);

        } else {
            p = ngx_sprintf(p, MPD_SEGMENT, elt->duration);
        }
    }

    for (i = 1; i < period->nelts; i++) {
        elt = &period->elts[i];

        if (elt->count > 1) {
            p = ngx_sprintf(p, MPD_SEGMENT_REPEAT,
                elt->duration, elt->count - 1);

        } else {
            p = ngx_sprintf(p, MPD_SEGMENT, elt->duration);
        }
    }

    p = ngx_copy(p, MPD_SEGMENT_TEMPLATE_FOOTER,
        sizeof(MPD_SEGMENT_TEMPLATE_FOOTER) - 1);

    return p;
}


static uint32_t
ngx_http_pckg_mpd_get_avg_segment_duration(ngx_pckg_period_t *period)
{
    uint32_t             sd;
    uint32_t             timescale;
    ngx_pckg_channel_t  *channel;

    channel = period->timeline->channel;
    timescale = channel->header->timescale;

    sd = rescale_time(period->duration / period->segment_count,
        timescale, 1000);

    return sd > 0 ? sd : 1;
}


static media_info_t *
ngx_http_pckg_mpd_get_sample_media_info(ngx_pckg_adapt_set_t *set,
    uint32_t segment_index)
{
    uint32_t              media_type;
    ngx_uint_t            i, n;
    media_info_t         *media_info;
    ngx_pckg_track_t     *track;
    ngx_pckg_variant_t  **variants, *variant;

    media_type = set->media_info->media_type;

    n = set->variants.nelts;
    variants = set->variants.elts;

    media_info = NULL;
    for (i = 0; i < n; i++) {
        variant = variants[i];
        track = variant->tracks[media_type];

        ngx_pckg_media_info_iter_get(&track->media_info_iter, segment_index,
            &media_info);
        if (media_info != NULL) {
            return media_info;
        }
    }

    return NULL;
}


static void
ngx_http_pckg_mpd_init_video_params(ngx_pckg_adapt_set_t *set,
    uint32_t segment_index, ngx_http_pckg_mpd_video_params_t *params)
{
    ngx_uint_t            i, n;
    media_info_t         *media_info;
    ngx_pckg_track_t     *track;
    ngx_pckg_variant_t  **variants, *variant;

    ngx_memzero(params, sizeof(*params));
    params->max_frame_rate_denom = 1;
    params->cea_captions = 1;

    n = set->variants.nelts;
    variants = set->variants.elts;

    for (i = 0; i < n; i++) {
        variant = variants[i];
        track = variant->tracks[KMP_MEDIA_VIDEO];

        ngx_pckg_media_info_iter_get(&track->media_info_iter, segment_index,
            &media_info);
        if (media_info == NULL) {
            continue;
        }

        /* Note: reporting cea captions only if ALL tracks have it */
        if (!media_info->u.video.cea_captions) {
            params->cea_captions = 0;
        }

        if (params->max_frame_rate_num * media_info->u.video.frame_rate_denom <
            media_info->u.video.frame_rate_num * params->max_frame_rate_denom)
        {
            params->max_frame_rate_num = media_info->u.video.frame_rate_num;
            params->max_frame_rate_denom =
                media_info->u.video.frame_rate_denom;
        }

        if (params->max_width < media_info->u.video.width) {
            params->max_width = media_info->u.video.width;
        }

        if (params->max_height < media_info->u.video.height) {
            params->max_height = media_info->u.video.height;
        }
    }
}


/* Note: the size of the variant ids must be added outside this function */
static size_t
ngx_http_pckg_mpd_video_adapt_set_get_size(ngx_pckg_adapt_set_t *set,
    ngx_pckg_period_t *period)
{
    ngx_str_t                    content_type;
    ngx_pckg_track_t            *track;
    ngx_pckg_variant_t         **variants;
    ngx_http_pckg_container_t   *container;

    container = ngx_http_pckg_mpd_get_container(set->media_info->codec_id);
    container->get_content_type(set->media_info, &content_type);

    variants = set->variants.elts;
    track = variants[0]->tracks[KMP_MEDIA_VIDEO];

    return sizeof(MPD_ADAPTATION_HEADER_VIDEO) - 1 + NGX_INT32_LEN * 5
        + sizeof(MPD_ACCESSIBILITY_CEA_608) - 1
        + ngx_http_pckg_seg_tmpl_get_size(period, container)
        + set->variants.nelts * (sizeof(MPD_REPRESENTATION_VIDEO) - 1
            + content_type.len + MAX_CODEC_NAME_SIZE + NGX_INT32_LEN * 5)
        + ngx_http_pckg_mpd_cont_prot_get_size(track)
        + sizeof(MPD_ADAPTATION_FOOTER) - 1;
}


static u_char *
ngx_http_pckg_mpd_video_adapt_set_write(u_char *p, ngx_http_request_t *r,
    ngx_pckg_adapt_set_t *set, ngx_pckg_period_t *period, uint32_t id)
{
    uint32_t                            bitrate;
    uint32_t                            segment_index;
    uint32_t                            segment_duration;
    ngx_str_t                           content_type;
    ngx_uint_t                          i, n;
    media_info_t                       *media_info;
    ngx_pckg_track_t                   *track;
    ngx_pckg_variant_t                **variants, *variant;
    ngx_http_pckg_container_t          *container;
    ngx_http_pckg_mpd_video_params_t    params;

    segment_index = period->header->segment_index;

    ngx_http_pckg_mpd_init_video_params(set, segment_index, &params);
    if (params.max_frame_rate_num == 0) {
        return p;
    }

    container = ngx_http_pckg_mpd_get_container(set->media_info->codec_id);
    container->get_content_type(set->media_info, &content_type);

    segment_duration = ngx_http_pckg_mpd_get_avg_segment_duration(period);

    p = ngx_sprintf(p, MPD_ADAPTATION_HEADER_VIDEO, id,
        params.max_width, params.max_height,
        params.max_frame_rate_num, params.max_frame_rate_denom);

    if (params.cea_captions) {
        p = ngx_copy(p, MPD_ACCESSIBILITY_CEA_608,
            sizeof(MPD_ACCESSIBILITY_CEA_608) - 1);
    }

    p = ngx_http_pckg_seg_tmpl_write(p, period, container);

    n = set->variants.nelts;
    variants = set->variants.elts;

    for (i = 0; i < n; i++) {
        variant = variants[i];
        track = variant->tracks[KMP_MEDIA_VIDEO];

        ngx_pckg_media_info_iter_get(&track->media_info_iter, segment_index,
            &media_info);
        if (media_info == NULL) {
            continue;
        }

        bitrate = ngx_http_pckg_estimate_bitrate(r, container,
            &media_info, 1, segment_duration);

        p = ngx_sprintf(p, MPD_REPRESENTATION_VIDEO,
            &variant->id,
            bitrate,
            (uint32_t) media_info->u.video.width,
            (uint32_t) media_info->u.video.height,
            media_info->u.video.frame_rate_num,
            media_info->u.video.frame_rate_denom,
            &content_type,
            &media_info->codec_name);
    }

    track = variants[0]->tracks[KMP_MEDIA_VIDEO];
    p = ngx_http_pckg_mpd_cont_prot_write(p, track);

    p = ngx_copy(p, MPD_ADAPTATION_FOOTER, sizeof(MPD_ADAPTATION_FOOTER) - 1);

    return p;
}


/* Note: the size of the variant ids must be added outside this function */
static size_t
ngx_http_pckg_mpd_audio_adapt_set_get_size(ngx_pckg_adapt_set_t *set,
    ngx_pckg_period_t *period)
{
    size_t                       size;
    ngx_str_t                    content_type;
    ngx_pckg_track_t            *track;
    ngx_pckg_variant_t         **variants;
    ngx_http_pckg_container_t   *container;

    container = ngx_http_pckg_mpd_get_container(set->media_info->codec_id);
    container->get_content_type(set->media_info, &content_type);

    variants = set->variants.elts;
    track = variants[0]->tracks[KMP_MEDIA_AUDIO];

    size = sizeof(MPD_ADAPTATION_HEADER_AUDIO_LANG) - 1 + NGX_INT32_LEN
            + variants[0]->lang.len
        + sizeof(MPD_ADAPTATION_LABEL) - 1 + variants[0]->label.len
        + ngx_http_pckg_seg_tmpl_get_size(period, container)
        + set->variants.nelts * (sizeof(MPD_REPRESENTATION_AUDIO) - 1
            + NGX_INT32_LEN * 2 + content_type.len + MAX_CODEC_NAME_SIZE)
        + ngx_http_pckg_mpd_cont_prot_get_size(track)
        + sizeof(MPD_ADAPTATION_FOOTER) - 1;

    if (set->media_info->codec_id == VOD_CODEC_ID_EAC3) {
        size += sizeof(MPD_AUDIO_CHANNEL_CONFIG_EAC3) - 1
            + NGX_INT32_HEX_LEN;

    } else {
        size += sizeof(MPD_AUDIO_CHANNEL_CONFIG) - 1 + NGX_INT32_LEN;
    }

    return size;
}


static u_char *
ngx_http_pckg_mpd_audio_adapt_set_write(u_char *p, ngx_http_request_t *r,
    ngx_pckg_adapt_set_t *set, ngx_pckg_period_t *period, uint32_t id)
{
    uint32_t                     bitrate;
    uint32_t                     codec_id;
    uint32_t                     segment_index;
    uint32_t                     segment_duration;
    ngx_str_t                    content_type;
    ngx_uint_t                   i, n;
    media_info_t                *media_info;
    ngx_pckg_track_t            *track;
    ngx_pckg_variant_t         **variants, *variant;
    ngx_http_pckg_container_t   *container;

    segment_index = period->header->segment_index;

    media_info = ngx_http_pckg_mpd_get_sample_media_info(set, segment_index);
    if (media_info == NULL) {
        return p;
    }

    codec_id = set->media_info->codec_id;
    container = ngx_http_pckg_mpd_get_container(codec_id);
    container->get_content_type(set->media_info, &content_type);

    segment_duration = ngx_http_pckg_mpd_get_avg_segment_duration(period);

    n = set->variants.nelts;
    variants = set->variants.elts;

    if (variants[0]->lang.len != 0) {
        p = ngx_sprintf(p, MPD_ADAPTATION_HEADER_AUDIO_LANG, id,
            &variants[0]->lang);

    } else {
        p = ngx_sprintf(p, MPD_ADAPTATION_HEADER_AUDIO, id);
    }

    if (variants[0]->label.len != 0) {
        p = ngx_sprintf(p, MPD_ADAPTATION_LABEL, &variants[0]->label);
    }

    if (codec_id == VOD_CODEC_ID_EAC3) {
        p = ngx_sprintf(p, MPD_AUDIO_CHANNEL_CONFIG_EAC3,
            ngx_http_pckg_mpd_get_eac3_channel_config(media_info));

    } else {
        p = ngx_sprintf(p, MPD_AUDIO_CHANNEL_CONFIG,
            (uint32_t) media_info->u.audio.channels);
    }

    p = ngx_http_pckg_seg_tmpl_write(p, period, container);

    for (i = 0; i < n; i++) {
        variant = variants[i];
        track = variant->tracks[KMP_MEDIA_AUDIO];

        ngx_pckg_media_info_iter_get(&track->media_info_iter, segment_index,
            &media_info);
        if (media_info == NULL) {
            continue;
        }

        bitrate = ngx_http_pckg_estimate_bitrate(r, container,
            &media_info, 1, segment_duration);

        p = ngx_sprintf(p, MPD_REPRESENTATION_AUDIO,
            &variant->id,
            bitrate,
            media_info->u.audio.sample_rate,
            &content_type,
            &media_info->codec_name);
    }

    track = variants[0]->tracks[KMP_MEDIA_AUDIO];
    p = ngx_http_pckg_mpd_cont_prot_write(p, track);

    p = ngx_copy(p, MPD_ADAPTATION_FOOTER, sizeof(MPD_ADAPTATION_FOOTER) - 1);

    return p;
}


static size_t
ngx_http_pckg_mpd_adapt_sets_get_size(ngx_pckg_adapt_sets_t *sets,
    ngx_pckg_period_t *period)
{
    size_t                 size;
    ngx_queue_t           *q;
    ngx_pckg_adapt_set_t  *set;

    size = 0;

    for (q = ngx_queue_head(&sets->queue[KMP_MEDIA_VIDEO]);
        q != ngx_queue_sentinel(&sets->queue[KMP_MEDIA_VIDEO]);
        q = ngx_queue_next(q))
    {
        set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

        size += ngx_http_pckg_mpd_video_adapt_set_get_size(set, period);
    }

    for (q = ngx_queue_head(&sets->queue[KMP_MEDIA_AUDIO]);
        q != ngx_queue_sentinel(&sets->queue[KMP_MEDIA_AUDIO]);
        q = ngx_queue_next(q))
    {
        set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

        size += ngx_http_pckg_mpd_audio_adapt_set_get_size(set, period);
    }

    return size;
}


static u_char *
ngx_http_pckg_mpd_adapt_sets_write(u_char *p, ngx_http_request_t *r,
    ngx_pckg_adapt_sets_t *sets, ngx_pckg_period_t *period)
{
    uint32_t               adapt_id;
    ngx_queue_t           *q;
    ngx_pckg_adapt_set_t  *set;

    adapt_id = 0;

    for (q = ngx_queue_head(&sets->queue[KMP_MEDIA_VIDEO]);
        q != ngx_queue_sentinel(&sets->queue[KMP_MEDIA_VIDEO]);
        q = ngx_queue_next(q))
    {
        set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

        adapt_id++;

        p = ngx_http_pckg_mpd_video_adapt_set_write(p, r, set, period,
            adapt_id);
    }

    for (q = ngx_queue_head(&sets->queue[KMP_MEDIA_AUDIO]);
        q != ngx_queue_sentinel(&sets->queue[KMP_MEDIA_AUDIO]);
        q = ngx_queue_next(q))
    {
        set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

        adapt_id++;

        p = ngx_http_pckg_mpd_audio_adapt_set_write(p, r, set, period,
            adapt_id);
    }

    return p;
}


static size_t
ngx_http_pckg_mpd_header_get_size(ngx_str_t *profiles)
{
    return sizeof(MPD_HEADER1) - 1 + profiles->len + MPD_DATE_TIME_LEN * 2 +
        sizeof(MPD_MEDIA_PRES_DURATION) - 1 + NGX_INT32_LEN * 2 +
        sizeof(MPD_HEADER2) - 1 + NGX_INT32_LEN * 6;
}

static u_char *
ngx_http_pckg_mpd_header_write(u_char *p, ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_str_t *profiles)
{
    int64_t                        segment_time;
    uint32_t                       timescale;
    uint32_t                       buffer_time;
    uint64_t                       buffer_depth;
    uint64_t                       presentation_delay;
    ngx_tm_t                       avail_time_gmt;
    ngx_tm_t                       publish_time_gmt;
    ngx_uint_t                     duration;
    ngx_uint_t                     min_update_period;
    ngx_pckg_timeline_t           *timeline;
    ngx_http_pckg_mpd_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_mpd_module);

    timeline = &channel->timeline;
    timescale = channel->header->timescale;

    ngx_gmtime(timeline->header->availability_start_time / timescale,
        &avail_time_gmt);

    ngx_gmtime(timeline->last_time / timescale, &publish_time_gmt);

    p = ngx_sprintf(p, MPD_HEADER1,
        profiles,
        mpd_date_time_params(avail_time_gmt),
        mpd_date_time_params(publish_time_gmt));


    if (!timeline->header->end_list) {
        min_update_period = rescale_time(
            timeline->duration / timeline->segment_count, timescale, 1000);

        p = ngx_sprintf(p, MPD_MIN_UPDATE_PERIOD,
            (uint32_t) (min_update_period / 1000),
            (uint32_t) (min_update_period % 1000));

    } else {
        duration = rescale_time(timeline->duration, timescale, 1000);

        p = ngx_sprintf(p, MPD_MEDIA_PRES_DURATION,
            (uint32_t) (duration / 1000),
            (uint32_t) (duration % 1000));
    }


    buffer_time = rescale_time(timeline->header->target_duration,
        timescale, 1000);

    buffer_depth = rescale_time(timeline->duration, timescale, 1000);

    segment_time = ngx_http_pckg_mpd_get_segment_time(
        &channel->timeline, mlcf->pres_delay_segments);

    presentation_delay =
        channel->header->now * 1000 -
        rescale_time(segment_time, timescale, 1000);

    p = ngx_sprintf(p,
        MPD_HEADER2,
        (uint32_t) (buffer_time / 1000),
        (uint32_t) (buffer_time % 1000),
        (uint32_t) (buffer_depth / 1000),
        (uint32_t) (buffer_depth % 1000),
        (uint32_t) (presentation_delay / 1000),
        (uint32_t) (presentation_delay % 1000));

    return p;
}

static ngx_int_t
ngx_http_pckg_mpd_build(ngx_http_request_t *r, ngx_pckg_channel_t *channel,
    ngx_str_t *result)
{
    u_char                        *p;
    size_t                         size;
    size_t                         variant_ids_size;
    int64_t                        availability_start_time;
    int64_t                        end;
    int64_t                        start;
    int64_t                        duration;
    ngx_tm_t                       cur_time_gmt;
    uint32_t                       timescale;
    ngx_str_t                      profiles;
    ngx_uint_t                     i, n;
    ngx_pckg_period_t             *periods, *period;
    ngx_pckg_timeline_t           *timeline;
    ngx_pckg_adapt_sets_t          sets;
    ngx_http_pckg_mpd_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_mpd_module);

    if (mlcf->profiles != NULL) {
        if (ngx_http_complex_value(r, mlcf->profiles, &profiles) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_mpd_build: complex value failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        ngx_str_set(&profiles, "urn:mpeg:dash:profile:isoff-live:2011");
    }

    sets.channel = channel;

    if (ngx_pckg_adapt_sets_init(&sets) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_mpd_build: init sets failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    /* get size */
    variant_ids_size = ngx_pckg_adapt_sets_get_variant_ids_size(&sets);

    size = ngx_http_pckg_mpd_header_get_size(&profiles)
        + n * (sizeof(MPD_PERIOD_HEADER_START_DURATION) - 1 + NGX_INT32_LEN * 5
            + variant_ids_size
            + sizeof(MPD_PERIOD_FOOTER) - 1)
        + sizeof(MPD_UTC_TIMING) - 1 + MPD_DATE_TIME_LEN
        + sizeof(MPD_FOOTER) - 1;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        size += ngx_http_pckg_mpd_adapt_sets_get_size(&sets, period);
    }

    /* allocate */
    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_mpd_build: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    /* write */
    p = ngx_http_pckg_mpd_header_write(p, r, channel, &profiles);

    timescale = channel->header->timescale;

    availability_start_time = timeline->header->availability_start_time
        / timescale * 1000;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        if (i == 0) {
            start = timeline->header->first_period_initial_time;

        } else {
            start = period->header->time;
        }

        start = rescale_time(start, timescale, 1000) - availability_start_time;

        end = period->header->time + period->duration;

        if (i + 1 < n && end != periods[i + 1].header->time) {
            duration = rescale_time(period->duration, timescale, 1000);

            p = ngx_sprintf(p, MPD_PERIOD_HEADER_START_DURATION,
                timeline->header->first_period_index + i,
                (uint32_t) (start / 1000),
                (uint32_t) (start % 1000),
                (uint32_t) (duration / 1000),
                (uint32_t) (duration % 1000));

        } else {
            p = ngx_sprintf(p, MPD_PERIOD_HEADER_START,
                timeline->header->first_period_index + i,
                (uint32_t) (start / 1000),
                (uint32_t) (start % 1000));
        }

        p = ngx_http_pckg_mpd_adapt_sets_write(p, r, &sets, period);

        p = ngx_copy(p, MPD_PERIOD_FOOTER, sizeof(MPD_PERIOD_FOOTER) - 1);
    }

    ngx_gmtime(channel->header->now, &cur_time_gmt);

    p = ngx_sprintf(p, MPD_UTC_TIMING,
        mpd_date_time_params(cur_time_gmt));

    p = ngx_copy(p, MPD_FOOTER, sizeof(MPD_FOOTER) - 1);

    /* validate */
    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_mpd_build: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pckg_fmp4_handle_mpd(ngx_http_request_t *r)
{
    int64_t                    last_modified;
    ngx_int_t                  rc;
    ngx_str_t                  response;
    ngx_pckg_channel_t        *channel;
    ngx_http_pckg_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pckg_core_module);
    channel = ctx->channel;

    rc = ngx_http_pckg_mpd_build(r, channel, &response);
    if (rc != NGX_OK) {
        return rc;
    }

    last_modified = ngx_max(channel->header->last_modified,
        channel->timeline.header->last_modified);

    rc = ngx_http_pckg_send_header(r, response.len,
        &ngx_http_pckg_mpd_content_type, last_modified,
        NGX_HTTP_PCKG_EXPIRES_INDEX);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pckg_send_response(r, &response);
}


static ngx_http_pckg_request_handler_t  ngx_http_pckg_fmp4_mpd_handler = {
    ngx_http_pckg_fmp4_handle_mpd,
    NULL,
};


static ngx_int_t
ngx_http_pckg_mpd_parse_request(ngx_http_request_t *r, u_char *start_pos,
    u_char *end_pos, ngx_pckg_ksmp_req_t *result,
    ngx_http_pckg_request_handler_t **handler)
{
    uint32_t                        flags;
    ngx_http_pckg_core_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_core_module);

    if (ngx_http_pckg_match_prefix(start_pos, end_pos,
        ngx_http_pckg_prefix_manifest))
    {
        start_pos += ngx_http_pckg_prefix_manifest.len;

        *handler = &ngx_http_pckg_fmp4_mpd_handler;

        flags = NGX_HTTP_PCKG_PARSE_OPTIONAL_VARIANTS |
            NGX_HTTP_PCKG_PARSE_OPTIONAL_MEDIA_TYPE;

        result->flags = plcf->active_policy | NGX_KSMP_FLAG_CHECK_EXPIRY
            | NGX_KSMP_FLAG_TIMELINE | NGX_KSMP_FLAG_PERIODS
            | NGX_KSMP_FLAG_MEDIA_INFO;

        result->parse_flags = NGX_PCKG_KSMP_PARSE_FLAG_CODEC_NAME;

    } else {
        return NGX_DECLINED;
    }

    return ngx_http_pckg_parse_uri_file_name(r, start_pos, end_pos,
        flags, result);
}


static ngx_int_t
ngx_http_pckg_mpd_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_http_pckg_core_add_handler(cf, &ngx_http_pckg_mpd_ext,
        ngx_http_pckg_mpd_parse_request) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_pckg_mpd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pckg_mpd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pckg_mpd_loc_conf_t));
    if (conf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "ngx_http_pckg_mpd_create_loc_conf: ngx_pcalloc failed");
        return NGX_CONF_ERROR;
    }

    conf->pres_delay_segments = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_pckg_mpd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pckg_mpd_loc_conf_t  *prev = parent;
    ngx_http_pckg_mpd_loc_conf_t  *conf = child;

    if (conf->profiles == NULL) {
        conf->profiles = prev->profiles;
    }

    ngx_conf_merge_uint_value(conf->pres_delay_segments,
                              prev->pres_delay_segments, 3);

    return NGX_CONF_OK;
}
