#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pckg_hls_m3u8.h"
#include "ngx_http_pckg_hls_module.h"
#include "ngx_pckg_media_info.h"
#include "ngx_pckg_segment_info.h"
#include "media/hls/hls_muxer.h"
#include "media/mp4/mp4_muxer.h"


/* master playlist */
#define M3U8_MASTER_HEADER           "#EXTM3U\n#EXT-X-INDEPENDENT-SEGMENTS\n"

#define M3U8_STREAM_VIDEO            "#EXT-X-STREAM-INF:PROGRAM-ID=1"       \
    ",BANDWIDTH=%uD,RESOLUTION=%uDx%uD,FRAME-RATE=%uD.%03uD,CODECS=\"%V"
#define M3U8_STREAM_AUDIO            "#EXT-X-STREAM-INF:PROGRAM-ID=1"       \
    ",BANDWIDTH=%uD,CODECS=\"%V"
#define M3U8_STREAM_VIDEO_RANGE_SDR  ",VIDEO-RANGE=SDR"
#define M3U8_STREAM_VIDEO_RANGE_PQ   ",VIDEO-RANGE=PQ"
#define M3U8_STREAM_TAG_AUDIO        ",AUDIO=\"%V\""

#define M3U8_MEDIA_BASE              "#EXT-X-MEDIA:TYPE=%V,GROUP-ID=\"%V\"" \
    ",NAME=\"%V\","
#define M3U8_MEDIA_LANG              "LANGUAGE=\"%V\","
#define M3U8_MEDIA_DEFAULT           "AUTOSELECT=YES,DEFAULT=YES,"
#define M3U8_MEDIA_NON_DEFAULT       "AUTOSELECT=NO,DEFAULT=NO,"
#define M3U8_MEDIA_CHANNELS          "CHANNELS=\"%uD\","
#define M3U8_MEDIA_URI               "URI=\""

/* index playlist */
#define M3U8_INDEX_HEADER            "#EXTM3U\n#EXT-X-TARGETDURATION:%uD\n" \
    "#EXT-X-VERSION:%uD\n#EXT-X-MEDIA-SEQUENCE:%uD\n"                       \
    "#EXT-X-DISCONTINUITY-SEQUENCE:%uD\n#EXT-X-INDEPENDENT-SEGMENTS\n"      \
    "#EXT-X-ALLOW-CACHE:YES\n"
#define M3U8_EXTINF                  "#EXTINF:"
#define M3U8_GAP                     "#EXT-X-GAP\n"
#define M3U8_BITRATE                 "#EXT-X-BITRATE:"
#define M3U8_DISCONTINUITY           "#EXT-X-DISCONTINUITY\n"
#define M3U8_PROGRAM_DATE_TIME                                              \
    "#EXT-X-PROGRAM-DATE-TIME:%4d-%02d-%02dT%02d:%02d:%02d.%03d+00:00\n"
#define M3U8_PROGRAM_DATE_TIME_LEN                                          \
    (sizeof("#EXT-X-PROGRAM-DATE-TIME:2000-01-01T00:00:00.000+00:00\n") - 1)
#define M3U8_MAP_BASE                "#EXT-X-MAP:URI=\""

#define M3U8_ENC_KEY_BASE            "#EXT-X-KEY:METHOD="
#define M3U8_ENC_KEY_URI             ",URI=\""
#define M3U8_ENC_KEY_IV              ",IV=0x"
#define M3U8_ENC_KEY_KEY_FORMAT      ",KEYFORMAT=\""
#define M3U8_ENC_KEY_KEY_FORMAT_VER  ",KEYFORMATVERSIONS=\""

#define M3U8_ENC_METHOD_AES_128      "AES-128"
#define M3U8_ENC_METHOD_SAMPLE_AES   "SAMPLE-AES"
#define M3U8_ENC_METHOD_SAMPLE_AES_CENC  "SAMPLE-AES-CENC"

#define M3U8_END_LIST                "#EXT-X-ENDLIST\n"


ngx_str_t  ngx_http_pckg_hls_prefix_seg = ngx_string("seg");
ngx_str_t  ngx_http_pckg_hls_ext_seg_ts = ngx_string(".ts");
ngx_str_t  ngx_http_pckg_hls_ext_seg_m4s = ngx_string(".m4s");

ngx_str_t  ngx_http_pckg_hls_prefix_master = ngx_string("master");
ngx_str_t  ngx_http_pckg_hls_prefix_index = ngx_string("index");
ngx_str_t  ngx_http_pckg_hls_ext_m3u8 = ngx_string(".m3u8");

ngx_str_t  ngx_http_pckg_hls_prefix_enc_key = ngx_string("encryption");
ngx_str_t  ngx_http_pckg_hls_ext_enc_key = ngx_string(".key");

ngx_str_t  ngx_http_pckg_hls_prefix_init_seg = ngx_string("init");
ngx_str_t  ngx_http_pckg_hls_ext_init_seg = ngx_string(".mp4");


typedef struct {
    ngx_queue_t    queue;
    ngx_str_t      id;
    ngx_array_t    variants;    /* ngx_pckg_variant_t * */
    media_info_t  *media_info;
} ngx_http_pckg_hls_media_group_t;

typedef struct {
    ngx_array_t    streams;     /* ngx_pckg_variant_t * */
    ngx_queue_t    media_groups[KMP_MEDIA_COUNT];
} ngx_http_pckg_hls_master_t;


static ngx_str_t  ngx_http_pckg_hls_media_group_id[KMP_MEDIA_COUNT] = {
    ngx_string("vid"),
    ngx_string("aud"),
};

static ngx_str_t  ngx_http_pckg_hls_media_type_name[KMP_MEDIA_COUNT] = {
    ngx_string("VIDEO"),
    ngx_string("AUDIO"),
};


/* shared */

static ngx_uint_t
ngx_http_pckg_hls_get_container_format(ngx_http_pckg_hls_loc_conf_t *hlcf,
    ngx_pckg_track_t **tracks)
{
    ngx_uint_t     container_format;
    media_info_t  *media_info;

    container_format = hlcf->m3u8_config.container_format;
    if (container_format != NGX_HTTP_PCKG_HLS_CONTAINER_AUTO) {
        return container_format;
    }

    if (hlcf->encryption_method == HLS_ENC_SAMPLE_AES_CENC) {
        return NGX_HTTP_PCKG_HLS_CONTAINER_FMP4;
    }

    if (tracks[KMP_MEDIA_VIDEO] == NULL) {
        return NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS;
    }

    media_info = &tracks[KMP_MEDIA_VIDEO]->last_media_info->media_info;
    if (media_info != NULL && media_info->codec_id == VOD_CODEC_ID_HEVC) {
        return NGX_HTTP_PCKG_HLS_CONTAINER_FMP4;
    }

    return NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS;
}


static void
ngx_http_pckg_hls_get_bitrate_estimator(ngx_http_pckg_hls_loc_conf_t *hlcf,
    ngx_uint_t container_format, media_info_t **media_infos, uint32_t count,
    media_bitrate_estimator_t *result)
{
    if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS) {
        hls_muxer_get_bitrate_estimator(&hlcf->mpegts_muxer, media_infos,
            count, result);

    } else {
        mp4_muxer_get_bitrate_estimator(media_infos, count, result);
    }
}


/* master */

static uint32_t
ngx_http_pckg_hls_estimate_bitrate(ngx_http_pckg_hls_loc_conf_t *hlcf,
    ngx_uint_t container_format, media_info_t **media_infos, uint32_t count,
    uint32_t segment_duration)
{
    uint32_t                    i;
    uint32_t                    result;
    media_bitrate_estimator_t  *est;
    media_bitrate_estimator_t   estimators[KMP_MEDIA_COUNT];

    ngx_http_pckg_hls_get_bitrate_estimator(hlcf, container_format,
        media_infos, count, estimators);

    result = 0;
    for (i = 0; i < count; i++) {

        est = &estimators[i];
        result += media_bitrate_estimate(*est, media_infos[i]->bitrate,
            segment_duration);
    }

    return result;
}


static ngx_http_pckg_hls_media_group_t *
ngx_http_pckg_hls_media_group_get(ngx_http_request_t *r,
    ngx_http_pckg_hls_master_t *master, ngx_pckg_track_t *track,
    media_info_t *media_info)
{
    uint32_t                          media_type;
    ngx_str_t                        *group_id;
    ngx_queue_t                      *q;
    ngx_http_pckg_hls_media_group_t  *group;

    media_type = media_info->media_type;

    for (q = ngx_queue_head(&master->media_groups[media_type]);
        q != ngx_queue_sentinel(&master->media_groups[media_type]);
        q = ngx_queue_next(q))
    {
        group = ngx_queue_data(q, ngx_http_pckg_hls_media_group_t, queue);

        if (group->media_info->codec_id == media_info->codec_id) {
            return group;
        }
    }

    group_id = &ngx_http_pckg_hls_media_group_id[media_type];

    group = ngx_palloc(r->pool, sizeof(*group) + group_id->len +
        NGX_INT32_LEN);
    if (group == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_media_group_get: alloc failed");
        return NULL;
    }

    if (ngx_array_init(&group->variants, r->pool, 2,
                       sizeof(ngx_pckg_variant_t *)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_media_group_get: array init failed");
        return NULL;
    }

    group->id.data = (void *) (group + 1);
    group->id.len = ngx_sprintf(group->id.data, "%V%uD", group_id,
        media_info->codec_id) - group->id.data;

    group->media_info = media_info;

    ngx_queue_insert_tail(&master->media_groups[media_type], &group->queue);

    return group;
}


static ngx_flag_t
ngx_http_pckg_hls_media_group_label_exists(
    ngx_http_pckg_hls_media_group_t *group, ngx_str_t *label)
{
    ngx_str_t            *cur_label;
    ngx_pckg_variant_t  **cur;
    ngx_pckg_variant_t  **last;

    cur = group->variants.elts;
    for (last = cur + group->variants.nelts; cur < last; cur++) {

        cur_label = &(*cur)->label;
        if (cur_label->len == label->len &&
            ngx_memcmp(cur_label->data, label->data, label->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static size_t
ngx_http_pckg_hls_media_group_get_size(ngx_http_pckg_hls_media_group_t *group,
    uint32_t media_type)
{
    size_t               result;
    size_t               base_size;
    ngx_uint_t           i, n;
    ngx_pckg_variant_t  *variant, **variants;

    base_size = sizeof(M3U8_MEDIA_BASE) - 1 +
        ngx_http_pckg_hls_media_type_name[media_type].len +
        group->id.len + sizeof(M3U8_MEDIA_LANG) - 1 +
        sizeof(M3U8_MEDIA_DEFAULT) - 1 +
        sizeof(M3U8_MEDIA_CHANNELS) + NGX_INT32_LEN +
        sizeof(M3U8_MEDIA_URI) - 1 +
        ngx_http_pckg_hls_prefix_index.len +
        sizeof("-s-v\"\n") - 1 +
        ngx_http_pckg_hls_ext_m3u8.len;

    result = sizeof("\n") - 1 + base_size * group->variants.nelts;

    variants = group->variants.elts;
    n = group->variants.nelts;

    for (i = 0; i < n; i++) {
        variant = variants[i];

        result += variant->label.len + variant->lang.len + variant->id.len;
    }

    return result;
}

static u_char *
ngx_http_pckg_hls_media_group_write(u_char *p,
    ngx_http_pckg_hls_media_group_t *group, uint32_t media_type)
{
    ngx_uint_t           i, n;
    media_info_t        *media_info;
    ngx_pckg_track_t    *track;
    ngx_pckg_variant_t  *variant, **variants;

    *p++ = '\n';

    variants = group->variants.elts;
    n = group->variants.nelts;

    for (i = 0; i < n; i++) {
        variant = variants[i];

        p = vod_sprintf(p, M3U8_MEDIA_BASE,
            &ngx_http_pckg_hls_media_type_name[media_type],
            &group->id,
            &variant->label);

        if (variant->lang.len) {
            p = vod_sprintf(p, M3U8_MEDIA_LANG, &variant->lang);
        }

        if (variant->header->is_default) {
            p = ngx_copy_fix(p, M3U8_MEDIA_DEFAULT);

        } else {
            p = ngx_copy_fix(p, M3U8_MEDIA_NON_DEFAULT);
        }

        if (media_type == KMP_MEDIA_AUDIO) {
            track = variant->tracks[media_type];
            media_info = &track->last_media_info->media_info;
            p = vod_sprintf(p, M3U8_MEDIA_CHANNELS,
                (uint32_t) media_info->u.audio.channels);
        }

        p = ngx_copy_fix(p, M3U8_MEDIA_URI);

        p = ngx_sprintf(p, "%V-s%V-%c%V", &ngx_http_pckg_hls_prefix_index,
            &variant->id, ngx_http_pckg_media_type_code[media_type],
            &ngx_http_pckg_hls_ext_m3u8);

        *p++ = '"';
        *p++ = '\n';
    }

    return p;
}


static ngx_int_t
ngx_http_pckg_hls_group_variants(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_http_pckg_hls_master_t *result)
{
    ngx_uint_t                         i, n;
    ngx_uint_t                         media_type;
    ngx_array_t                       *variant_arr;
    media_info_t                      *media_info;
    ngx_pckg_track_t                  *track;
    ngx_pckg_variant_t                *variant, *variants;
    ngx_pckg_variant_t               **variant_ptr;
    ngx_http_pckg_hls_media_group_t   *group;

    if (ngx_array_init(&result->streams, r->pool, 2, sizeof(*variant_ptr))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_group_variants: array init failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        ngx_queue_init(&result->media_groups[media_type]);
    }

    variants = channel->variants.elts;
    n = channel->variants.nelts;

    for (i = 0; i < n; i++) {
        variant = &variants[i];

        switch (variant->header->role) {

        case ngx_ksmp_variant_role_alternate:

            /* Note: supporting only alternative audio */

            track = variant->tracks[KMP_MEDIA_AUDIO];
            if (track == NULL) {
                continue;
            }

            media_info = &track->last_media_info->media_info;

            group = ngx_http_pckg_hls_media_group_get(r, result,
                track, media_info);
            if (group == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_pckg_hls_media_group_label_exists(group,
                &variant->label))
            {
                continue;
            }

            variant_arr = &group->variants;
            break;

        default:    /* ngx_ksmp_variant_role_main */
            variant_arr = &result->streams;
            break;
        }

        variant_ptr = ngx_array_push(variant_arr);
        if (variant_ptr == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_pckg_hls_group_variants: array push failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *variant_ptr = variant;
    }

    if (result->streams.nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_pckg_hls_group_variants: no streams found");
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}


static u_char *
ngx_http_pckg_hls_write_video_range(u_char *p,
    u_char transfer_characteristics)
{
    switch (transfer_characteristics) {

    case 1:
        p = ngx_copy_fix(p, M3U8_STREAM_VIDEO_RANGE_SDR);
        break;

    case 16:
    case 18:
        p = ngx_copy_fix(p, M3U8_STREAM_VIDEO_RANGE_PQ);
        break;
    }

    return p;
}


static size_t
ngx_http_pckg_hls_m3u8_streams_get_size(ngx_array_t *streams,
    ngx_http_pckg_hls_media_group_t *audio_group)
{
    size_t                result;
    size_t                base_size;
    ngx_pckg_variant_t   *variant;
    ngx_pckg_variant_t  **cur, **last;

    base_size = sizeof(M3U8_STREAM_VIDEO) - 1 + 5 * NGX_INT32_LEN +
        MAX_CODEC_NAME_SIZE * 2 + sizeof(",\"\n") - 1 +
        sizeof(M3U8_STREAM_VIDEO_RANGE_SDR) - 1 +
        ngx_http_pckg_hls_prefix_index.len +
        ngx_http_pckg_hls_ext_m3u8.len + sizeof("\n") - 1;

    if (audio_group != NULL) {
        base_size += sizeof(M3U8_STREAM_TAG_AUDIO) - 1 + audio_group->id.len;
    }

    result = sizeof("\n") - 1 + base_size * streams->nelts;

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {
        variant = *cur;

        result += ngx_http_pckg_selector_get_size(variant);
    }

    return result;
}


static u_char *
ngx_http_pckg_hls_m3u8_streams_write(u_char *p,
    ngx_http_pckg_hls_loc_conf_t *hlcf, ngx_array_t *streams,
    ngx_pckg_channel_t *channel, ngx_http_pckg_hls_media_group_t *audio_group,
    uint32_t segment_duration)
{
    uint32_t              bitrate;
    uint32_t              frame_rate;
    uint32_t              frame_rate_frac;
    ngx_uint_t            container_format;
    media_info_t         *video;
    media_info_t         *audio;
    media_info_t         *media_infos[KMP_MEDIA_COUNT];
    ngx_pckg_track_t    **tracks;
    ngx_pckg_variant_t  **cur;
    ngx_pckg_variant_t  **last;
    ngx_pckg_variant_t   *variant;

    *p++ = '\n';

    cur = streams->elts;
    for (last = cur + streams->nelts; cur < last; cur++) {

        variant = *cur;
        tracks = variant->tracks;

        container_format = ngx_http_pckg_hls_get_container_format(hlcf,
            tracks);

        if (tracks[KMP_MEDIA_VIDEO] != NULL) {
            video = &tracks[KMP_MEDIA_VIDEO]->last_media_info->media_info;

        } else {
            video = NULL;
        }

        if (audio_group != NULL) {
            audio = audio_group->media_info;

        } else if (tracks[KMP_MEDIA_AUDIO] != NULL) {
            audio = &tracks[KMP_MEDIA_AUDIO]->last_media_info->media_info;

        } else {
            audio = NULL;
        }

        if (video != NULL) {

            if (audio != NULL) {
                if (audio_group != NULL) {
                    bitrate = ngx_http_pckg_hls_estimate_bitrate(hlcf,
                        container_format, &video, 1, segment_duration) +
                        ngx_http_pckg_hls_estimate_bitrate(hlcf,
                        container_format, &audio, 1, segment_duration);

                } else {
                    media_infos[0] = video;
                    media_infos[1] = audio;
                    bitrate = ngx_http_pckg_hls_estimate_bitrate(hlcf,
                        container_format, media_infos, 2, segment_duration);
                }

            } else {
                bitrate = ngx_http_pckg_hls_estimate_bitrate(hlcf,
                    container_format, &video, 1, segment_duration);
            }

            frame_rate = video->u.video.frame_rate_num /
                video->u.video.frame_rate_denom;
            frame_rate_frac = ((((uint64_t) video->u.video.frame_rate_num *
                1000) / video->u.video.frame_rate_denom) % 1000);

            p = ngx_sprintf(p, M3U8_STREAM_VIDEO, bitrate,
                (uint32_t) video->u.video.width,
                (uint32_t) video->u.video.height,
                frame_rate, frame_rate_frac, &video->codec_name);
            if (audio != NULL) {
                *p++ = ',';
                p = ngx_copy_str(p, audio->codec_name);
            }

        } else if (audio != NULL) {

            bitrate = ngx_http_pckg_hls_estimate_bitrate(hlcf,
                container_format, &audio, 1, segment_duration);

            p = ngx_sprintf(p, M3U8_STREAM_AUDIO, bitrate,
                &audio->codec_name);

        } else {
            continue;
        }

        *p++ = '\"';

        if (video != NULL) {
            p = ngx_http_pckg_hls_write_video_range(p,
                video->u.video.transfer_characteristics);
        }

        if (audio_group != NULL) {
            p = vod_sprintf(p, M3U8_STREAM_TAG_AUDIO, &audio_group->id);
        }

        *p++ = '\n';

        p = ngx_copy_str(p, ngx_http_pckg_hls_prefix_index);
        p = ngx_http_pckg_selector_write(p, channel, variant);
        p = ngx_copy_str(p, ngx_http_pckg_hls_ext_m3u8);
        *p++ = '\n';
    }

    return p;
}


ngx_int_t
ngx_http_pckg_hls_m3u8_build_master(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_str_t *result)
{
    u_char                           *p;
    size_t                            size;
    uint32_t                          media_type;
    uint32_t                          segment_duration;
    ngx_int_t                         rc;
    ngx_queue_t                      *q;
    ngx_http_pckg_hls_master_t        master;
    ngx_http_pckg_hls_loc_conf_t     *hlcf;
    ngx_http_pckg_hls_media_group_t  *group;

    /* group the variants */
    rc = ngx_http_pckg_hls_group_variants(r, channel, &master);
    if (rc != NGX_OK) {
        return rc;
    }

    /* get the response size */
    size = sizeof(M3U8_MASTER_HEADER) - 1;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        for (q = ngx_queue_head(&master.media_groups[media_type]);
            q != ngx_queue_sentinel(&master.media_groups[media_type]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_pckg_hls_media_group_t, queue);

            size += ngx_http_pckg_hls_media_group_get_size(group, media_type);
        }
    }

    if (!ngx_queue_empty(&master.media_groups[KMP_MEDIA_AUDIO])) {

        for (q = ngx_queue_head(&master.media_groups[KMP_MEDIA_AUDIO]);
            q != ngx_queue_sentinel(&master.media_groups[KMP_MEDIA_AUDIO]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_pckg_hls_media_group_t, queue);

            size += ngx_http_pckg_hls_m3u8_streams_get_size(&master.streams,
                group);
        }

    } else {
        size += ngx_http_pckg_hls_m3u8_streams_get_size(&master.streams,
            NULL);
    }

    /* allocate */
    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_master: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    p = ngx_copy_fix(p, M3U8_MASTER_HEADER);

    /* write media groups */
    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        for (q = ngx_queue_head(&master.media_groups[media_type]);
            q != ngx_queue_sentinel(&master.media_groups[media_type]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_pckg_hls_media_group_t, queue);

            p = ngx_http_pckg_hls_media_group_write(p, group, media_type);
        }
    }

    /* write streams */
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    segment_duration = rescale_time(channel->timeline.header->target_duration,
        channel->header->timescale, 1000);
    if (segment_duration <= 0) {
        segment_duration = 1;
    }

    if (!ngx_queue_empty(&master.media_groups[KMP_MEDIA_AUDIO])) {

        for (q = ngx_queue_head(&master.media_groups[KMP_MEDIA_AUDIO]);
            q != ngx_queue_sentinel(&master.media_groups[KMP_MEDIA_AUDIO]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_pckg_hls_media_group_t, queue);

            p = ngx_http_pckg_hls_m3u8_streams_write(p, hlcf, &master.streams,
                channel, group, segment_duration);
        }

    } else {
        p = ngx_http_pckg_hls_m3u8_streams_write(p, hlcf, &master.streams,
            channel, NULL, segment_duration);
    }

    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_master: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


/* index */

static size_t
ngx_http_pckg_hls_m3u8_enc_key_get_size(ngx_http_pckg_hls_m3u8_config_t *conf,
    ngx_pckg_channel_t *channel, hls_encryption_params_t *enc_params)
{
    size_t               result;
    ngx_pckg_variant_t  *variant;

    result = sizeof(M3U8_ENC_KEY_BASE) - 1 +
        sizeof(M3U8_ENC_METHOD_SAMPLE_AES_CENC) - 1 +
        sizeof(M3U8_ENC_KEY_URI) - 1 +
        2;            /* '"', '\n' */

    if (enc_params->key_uri.len != 0) {
        result += enc_params->key_uri.len;

    } else {
        variant = channel->variants.elts;
        result += ngx_http_pckg_hls_prefix_enc_key.len +
            sizeof("-s") - 1 + variant->id.len +
            ngx_http_pckg_hls_ext_enc_key.len;
    }

    if (enc_params->return_iv) {
        result += sizeof(M3U8_ENC_KEY_IV) - 1 +
            sizeof(enc_params->iv_buf) * 2;
    }

    if (conf->enc_key_format.len != 0) {
        result += sizeof(M3U8_ENC_KEY_KEY_FORMAT) +         /* '"' */
            conf->enc_key_format.len;
    }

    if (conf->enc_key_format_versions.len != 0) {
        result += sizeof(M3U8_ENC_KEY_KEY_FORMAT_VER) +     /* '"' */
            conf->enc_key_format_versions.len;
    }

    return result;
}


static u_char *
ngx_http_pckg_hls_m3u8_enc_key_write(u_char *p,
    ngx_http_pckg_hls_m3u8_config_t *conf,
    ngx_pckg_channel_t *channel,
    hls_encryption_params_t *enc_params)
{
    ngx_pckg_variant_t  *variant;

    p = ngx_copy_fix(p, M3U8_ENC_KEY_BASE);

    switch (enc_params->type) {

    case HLS_ENC_SAMPLE_AES:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES);
        break;

    case HLS_ENC_SAMPLE_AES_CENC:
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_SAMPLE_AES_CENC);
        break;

    default:        /* HLS_ENC_AES_128 */
        p = ngx_copy_fix(p, M3U8_ENC_METHOD_AES_128);
        break;
    }

    /* uri */
    p = ngx_copy_fix(p, M3U8_ENC_KEY_URI);
    if (enc_params->key_uri.len != 0) {
        p = ngx_copy_str(p, enc_params->key_uri);

    } else {
        variant = channel->variants.elts;
        p = ngx_copy_str(p, ngx_http_pckg_hls_prefix_enc_key);
        p = vod_sprintf(p, "-s%V", &variant->id);
        p = ngx_copy_str(p, ngx_http_pckg_hls_ext_enc_key);
    }
    *p++ = '"';

    /* iv */
    if (enc_params->return_iv) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_IV);
        p = vod_append_hex_string(p, enc_params->iv,
            sizeof(enc_params->iv_buf));
    }

    /* keyformat */
    if (conf->enc_key_format.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT);
        p = ngx_copy_str(p, conf->enc_key_format);
        *p++ = '"';
    }

    /* keyformatversions */
    if (conf->enc_key_format_versions.len != 0) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_KEY_FORMAT_VER);
        p = ngx_copy_str(p, conf->enc_key_format_versions);
        *p++ = '"';
    }

    *p++ = '\n';

    return p;
}


static ngx_inline u_char *
ngx_http_pckg_hls_append_extinf_tag(u_char *p, uint32_t duration)
{
    p = ngx_copy_fix(p, M3U8_EXTINF);
    p = ngx_sprintf(p, "%d.%03d", (int) (duration / 1000),
        (int) (duration % 1000));
    *p++ = ',';
    *p++ = '\n';
    return p;
}


static size_t
ngx_http_pckg_hls_get_gap_size(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_pckg_segment_info_ctx_t *bi)
{
    uint32_t              cur;
    uint32_t              total;
    uint32_t              last_segment;
    uint32_t              first_segment;
    ngx_uint_t            i, n;
    ngx_pckg_period_t    *periods, *period;
    ngx_pckg_timeline_t  *timeline;

    total = 0;

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        first_segment = period->header->segment_index;
        last_segment = first_segment + period->segment_count;

        /* Note: using the min gap count since a gap is returned only if
            ALL tracks have a gap */

        cur = ngx_pckg_segment_info_min_gap_count(bi, first_segment,
            last_segment);

        total += cur;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_get_gap_size: "
            "period %uD..%ui, gaps: %uD",
            first_segment, last_segment, cur);
    }

    return total * (sizeof(M3U8_GAP) - 1);
}


static void
ngx_http_pckg_hls_period_get_bitrate_count(ngx_pckg_period_t *period,
    ngx_pckg_segment_info_ctx_t *bi, uint32_t milliscale,
    uint32_t *gap_count, uint32_t *bitrate_count)
{
    int64_t                     time;
    int64_t                     start, end;
    uint32_t                    bitrate;
    uint32_t                    duration;
    uint32_t                    last_bitrate;
    uint32_t                    segment_index;
    uint32_t                    last_segment_index;
    ngx_uint_t                  i, n;
    ngx_ksmp_segment_repeat_t  *elt;

    segment_index = period->header->segment_index;

    time = period->header->time;
    start = time / milliscale;

    last_bitrate = 0;

    n = period->nelts;
    for (i = 0; i < n; i++) {
        elt = &period->elts[i];

        for (last_segment_index = segment_index + elt->count;
            segment_index < last_segment_index;
            segment_index++)
        {
            time += elt->duration;
            end = time / milliscale;
            duration = end - start;

            bitrate = ngx_pckg_segment_info_get(bi, segment_index, duration);

            if (bitrate == 0) {
                (*gap_count)++;

            } else {
                /* bps -> kbps */
                bitrate = bitrate > 1000 ? bitrate / 1000 : 1;

                if (bitrate != NGX_KSMP_SEGMENT_NO_BITRATE &&
                    bitrate != last_bitrate)
                {
                    (*bitrate_count)++;

                    last_bitrate = bitrate;
                }
            }

            start = end;
        }
    }
}


static size_t
ngx_http_pckg_hls_period_get_bitrate_size(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_pckg_media_info_ctx_t *mi,
    ngx_pckg_segment_info_ctx_t *bi, ngx_uint_t container_format)
{
    uint32_t                       ignore;
    uint32_t                       gap_count;
    uint32_t                       bitrate_count;
    uint32_t                       milliscale;
    ngx_uint_t                     i, n;
    ngx_pckg_period_t             *periods, *period;
    ngx_pckg_timeline_t           *timeline;
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    milliscale = channel->header->timescale / 1000;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    gap_count = 0;
    bitrate_count = 0;

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {
        period = &periods[i];

        ngx_pckg_media_info_get(mi, period->header->segment_index, &ignore);

        ngx_http_pckg_hls_get_bitrate_estimator(hlcf, container_format,
            mi->media_infos, channel->tracks.nelts, bi->estimators);

        ngx_http_pckg_hls_period_get_bitrate_count(period, bi, milliscale,
            &gap_count, &bitrate_count);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_pckg_hls_period_get_bitrate_size: "
            "period %uD..%ui, accum_gaps: %uD, accum_bitrate: %uD",
            period->header->segment_index,
            (ngx_uint_t) period->header->segment_index + period->segment_count,
            gap_count, bitrate_count);
    }

    return
        bitrate_count * (sizeof(M3U8_BITRATE) + NGX_INT32_LEN) + /* 1 = '\n' */
        gap_count * (sizeof(M3U8_GAP) - 1);
}


static u_char *
ngx_http_pckg_hls_write_period_segments(u_char *p, ngx_pckg_period_t *period,
    ngx_str_t *seg_suffix, uint32_t milliscale,
    ngx_pckg_segment_info_ctx_t *bi)
{
    int64_t                     time;
    int64_t                     start, end;
    uint32_t                    bitrate;
    uint32_t                    duration;
    uint32_t                    last_bitrate;
    uint32_t                    segment_index;
    uint32_t                    last_segment_index;
    ngx_uint_t                  i, n;
    ngx_ksmp_segment_repeat_t  *elt;

    segment_index = period->header->segment_index;

    time = period->header->time;
    start = time / milliscale;

    last_bitrate = 0;

    n = period->nelts;
    for (i = 0; i < n; i++) {
        elt = &period->elts[i];

        last_segment_index = segment_index + elt->count;

        for (; segment_index < last_segment_index; )
        {
            time += elt->duration;
            end = time / milliscale;
            duration = end - start;

            p = ngx_http_pckg_hls_append_extinf_tag(p, duration);

            bitrate = ngx_pckg_segment_info_get(bi, segment_index, duration);

            if (bitrate == 0) {
                p = ngx_copy_fix(p, M3U8_GAP);

            } else {
                /* bps -> kbps */
                bitrate = bitrate > 1000 ? bitrate / 1000 : 1;

                if (bitrate != NGX_KSMP_SEGMENT_NO_BITRATE &&
                    bitrate != last_bitrate)
                {
                    p = ngx_copy_fix(p, M3U8_BITRATE);
                    p = ngx_sprintf(p, "%uD", bitrate);
                    *p++ = '\n';

                    last_bitrate = bitrate;
                }
            }

            segment_index++;
            p = ngx_copy_str(p, ngx_http_pckg_hls_prefix_seg);
            p = ngx_sprintf(p, "-%uD", segment_index);
            p = ngx_copy_str(p, *seg_suffix);

            start = end;
        }
    }

    return p;
}


static ngx_int_t
ngx_http_pckg_hls_m3u8_get_selector(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel, ngx_str_t *result)
{
    u_char              *p;
    size_t               size;
    ngx_pckg_variant_t  *variant;

    variant = channel->variants.elts;

    size = ngx_http_pckg_selector_get_size(variant);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_get_selector: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;
    p = ngx_http_pckg_selector_write(p, channel, variant);
    result->len = p - result->data;

    return NGX_OK;
}


ngx_int_t
ngx_http_pckg_hls_m3u8_build_index(ngx_http_request_t *r,
    ngx_pckg_channel_t *channel,
    hls_encryption_params_t *enc_params, ngx_str_t *result)
{
    u_char                        *p;
    size_t                         result_size;
    size_t                         period_size;
    size_t                         segment_size;
    ngx_tm_t                       gmt;
    uint32_t                       version;
    uint32_t                       timescale;
    uint32_t                       milliscale;
    uint32_t                       map_index;
    uint32_t                       last_map_index;
    uint32_t                       target_duration;
    uint32_t                       segment_index_size;
    ngx_int_t                      rc;
    ngx_str_t                     *seg_ext;
    ngx_str_t                      selector;
    ngx_str_t                      seg_suffix;
    ngx_uint_t                     i, n;
    ngx_uint_t                     container_format;
    ngx_pckg_period_t             *period;
    ngx_pckg_period_t             *periods;
    ngx_pckg_variant_t            *variant;
    ngx_pckg_timeline_t           *timeline;
    media_bitrate_estimator_t     *estimators;
    ngx_pckg_media_info_ctx_t     *mi;
    ngx_pckg_segment_info_ctx_t   *bi;
    ngx_http_pckg_hls_loc_conf_t  *hlcf;

    /* get the container format */
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_pckg_hls_module);

    variant = channel->variants.elts;

    container_format = ngx_http_pckg_hls_get_container_format(
        hlcf, variant->tracks);

    /* build the segment track selector */
    rc = ngx_http_pckg_hls_m3u8_get_selector(r, channel, &selector);
    if (rc != NGX_OK) {
        return rc;
    }

    if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_MPEGTS) {
        seg_ext = &ngx_http_pckg_hls_ext_seg_ts;

    } else {
        seg_ext = &ngx_http_pckg_hls_ext_seg_m4s;
    }

    /* build the segment url suffix */
    p = ngx_pnalloc(r->pool, selector.len + seg_ext->len + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_index: alloc suffix failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    seg_suffix.data = p;
    p = ngx_copy_str(p, selector);
    p = ngx_copy_str(p, *seg_ext);
    *p++ = '\n';
    seg_suffix.len = p - seg_suffix.data;

    /* get response size limit */
    estimators = ngx_palloc(r->pool,
        channel->tracks.nelts * sizeof(estimators[0]));
    if (estimators == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_index: alloc estimators failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    mi = ngx_pckg_media_info_create(channel);
    if (mi == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    bi = ngx_pckg_segment_info_create(channel, estimators);
    if (bi == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    timeline = &channel->timeline;

    periods = timeline->periods.elts;
    period = &periods[timeline->periods.nelts - 1];
    segment_index_size = vod_get_int_print_len(
        period->header->segment_index + period->segment_count);

    segment_size =
        sizeof(M3U8_EXTINF) - 1 + NGX_INT64_LEN + sizeof(".000,\n") - 1 +
        ngx_http_pckg_hls_prefix_seg.len + sizeof("-") - 1 +
        segment_index_size + seg_suffix.len;

    period_size = sizeof(M3U8_DISCONTINUITY) - 1 + M3U8_PROGRAM_DATE_TIME_LEN;

    if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_FMP4) {
        period_size +=
            sizeof(M3U8_MAP_BASE) - 1 + sizeof("\"\n") - 1 +
            ngx_http_pckg_hls_prefix_init_seg.len + segment_index_size +
            selector.len + ngx_http_pckg_hls_ext_init_seg.len;
    }

    result_size = sizeof(M3U8_INDEX_HEADER) + 4 * NGX_INT32_LEN +
        period_size * timeline->periods.nelts +
        segment_size * timeline->segment_count +
        sizeof(M3U8_END_LIST) - 1;

    if (enc_params->type != HLS_ENC_NONE) {
        result_size += ngx_http_pckg_hls_m3u8_enc_key_get_size(
            &hlcf->m3u8_config, channel, enc_params);
    }

    if (ngx_pckg_segment_info_has_bitrate(bi)) {
        result_size += ngx_http_pckg_hls_period_get_bitrate_size(r, channel,
            mi, bi, container_format);
        ngx_pckg_media_info_reset(mi, channel);

    } else {
        /* more optimized implementation that only counts gaps */
        result_size += ngx_http_pckg_hls_get_gap_size(r, channel, bi);
    }

    ngx_pckg_segment_info_reset(bi, channel);

    /* allocate the buffer */
    p = ngx_pnalloc(r->pool, result_size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_index: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    /* Note: assuming timescale is a multiple of 1000, if it's not, this will
            cause drift over time */
    timescale = channel->header->timescale;
    milliscale = timescale / 1000;

    /* header */
    target_duration = (timeline->header->target_duration + timescale / 2)
        / timescale;

    version = hlcf->m3u8_config.m3u8_version;
    if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_FMP4 &&
        version < 6)
    {
        version = 6;
    }

    p = ngx_sprintf(p, M3U8_INDEX_HEADER, target_duration, version,
        timeline->header->sequence - timeline->segment_count,
        timeline->header->first_period_index);

    if (enc_params->type != HLS_ENC_NONE) {
        p = ngx_http_pckg_hls_m3u8_enc_key_write(p, &hlcf->m3u8_config,
            channel, enc_params);
    }

    last_map_index = NGX_KSMP_INVALID_SEGMENT_INDEX;

    n = timeline->periods.nelts;

    for (i = 0; i < n; i++) {

        period = &periods[i];
        if (i > 0) {
            p = ngx_copy_fix(p, M3U8_DISCONTINUITY);
        }

        ngx_gmtime(period->header->time / timescale, &gmt);

        p = ngx_sprintf(p, M3U8_PROGRAM_DATE_TIME,
            gmt.ngx_tm_year, gmt.ngx_tm_mon, gmt.ngx_tm_mday,
            gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec,
            (int) ((period->header->time / milliscale) % 1000));

        ngx_pckg_media_info_get(mi, period->header->segment_index,
            &map_index);

        if (container_format == NGX_HTTP_PCKG_HLS_CONTAINER_FMP4 &&
            map_index != last_map_index)
        {
            p = ngx_copy_fix(p, M3U8_MAP_BASE);
            p = ngx_copy_str(p, ngx_http_pckg_hls_prefix_init_seg);
            p = ngx_sprintf(p, "-%uD", map_index + 1);
            p = ngx_copy_str(p, selector);
            p = ngx_copy_str(p, ngx_http_pckg_hls_ext_init_seg);
            *p++ = '"';
            *p++ = '\n';

            last_map_index = map_index;
        }

        ngx_http_pckg_hls_get_bitrate_estimator(hlcf, container_format,
            mi->media_infos, channel->tracks.nelts, estimators);

        p = ngx_http_pckg_hls_write_period_segments(p, period,
            &seg_suffix, milliscale, bi);
    }

    /* write the footer */
    if (timeline->header->end_list) {
        p = ngx_copy_fix(p, M3U8_END_LIST);
    }

    result->len = p - result->data;

    if (result->len > result_size) {
        vod_log_error(VOD_LOG_ALERT, r->connection->log, 0,
            "ngx_http_pckg_hls_m3u8_build_index: "
            "result length %uz greater than allocated length %uz",
            result->len, result_size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
