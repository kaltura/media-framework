#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_live_hls_m3u8.h"
#include "../ngx_live_media_info.h"
#include "../ngx_live_segment_info.h"


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


ngx_str_t  ngx_http_live_hls_prefix_seg = ngx_string("seg");
ngx_str_t  ngx_http_live_hls_ext_seg_ts = ngx_string(".ts");
ngx_str_t  ngx_http_live_hls_ext_seg_m4s = ngx_string(".m4s");

ngx_str_t  ngx_http_live_hls_prefix_master = ngx_string("master");
ngx_str_t  ngx_http_live_hls_prefix_index = ngx_string("index");
ngx_str_t  ngx_http_live_hls_ext_m3u8 = ngx_string(".m3u8");

ngx_str_t  ngx_http_live_hls_prefix_enc_key = ngx_string("encryption");
ngx_str_t  ngx_http_live_hls_ext_enc_key = ngx_string(".key");

ngx_str_t  ngx_http_live_hls_prefix_init_seg = ngx_string("init");
ngx_str_t  ngx_http_live_hls_ext_init_seg = ngx_string(".mp4");


typedef struct {
    ngx_queue_t    queue;
    ngx_str_t      id;
    ngx_array_t    variants;
    media_info_t  *media_info;
} ngx_http_live_hls_media_group_t;

typedef struct {
    ngx_array_t    streams;
    ngx_queue_t    media_groups[KMP_MEDIA_COUNT];
} ngx_http_live_hls_master_t;


typedef struct {
    ngx_live_segment_info_iter_t  iters[KMP_MEDIA_COUNT];
    uint32_t                      track_count;
} ngx_http_live_hls_bitrate_iter_t;

typedef struct {
    ngx_live_media_info_iter_t    iters[KMP_MEDIA_COUNT];
    uint32_t                      track_count;
} ngx_http_live_hls_map_index_iter_t;


static ngx_str_t  ngx_http_live_hls_media_group_id[KMP_MEDIA_COUNT] = {
    ngx_string("vid"),
    ngx_string("aud"),
};

static ngx_str_t  ngx_http_live_hls_media_type_name[KMP_MEDIA_COUNT] = {
    ngx_string("VIDEO"),
    ngx_string("AUDIO"),
};


/* master */

static ngx_http_live_hls_media_group_t *
ngx_http_live_hls_media_group_get(ngx_http_request_t *r,
    ngx_http_live_hls_master_t *master, ngx_live_track_t *track,
    media_info_t *media_info)
{
    uint32_t                          media_type;
    ngx_str_t                        *group_id;
    ngx_queue_t                      *q;
    ngx_http_live_hls_media_group_t  *group;

    media_type = media_info->media_type;

    for (q = ngx_queue_head(&master->media_groups[media_type]);
        q != ngx_queue_sentinel(&master->media_groups[media_type]);
        q = ngx_queue_next(q))
    {
        group = ngx_queue_data(q, ngx_http_live_hls_media_group_t, queue);

        if (group->media_info->codec_id == media_info->codec_id) {
            return group;
        }
    }

    group_id = &ngx_http_live_hls_media_group_id[media_type];

    group = ngx_palloc(r->pool, sizeof(*group) + group_id->len +
        NGX_INT32_LEN);
    if (group == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_media_group_get: alloc failed");
        return NULL;
    }

    if (ngx_array_init(&group->variants, r->pool, 2,
        sizeof(ngx_live_variant_t *)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_media_group_get: array init failed");
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
ngx_http_live_hls_media_group_label_exists(
    ngx_http_live_hls_media_group_t *group, ngx_str_t *label)
{
    ngx_str_t            *cur_label;
    ngx_live_variant_t  **cur;
    ngx_live_variant_t  **last;

    for (cur = group->variants.elts, last = cur + group->variants.nelts;
        cur < last;
        cur++)
    {
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
ngx_http_live_hls_media_group_get_size(ngx_http_live_hls_media_group_t *group,
    uint32_t media_type)
{
    size_t               result;
    size_t               base_size;
    ngx_uint_t           i;
    ngx_live_variant_t  *variant;

    base_size = sizeof(M3U8_MEDIA_BASE) - 1 +
        ngx_http_live_hls_media_type_name[media_type].len +
        group->id.len + sizeof(M3U8_MEDIA_LANG) - 1 +
        sizeof(M3U8_MEDIA_DEFAULT) - 1 +
        sizeof(M3U8_MEDIA_CHANNELS) + NGX_INT32_LEN +
        sizeof(M3U8_MEDIA_URI) - 1 +
        ngx_http_live_hls_prefix_index.len +
        sizeof("-s-v\"\n") - 1 +
        ngx_http_live_hls_ext_m3u8.len;

    result = sizeof("\n") - 1 + base_size * group->variants.nelts;

    for (i = 0; i < group->variants.nelts; i++) {

        variant = ((ngx_live_variant_t **) group->variants.elts)[i];

        result += variant->label.len + variant->lang.len + variant->sn.str.len;
    }

    return result;
}

static u_char *
ngx_http_live_hls_media_group_write(u_char *p,
    ngx_http_live_hls_media_group_t *group, uint32_t media_type)
{
    ngx_uint_t           i;
    media_info_t        *media_info;
    ngx_live_variant_t  *variant;

    *p++ = '\n';

    for (i = 0; i < group->variants.nelts; i++) {

        variant = ((ngx_live_variant_t **) group->variants.elts)[i];
        p = vod_sprintf(p, M3U8_MEDIA_BASE,
            &ngx_http_live_hls_media_type_name[media_type],
            &group->id,
            &variant->label);

        if (variant->lang.len) {
            p = vod_sprintf(p, M3U8_MEDIA_LANG, &variant->lang);
        }

        if (variant->is_default) {
            p = ngx_copy_fix(p, M3U8_MEDIA_DEFAULT);

        } else {
            p = ngx_copy_fix(p, M3U8_MEDIA_NON_DEFAULT);
        }

        if (media_type == KMP_MEDIA_AUDIO) {
            media_info = ngx_live_media_info_queue_get_last(
                variant->tracks[media_type], NULL);
            p = vod_sprintf(p, M3U8_MEDIA_CHANNELS,
                (uint32_t) media_info->u.audio.channels);
        }

        p = ngx_copy_fix(p, M3U8_MEDIA_URI);

        p = ngx_sprintf(p, "%V-s%V-%c%V", &ngx_http_live_hls_prefix_index,
            &variant->sn.str, ngx_http_live_media_type_code[media_type],
            &ngx_http_live_hls_ext_m3u8);

        *p++ = '"';
        *p++ = '\n';
    }

    return p;
}

static ngx_int_t
ngx_http_live_hls_group_variants(ngx_http_request_t *r,
    ngx_live_channel_t *channel, ngx_http_live_hls_master_t *result)
{
    ngx_uint_t                         media_type;
    ngx_queue_t                       *q;
    ngx_array_t                       *variant_arr;
    media_info_t                      *media_info;
    ngx_live_variant_t                *variant;
    ngx_live_variant_t               **variant_ptr;
    ngx_http_live_core_ctx_t          *ctx;
    ngx_http_live_hls_media_group_t   *group;

    if (ngx_array_init(&result->streams, r->pool, 2, sizeof(*variant_ptr))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_group_variants: array init failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        ngx_queue_init(&result->media_groups[media_type]);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    for (q = ngx_queue_head(&channel->variants.queue);
        q != ngx_queue_sentinel(&channel->variants.queue);
        q = ngx_queue_next(q))
    {
        variant = ngx_queue_data(q, ngx_live_variant_t, queue);

        if (!ngx_http_live_output_variant(ctx, variant)) {
            continue;
        }

        switch (variant->role) {

        case ngx_live_variant_role_alternate:

            /* Note: supporting only alternative audio */

            if (variant->tracks[KMP_MEDIA_AUDIO] == NULL) {
                continue;
            }

            media_info = ngx_live_media_info_queue_get_last(
                variant->tracks[KMP_MEDIA_AUDIO], NULL);
            if (media_info == NULL) {
                continue;
            }

            group = ngx_http_live_hls_media_group_get(r, result,
                variant->tracks[KMP_MEDIA_AUDIO], media_info);
            if (group == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_live_hls_media_group_label_exists(group,
                &variant->label))
            {
                continue;
            }

            variant_arr = &group->variants;
            break;

        default:    /* ngx_live_variant_role_main */
            variant_arr = &result->streams;
            break;
        }

        variant_ptr = ngx_array_push(variant_arr);
        if (variant_ptr == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "ngx_http_live_hls_group_variants: array push failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *variant_ptr = variant;
    }

    if (result->streams.nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_live_hls_group_variants: no streams found");
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}

static u_char *
ngx_http_live_hls_write_video_range(u_char *p,
    uint8_t transfer_characteristics)
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
ngx_http_live_hls_m3u8_streams_get_size(ngx_array_t *streams,
    ngx_http_live_hls_media_group_t *audio_group)
{
    size_t                result;
    size_t                base_size;
    ngx_live_variant_t  **cur;
    ngx_live_variant_t  **last;
    ngx_live_variant_t   *variant;

    base_size = sizeof(M3U8_STREAM_VIDEO) - 1 + 5 * NGX_INT32_LEN +
        MAX_CODEC_NAME_SIZE * 2 + sizeof(",\"\n") - 1 +
        sizeof(M3U8_STREAM_VIDEO_RANGE_SDR) - 1 +
        sizeof("-s-\n") - 1 + ngx_http_live_hls_prefix_index.len +
        KMP_MEDIA_COUNT + ngx_http_live_hls_ext_m3u8.len;

    if (audio_group != NULL) {
        base_size += sizeof(M3U8_STREAM_TAG_AUDIO) - 1 + audio_group->id.len;
    }

    result = sizeof("\n") - 1 + base_size * streams->nelts;

    for (cur = streams->elts, last = cur + streams->nelts; cur < last; cur++) {

        variant = *cur;

        result += variant->sn.str.len;
    }

    return result;
}

static u_char *
ngx_http_live_hls_m3u8_streams_write(u_char *p, ngx_array_t *streams,
    ngx_http_live_request_params_t *params,
    ngx_http_live_hls_media_group_t *audio_group)
{
    uint32_t              i;
    uint32_t              bitrate;
    uint32_t              frame_rate;
    uint32_t              frame_rate_frac;
    media_info_t         *video;
    media_info_t         *audio;
    ngx_live_track_t     *tracks[KMP_MEDIA_COUNT];
    ngx_live_variant_t  **cur;
    ngx_live_variant_t  **last;
    ngx_live_variant_t   *variant;

    *p++ = '\n';

    for (cur = streams->elts, last = cur + streams->nelts; cur < last; cur++) {

        variant = *cur;

        for (i = 0; i < KMP_MEDIA_COUNT; i++) {
            if (params->media_type_mask & (1 << i)) {
                tracks[i] = variant->tracks[i];

            } else {
                tracks[i] = NULL;
            }
        }

        if (tracks[KMP_MEDIA_VIDEO] != NULL) {

            video = ngx_live_media_info_queue_get_last(
                tracks[KMP_MEDIA_VIDEO], NULL);
            if (video == NULL) {
                continue;
            }

            bitrate = video->bitrate;
            if (audio_group != NULL) {
                audio = audio_group->media_info;
                bitrate += audio->bitrate;

            } else if (tracks[KMP_MEDIA_AUDIO] != NULL) {
                audio = ngx_live_media_info_queue_get_last(
                    tracks[KMP_MEDIA_AUDIO], NULL);
                if (audio == NULL) {
                    continue;
                }

                bitrate += audio->bitrate;

            } else {
                audio = NULL;
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

        } else if (tracks[KMP_MEDIA_AUDIO] != NULL) {

            if (audio_group != NULL) {
                audio = audio_group->media_info;

            } else {
                audio = ngx_live_media_info_queue_get_last(
                    tracks[KMP_MEDIA_AUDIO], NULL);
                if (audio == NULL) {
                    continue;
                }
            }

            video = NULL;

            p = ngx_sprintf(p, M3U8_STREAM_AUDIO, audio->bitrate,
                &audio->codec_name);

        } else {
            continue;
        }

        *p++ = '\"';

        if (video != NULL) {
            p = ngx_http_live_hls_write_video_range(p,
                video->u.video.transfer_characteristics);
        }

        if (audio_group != NULL) {
            p = vod_sprintf(p, M3U8_STREAM_TAG_AUDIO, &audio_group->id);
        }

        *p++ = '\n';

        p = ngx_sprintf(p, "%V-s%V", &ngx_http_live_hls_prefix_index,
            &variant->sn.str);
        p = ngx_http_live_write_media_type_mask(p,
            params->media_type_mask);
        p = ngx_copy_str(p, ngx_http_live_hls_ext_m3u8);
        *p++ = '\n';
    }

    return p;
}

ngx_int_t
ngx_http_live_hls_m3u8_build_master(ngx_http_request_t *r,
    ngx_live_channel_t *channel, ngx_str_t *result)
{
    u_char                           *p;
    size_t                            size;
    uint32_t                          media_type;
    ngx_int_t                         rc;
    ngx_queue_t                      *q;
    ngx_http_live_core_ctx_t         *ctx;
    ngx_http_live_hls_master_t        master;
    ngx_http_live_hls_media_group_t  *group;

    /* group the variants */
    rc = ngx_http_live_hls_group_variants(r, channel, &master);
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
            group = ngx_queue_data(q, ngx_http_live_hls_media_group_t, queue);

            size += ngx_http_live_hls_media_group_get_size(group, media_type);
        }
    }

    if (!ngx_queue_empty(&master.media_groups[KMP_MEDIA_AUDIO])) {

        for (q = ngx_queue_head(&master.media_groups[KMP_MEDIA_AUDIO]);
            q != ngx_queue_sentinel(&master.media_groups[KMP_MEDIA_AUDIO]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_live_hls_media_group_t, queue);

            size += ngx_http_live_hls_m3u8_streams_get_size(&master.streams,
                group);
        }

    } else {
        size += ngx_http_live_hls_m3u8_streams_get_size(&master.streams,
            NULL);
    }

    /* allocate */
    p = ngx_palloc(r->pool, size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_m3u8_build_master: alloc failed");
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
            group = ngx_queue_data(q, ngx_http_live_hls_media_group_t, queue);

            p = ngx_http_live_hls_media_group_write(p, group, media_type);
        }
    }

    /* write streams */
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    if (!ngx_queue_empty(&master.media_groups[KMP_MEDIA_AUDIO])) {

        for (q = ngx_queue_head(&master.media_groups[KMP_MEDIA_AUDIO]);
            q != ngx_queue_sentinel(&master.media_groups[KMP_MEDIA_AUDIO]);
            q = ngx_queue_next(q))
        {
            group = ngx_queue_data(q, ngx_http_live_hls_media_group_t, queue);

            p = ngx_http_live_hls_m3u8_streams_write(p, &master.streams,
                &ctx->params, group);
        }

    } else {
        p = ngx_http_live_hls_m3u8_streams_write(p, &master.streams,
            &ctx->params, NULL);
    }

    result->len = p - result->data;

    if (result->len > size) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_hls_m3u8_build_master: "
            "result length %uz greater than allocated length %uz",
            result->len, size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


/* index */

static void
ngx_http_live_hls_bitrate_iter_init(ngx_http_request_t *r,
    ngx_http_live_hls_bitrate_iter_t *iter,
    ngx_http_live_request_objects_t *objects, uint32_t segment_index)
{
    uint32_t                       i;
    ngx_live_track_t              *cur_track;
    ngx_live_segment_info_iter_t  *cur;

    cur = iter->iters;
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        cur_track = objects->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        ngx_live_segment_info_iter_init(cur, cur_track, segment_index);

        cur++;
    }

    iter->track_count = objects->track_count;
}

static uint32_t
ngx_http_live_hls_bitrate_iter_get(ngx_http_live_hls_bitrate_iter_t *iter,
    uint32_t segment_index)
{
    uint32_t  i;
    uint32_t  cur_bitrate;
    uint32_t  result;

    result = 0;
    for (i = 0; i < iter->track_count; i++) {

        cur_bitrate = ngx_live_segment_info_iter_next(
            &iter->iters[i], segment_index);
        if (cur_bitrate == NGX_LIVE_SEGMENT_NO_BITRATE) {
            return NGX_LIVE_SEGMENT_NO_BITRATE;
        }

        result += cur_bitrate;
    }

    if (result == 0) {
        return 0;
    }

    return result > 1000 ? result / 1000 : 1;     /* bps -> kbps */
}


static ngx_int_t
ngx_http_live_hls_map_index_iter_init(ngx_http_request_t *r,
    ngx_http_live_hls_map_index_iter_t *iter,
    ngx_http_live_request_objects_t *objects)
{
    uint32_t                     i;
    ngx_live_track_t            *cur_track;
    ngx_live_media_info_iter_t  *cur;

    cur = iter->iters;
    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        cur_track = objects->tracks[i];
        if (cur_track == NULL) {
            continue;
        }

        if (!ngx_live_media_info_iter_init(cur, cur_track)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_live_hls_map_index_iter_init: "
                "no media info for track \"%V\"",
                &cur_track->sn.str);
            return NGX_HTTP_BAD_REQUEST;
        }

        cur++;
    }

    iter->track_count = objects->track_count;

    return NGX_OK;
}

static uint32_t
ngx_http_live_hls_map_index_iter_get(ngx_http_live_hls_map_index_iter_t *iter,
    uint32_t segment_index)
{
    uint32_t  i;
    uint32_t  cur_index;
    uint32_t  max_index;

    max_index = 0;
    for (i = 0; i < iter->track_count; i++) {

        cur_index = ngx_live_media_info_iter_next(&iter->iters[i],
            segment_index);
        if (cur_index > max_index) {
            max_index = cur_index;
        }
    }

    return max_index;
}


static size_t
ngx_http_live_hls_m3u8_enc_key_get_size(ngx_http_live_hls_m3u8_config_t *conf,
    ngx_http_live_request_params_t *params,
    hls_encryption_params_t *encryption_params)
{
    size_t  result;

    result = sizeof(M3U8_ENC_KEY_BASE) - 1 +
        sizeof(M3U8_ENC_METHOD_SAMPLE_AES_CENC) - 1 +
        sizeof(M3U8_ENC_KEY_URI) - 1 +
        2;            /* '"', '\n' */

    if (encryption_params->key_uri.len != 0) {
        result += encryption_params->key_uri.len;

    } else {
        result += ngx_http_live_hls_prefix_enc_key.len +
            sizeof("-s") - 1 + params->variant_id.len +
            ngx_http_live_hls_ext_enc_key.len;
    }

    if (encryption_params->return_iv) {
        result += sizeof(M3U8_ENC_KEY_IV) - 1 +
            sizeof(encryption_params->iv_buf) * 2;
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
ngx_http_live_hls_m3u8_enc_key_write(u_char *p,
    ngx_http_live_hls_m3u8_config_t *conf,
    ngx_http_live_request_params_t *params,
    hls_encryption_params_t *encryption_params)
{
    p = ngx_copy_fix(p, M3U8_ENC_KEY_BASE);

    switch (encryption_params->type) {

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
    if (encryption_params->key_uri.len != 0) {
        p = ngx_copy_str(p, encryption_params->key_uri);

    } else {
        p = ngx_copy_str(p, ngx_http_live_hls_prefix_enc_key);
        p = vod_sprintf(p, "-s%V", &params->variant_id);
        p = ngx_copy_str(p, ngx_http_live_hls_ext_enc_key);
    }
    *p++ = '"';

    /* iv */
    if (encryption_params->return_iv) {
        p = ngx_copy_fix(p, M3U8_ENC_KEY_IV);
        p = vod_append_hex_string(p, encryption_params->iv,
            sizeof(encryption_params->iv_buf));
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
ngx_http_live_hls_append_extinf_tag(u_char *p, uint32_t duration)
{
    p = ngx_copy_fix(p, M3U8_EXTINF);
    p = ngx_sprintf(p, "%d.%03d", (int) (duration / 1000),
        (int) (duration % 1000));
    *p++ = ',';
    *p++ = '\n';
    return p;
}

static size_t
ngx_http_live_hls_bitrate_gap_get_size(ngx_http_request_t *r,
    ngx_live_period_t *first_period, ngx_live_track_t **tracks)
{
    size_t              result;
    uint32_t            i;
    uint32_t            gap_count;
    uint32_t            min_gap_count;
    uint32_t            bitrate_count;
    uint32_t            left;
    ngx_live_track_t   *cur_track;
    ngx_live_period_t  *period;

    result = 0;

    for (period = first_period; period != NULL; period = period->next) {

        /* Note: using the min gap count since a gap is returned only if
            ALL tracks have a gap */

        bitrate_count = 0;
        min_gap_count = NGX_MAX_UINT32_VALUE;

        for (i = 0; i < KMP_MEDIA_COUNT; i++) {

            cur_track = tracks[i];
            if (cur_track == NULL) {
                continue;
            }

            gap_count = 0;
            ngx_live_segment_info_count(cur_track, period->node.key,
                period->node.key + period->segment_count, &bitrate_count,
                &gap_count);

            if (min_gap_count > gap_count) {
                min_gap_count = gap_count;
            }
        }

        if (bitrate_count > period->segment_count) {
            bitrate_count = period->segment_count;
        }
        result += bitrate_count *
            (sizeof(M3U8_BITRATE) - 1 + NGX_INT32_LEN + 1);     /* 1 = '\n' */

        /* Note: EXT-X-BITRATE is larger than EXT-X-GAP - segments that were
            already counted as bitrate are covered */
        left = period->segment_count - bitrate_count;
        if (min_gap_count > left) {
            min_gap_count = left;
        }

        result += min_gap_count * (sizeof(M3U8_GAP) - 1);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_http_live_hls_bitrate_gap_get_size: "
            "bitrates: %uD, gaps: %uD", bitrate_count, min_gap_count);
    }

    return result;
}

static u_char *
ngx_http_live_hls_write_period_segments(u_char *p, ngx_live_period_t *period,
    ngx_str_t *seg_suffix, uint32_t milliscale,
    ngx_http_live_hls_bitrate_iter_t *bitrate_iter)
{
    int64_t                    time;
    int64_t                    start, end;
    uint32_t                   bitrate;
    uint32_t                   last_bitrate;
    uint32_t                   segment_count;
    uint32_t                   segment_index;
    uint32_t                   last_segment_index;
    ngx_live_segment_iter_t    segment_iter;
    ngx_live_segment_repeat_t  segment_duration;

    segment_iter = period->segment_iter;
    segment_count = period->segment_count;
    segment_index = period->node.key;

    time = period->time;
    start = time / milliscale;

    last_bitrate = 0;

    while (segment_count > 0) {

        ngx_live_segment_iter_get_element(&segment_iter, &segment_duration);

        if (segment_duration.repeat_count > segment_count) {
            segment_duration.repeat_count = segment_count;
        }
        segment_count -= segment_duration.repeat_count;

        last_segment_index = segment_index + segment_duration.repeat_count;

        for (; segment_index < last_segment_index; )
        {
            time += segment_duration.duration;
            end = time / milliscale;

            p = ngx_http_live_hls_append_extinf_tag(p, end - start);

            bitrate = ngx_http_live_hls_bitrate_iter_get(bitrate_iter,
                segment_index);
            if (bitrate == 0) {
                p = ngx_copy_fix(p, M3U8_GAP);

            } else if (bitrate != NGX_LIVE_SEGMENT_NO_BITRATE &&
                bitrate != last_bitrate)
            {
                p = ngx_copy_fix(p, M3U8_BITRATE);
                p = ngx_sprintf(p, "%uD", bitrate);
                *p++ = '\n';

                last_bitrate = bitrate;
            }

            segment_index++;
            p = ngx_copy_str(p, ngx_http_live_hls_prefix_seg);
            p = ngx_sprintf(p, "-%uD", segment_index);
            p = ngx_copy_str(p, *seg_suffix);

            start = end;
        }
    }

    return p;
}

static ngx_int_t
ngx_http_live_hls_m3u8_get_selector(ngx_http_request_t *r, ngx_str_t *result)
{
    u_char                    *p;
    ngx_http_live_core_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    p = ngx_pnalloc(r->pool, sizeof("-s-") - 1 +
        ctx->params.variant_id.len + KMP_MEDIA_COUNT);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_m3u8_get_selector: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    *p++ = '-';
    *p++ = 's';
    p = ngx_copy_str(p, ctx->params.variant_id);

    p = ngx_http_live_write_media_type_mask(p,
        ctx->params.media_type_mask);

    result->len = p - result->data;

    return NGX_OK;
}

ngx_int_t
ngx_http_live_hls_m3u8_build_index(ngx_http_request_t *r,
    ngx_http_live_hls_m3u8_config_t *conf,
    ngx_http_live_request_objects_t *objects,
    hls_encryption_params_t *encryption_params, ngx_uint_t container_format,
    ngx_str_t *result)
{
    u_char                              *p;
    size_t                               result_size;
    size_t                               period_size;
    size_t                               segment_size;
    ngx_tm_t                             gmt;
    uint32_t                             version;
    uint32_t                             timescale;
    uint32_t                             milliscale;
    uint32_t                             map_index;
    uint32_t                             last_map_index;
    uint32_t                             target_duration;
    uint32_t                             segment_index_size;
    ngx_int_t                            rc;
    ngx_str_t                           *seg_ext;
    ngx_str_t                            selector;
    ngx_str_t                            seg_suffix;
    ngx_live_period_t                   *period;
    ngx_live_period_t                   *first_period;
    ngx_live_timeline_t                 *timeline;
    ngx_http_live_core_ctx_t            *ctx;
    ngx_live_core_preset_conf_t         *cpcf;
    ngx_http_live_hls_bitrate_iter_t     bitrate_iter;
    ngx_http_live_hls_map_index_iter_t   map_iter;

    /* build the segment track selector */
    rc = ngx_http_live_hls_m3u8_get_selector(r, &selector);
    if (rc != NGX_OK) {
        return rc;
    }

    if (container_format == NGX_HTTP_LIVE_HLS_CONTAINER_MPEGTS) {
        seg_ext = &ngx_http_live_hls_ext_seg_ts;

    } else {
        seg_ext = &ngx_http_live_hls_ext_seg_m4s;
    }

    /* build the segment url suffix */
    p = ngx_palloc(r->pool, selector.len + seg_ext->len + 1);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_m3u8_build_index: alloc suffix failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_live_core_module);

    seg_suffix.data = p;
    p = ngx_copy_str(p, selector);
    p = ngx_copy_str(p, *seg_ext);
    *p++ = '\n';
    seg_suffix.len = p - seg_suffix.data;

    /* get response size limit */
    timeline = objects->timeline;
    period = timeline->last_period;
    segment_index_size = vod_get_int_print_len(period->node.key +
        period->segment_count);

    segment_size =
        sizeof(M3U8_EXTINF) - 1 + NGX_INT64_LEN + sizeof(".000,\n") - 1 +
        ngx_http_live_hls_prefix_seg.len + sizeof("-") - 1 +
        segment_index_size + seg_suffix.len;

    period_size = sizeof(M3U8_DISCONTINUITY) - 1 + M3U8_PROGRAM_DATE_TIME_LEN;

    if (container_format == NGX_HTTP_LIVE_HLS_CONTAINER_FMP4) {

        period_size +=
            sizeof(M3U8_MAP_BASE) - 1 + sizeof("\"\n") - 1 +
            ngx_http_live_hls_prefix_init_seg.len + segment_index_size +
            selector.len + ngx_http_live_hls_ext_init_seg.len;

        rc = ngx_http_live_hls_map_index_iter_init(r, &map_iter, objects);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    first_period = &timeline->manifest.first_period;

    result_size =
        sizeof(M3U8_INDEX_HEADER) + 4 * NGX_INT32_LEN +
        period_size * timeline->manifest.period_count +
        segment_size * timeline->manifest.segment_count +
        ngx_http_live_hls_bitrate_gap_get_size(r, first_period,
            objects->tracks) +
        sizeof(M3U8_END_LIST) - 1;

    if (encryption_params->type != HLS_ENC_NONE) {
        result_size += ngx_http_live_hls_m3u8_enc_key_get_size(conf,
            &ctx->params, encryption_params);
    }

    /* allocate the buffer */
    p = ngx_pnalloc(r->pool, result_size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ngx_http_live_hls_m3u8_build_index: alloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    result->data = p;

    /* get timescale */
    cpcf = ngx_live_get_module_preset_conf(objects->channel,
        ngx_live_core_module);

    /* Note: assuming timescale is a multiple of 1000, if it's not, this will
            cause drift over time */
    timescale = cpcf->timescale;
    milliscale = timescale / 1000;

    /* header */
    target_duration = (timeline->manifest.target_duration + timescale / 2)
        / timescale;

    version = conf->m3u8_version;
    if (container_format == NGX_HTTP_LIVE_HLS_CONTAINER_FMP4 &&
        version < 6)
    {
        version = 6;
    }

    p = ngx_sprintf(p, M3U8_INDEX_HEADER, target_duration, version,
        timeline->manifest.sequence - timeline->manifest.segment_count,
        timeline->manifest.first_period_index);

    if (encryption_params->type != HLS_ENC_NONE) {
        p = ngx_http_live_hls_m3u8_enc_key_write(p, conf, &ctx->params,
            encryption_params);
    }

    last_map_index = NGX_MAX_UINT32_VALUE;

    for (period = first_period; period != NULL; period = period->next) {

        if (period != first_period) {
            p = ngx_copy_fix(p, M3U8_DISCONTINUITY);
        }

        ngx_gmtime(period->time / timescale, &gmt);

        p = ngx_sprintf(p, M3U8_PROGRAM_DATE_TIME,
            gmt.ngx_tm_year, gmt.ngx_tm_mon, gmt.ngx_tm_mday,
            gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec,
            (int) ((period->time / milliscale) % 1000));

        if (container_format == NGX_HTTP_LIVE_HLS_CONTAINER_FMP4) {

            map_index = ngx_http_live_hls_map_index_iter_get(&map_iter,
                period->node.key);

            if (map_index != last_map_index) {
                p = ngx_copy_fix(p, M3U8_MAP_BASE);
                p = ngx_copy_str(p, ngx_http_live_hls_prefix_init_seg);
                p = ngx_sprintf(p, "-%uD", map_index + 1);
                p = ngx_copy_str(p, selector);
                p = ngx_copy_str(p, ngx_http_live_hls_ext_init_seg);
                *p++ = '"';
                *p++ = '\n';

                last_map_index = map_index;
            }
        }

        ngx_http_live_hls_bitrate_iter_init(r, &bitrate_iter, objects,
            period->node.key);

        p = ngx_http_live_hls_write_period_segments(p, period,
            &seg_suffix, milliscale, &bitrate_iter);
    }

    /* write the footer */
    if (!timeline->conf.active) {
        p = ngx_copy_fix(p, M3U8_END_LIST);
    }

    result->len = p - result->data;

    if (result->len > result_size) {
        vod_log_error(VOD_LOG_ALERT, r->connection->log, 0,
            "ngx_http_live_hls_build_index_playlist: "
            "result length %uz greater than allocated length %uz",
            result->len, result_size);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
