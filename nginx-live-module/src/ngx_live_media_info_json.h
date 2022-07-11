/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

/* ngx_live_media_info_json_stats writer */

static size_t
ngx_live_media_info_json_stats_get_size(ngx_live_media_info_node_t *obj)
{
    size_t  result;

    result =
        sizeof("\"bitrate_max\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"bitrate_avg\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"frame_rate_min\":") - 1 + NGX_INT32_LEN + 1 +
        sizeof(",\"frame_rate_max\":") - 1 + NGX_INT32_LEN + 1 +
        sizeof(",\"frame_rate_avg\":") - 1 + NGX_INT32_LEN + 1;

    return result;
}


static u_char *
ngx_live_media_info_json_stats_write(u_char *p, ngx_live_media_info_node_t
    *obj)
{
    uint32_t                      frame_rate_avg;
    ngx_ksmp_media_info_stats_t  *stats;

    stats = &obj->stats;
    frame_rate_avg = (stats->duration > 0 ? 100 * stats->frame_count *
        obj->media_info.info.timescale / stats->duration : 0);
    p = ngx_copy_fix(p, "\"bitrate_max\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) stats->bitrate_max);
    p = ngx_copy_fix(p, ",\"bitrate_avg\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) (stats->bitrate_count > 0 ?
        stats->bitrate_sum / stats->bitrate_count : 0));
    p = ngx_copy_fix(p, ",\"frame_rate_min\":");
    p = ngx_sprintf(p, "%uD.%02uD", (uint32_t) (stats->frame_rate_min / 100),
        (uint32_t) (stats->frame_rate_min % 100));
    p = ngx_copy_fix(p, ",\"frame_rate_max\":");
    p = ngx_sprintf(p, "%uD.%02uD", (uint32_t) (stats->frame_rate_max / 100),
        (uint32_t) (stats->frame_rate_max % 100));
    p = ngx_copy_fix(p, ",\"frame_rate_avg\":");
    p = ngx_sprintf(p, "%uD.%02uD", (uint32_t) (frame_rate_avg / 100),
        (uint32_t) (frame_rate_avg % 100));

    return p;
}


/* ngx_live_media_info_json_base writer */

static size_t
ngx_live_media_info_json_base_get_size(ngx_live_media_info_node_t *obj)
{
    size_t                  result;
    ngx_live_media_info_t  *mi;

    mi = &obj->media_info;
    result =
        sizeof("\"segment_index\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"codec_id\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"bitrate\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"extra_data\":\"") - 1 + mi->extra.len * 2 +
        sizeof("\"") - 1;

    return result;
}


static u_char *
ngx_live_media_info_json_base_write(u_char *p, ngx_live_media_info_node_t *obj)
{
    ngx_live_media_info_t  *mi;

    mi = &obj->media_info;
    p = ngx_copy_fix(p, "\"segment_index\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->node.key);
    p = ngx_copy_fix(p, ",\"codec_id\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.codec_id);
    p = ngx_copy_fix(p, ",\"bitrate\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.bitrate);
    p = ngx_copy_fix(p, ",\"extra_data\":\"");
    p = ngx_hex_dump(p, mi->extra.data, mi->extra.len);
    *p++ = '\"';

    return p;
}


/* ngx_live_media_info_json_video writer */

static size_t
ngx_live_media_info_json_video_get_size(ngx_live_media_info_node_t *obj)
{
    size_t  result;

    result =
        sizeof("{") - 1 + ngx_live_media_info_json_base_get_size(obj) +
        sizeof(",\"width\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"height\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"frame_rate\":") - 1 + NGX_INT32_LEN + 3 +
        sizeof(",\"cea_captions\":") - 1 + sizeof("false") - 1 +
        sizeof(",") - 1 + ngx_live_media_info_json_stats_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_live_media_info_json_video_write(u_char *p, ngx_live_media_info_node_t
    *obj)
{
    u_char                 *next;
    uint32_t                n, d;
    ngx_live_media_info_t  *mi;

    mi = &obj->media_info;
    *p++ = '{';
    p = ngx_live_media_info_json_base_write(p, obj);
    p = ngx_copy_fix(p, ",\"width\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.u.video.width);
    p = ngx_copy_fix(p, ",\"height\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.u.video.height);
    p = ngx_copy_fix(p, ",\"frame_rate\":");
    d = mi->info.u.video.frame_rate.denom;
    if (d) {
        n = mi->info.u.video.frame_rate.num;
        p = ngx_sprintf(p, "%uD.%02uD", (uint32_t) (n / d), (uint32_t) (n % d
            * 100) / d);

    } else {
        *p++ = '0';
    }

    p = ngx_copy_fix(p, ",\"cea_captions\":");
    if (mi->info.u.video.cea_captions) {
        p = ngx_copy_fix(p, "true");

    } else {
        p = ngx_copy_fix(p, "false");
    }

    *p++ = ',';
    next = ngx_live_media_info_json_stats_write(p, obj);
    p = next == p ? p - 1 : next;
    *p++ = '}';

    return p;
}


/* ngx_live_media_info_json_audio writer */

static size_t
ngx_live_media_info_json_audio_get_size(ngx_live_media_info_node_t *obj)
{
    size_t  result;

    result =
        sizeof("{") - 1 + ngx_live_media_info_json_base_get_size(obj) +
        sizeof(",\"channels\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"channel_layout\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"bits_per_sample\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"sample_rate\":") - 1 + NGX_INT32_LEN +
        sizeof(",") - 1 + ngx_live_media_info_json_stats_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_live_media_info_json_audio_write(u_char *p, ngx_live_media_info_node_t
    *obj)
{
    u_char                 *next;
    ngx_live_media_info_t  *mi;

    mi = &obj->media_info;
    *p++ = '{';
    p = ngx_live_media_info_json_base_write(p, obj);
    p = ngx_copy_fix(p, ",\"channels\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.u.audio.channels);
    p = ngx_copy_fix(p, ",\"channel_layout\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) mi->info.u.audio.channel_layout);
    p = ngx_copy_fix(p, ",\"bits_per_sample\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.u.audio.bits_per_sample);
    p = ngx_copy_fix(p, ",\"sample_rate\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) mi->info.u.audio.sample_rate);
    *p++ = ',';
    next = ngx_live_media_info_json_stats_write(p, obj);
    p = next == p ? p - 1 : next;
    *p++ = '}';

    return p;
}
