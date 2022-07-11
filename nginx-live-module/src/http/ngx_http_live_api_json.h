/* auto-generated by generate_json_header.py */

#ifndef ngx_array_entries
#define ngx_array_entries(x)     (sizeof(x) / sizeof(x[0]))
#endif

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

/* ngx_live_channel_json reader */

typedef struct {
    ngx_str_t   id;
    ngx_str_t   preset;
    ngx_str_t   opaque;
    ngx_flag_t  read;
    int64_t     initial_segment_index;
    int64_t     segment_duration;
} ngx_live_channel_json_t;


static ngx_json_prop_t  ngx_live_channel_json_id = {
    ngx_string("id"),
    3355ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_channel_json_t, id),
    NULL
};


static ngx_json_prop_t  ngx_live_channel_json_preset = {
    ngx_string("preset"),
    3314868959ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_channel_json_t, preset),
    NULL
};


static ngx_json_prop_t  ngx_live_channel_json_opaque = {
    ngx_string("opaque"),
    3284272161ULL,
    NGX_JSON_STRING,
    ngx_json_set_raw_str_slot,
    offsetof(ngx_live_channel_json_t, opaque),
    NULL
};


static ngx_json_prop_t  ngx_live_channel_json_read = {
    ngx_string("read"),
    3496342ULL,
    NGX_JSON_BOOL,
    ngx_json_set_flag_slot,
    offsetof(ngx_live_channel_json_t, read),
    NULL
};


static ngx_json_prop_t  ngx_live_channel_json_initial_segment_index = {
    ngx_string("initial_segment_index"),
    18106540101855730443ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_channel_json_t, initial_segment_index),
    NULL
};


static ngx_json_prop_t  ngx_live_channel_json_segment_duration = {
    ngx_string("segment_duration"),
    15286675145585412384ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_channel_json_t, segment_duration),
    NULL
};


static ngx_json_prop_t  *ngx_live_channel_json[] = {
    NULL,
    &ngx_live_channel_json_opaque,
    &ngx_live_channel_json_read,
    &ngx_live_channel_json_initial_segment_index,
    &ngx_live_channel_json_segment_duration,
    &ngx_live_channel_json_id,
    NULL,
    NULL,
    NULL,
    &ngx_live_channel_json_preset,
};


/* ngx_live_variant_json reader */

typedef struct {
    ngx_str_t           id;
    ngx_str_t           opaque;
    ngx_str_t           label;
    ngx_str_t           lang;
    ngx_uint_t          role;
    ngx_flag_t          is_default;
    ngx_json_object_t  *track_ids;
} ngx_live_variant_json_t;


static ngx_json_prop_t  ngx_live_variant_json_id = {
    ngx_string("id"),
    3355ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_variant_json_t, id),
    NULL
};


static ngx_json_prop_t  ngx_live_variant_json_opaque = {
    ngx_string("opaque"),
    3284272161ULL,
    NGX_JSON_STRING,
    ngx_json_set_raw_str_slot,
    offsetof(ngx_live_variant_json_t, opaque),
    NULL
};


static ngx_json_prop_t  ngx_live_variant_json_label = {
    ngx_string("label"),
    102727412ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_variant_json_t, label),
    NULL
};


static ngx_json_prop_t  ngx_live_variant_json_lang = {
    ngx_string("lang"),
    3314158ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_variant_json_t, lang),
    NULL
};


static ngx_json_prop_t  ngx_live_variant_json_role = {
    ngx_string("role"),
    3506294ULL,
    NGX_JSON_STRING,
    ngx_json_set_enum_slot,
    offsetof(ngx_live_variant_json_t, role),
    &ngx_live_variant_role_names
};


static ngx_json_prop_t  ngx_live_variant_json_is_default = {
    ngx_string("is_default"),
    2876948233633836ULL,
    NGX_JSON_BOOL,
    ngx_json_set_flag_slot,
    offsetof(ngx_live_variant_json_t, is_default),
    NULL
};


static ngx_json_prop_t  ngx_live_variant_json_track_ids = {
    ngx_string("track_ids"),
    102160822245828ULL,
    NGX_JSON_OBJECT,
    ngx_json_set_obj_slot,
    offsetof(ngx_live_variant_json_t, track_ids),
    NULL
};


static ngx_json_prop_t  *ngx_live_variant_json[] = {
    &ngx_live_variant_json_is_default,
    NULL,
    &ngx_live_variant_json_role,
    NULL,
    NULL,
    NULL,
    &ngx_live_variant_json_track_ids,
    &ngx_live_variant_json_id,
    &ngx_live_variant_json_label,
    &ngx_live_variant_json_opaque,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &ngx_live_variant_json_lang,
    NULL,
};


/* ngx_live_track_json reader */

typedef struct {
    ngx_str_t   id;
    ngx_uint_t  media_type;
    ngx_str_t   opaque;
} ngx_live_track_json_t;


static ngx_json_prop_t  ngx_live_track_json_id = {
    ngx_string("id"),
    3355ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_track_json_t, id),
    NULL
};


static ngx_json_prop_t  ngx_live_track_json_media_type = {
    ngx_string("media_type"),
    2970908127930037ULL,
    NGX_JSON_STRING,
    ngx_json_set_enum_slot,
    offsetof(ngx_live_track_json_t, media_type),
    &ngx_live_track_media_type_names
};


static ngx_json_prop_t  ngx_live_track_json_opaque = {
    ngx_string("opaque"),
    3284272161ULL,
    NGX_JSON_STRING,
    ngx_json_set_raw_str_slot,
    offsetof(ngx_live_track_json_t, opaque),
    NULL
};


static ngx_json_prop_t  *ngx_live_track_json[] = {
    &ngx_live_track_json_id,
    &ngx_live_track_json_opaque,
    &ngx_live_track_json_media_type,
    NULL,
    NULL,
};


/* ngx_live_timeline_source_json reader */

typedef struct {
    ngx_str_t  id;
    int64_t    start_offset;
    int64_t    end_offset;
} ngx_live_timeline_source_json_t;


static ngx_json_prop_t  ngx_live_timeline_source_json_id = {
    ngx_string("id"),
    3355ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_timeline_source_json_t, id),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_source_json_start_offset = {
    ngx_string("start_offset"),
    3019716876355455760ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_source_json_t, start_offset),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_source_json_end_offset = {
    ngx_string("end_offset"),
    2767058701794423ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_source_json_t, end_offset),
    NULL
};


static ngx_json_prop_t  *ngx_live_timeline_source_json[] = {
    NULL,
    &ngx_live_timeline_source_json_id,
    NULL,
    &ngx_live_timeline_source_json_end_offset,
    &ngx_live_timeline_source_json_start_offset,
    NULL,
};


/* ngx_live_timeline_json reader */

typedef struct {
    ngx_str_t           id;
    ngx_json_object_t  *source;
    ngx_flag_t          active;
    ngx_flag_t          no_truncate;
    ngx_flag_t          end_list;
    int64_t             period_gap;
    int64_t             max_segments;
    int64_t             max_duration;
    int64_t             start;
    int64_t             end;
    int64_t             manifest_max_segments;
    int64_t             manifest_max_duration;
    int64_t             manifest_expiry_threshold;
    int64_t             manifest_target_duration_segments;
} ngx_live_timeline_json_t;


static ngx_json_prop_t  ngx_live_timeline_json_id = {
    ngx_string("id"),
    3355ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_live_timeline_json_t, id),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_source = {
    ngx_string("source"),
    3398461467ULL,
    NGX_JSON_OBJECT,
    ngx_json_set_obj_slot,
    offsetof(ngx_live_timeline_json_t, source),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_active = {
    ngx_string("active"),
    2872016646ULL,
    NGX_JSON_BOOL,
    ngx_json_set_flag_slot,
    offsetof(ngx_live_timeline_json_t, active),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_no_truncate = {
    ngx_string("no_truncate"),
    93178230369180196ULL,
    NGX_JSON_BOOL,
    ngx_json_set_flag_slot,
    offsetof(ngx_live_timeline_json_t, no_truncate),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_end_list = {
    ngx_string("end_list"),
    2879353401730ULL,
    NGX_JSON_BOOL,
    ngx_json_set_flag_slot,
    offsetof(ngx_live_timeline_json_t, end_list),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_period_gap = {
    ngx_string("period_gap"),
    3050612575791960ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, period_gap),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_max_segments = {
    ngx_string("max_segments"),
    2852284961494180891ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, max_segments),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_max_duration = {
    ngx_string("max_duration"),
    2852284563309308431ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, max_duration),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_start = {
    ngx_string("start"),
    109757538ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, start),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_end = {
    ngx_string("end"),
    100571ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, end),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_manifest_max_segments = {
    ngx_string("manifest_max_segments"),
    612119576334148651ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, manifest_max_segments),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_manifest_max_duration = {
    ngx_string("manifest_max_duration"),
    612119178149276191ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, manifest_max_duration),
    NULL
};


static ngx_json_prop_t  ngx_live_timeline_json_manifest_expiry_threshold = {
    ngx_string("manifest_expiry_threshold"),
    8208201564390535279ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, manifest_expiry_threshold),
    NULL
};


static ngx_json_prop_t
    ngx_live_timeline_json_manifest_target_duration_segments =
{
    ngx_string("manifest_target_duration_segments"),
    7444509727656907469ULL,
    NGX_JSON_INT,
    ngx_json_set_num_slot,
    offsetof(ngx_live_timeline_json_t, manifest_target_duration_segments),
    NULL
};


static ngx_json_prop_t  *ngx_live_timeline_json[] = {
    &ngx_live_timeline_json_start,
    NULL,
    NULL,
    NULL,
    &ngx_live_timeline_json_no_truncate,
    NULL,
    &ngx_live_timeline_json_source,
    &ngx_live_timeline_json_id,
    NULL,
    NULL,
    &ngx_live_timeline_json_manifest_max_segments,
    NULL,
    NULL,
    &ngx_live_timeline_json_manifest_max_duration,
    NULL,
    NULL,
    &ngx_live_timeline_json_end_list,
    NULL,
    NULL,
    &ngx_live_timeline_json_max_segments,
    &ngx_live_timeline_json_manifest_target_duration_segments,
    &ngx_live_timeline_json_period_gap,
    &ngx_live_timeline_json_max_duration,
    &ngx_live_timeline_json_end,
    &ngx_live_timeline_json_active,
    &ngx_live_timeline_json_manifest_expiry_threshold,
    NULL,
};


/* ngx_http_live_api_json writer */

static size_t
ngx_http_live_api_json_get_size(void *obj)
{
    size_t  result;

    result =
        sizeof("{\"version\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_live_version) +
        sizeof("\",\"nginx_version\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_live_nginx_version) +
        sizeof("\",\"compiler\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_live_compiler) +
        sizeof("\",\"built\":\"") - 1 +
            ngx_json_str_get_size(&ngx_http_live_built) +
        sizeof("\",\"pid\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"time\":") - 1 + NGX_TIME_T_LEN +
        sizeof(",\"uptime\":") - 1 + NGX_TIME_T_LEN +
        sizeof(",") - 1 + ngx_live_core_json_get_size(NULL, NULL,
            NGX_LIVE_JSON_CTX_GLOBAL) +
        sizeof(",\"channels\":") - 1 + ngx_live_channels_json_get_size(NULL) +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_http_live_api_json_write(u_char *p, void *obj)
{
    u_char  *next;

    p = ngx_copy_fix(p, "{\"version\":\"");
    p = ngx_json_str_write(p, &ngx_http_live_version);
    p = ngx_copy_fix(p, "\",\"nginx_version\":\"");
    p = ngx_json_str_write(p, &ngx_http_live_nginx_version);
    p = ngx_copy_fix(p, "\",\"compiler\":\"");
    p = ngx_json_str_write(p, &ngx_http_live_compiler);
    p = ngx_copy_fix(p, "\",\"built\":\"");
    p = ngx_json_str_write(p, &ngx_http_live_built);
    p = ngx_copy_fix(p, "\",\"pid\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) ngx_getpid());
    p = ngx_copy_fix(p, ",\"time\":");
    p = ngx_sprintf(p, "%T", (time_t) ngx_time());
    p = ngx_copy_fix(p, ",\"uptime\":");
    p = ngx_sprintf(p, "%T", (time_t) (ngx_time() - ngx_http_live_start_time));
    *p++ = ',';
    next = ngx_live_core_json_write(p, NULL, NULL, NGX_LIVE_JSON_CTX_GLOBAL);
    p = next == p ? p - 1 : next;
    p = ngx_copy_fix(p, ",\"channels\":");
    p = ngx_live_channels_json_write(p, NULL);
    *p++ = '}';

    return p;
}
