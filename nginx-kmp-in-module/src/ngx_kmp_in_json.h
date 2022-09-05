/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

/* ngx_kmp_in_stats_latency_json writer */

size_t
ngx_kmp_in_stats_latency_json_get_size(ngx_kmp_in_stats_latency_t *obj)
{
    size_t  result;

    if (obj->count <= 0) {
        return sizeof("null") - 1;
    }

    result =
        sizeof("{\"min\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"max\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"avg\":") - 1 + NGX_INT64_LEN +
        sizeof("}") - 1;

    return result;
}


u_char *
ngx_kmp_in_stats_latency_json_write(u_char *p, ngx_kmp_in_stats_latency_t *obj)
{
    if (obj->count <= 0) {
        p = ngx_copy_fix(p, "null");
        return p;
    }

    p = ngx_copy_fix(p, "{\"min\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->min);
    p = ngx_copy_fix(p, ",\"max\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->max);
    p = ngx_copy_fix(p, ",\"avg\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->sum / obj->count);
    *p++ = '}';

    return p;
}


/* ngx_kmp_in_stats_skip_json writer */

static size_t
ngx_kmp_in_stats_skip_json_get_size(ngx_kmp_in_stats_skip_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"duplicate\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"empty\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"no_media_info\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"no_key\":") - 1 + NGX_INT_T_LEN +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_kmp_in_stats_skip_json_write(u_char *p, ngx_kmp_in_stats_skip_t *obj)
{
    p = ngx_copy_fix(p, "{\"duplicate\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->duplicate);
    p = ngx_copy_fix(p, ",\"empty\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->empty);
    p = ngx_copy_fix(p, ",\"no_media_info\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->no_media_info);
    p = ngx_copy_fix(p, ",\"no_key\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->no_key);
    *p++ = '}';

    return p;
}


/* ngx_kmp_in_json writer */

size_t
ngx_kmp_in_json_get_size(ngx_kmp_in_ctx_t *obj)
{
    size_t  result;

    if (!obj) {
        return sizeof("null") - 1;
    }

    result =
        sizeof("{\"connection\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"remote_addr\":\"") - 1 +
            ngx_json_str_get_size(&obj->remote_addr) +
        sizeof("\",\"uptime\":") - 1 + NGX_TIME_T_LEN +
        sizeof(",\"received_bytes\":") - 1 + NGX_OFF_T_LEN +
        sizeof(",\"skipped_frames\":") - 1 +
            ngx_kmp_in_stats_skip_json_get_size(&obj->skipped) +
        sizeof(",\"latency\":") - 1 +
            ngx_kmp_in_stats_latency_json_get_size(&obj->latency) +
        sizeof("}") - 1;

    return result;
}


u_char *
ngx_kmp_in_json_write(u_char *p, ngx_kmp_in_ctx_t *obj)
{
    if (!obj) {
        p = ngx_copy_fix(p, "null");
        return p;
    }

    p = ngx_copy_fix(p, "{\"connection\":");
    p = ngx_sprintf(p, "%uA", (ngx_atomic_uint_t) obj->connection->number);
    p = ngx_copy_fix(p, ",\"remote_addr\":\"");
    p = ngx_json_str_write(p, &obj->remote_addr);
    p = ngx_copy_fix(p, "\",\"uptime\":");
    p = ngx_sprintf(p, "%T", (time_t) (ngx_time() - obj->start_sec));
    p = ngx_copy_fix(p, ",\"received_bytes\":");
    p = ngx_sprintf(p, "%O", (off_t) obj->received_bytes);
    p = ngx_copy_fix(p, ",\"skipped_frames\":");
    p = ngx_kmp_in_stats_skip_json_write(p, &obj->skipped);
    p = ngx_copy_fix(p, ",\"latency\":");
    p = ngx_kmp_in_stats_latency_json_write(p, &obj->latency);
    *p++ = '}';

    return p;
}
