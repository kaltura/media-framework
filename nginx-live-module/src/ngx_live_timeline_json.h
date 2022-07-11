/* auto-generated by generate_json_header.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

/* ngx_live_period_json writer */

static size_t
ngx_live_period_json_get_size(ngx_live_period_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"time\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"segment_index\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"segment_count\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_live_period_json_write(u_char *p, ngx_live_period_t *obj)
{
    p = ngx_copy_fix(p, "{\"time\":");
    p = ngx_sprintf(p, "%L", (int64_t) obj->time);
    p = ngx_copy_fix(p, ",\"duration\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->duration);
    p = ngx_copy_fix(p, ",\"segment_index\":");
    p = ngx_sprintf(p, "%ui", (ngx_uint_t) obj->node.key);
    p = ngx_copy_fix(p, ",\"segment_count\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->segment_count);
    *p++ = '}';

    return p;
}


/* ngx_live_timeline_conf_json writer */

static size_t
ngx_live_timeline_conf_json_get_size(ngx_live_timeline_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"active\":") - 1 + sizeof("false") - 1 +
        sizeof(",\"no_truncate\":") - 1 + sizeof("false") - 1 +
        sizeof(",\"end_list\":") - 1 + sizeof("false") - 1 +
        sizeof(",\"period_gap\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"max_segments\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"max_duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"start\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"end\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"manifest_max_segments\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"manifest_max_duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"manifest_expiry_threshold\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"manifest_target_duration_segments\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;

    return result;
}


static u_char *
ngx_live_timeline_conf_json_write(u_char *p, ngx_live_timeline_t *obj)
{
    p = ngx_copy_fix(p, "{\"active\":");
    if (obj->conf.active) {
        p = ngx_copy_fix(p, "true");

    } else {
        p = ngx_copy_fix(p, "false");
    }

    p = ngx_copy_fix(p, ",\"no_truncate\":");
    if (obj->conf.no_truncate) {
        p = ngx_copy_fix(p, "true");

    } else {
        p = ngx_copy_fix(p, "false");
    }

    p = ngx_copy_fix(p, ",\"end_list\":");
    if (obj->manifest.conf.end_list) {
        p = ngx_copy_fix(p, "true");

    } else {
        p = ngx_copy_fix(p, "false");
    }

    p = ngx_copy_fix(p, ",\"period_gap\":");
    p = ngx_sprintf(p, "%L", (int64_t) obj->conf.period_gap);
    p = ngx_copy_fix(p, ",\"max_segments\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) (obj->conf.max_segments !=
        NGX_MAX_UINT32_VALUE ? obj->conf.max_segments : 0));
    p = ngx_copy_fix(p, ",\"max_duration\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) (obj->conf.max_duration != ULLONG_MAX
        ? obj->conf.max_duration : 0));
    p = ngx_copy_fix(p, ",\"start\":");
    p = ngx_sprintf(p, "%L", (int64_t) obj->conf.start);
    p = ngx_copy_fix(p, ",\"end\":");
    p = ngx_sprintf(p, "%L", (int64_t) (obj->conf.end != LLONG_MAX ?
        obj->conf.end : 0));
    p = ngx_copy_fix(p, ",\"manifest_max_segments\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) (obj->manifest.conf.max_segments !=
        NGX_MAX_UINT32_VALUE ? obj->manifest.conf.max_segments : 0));
    p = ngx_copy_fix(p, ",\"manifest_max_duration\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) (obj->manifest.conf.max_duration !=
        ULLONG_MAX ? obj->manifest.conf.max_duration : 0));
    p = ngx_copy_fix(p, ",\"manifest_expiry_threshold\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->manifest.conf.expiry_threshold);
    p = ngx_copy_fix(p, ",\"manifest_target_duration_segments\":");
    p = ngx_sprintf(p, "%uD", (uint32_t)
        obj->manifest.conf.target_duration_segments);
    *p++ = '}';

    return p;
}


/* ngx_live_timeline_json writer */

size_t
ngx_live_timeline_json_get_size(ngx_live_timeline_t *obj)
{
    size_t  result;

    result =
        sizeof("{\"conf\":") - 1 + ngx_live_timeline_conf_json_get_size(obj) +
        sizeof(",\"period_count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"segment_count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"first_segment_index\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"last_segment_created\":") - 1 + NGX_TIME_T_LEN +
        sizeof(",\"last_accessed\":") - 1 + NGX_TIME_T_LEN +
        sizeof(",\"last_periods\":") - 1 +
            ngx_live_timeline_last_periods_json_get_size(obj) +
        sizeof("}") - 1;

    return result;
}


u_char *
ngx_live_timeline_json_write(u_char *p, ngx_live_timeline_t *obj)
{
    p = ngx_copy_fix(p, "{\"conf\":");
    p = ngx_live_timeline_conf_json_write(p, obj);
    p = ngx_copy_fix(p, ",\"period_count\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->period_count);
    p = ngx_copy_fix(p, ",\"segment_count\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->segment_count);
    p = ngx_copy_fix(p, ",\"duration\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->duration);
    p = ngx_copy_fix(p, ",\"first_segment_index\":");
    p = ngx_sprintf(p, "%uD", (uint32_t)
        ngx_live_timeline_get_first_index(obj));
    p = ngx_copy_fix(p, ",\"last_segment_created\":");
    p = ngx_sprintf(p, "%T", (time_t) obj->last_segment_created);
    p = ngx_copy_fix(p, ",\"last_accessed\":");
    p = ngx_sprintf(p, "%T", (time_t) obj->last_accessed);
    p = ngx_copy_fix(p, ",\"last_periods\":");
    p = ngx_live_timeline_last_periods_json_write(p, obj);
    *p++ = '}';

    return p;
}


/* ngx_live_timelines_json writer */

static size_t
ngx_live_timelines_json_get_size(ngx_live_timeline_channel_ctx_t *obj)
{
    size_t                result;
    ngx_queue_t          *q;
    ngx_live_timeline_t  *cur;

    result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&obj->queue);
        q != ngx_queue_sentinel(&obj->queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_timeline_t, queue);
        result += cur->sn.str.len + cur->id_escape;
        result += ngx_live_timeline_json_get_size(cur) + sizeof(",\"\":") - 1;
    }

    return result;
}


static u_char *
ngx_live_timelines_json_write(u_char *p, ngx_live_timeline_channel_ctx_t *obj)
{
    ngx_queue_t          *q;
    ngx_live_timeline_t  *cur;

    *p++ = '{';

    for (q = ngx_queue_head(&obj->queue);
        q != ngx_queue_sentinel(&obj->queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_timeline_t, queue);

        if (q != ngx_queue_head(&obj->queue))
        {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
        *p++ = ':';
        p = ngx_live_timeline_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}


/* ngx_live_timeline_ids_json writer */

size_t
ngx_live_timeline_ids_json_get_size(ngx_live_channel_t *obj)
{
    size_t                            result;
    ngx_queue_t                      *q;
    ngx_live_timeline_t              *cur;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(obj, ngx_live_timeline_module);
    result =
        sizeof("[") - 1 +
        sizeof("]") - 1;

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_timeline_t, queue);
        result += cur->sn.str.len + cur->id_escape + sizeof(",\"\"") - 1;
    }

    return result;
}


u_char *
ngx_live_timeline_ids_json_write(u_char *p, ngx_live_channel_t *obj)
{
    ngx_queue_t                      *q;
    ngx_live_timeline_t              *cur;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(obj, ngx_live_timeline_module);
    *p++ = '[';

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_timeline_t, queue);

        if (q != ngx_queue_head(&cctx->queue))
        {
            *p++ = ',';
        }

        *p++ = '"';
        p = ngx_json_str_write_escape(p, &cur->sn.str, cur->id_escape);
        *p++ = '"';
    }

    *p++ = ']';

    return p;
}


/* ngx_live_timelines_module_json writer */

static size_t
ngx_live_timelines_module_json_get_size(ngx_live_timeline_channel_ctx_t *obj)
{
    size_t  result;

    result =
        sizeof("\"timelines\":") - 1 + ngx_live_timelines_json_get_size(obj) +
        sizeof(",\"segment_list\":") - 1 +
            ngx_live_segment_list_json_get_size(&obj->segment_list) +
        sizeof(",\"truncate\":") - 1 + NGX_INT32_LEN;

    return result;
}


static u_char *
ngx_live_timelines_module_json_write(u_char *p,
    ngx_live_timeline_channel_ctx_t *obj)
{
    p = ngx_copy_fix(p, "\"timelines\":");
    p = ngx_live_timelines_json_write(p, obj);
    p = ngx_copy_fix(p, ",\"segment_list\":");
    p = ngx_live_segment_list_json_write(p, &obj->segment_list);
    p = ngx_copy_fix(p, ",\"truncate\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->truncate);

    return p;
}
