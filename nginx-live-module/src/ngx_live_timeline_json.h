/* auto-generated by generate_json_builder.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif


static size_t
ngx_live_period_json_get_size(ngx_live_period_t *obj)
{
    size_t  result =
        sizeof("{\"time\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"duration\":") - 1 + NGX_INT64_LEN +
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
    p = ngx_copy_fix(p, ",\"segment_count\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->segment_count);
    *p++ = '}';

    return p;
}

size_t
ngx_live_timeline_json_get_size(ngx_live_timeline_t *obj)
{
    ngx_live_period_t  *cur;
    size_t  result =
        sizeof("{\"active\":") - 1 + sizeof("false") - 1 +
        sizeof(",\"no_truncate\":") - 1 + sizeof("false") - 1 +
        sizeof(",\"max_segments\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"max_duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"start\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"end\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"manifest_max_segments\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"manifest_max_duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"manifest_expiry_threshold\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"manifest_target_duration_segments\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"segment_count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"duration\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"periods\":[") - 1 +
        sizeof("]}") - 1;

    for (cur = obj->head_period; cur; cur = cur->next) {
        result += ngx_live_period_json_get_size(cur) + sizeof(",") - 1;
    }

    return result;
}

u_char *
ngx_live_timeline_json_write(u_char *p, ngx_live_timeline_t *obj)
{
    ngx_live_period_t  *cur;
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
    p = ngx_copy_fix(p, ",\"segment_count\":");
    p = ngx_sprintf(p, "%uD", (uint32_t) obj->segment_count);
    p = ngx_copy_fix(p, ",\"duration\":");
    p = ngx_sprintf(p, "%uL", (uint64_t) obj->duration);
    p = ngx_copy_fix(p, ",\"periods\":[");

    for (cur = obj->head_period; cur; cur = cur->next) {

        if (cur != obj->head_period) {
            *p++ = ',';
        }
        p = ngx_live_period_json_write(p, cur);
    }

    p = ngx_copy_fix(p, "]}");

    return p;
}

static size_t
ngx_live_timelines_json_get_size(ngx_live_timeline_channel_ctx_t *obj)
{
    ngx_queue_t  *q;
    size_t  result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&obj->queue);
        q != ngx_queue_sentinel(&obj->queue);
        q = ngx_queue_next(q))
    {
        ngx_live_timeline_t *cur = ngx_queue_data(q, ngx_live_timeline_t,
            queue);
        result += cur->sn.str.len + ngx_escape_json(NULL, cur->sn.str.data,
            cur->sn.str.len);
        result += ngx_live_timeline_json_get_size(cur) + sizeof(",\"\":") - 1;
    }

    return result;
}

static u_char *
ngx_live_timelines_json_write(u_char *p, ngx_live_timeline_channel_ctx_t *obj)
{
    ngx_queue_t  *q;
    *p++ = '{';

    for (q = ngx_queue_head(&obj->queue);
        q != ngx_queue_sentinel(&obj->queue);
        q = ngx_queue_next(q))
    {
        ngx_live_timeline_t *cur = ngx_queue_data(q, ngx_live_timeline_t,
            queue);

        if (q != ngx_queue_head(&obj->queue))
        {
            *p++ = ',';
        }
        *p++ = '"';
        p = (u_char *) ngx_escape_json(p, cur->sn.str.data, cur->sn.str.len);
        *p++ = '"';
        *p++ = ':';
        p = ngx_live_timeline_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}

static size_t
ngx_live_timelines_module_json_get_size(ngx_live_timeline_channel_ctx_t *obj)
{
    size_t  result =
        sizeof("\"timelines\":") - 1 + ngx_live_timelines_json_get_size(obj) +
        sizeof(",\"segment_list\":") - 1 +
            ngx_live_segment_list_json_get_size(&obj->segment_list);

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

    return p;
}
