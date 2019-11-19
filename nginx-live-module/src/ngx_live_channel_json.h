/* auto-generated by generate_json_builder.py */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif


static size_t
ngx_live_track_json_get_size(ngx_live_track_t *obj)
{
    size_t  result =
        sizeof("{\"time\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"connection\":") - 1 + NGX_INT_T_LEN +
        sizeof(",\"remote_addr\":\"") - 1 + obj->input.remote_addr.len +
            ngx_escape_json(NULL, obj->input.remote_addr.data,
            obj->input.remote_addr.len) +
        sizeof("\",\"opaque\":\"") - 1 + obj->opaque.len +
        sizeof("\",") - 1 + ngx_live_core_json_get_size(obj, obj->channel,
            NGX_LIVE_JSON_CTX_TRACK) +
        sizeof("}") - 1;

    return result;
}

static u_char *
ngx_live_track_json_write(u_char *p, ngx_live_track_t *obj)
{
    u_char  *next;
    p = ngx_copy_fix(p, "{\"time\":");
    p = ngx_sprintf(p, "%i", (ngx_int_t) (ngx_current_msec - obj->start_msec));
    p = ngx_copy_fix(p, ",\"connection\":");
    p = ngx_sprintf(p, "%uA", (ngx_atomic_uint_t) obj->input.connection);
    p = ngx_copy_fix(p, ",\"remote_addr\":\"");
    p = (u_char *) ngx_escape_json(p, obj->input.remote_addr.data,
        obj->input.remote_addr.len);
    p = ngx_copy_fix(p, "\",\"opaque\":\"");
    p = ngx_block_str_write(p, &obj->opaque);
    p = ngx_copy_fix(p, "\",");
    next = ngx_live_core_json_write(p, obj, obj->channel,
        NGX_LIVE_JSON_CTX_TRACK);
    p = next == p ? p - 1 : next;
    *p++ = '}';

    return p;
}

size_t
ngx_live_tracks_json_get_size(ngx_live_channel_t *obj)
{
    ngx_queue_t  *q;
    size_t  result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&obj->tracks_queue);
        q != ngx_queue_sentinel(&obj->tracks_queue);
        q = ngx_queue_next(q))
    {
        ngx_live_track_t *cur = ngx_queue_data(q, ngx_live_track_t, queue);
        result += cur->sn.str.len + ngx_escape_json(NULL, cur->sn.str.data,
            cur->sn.str.len);
        result += ngx_live_track_json_get_size(cur) + sizeof(",\"\":") - 1;
    }

    return result;
}

u_char *
ngx_live_tracks_json_write(u_char *p, ngx_live_channel_t *obj)
{
    ngx_queue_t  *q;
    *p++ = '{';

    for (q = ngx_queue_head(&obj->tracks_queue);
        q != ngx_queue_sentinel(&obj->tracks_queue);
        q = ngx_queue_next(q))
    {
        ngx_live_track_t *cur = ngx_queue_data(q, ngx_live_track_t, queue);

        if (q != ngx_queue_head(&obj->tracks_queue))
        {
            *p++ = ',';
        }
        *p++ = '"';
        p = (u_char *) ngx_escape_json(p, cur->sn.str.data, cur->sn.str.len);
        *p++ = '"';
        *p++ = ':';
        p = ngx_live_track_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}

static size_t
ngx_live_variant_json_get_size(ngx_live_variant_t *obj)
{
    size_t  result =
        sizeof("{\"track_ids\":{") - 1 +
            ngx_live_variant_json_track_ids_get_size(obj) +
        sizeof("},\"opaque\":\"") - 1 + obj->opaque.len +
        sizeof("\",\"label\":\"") - 1 + obj->label.len + ngx_escape_json(NULL,
            obj->label.data, obj->label.len) +
        sizeof("\",\"lang\":\"") - 1 + obj->lang.len + ngx_escape_json(NULL,
            obj->lang.data, obj->lang.len) +
        sizeof("\",\"role\":\"") - 1 +
            ngx_live_variant_role_names[obj->role].len +
        sizeof("\",\"is_default\":") - 1 + sizeof("false") - 1 +
        sizeof("}") - 1;

    return result;
}

static u_char *
ngx_live_variant_json_write(u_char *p, ngx_live_variant_t *obj)
{
    p = ngx_copy_fix(p, "{\"track_ids\":{");
    p = ngx_live_variant_json_track_ids_write(p, obj);
    p = ngx_copy_fix(p, "},\"opaque\":\"");
    p = ngx_block_str_write(p, &obj->opaque);
    p = ngx_copy_fix(p, "\",\"label\":\"");
    p = (u_char *) ngx_escape_json(p, obj->label.data, obj->label.len);
    p = ngx_copy_fix(p, "\",\"lang\":\"");
    p = (u_char *) ngx_escape_json(p, obj->lang.data, obj->lang.len);
    p = ngx_copy_fix(p, "\",\"role\":\"");
    p = ngx_sprintf(p, "%V", &ngx_live_variant_role_names[obj->role]);
    p = ngx_copy_fix(p, "\",\"is_default\":");
    if (obj->is_default) {
        p = ngx_copy_fix(p, "true");
    } else {
        p = ngx_copy_fix(p, "false");
    }
    *p++ = '}';

    return p;
}

size_t
ngx_live_variants_json_get_size(ngx_live_channel_t *obj)
{
    ngx_queue_t  *q;
    size_t  result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&obj->variants_queue);
        q != ngx_queue_sentinel(&obj->variants_queue);
        q = ngx_queue_next(q))
    {
        ngx_live_variant_t *cur = ngx_queue_data(q, ngx_live_variant_t, queue);
        result += cur->sn.str.len + ngx_escape_json(NULL, cur->sn.str.data,
            cur->sn.str.len);
        result += ngx_live_variant_json_get_size(cur) + sizeof(",\"\":") - 1;
    }

    return result;
}

u_char *
ngx_live_variants_json_write(u_char *p, ngx_live_channel_t *obj)
{
    ngx_queue_t  *q;
    *p++ = '{';

    for (q = ngx_queue_head(&obj->variants_queue);
        q != ngx_queue_sentinel(&obj->variants_queue);
        q = ngx_queue_next(q))
    {
        ngx_live_variant_t *cur = ngx_queue_data(q, ngx_live_variant_t, queue);

        if (q != ngx_queue_head(&obj->variants_queue))
        {
            *p++ = ',';
        }
        *p++ = '"';
        p = (u_char *) ngx_escape_json(p, cur->sn.str.data, cur->sn.str.len);
        *p++ = '"';
        *p++ = ':';
        p = ngx_live_variant_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}

size_t
ngx_live_channel_json_get_size(ngx_live_channel_t *obj)
{
    ngx_live_core_preset_conf_t *cpcf = ngx_live_get_module_preset_conf(obj,
        ngx_live_core_module);
    size_t  result =
        sizeof("{\"opaque\":\"") - 1 + obj->opaque.len +
        sizeof("\",\"preset_name\":\"") - 1 + cpcf->name.len +
            ngx_escape_json(NULL, cpcf->name.data, cpcf->name.len) +
        sizeof("\",\"mem_left\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"mem_limit\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"mem_blocks\":") - 1 +
            ngx_block_pool_auto_json_get_size(obj->block_pool,
            NGX_LIVE_BP_COUNT, 0) +
        sizeof(",\"tracks\":") - 1 + ngx_live_tracks_json_get_size(obj) +
        sizeof(",\"variants\":") - 1 + ngx_live_variants_json_get_size(obj) +
        sizeof(",") - 1 + ngx_live_core_json_get_size(obj, obj,
            NGX_LIVE_JSON_CTX_CHANNEL) +
        sizeof("}") - 1;

    return result;
}

u_char *
ngx_live_channel_json_write(u_char *p, ngx_live_channel_t *obj)
{
    ngx_live_core_preset_conf_t *cpcf = ngx_live_get_module_preset_conf(obj,
        ngx_live_core_module);
    u_char  *next;
    p = ngx_copy_fix(p, "{\"opaque\":\"");
    p = ngx_block_str_write(p, &obj->opaque);
    p = ngx_copy_fix(p, "\",\"preset_name\":\"");
    p = (u_char *) ngx_escape_json(p, cpcf->name.data, cpcf->name.len);
    p = ngx_copy_fix(p, "\",\"mem_left\":");
    p = ngx_sprintf(p, "%uz", (size_t) obj->mem_left);
    p = ngx_copy_fix(p, ",\"mem_limit\":");
    p = ngx_sprintf(p, "%uz", (size_t) cpcf->mem_limit);
    p = ngx_copy_fix(p, ",\"mem_blocks\":");
    p = ngx_block_pool_auto_json_write(p, obj->block_pool, NGX_LIVE_BP_COUNT,
        0);
    p = ngx_copy_fix(p, ",\"tracks\":");
    p = ngx_live_tracks_json_write(p, obj);
    p = ngx_copy_fix(p, ",\"variants\":");
    p = ngx_live_variants_json_write(p, obj);
    *p++ = ',';
    next = ngx_live_core_json_write(p, obj, obj, NGX_LIVE_JSON_CTX_CHANNEL);
    p = next == p ? p - 1 : next;
    *p++ = '}';

    return p;
}

size_t
ngx_live_channels_json_get_size(void *obj)
{
    ngx_queue_t  *q;
    size_t  result =
        sizeof("{") - 1 +
        sizeof("}") - 1;

    for (q = ngx_queue_head(&ngx_live_channels.queue);
        q != ngx_queue_sentinel(&ngx_live_channels.queue);
        q = ngx_queue_next(q))
    {
        ngx_live_channel_t *cur = ngx_queue_data(q, ngx_live_channel_t, queue);
        result += cur->sn.str.len + ngx_escape_json(NULL, cur->sn.str.data,
            cur->sn.str.len);
        result += ngx_live_channel_json_get_size(cur) + sizeof(",\"\":") - 1;
    }

    return result;
}

u_char *
ngx_live_channels_json_write(u_char *p, void *obj)
{
    ngx_queue_t  *q;
    *p++ = '{';

    for (q = ngx_queue_head(&ngx_live_channels.queue);
        q != ngx_queue_sentinel(&ngx_live_channels.queue);
        q = ngx_queue_next(q))
    {
        ngx_live_channel_t *cur = ngx_queue_data(q, ngx_live_channel_t, queue);

        if (q != ngx_queue_head(&ngx_live_channels.queue))
        {
            *p++ = ',';
        }
        *p++ = '"';
        p = (u_char *) ngx_escape_json(p, cur->sn.str.data, cur->sn.str.len);
        *p++ = '"';
        *p++ = ':';
        p = ngx_live_channel_json_write(p, cur);
    }

    *p++ = '}';

    return p;
}