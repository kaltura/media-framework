#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_media_group.h"


static ngx_flag_t
ngx_pckg_media_group_has_label(ngx_pckg_media_group_t *group, ngx_str_t *label)
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


static ngx_pckg_media_group_t *
ngx_pckg_media_group_get(ngx_pckg_media_groups_t *groups,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_queue_t             *q, *queue;
    media_info_t            *media_info;
    ngx_pckg_track_t        *track;
    ngx_pckg_media_group_t  *group;

    track = variant->tracks[media_type];
    media_info = &track->last_media_info->media_info;

    queue = &groups->queue[media_type];

    for (q = ngx_queue_head(queue);
        q != ngx_queue_sentinel(queue);
        q = ngx_queue_next(q))
    {
        group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);

        if (group->media_info->codec_id != media_info->codec_id) {
            continue;
        }

        return group;
    }

    return NULL;
}


static ngx_pckg_media_group_t *
ngx_pckg_media_group_add(ngx_pckg_media_groups_t *groups,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_pckg_track_t        *track;
    ngx_pckg_channel_t      *channel;
    ngx_pckg_media_group_t  *group;

    channel = groups->channel;

    group = ngx_palloc(channel->pool, sizeof(*group));
    if (group == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_media_group_add: alloc failed");
        return NULL;
    }

    if (ngx_array_init(&group->variants, channel->pool, 1,
                       sizeof(ngx_pckg_variant_t *))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_media_group_add: array init failed");
        return NULL;
    }

    track = variant->tracks[media_type];

    group->variant = variant;
    group->media_info = &track->last_media_info->media_info;

    ngx_queue_insert_tail(&groups->queue[media_type], &group->queue);
    groups->count[media_type]++;

    return group;
}


static ngx_int_t
ngx_pckg_media_group_add_track(ngx_pckg_media_groups_t *groups,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_pckg_variant_t      **pvariant;
    ngx_pckg_media_group_t   *group;

    group = ngx_pckg_media_group_get(groups, variant, media_type);
    if (group == NULL) {
        group = ngx_pckg_media_group_add(groups, variant, media_type);
        if (group == NULL) {
            return NGX_ERROR;
        }

    } else {
        if (ngx_pckg_media_group_has_label(group, &variant->label)) {
            return NGX_OK;
        }
    }

    pvariant = ngx_array_push(&group->variants);
    if (pvariant == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, groups->channel->log, 0,
            "ngx_pckg_media_group_add_track: push failed");
        return NGX_ERROR;
    }

    *pvariant = variant;

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_media_groups_add_variants(ngx_pckg_media_groups_t *groups)
{
    uint32_t             media_type;
    ngx_pckg_track_t    *track;
    ngx_pckg_stream_t   *stream;
    ngx_pckg_channel_t  *channel;
    ngx_pckg_variant_t  *cur;
    ngx_pckg_variant_t  *last;

    channel = groups->channel;

    cur = channel->variants.elts;
    for (last = cur + channel->variants.nelts; cur < last; cur++) {

        if (cur->header.role == ngx_ksmp_variant_role_main) {
            stream = ngx_array_push(&groups->streams);
            if (stream == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
                    "ngx_pckg_media_groups_add_variants: push failed");
                return NGX_ERROR;
            }

            stream->variant = cur;
            ngx_memzero(stream->groups, sizeof(stream->groups));

            if (groups->flags & NGX_PCKG_MEDIA_GROUP_MUX_SEGMENTS) {
                stream->media_types = channel->media_types;
                continue;
            }

            /* take only the first track, add the rest to media groups */

            for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
                track = cur->tracks[media_type];
                if (track != NULL) {
                    break;
                }
            }

            stream->media_types = 1 << media_type;
            media_type++;

        } else {
            /* Note: alternate video not supported, starting from audio */
            media_type = KMP_MEDIA_AUDIO;
        }

        for (; media_type < KMP_MEDIA_COUNT; media_type++) {

            track = cur->tracks[media_type];
            if (track == NULL) {
                continue;
            }

            if (ngx_pckg_media_group_add_track(groups, cur, media_type)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_media_groups_derive_streams(ngx_pckg_media_groups_t *groups,
    uint32_t media_type)
{
    ngx_queue_t              *q;
    ngx_pckg_stream_t        *cur;
    ngx_pckg_variant_t      **variants;
    ngx_pckg_media_group_t   *group;

    cur = ngx_array_push_n(&groups->streams, groups->count[media_type]);
    if (cur == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, groups->channel->log, 0,
            "ngx_pckg_media_groups_derive_streams: push failed");
        return NGX_ERROR;
    }

    /* create a stream from the first variant in each group */

    for (q = ngx_queue_head(&groups->queue[media_type]);
        q != ngx_queue_sentinel(&groups->queue[media_type]);
        cur++)
    {
        group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);
        q = ngx_queue_next(q);      /* group may be removed */

        variants = group->variants.elts;
        cur->variant = variants[0];
        cur->media_types = 1 << media_type;
        ngx_memzero(cur->groups, sizeof(cur->groups));

        if (group->variants.nelts > 1) {
            cur->groups[media_type] = group;

        } else {
            ngx_queue_remove(&group->queue);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_pckg_media_groups_assign_groups(ngx_pckg_media_groups_t *groups,
    uint32_t media_type)
{
    ngx_uint_t               i, n;
    ngx_queue_t             *q;
    ngx_pckg_stream_t       *streams, *cur;
    ngx_pckg_media_group_t  *group;

    if (groups->count[media_type] <= 0) {
        return NGX_OK;
    }

    /* duplicate the streams, once for each group */

    n = groups->streams.nelts;
    if (ngx_array_push_n(&groups->streams,
                         n * (groups->count[media_type] - 1))
        == NULL)
    {
        return NGX_ERROR;
    }

    cur = streams = groups->streams.elts;

    for (q = ngx_queue_head(&groups->queue[media_type]);
        q != ngx_queue_sentinel(&groups->queue[media_type]);
        q = ngx_queue_next(q))
    {
        group = ngx_queue_data(q, ngx_pckg_media_group_t, queue);

        for (i = 0; i < n; i++, cur++) {
            cur->variant = streams[i].variant;
            cur->media_types = streams[i].media_types;
            cur->groups[media_type] = group;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_pckg_media_groups_init(ngx_pckg_media_groups_t *groups)
{
    uint32_t             media_type;
    ngx_pckg_channel_t  *channel;

    channel = groups->channel;

    if (ngx_array_init(&groups->streams, channel->pool, 1,
                       sizeof(ngx_pckg_stream_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_media_groups_init: array init failed");
        return NGX_ERROR;
    }

    ngx_memzero(groups->count, sizeof(groups->count));

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        ngx_queue_init(&groups->queue[media_type]);
    }

    if (ngx_pckg_media_groups_add_variants(groups) != NGX_OK) {
        return NGX_ERROR;
    }

    if (groups->streams.nelts <= 0) {
        return ngx_pckg_media_groups_derive_streams(groups, KMP_MEDIA_AUDIO);
    }

    if (ngx_pckg_media_groups_assign_groups(groups, KMP_MEDIA_AUDIO) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
