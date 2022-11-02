#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_adapt_set.h"
#include "ngx_pckg_utils.h"


static ngx_flag_t
ngx_pckg_adapt_set_has_track(ngx_pckg_adapt_set_t *set,
    ngx_pckg_track_t *track)
{
    uint32_t              media_type;
    ngx_pckg_variant_t  **cur;
    ngx_pckg_variant_t  **last;

    media_type = track->header.media_type;

    cur = set->variants.elts;
    for (last = cur + set->variants.nelts; cur < last; cur++) {
        if ((*cur)->tracks[media_type] == track) {
            return 1;
        }
    }

    return 0;
}


static ngx_pckg_adapt_set_t *
ngx_pckg_adapt_set_get(ngx_pckg_adapt_sets_t *sets,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_queue_t           *q, *queue;
    media_info_t          *media_info;
    ngx_pckg_track_t      *track;
    ngx_pckg_adapt_set_t  *set;

    track = variant->tracks[media_type];
    media_info = &track->last_media_info->media_info;
    queue = &sets->queue[media_type];

    for (q = ngx_queue_head(queue);
        q != ngx_queue_sentinel(queue);
        q = ngx_queue_next(q))
    {
        set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

        if (set->media_info->codec_id != media_info->codec_id) {
            continue;
        }

        if (set->variant->label.len != variant->label.len ||
            ngx_memcmp(set->variant->label.data, variant->label.data,
                       variant->label.len) != 0)
        {
            continue;
        }

        return set;
    }

    return NULL;
}


static ngx_pckg_adapt_set_t *
ngx_pckg_adapt_set_add(ngx_pckg_adapt_sets_t *sets,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_pckg_track_t      *track;
    ngx_pckg_channel_t    *channel;
    ngx_pckg_adapt_set_t  *set;

    channel = sets->channel;

    set = ngx_palloc(channel->pool, sizeof(*set));
    if (set == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_adapt_set_add: alloc failed");
        return NULL;
    }

    if (ngx_array_init(&set->variants, channel->pool, 1,
                       sizeof(ngx_pckg_variant_t *))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_adapt_set_add: array init failed");
        return NULL;
    }

    track = variant->tracks[media_type];

    set->variant = variant;
    set->media_info = &track->last_media_info->media_info;

    ngx_queue_insert_tail(&sets->queue[media_type], &set->queue);

    return set;
}


static ngx_int_t
ngx_pckg_adapt_set_add_track(ngx_pckg_adapt_sets_t *sets,
    ngx_pckg_variant_t *variant, uint32_t media_type)
{
    ngx_pckg_variant_t    **pvariant;
    ngx_pckg_adapt_set_t   *set;

    if (sets->skip_media_types[variant->header.role] & (1 << media_type)) {
        return NGX_OK;
    }

    set = ngx_pckg_adapt_set_get(sets, variant, media_type);
    if (set == NULL) {
        set = ngx_pckg_adapt_set_add(sets, variant, media_type);
        if (set == NULL) {
            return NGX_ERROR;
        }

    } else {
        if (ngx_pckg_adapt_set_has_track(set, variant->tracks[media_type])) {
            return NGX_OK;
        }
    }

    pvariant = ngx_array_push(&set->variants);
    if (pvariant == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, sets->channel->log, 0,
            "ngx_pckg_adapt_set_add_track: push failed");
        return NGX_ERROR;
    }

    *pvariant = variant;

    return NGX_OK;
}


static void
ngx_pckg_adapt_set_get_role_media_types(ngx_pckg_channel_t *channel,
    uint32_t *role_media_types)
{
    uint32_t            *dest;
    uint32_t             media_type;
    ngx_pckg_variant_t  *cur;
    ngx_pckg_variant_t  *last;

    ngx_memzero(role_media_types,
        sizeof(role_media_types[0]) * ngx_ksmp_variant_role_count);

    cur = channel->variants.elts;
    for (last = cur + channel->variants.nelts; cur < last; cur++) {

        dest = &role_media_types[cur->header.role];

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
            if (cur->tracks[media_type] != NULL) {
                *dest |= 1 << media_type;
            }
        }
    }
}


ngx_int_t
ngx_pckg_adapt_sets_init(ngx_pckg_adapt_sets_t *sets)
{
    uint32_t             media_type;
    uint32_t             role_media_types[ngx_ksmp_variant_role_count];
    ngx_pckg_track_t    *track;
    ngx_pckg_channel_t  *channel;
    ngx_pckg_variant_t  *cur;
    ngx_pckg_variant_t  *last;

    channel = sets->channel;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        ngx_queue_init(&sets->queue[media_type]);
    }

    /* skip tracks of variants with 'main' role that have an alternate */
    ngx_pckg_adapt_set_get_role_media_types(channel, role_media_types);

    sets->skip_media_types[ngx_ksmp_variant_role_main] =
        role_media_types[ngx_ksmp_variant_role_alternate];
    sets->skip_media_types[ngx_ksmp_variant_role_alternate] = 0;


    cur = channel->variants.elts;
    for (last = cur + channel->variants.nelts; cur < last; cur++) {

        for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

            track = cur->tracks[media_type];
            if (track == NULL) {
                continue;
            }

            if (ngx_pckg_adapt_set_add_track(sets, cur, media_type)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static size_t
ngx_pckg_adapt_set_get_selectors_size(ngx_pckg_adapt_set_t *set)
{
    size_t                size;
    ngx_uint_t            i, n;
    ngx_pckg_variant_t  **variants;

    n = set->variants.nelts;
    variants = set->variants.elts;

    size = 0;
    for (i = 0; i < n; i++) {
        size += ngx_pckg_selector_get_size(&variants[i]->id);
    }

    return size;
}


size_t
ngx_pckg_adapt_sets_get_selectors_size(ngx_pckg_adapt_sets_t *sets)
{
    size_t                 size;
    uint32_t               media_type;
    ngx_queue_t           *q;
    ngx_pckg_adapt_set_t  *set;

    size = 0;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        for (q = ngx_queue_head(&sets->queue[media_type]);
            q != ngx_queue_sentinel(&sets->queue[media_type]);
            q = ngx_queue_next(q))
        {
            set = ngx_queue_data(q, ngx_pckg_adapt_set_t, queue);

            size += ngx_pckg_adapt_set_get_selectors_size(set);
        }
    }

    return size;
}