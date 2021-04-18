#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_media_info.h"


void
ngx_pckg_media_info_iter_reset(ngx_pckg_media_info_iter_t *iter,
    ngx_pckg_track_t *track)
{
    iter->cur = track->media_info.elts;
    iter->last = iter->cur + track->media_info.nelts;
}


uint32_t
ngx_pckg_media_info_iter_get(ngx_pckg_media_info_iter_t *iter,
    uint32_t segment_index, media_info_t **media_info)
{
    if (iter->cur >= iter->last) {
        return NGX_KSMP_INVALID_SEGMENT_INDEX;
    }

    while (iter->cur + 1 < iter->last &&
        iter->cur[1].header->start_segment_index <= segment_index)
    {
        iter->cur++;
    }

    if (segment_index >= iter->cur->header->start_segment_index) {
        *media_info = &iter->cur->media_info;
    }

    return iter->cur->header->start_segment_index;
}


ngx_pckg_media_info_ctx_t *
ngx_pckg_media_info_create(ngx_pckg_channel_t *channel)
{
    ngx_pckg_media_info_ctx_t  *ctx;

    ctx = ngx_palloc(channel->pool,
        offsetof(ngx_pckg_media_info_ctx_t, iters)
        + sizeof(ctx->iters[0]) * channel->tracks.nelts);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_media_info_create: alloc failed (1)");
        return NULL;
    }

    ctx->media_infos = ngx_palloc(channel->pool,
        sizeof(ctx->media_infos[0]) * channel->tracks.nelts);
    if (ctx->media_infos == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_media_info_create: alloc failed (2)");
        return NULL;
    }

    ctx->track_count = channel->tracks.nelts;

    ngx_pckg_media_info_reset(ctx, channel);

    return ctx;
}

void
ngx_pckg_media_info_reset(ngx_pckg_media_info_ctx_t *ctx,
    ngx_pckg_channel_t *channel)
{
    ngx_uint_t                   i, n;
    ngx_pckg_track_t            *tracks;
    ngx_pckg_media_info_iter_t  *cur;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;

    for (i = 0, cur = ctx->iters; i < n; i++, cur++) {
        ngx_pckg_media_info_iter_reset(cur, &tracks[i]);
    }

    ngx_memzero(ctx->media_infos,
        sizeof(ctx->media_infos[0]) * channel->tracks.nelts);
}


void
ngx_pckg_media_info_get(ngx_pckg_media_info_ctx_t *ctx, uint32_t segment_index,
    uint32_t *map_index)
{
    uint32_t  i;
    uint32_t  cur_index;

    *map_index = NGX_KSMP_INVALID_SEGMENT_INDEX;

    for (i = 0; i < ctx->track_count; i++) {

        cur_index = ngx_pckg_media_info_iter_get(&ctx->iters[i],
            segment_index, &ctx->media_infos[i]);

        if (*map_index > segment_index) {
            /* take the min of future segment indexes */
            if (cur_index < *map_index) {
                *map_index = cur_index;
            }

        } else if (cur_index > *map_index && cur_index <= segment_index) {
            /* take the max of past segment indexes */
            *map_index = cur_index;
        }
    }
}
