#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_segment_info.h"


void
ngx_pckg_segment_info_iter_reset(ngx_pckg_segment_info_iter_t *iter,
    ngx_pckg_track_t *track)
{
    iter->cur = track->segment_info.elts;
    iter->last = iter->cur + track->segment_info.nelts;
    iter->bitrate = NGX_KSMP_SEGMENT_NO_BITRATE;
}


uint32_t
ngx_pckg_segment_info_iter_get(ngx_pckg_segment_info_iter_t *iter,
    uint32_t segment_index)
{
    while (iter->cur < iter->last && iter->cur->index <= segment_index) {
        iter->bitrate = iter->cur->bitrate;
        iter->cur++;
    }

    return iter->bitrate;
}


ngx_flag_t
ngx_pckg_segment_info_iter_has_bitrate(ngx_pckg_segment_info_iter_t *iter)
{
    ngx_ksmp_segment_info_elt_t  *cur;

    for (cur = iter->cur; cur < iter->last; cur++) {
        if (cur->bitrate != 0 && cur->bitrate != NGX_KSMP_SEGMENT_NO_BITRATE) {
            return 1;
        }
    }

    return 0;
}


uint32_t
ngx_pckg_segment_info_iter_gap_count(ngx_pckg_segment_info_iter_t *iter,
    uint32_t first_index, uint32_t last_index)
{
    uint32_t  start;
    uint32_t  gap_count;

    start = first_index;
    gap_count = 0;

    while (iter->cur < iter->last && iter->cur->index <= start) {
        iter->bitrate = iter->cur->bitrate;
        iter->cur++;
    }

    for ( ;; ) {

        if (iter->cur > iter->last || iter->cur->index >= last_index) {
            if (iter->bitrate == 0) {
                gap_count += last_index - start;
            }
            break;
        }

        if (iter->bitrate == 0) {
            gap_count += iter->cur->index - start;
        }

        iter->bitrate = iter->cur->bitrate;
        start = iter->cur->index;

        iter->cur++;
    }

    return gap_count;
}


ngx_pckg_segment_info_ctx_t *
ngx_pckg_segment_info_create(ngx_pckg_channel_t *channel,
    media_bitrate_estimator_t *estimators)
{
    ngx_pckg_segment_info_ctx_t  *ctx;

    ctx = ngx_palloc(channel->pool,
        offsetof(ngx_pckg_segment_info_ctx_t, iters)
        + sizeof(ctx->iters[0]) * channel->tracks.nelts);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, channel->log, 0,
            "ngx_pckg_segment_info_create: alloc failed");
        return NULL;
    }

    ctx->track_count = channel->tracks.nelts;
    ctx->estimators = estimators;

    ngx_pckg_segment_info_reset(ctx, channel);

    return ctx;
}


void
ngx_pckg_segment_info_reset(ngx_pckg_segment_info_ctx_t *ctx,
    ngx_pckg_channel_t *channel)
{
    ngx_uint_t                     i, n;
    ngx_pckg_track_t              *tracks;
    ngx_pckg_segment_info_iter_t  *cur;

    tracks = channel->tracks.elts;
    n = channel->tracks.nelts;

    for (i = 0, cur = ctx->iters; i < n; i++, cur++) {
        ngx_pckg_segment_info_iter_reset(cur, &tracks[i]);
    }
}


uint32_t
ngx_pckg_segment_info_get(ngx_pckg_segment_info_ctx_t *ctx,
    uint32_t segment_index, uint32_t duration)
{
    uint32_t                    cur_bitrate;
    uint32_t                    result;
    ngx_uint_t                  i;
    media_bitrate_estimator_t  *est;

    result = 0;
    for (i = 0; i < ctx->track_count; i++) {

        cur_bitrate = ngx_pckg_segment_info_iter_get(&ctx->iters[i],
            segment_index);

        switch (cur_bitrate) {

        case NGX_KSMP_SEGMENT_NO_BITRATE:
            return NGX_KSMP_SEGMENT_NO_BITRATE;

        case 0:
            continue;
        }

        est = &ctx->estimators[i];
        result += media_bitrate_estimate(*est, cur_bitrate, duration);
    }

    return result;
}


ngx_flag_t
ngx_pckg_segment_info_has_bitrate(ngx_pckg_segment_info_ctx_t *ctx)
{
    ngx_uint_t  i;

    for (i = 0; i < ctx->track_count; i++) {
        if (ngx_pckg_segment_info_iter_has_bitrate(&ctx->iters[i])) {
            return 1;
        }
    }

    return 0;
}


uint32_t
ngx_pckg_segment_info_min_gap_count(ngx_pckg_segment_info_ctx_t *ctx,
    uint32_t first_index, uint32_t last_index)
{
    uint32_t    gap_count;
    uint32_t    min_gap_count;
    ngx_uint_t  i;

    min_gap_count = NGX_MAX_UINT32_VALUE;

    for (i = 0; i < ctx->track_count; i++) {

        gap_count = ngx_pckg_segment_info_iter_gap_count(&ctx->iters[i],
            first_index, last_index);

        if (min_gap_count > gap_count) {
            min_gap_count = gap_count;
        }
    }

    return min_gap_count;
}
