#ifndef _NGX_PCKG_SEGMENT_INFO_H_INCLUDED_
#define _NGX_PCKG_SEGMENT_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"


typedef struct {
    ngx_ksmp_segment_info_elt_t   *cur;
    ngx_ksmp_segment_info_elt_t   *last;
    uint32_t                       bitrate;
} ngx_pckg_segment_info_iter_t;


typedef struct {
    ngx_uint_t                     track_count;
    media_bitrate_estimator_t     *estimators;
    ngx_pckg_segment_info_iter_t   iters[1];     /* must be last */
} ngx_pckg_segment_info_ctx_t;


void ngx_pckg_segment_info_iter_reset(ngx_pckg_segment_info_iter_t *iter,
    ngx_pckg_track_t *track);

uint32_t ngx_pckg_segment_info_iter_get(ngx_pckg_segment_info_iter_t *iter,
    uint32_t segment_index);

ngx_flag_t ngx_pckg_segment_info_iter_has_bitrate(
    ngx_pckg_segment_info_iter_t *iter);

uint32_t ngx_pckg_segment_info_iter_gap_count(
    ngx_pckg_segment_info_iter_t *iter, uint32_t first_index,
    uint32_t last_index);


ngx_pckg_segment_info_ctx_t *ngx_pckg_segment_info_create(
    ngx_pckg_channel_t *channel, media_bitrate_estimator_t *estimators);

void ngx_pckg_segment_info_reset(ngx_pckg_segment_info_ctx_t *ctx,
    ngx_pckg_channel_t *channel);

uint32_t ngx_pckg_segment_info_get(ngx_pckg_segment_info_ctx_t *ctx,
    uint32_t segment_index, uint32_t duration);

ngx_flag_t ngx_pckg_segment_info_has_bitrate(ngx_pckg_segment_info_ctx_t *ctx);

uint32_t ngx_pckg_segment_info_min_gap_count(ngx_pckg_segment_info_ctx_t *ctx,
    uint32_t first_index, uint32_t last_index);

#endif /* _NGX_PCKG_SEGMENT_INFO_H_INCLUDED_ */
