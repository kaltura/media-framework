#ifndef _NGX_PCKG_MEDIA_INFO_H_INCLUDED_
#define _NGX_PCKG_MEDIA_INFO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"


typedef struct {
    ngx_pckg_media_info_t        *cur;
    ngx_pckg_media_info_t        *last;
} ngx_pckg_media_info_iter_t;


typedef struct {
    uint32_t                      track_count;
    media_info_t                **media_infos;
    ngx_pckg_media_info_iter_t    iters[1];     /* must be last */
} ngx_pckg_media_info_ctx_t;


void ngx_pckg_media_info_iter_reset(ngx_pckg_media_info_iter_t *iter,
    ngx_pckg_track_t *track);

uint32_t ngx_pckg_media_info_iter_get(ngx_pckg_media_info_iter_t *iter,
    uint32_t segment_index, media_info_t **media_info);


ngx_pckg_media_info_ctx_t *ngx_pckg_media_info_create(
    ngx_pckg_channel_t *channel);

void ngx_pckg_media_info_reset(ngx_pckg_media_info_ctx_t *ctx,
    ngx_pckg_channel_t *channel);

void ngx_pckg_media_info_get(ngx_pckg_media_info_ctx_t *ctx,
    uint32_t segment_index, uint32_t *map_index);

#endif /* _NGX_PCKG_MEDIA_INFO_H_INCLUDED_ */
