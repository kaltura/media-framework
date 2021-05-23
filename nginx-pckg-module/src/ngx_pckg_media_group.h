#ifndef _NGX_PCKG_MEDIA_GROUP_H_INCLUDED_
#define _NGX_PCKG_MEDIA_GROUP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"


#define NGX_PCKG_MEDIA_GROUP_MUX_SEGMENTS  (0x1)


typedef struct {
    ngx_queue_t              queue;
    ngx_array_t              variants;  /* ngx_pckg_variant_t * */
    ngx_pckg_variant_t      *variant;
    media_info_t            *media_info;
} ngx_pckg_media_group_t;


typedef struct {
    ngx_pckg_variant_t      *variant;
    uint32_t                 media_types;
    ngx_pckg_media_group_t  *groups[KMP_MEDIA_COUNT];
} ngx_pckg_stream_t;


typedef struct {
    /* in */
    ngx_pckg_channel_t      *channel;
    uint32_t                 flags;

    /* out */
    ngx_array_t              streams;   /* ngx_pckg_stream_t */
    ngx_queue_t              queue[KMP_MEDIA_COUNT];
    uint32_t                 count[KMP_MEDIA_COUNT];
} ngx_pckg_media_groups_t;


ngx_int_t ngx_pckg_media_groups_init(ngx_pckg_media_groups_t *groups);

#endif /* _NGX_PCKG_MEDIA_GROUP_H_INCLUDED_ */
