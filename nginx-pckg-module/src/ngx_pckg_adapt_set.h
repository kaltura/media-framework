#ifndef _NGX_PCKG_ADAPT_SET_H_INCLUDED_
#define _NGX_PCKG_ADAPT_SET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_pckg_ksmp.h"


typedef struct {
    ngx_queue_t          queue;
    ngx_array_t          variants;      /* ngx_pckg_variant_t * */
    ngx_pckg_variant_t  *variant;
    media_info_t        *media_info;
} ngx_pckg_adapt_set_t;


typedef struct {
    ngx_pckg_channel_t  *channel;
    uint32_t             skip_media_types[ngx_ksmp_variant_role_count];
    ngx_queue_t          queue[KMP_MEDIA_COUNT];  /* ngx_pckg_adapt_set_t */
} ngx_pckg_adapt_sets_t;


ngx_int_t ngx_pckg_adapt_sets_init(ngx_pckg_adapt_sets_t *sets);

size_t ngx_pckg_adapt_sets_get_variant_ids_size(ngx_pckg_adapt_sets_t *sets);

#endif /* _NGX_PCKG_ADAPT_SET_H_INCLUDED_ */
