#ifndef _NGX_PCKG_KSMP_H_INCLUDED_
#define _NGX_PCKG_KSMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_persist.h>
#include <ngx_ksmp.h>
#include "media/media_format.h"


#define NGX_PCKG_PERSIST_TYPE_MEDIA          (0x73746773)    /* sgts */

#define NGX_INT32_HEX_LEN  (8)


typedef struct ngx_pckg_channel_s     ngx_pckg_channel_t;
typedef struct ngx_pckg_track_s       ngx_pckg_track_t;
typedef struct ngx_pckg_timeline_s    ngx_pckg_timeline_t;
typedef struct ngx_pckg_media_info_s  ngx_pckg_media_info_t;


#include "ngx_pckg_media_info.h"


typedef struct {
    ngx_str_t                      channel_id;
    ngx_str_t                      timeline_id;
    ngx_str_t                      variant_ids;
    uint32_t                       media_type_mask;
    uint32_t                       segment_index;
    int64_t                        time;
    uint32_t                       flags;
} ngx_pckg_ksmp_req_t;


typedef struct {
    ngx_pckg_timeline_t           *timeline;
    ngx_ksmp_period_header_t      *header;
    ngx_ksmp_segment_repeat_t     *elts;
    ngx_uint_t                     nelts;
    ngx_uint_t                     segment_count;
    uint64_t                       duration;
} ngx_pckg_period_t;


struct ngx_pckg_timeline_s {
    ngx_pckg_channel_t            *channel;
    ngx_str_t                      id;
    ngx_ksmp_timeline_header_t    *header;
    ngx_array_t                    periods;     /* ngx_pckg_period_t */
    ngx_uint_t                     segment_count;
    uint64_t                       duration;
    int64_t                        last_time;
    uint32_t                       last_segment;
};


typedef struct {
    ngx_ksmp_segment_info_elt_t   *elts;
    ngx_uint_t                     nelts;
} ngx_pckg_segment_info_t;


typedef struct {
    ngx_ksmp_segment_header_t     *header;
    ngx_ksmp_frame_t              *frames;
    ngx_str_t                      media;
} ngx_pckg_segment_t;


struct ngx_pckg_media_info_s {
    ngx_ksmp_media_info_header_t  *header;
    kmp_media_info_t              *kmp_media_info;
    media_info_t                   media_info;
    ngx_str_t                      extra_data;
    u_char                         codec_name[MAX_CODEC_NAME_SIZE];
};


struct ngx_pckg_track_s {
    ngx_pckg_channel_t            *channel;
    ngx_ksmp_track_header_t       *header;
    ngx_array_t                    media_info;  /* ngx_pckg_media_info_t */
    ngx_pckg_media_info_t         *last_media_info;
    ngx_pckg_media_info_iter_t     media_info_iter;
    ngx_pckg_segment_info_t        segment_info;
    ngx_pckg_segment_t            *segment;
};


typedef struct {
    ngx_str_t                      id;
    ngx_ksmp_variant_t            *header;
    ngx_str_t                      label;
    ngx_str_t                      lang;
    ngx_pckg_track_t              *tracks[KMP_MEDIA_COUNT];
} ngx_pckg_variant_t;


typedef struct {
    ngx_str_node_t                 sn;      /* must be first */
    ngx_str_t                      value;
} ngx_pckg_dynamic_var_t;


typedef struct {
    ngx_rbtree_t                   rbtree;
    ngx_rbtree_node_t              sentinel;
} ngx_pckg_dynamic_vars_t;


struct ngx_pckg_channel_s {
    ngx_pool_t                    *pool;
    ngx_log_t                     *log;
    ngx_persist_conf_t            *persist;
    uint32_t                       format;

    uint32_t                       flags;
    uint32_t                       track_id;        /* sgts only */

    ngx_str_t                      id;
    ngx_ksmp_channel_header_t     *header;
    ngx_pckg_timeline_t            timeline;
    ngx_array_t                    variants;    /* ngx_pckg_variant_t */
    ngx_array_t                    tracks;      /* ngx_pckg_track_t */
    ngx_pckg_track_t             **sorted_tracks;
    ngx_ksmp_segment_index_t      *segment_index;
    ngx_pckg_dynamic_vars_t        vars;
    uint32_t                       media_types;

    uint32_t                       err_code;
    ngx_str_t                      err_message;
};


ngx_persist_conf_t *ngx_pckg_ksmp_conf_create(ngx_conf_t *cf);

ngx_int_t ngx_pckg_ksmp_create_request(ngx_pool_t *pool,
    ngx_pckg_ksmp_req_t *req, ngx_str_t *result);

ngx_int_t ngx_pckg_ksmp_parse(ngx_pckg_channel_t *channel, ngx_str_t *buf,
    size_t max_size);

#endif /* _NGX_PCKG_KSMP_H_INCLUDED_ */
