#ifndef _NGX_KSMP_H_INCLUDED_
#define _NGX_KSMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_kmp.h"


#define NGX_KSMP_PERSIST_TYPE               (0x76726573)  /* serv */

#define NGX_KSMP_BLOCK_CHANNEL              (0x6c6e6863)  /* chnl */
#define NGX_KSMP_BLOCK_TIMELINE             (0x6e6c6d74)  /* tmln */
#define NGX_KSMP_BLOCK_PERIOD               (0x64727074)  /* tprd */
#define NGX_KSMP_BLOCK_VARIANT              (0x746e7276)  /* vrnt */
#define NGX_KSMP_BLOCK_TRACK                (0x6b617274)  /* trak */
#define NGX_KSMP_BLOCK_MEDIA_INFO_QUEUE     (0x7571696d)  /* miqu */
#define NGX_KSMP_BLOCK_MEDIA_INFO           (0x666e696d)  /* minf */
#define NGX_KSMP_BLOCK_SEGMENT_INFO         (0x666e6773)  /* sgnf */
#define NGX_KSMP_BLOCK_SEGMENT_INDEX        (0x78696773)  /* sgix */
#define NGX_KSMP_BLOCK_SEGMENT              (0x746d6773)  /* sgmt */
#define NGX_KSMP_BLOCK_FRAME_LIST           (0x6e757274)  /* trun */
#define NGX_KSMP_BLOCK_FRAME_DATA           (0x7461646d)  /* mdat */
#define NGX_KSMP_BLOCK_DYNAMIC_VAR          (0x766e7964)  /* dynv */
#define NGX_KSMP_BLOCK_ERROR                (0x72727265)  /* errr */
#define NGX_KSMP_BLOCK_PADDING              (0x65657266)  /* free */


#define NGX_KSMP_FLAG_MEDIA                 (0x00000001)
#define NGX_KSMP_FLAG_TIMELINE              (0x00000002)
#define NGX_KSMP_FLAG_PERIODS               (0x00000004)
#define NGX_KSMP_FLAG_MEDIA_INFO            (0x00000008)
#define NGX_KSMP_FLAG_SEGMENT_INFO          (0x00000010)
#define NGX_KSMP_FLAG_DYNAMIC_VAR           (0x00000020)

#define NGX_KSMP_FLAG_MEDIA_CLOSEST_KEY     (0x00001000)
#define NGX_KSMP_FLAG_MEDIA_MIN_GOP         (0x00002000)

#define NGX_KSMP_FLAG_TIME_START_RELATIVE   (0x00010000)
#define NGX_KSMP_FLAG_TIME_END_RELATIVE     (0x00020000)
#define NGX_KSMP_FLAG_TIME_USE_PERIOD_GAP   (0x00040000)

#define NGX_KSMP_FLAG_ACTIVE_LAST           (0x01000000)
#define NGX_KSMP_FLAG_ACTIVE_ANY            (0x02000000)
#define NGX_KSMP_FLAG_CHECK_EXPIRY          (0x04000000)
#define NGX_KSMP_FLAG_RELATIVE_DTS          (0x08000000)  /* to period start */
#define NGX_KSMP_FLAG_BACK_FILL             (0x10000000)
#define NGX_KSMP_FLAG_LAST_SEGMENT_ONLY     (0x20000000)


#define NGX_KSMP_FLAG_MEDIA_CLIP            (NGX_KSMP_FLAG_MEDIA_CLOSEST_KEY \
                                             | NGX_KSMP_FLAG_MEDIA_MIN_GOP)

#define NGX_KSMP_FLAG_TIME_RELATIVE         (NGX_KSMP_FLAG_TIME_START_RELATIVE \
                                            | NGX_KSMP_FLAG_TIME_END_RELATIVE)

#define NGX_KSMP_INVALID_SEGMENT_INDEX      (NGX_MAX_UINT32_VALUE)
#define NGX_KSMP_INVALID_TIMESTAMP          (LLONG_MAX)

#define NGX_KSMP_SEGMENT_NO_BITRATE         (1)


#define NGX_KSMP_MAX_TRACKS                 (1024)
#define NGX_KSMP_MAX_VARIANTS               (1024)
#define NGX_KSMP_MAX_PERIODS                (65536)
#define NGX_KSMP_MAX_MEDIA_INFOS            (65536)

#define NGX_KSMP_MIN_PADDING                sizeof(ngx_persist_block_header_t)
#define NGX_KSMP_MAX_PADDING                128


/* Note: ordered by desc prio */
enum {
#define KSMP_ERR(code, val)  NGX_KSMP_ERR_##code = val,
#include "ngx_ksmp_errs_x.h"
#undef KSMP_ERR
};


typedef enum {
    ngx_ksmp_variant_role_main,
    ngx_ksmp_variant_role_alternate,

    ngx_ksmp_variant_role_count
} ngx_ksmp_variant_role_e;


typedef struct {
    uint32_t                     track_count;
    uint32_t                     variant_count;
    uint32_t                     timescale;
    uint32_t                     req_media_types;
    uint32_t                     res_media_types;
    uint32_t                     reserved;
    int64_t                      last_modified;
    int64_t                      now;
} ngx_ksmp_channel_header_t;


typedef struct {
    int64_t                      availability_start_time;
    uint32_t                     period_count;
    uint32_t                     first_period_index;
    int64_t                      first_period_initial_time;
    uint32_t                     first_period_initial_segment_index;

    uint32_t                     sequence;
    int64_t                      last_modified;
    uint32_t                     target_duration;
    uint32_t                     end_list;
} ngx_ksmp_timeline_header_t;


typedef struct {
    int64_t                      time;
    uint32_t                     segment_index;
    uint32_t                     reserved;
} ngx_ksmp_period_header_t;


typedef struct {
    uint32_t                     count;
    uint32_t                     duration;
} ngx_ksmp_segment_repeat_t;


typedef struct {
    uint32_t                     role;
    uint32_t                     is_default;
} ngx_ksmp_variant_t;


typedef struct {
    uint32_t                     id;
    uint32_t                     media_type;
} ngx_ksmp_track_header_t;


typedef struct {
    uint32_t                     count;
} ngx_ksmp_media_info_queue_header_t;


typedef struct {
    uint64_t                     bitrate_sum;
    uint32_t                     bitrate_count;
    uint32_t                     bitrate_max;

    uint64_t                     duration;
    uint64_t                     frame_count;
    uint32_t                     frame_rate_min;     /* frames / 100 sec */
    uint32_t                     frame_rate_max;     /* frames / 100 sec */
} ngx_ksmp_media_info_stats_t;


typedef struct {
    uint32_t                     track_id;
    uint32_t                     segment_index;
    ngx_ksmp_media_info_stats_t  stats;
} ngx_ksmp_media_info_header_t;


typedef struct {
    uint32_t                     index;
    uint32_t                     bitrate;
} ngx_ksmp_segment_info_elt_t;


typedef struct {
    uint32_t                     index;
    uint32_t                     reserved;
    int64_t                      correction;
    int64_t                      time;
} ngx_ksmp_segment_index_t;


typedef struct {
    uint32_t                     track_id;
    uint32_t                     index;
    uint32_t                     frame_count;
    uint32_t                     reserved;
    int64_t                      start_dts;
} ngx_ksmp_segment_header_t;


typedef struct {
    uint32_t                     size;
    uint32_t                     key_frame;
    uint32_t                     duration;
    uint32_t                     pts_delay;
} ngx_ksmp_frame_t;

#endif /* _NGX_KSMP_H_INCLUDED_ */
