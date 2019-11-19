#ifndef _NGX_LIVE_TIMELINE_H_INCLUDED_
#define _NGX_LIVE_TIMELINE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_segment_list.h"
#include "ngx_live.h"


#define NGX_LIVE_TIMELINE_MAX_ID_LEN       (32)


typedef struct {
    uint64_t                           max_duration;
    uint32_t                           max_segments;
    int64_t                            start;
    int64_t                            end;
    unsigned                           active:1;
} ngx_live_timeline_conf_t;

typedef struct {
    uint64_t                           max_duration;
    uint32_t                           max_segments;
    uint32_t                           expiry_threshold;
    uint32_t                           target_duration_segments;
} ngx_live_timeline_manifest_conf_t;


typedef struct ngx_live_period_s  ngx_live_period_t;

struct ngx_live_period_s {
    ngx_rbtree_node_t                  node;          /* key = segment_index */
    ngx_live_period_t                 *next;

    ngx_live_segment_iterator_t        segment_iterator;
    int64_t                            time;
    uint64_t                           duration;
    uint32_t                           segment_count;
};


typedef struct {
    ngx_live_timeline_manifest_conf_t  conf;

    ngx_live_period_t                  first_period;
    int64_t                            first_period_initial_time;
    uint32_t                           first_period_initial_segment_index;
    uint32_t                           first_period_index;
    uint32_t                           sequence;

    int64_t                            availability_start_time;
    time_t                             last_modified;

    uint32_t                           target_duration;

    /* volatile */
    uint64_t                           duration;
    uint32_t                           segment_count;
    uint32_t                           period_count;
    uint32_t                           last_durations[3];
} ngx_live_manifest_timeline_t;


typedef struct {
    ngx_str_node_t                     sn;
    ngx_queue_t                        queue;
    u_char                             id_buf[NGX_LIVE_TIMELINE_MAX_ID_LEN];
    ngx_live_channel_t                *channel;

    ngx_rbtree_t                       rbtree;
    ngx_rbtree_node_t                  sentinel;
    ngx_live_period_t                 *head_period;

    ngx_live_timeline_conf_t           conf;
    time_t                             last_segment_created;

    ngx_live_manifest_timeline_t       manifest;

    /* volatile */
    ngx_live_period_t                 *last_period;
    uint64_t                           duration;
    uint32_t                           segment_count;
} ngx_live_timeline_t;


ngx_int_t ngx_live_timeline_create(ngx_live_channel_t *channel, ngx_str_t *id,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log,
    ngx_live_timeline_t **result);

void ngx_live_timeline_free(ngx_live_timeline_t *timeline);

ngx_live_timeline_t *ngx_live_timeline_get(ngx_live_channel_t *channel,
    ngx_str_t *id);

ngx_int_t ngx_live_timeline_update(ngx_live_timeline_t *timeline,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log);

ngx_int_t ngx_live_timeline_copy(ngx_live_timeline_t *dest,
    ngx_live_timeline_t *source);

ngx_flag_t ngx_live_timeline_contains_segment(ngx_live_timeline_t *timeline,
    uint32_t segment_index);

ngx_flag_t ngx_live_timeline_is_expired(ngx_live_timeline_t *timeline);


ngx_int_t ngx_live_timelines_add_segment(ngx_live_channel_t *channel,
    uint32_t segment_index, int64_t time, uint32_t duration,
    ngx_flag_t force_new_period);

void ngx_live_timelines_truncate(ngx_live_channel_t *channel,
    uint32_t segment_index);

ngx_int_t ngx_live_timelines_get_segment_time(ngx_live_channel_t *channel,
    uint32_t segment_index, int64_t *result);


size_t ngx_live_timeline_json_get_size(ngx_live_timeline_t *timeline);

u_char *ngx_live_timeline_json_write(u_char *p, ngx_live_timeline_t *timeline);

size_t ngx_live_timeline_channel_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_timeline_channel_json_write(u_char *p,
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_TIMELINE_H_INCLUDED_ */