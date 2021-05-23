#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_segment_index.h"
#include "ngx_live_timeline.h"


#define NGX_LIVE_INVALID_TIMELINE_ID  (0)

#define NGX_LIVE_TIMELINE_PERSIST_BLOCK               NGX_KSMP_BLOCK_TIMELINE
#define NGX_LIVE_TIMELINE_PERSIST_BLOCK_PERIODS       (0x64706c74)  /* tlpd */
#define NGX_LIVE_TIMELINE_PERSIST_BLOCK_CHANNEL       (0x68636c74)  /* tlch */


#define NGX_LIVE_TIMELINE_CLEANUP_INTERVAL  (60000)
#define NGX_LIVE_TIMELINE_JSON_MAX_PERIODS  (5)


enum {
    NGX_LIVE_BP_PERIOD,
    NGX_LIVE_BP_TIMELINE,
    NGX_LIVE_BP_SEGMENT_LIST_NODE,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    ngx_uint_t                bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_timeline_preset_conf_t;


typedef struct {
    ngx_live_segment_list_t   segment_list;
    ngx_rbtree_t              rbtree;
    ngx_rbtree_node_t         sentinel;
    ngx_queue_t               queue;        /* ngx_live_timeline_t */
    ngx_event_t               cleanup;
    uint32_t                  count;
    uint32_t                  last_id;
    int64_t                   last_segment_middle;
    uint32_t                  truncate;
} ngx_live_timeline_channel_ctx_t;


typedef struct {
    uint32_t                  id;
    int64_t                   last_time;
    int64_t                   last_segment_created;

    /* manifest */
    uint32_t                  target_duration;
    uint32_t                  target_duration_segments;
    uint32_t                  sequence;
    int64_t                   last_modified;
    uint32_t                  last_durations[NGX_LIVE_TIMELINE_LAST_DURATIONS];
} ngx_live_timeline_snap_t;


typedef struct {
    uint32_t                  merge;
    uint32_t                  reserved;
    int64_t                   first_period_initial_time;
} ngx_live_timeline_persist_periods_t;


typedef struct {
    uint32_t                  segment_index;
    uint32_t                  segment_count;
    int64_t                   correction;
} ngx_live_timeline_persist_period_t;


typedef struct {
    int64_t                   availability_start_time;
    uint32_t                  first_period_index;
    uint32_t                  first_period_segment_index;
    int64_t                   first_period_initial_time;
    uint32_t                  first_period_initial_segment_index;

    uint32_t                  sequence;
    int64_t                   last_modified;
    uint32_t                  target_duration;
    uint32_t                  target_duration_segments;
    uint32_t                  last_durations[NGX_LIVE_TIMELINE_LAST_DURATIONS];
    uint32_t                  reserved;
} ngx_live_timeline_persist_manifest_t;


typedef struct {
    int64_t                   last_time;
    int64_t                   last_segment_created;
} ngx_live_timeline_persist_t;


typedef struct {
    int64_t                   last_segment_middle;
    uint32_t                  truncate;
    uint32_t                  reserved;
} ngx_live_timeline_persist_channel_t;


static size_t ngx_live_timeline_last_periods_json_get_size(
    ngx_live_timeline_t *obj);
static u_char *ngx_live_timeline_last_periods_json_write(u_char *p,
    ngx_live_timeline_t *obj);

#include "ngx_live_timeline_json.h"


static ngx_int_t ngx_live_timeline_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_timeline_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_timeline_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_timeline_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static void ngx_live_timeline_inactive_remove_segments(
    ngx_live_timeline_t *timeline, uint32_t *min_segment_index);


static ngx_live_module_t  ngx_live_timeline_module_ctx = {
    ngx_live_timeline_preconfiguration,       /* preconfiguration */
    ngx_live_timeline_postconfiguration,      /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_timeline_create_preset_conf,     /* create preset configuration */
    ngx_live_timeline_merge_preset_conf,      /* merge preset configuration */
};

ngx_module_t  ngx_live_timeline_module = {
    NGX_MODULE_V1,
    &ngx_live_timeline_module_ctx,            /* module context */
    NULL,                                     /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


/* period */

static ngx_live_period_t *
ngx_live_period_create(ngx_live_channel_t *channel)
{
    ngx_live_period_t                *period;
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    period = ngx_block_pool_alloc(channel->block_pool,
        tpcf->bp_idx[NGX_LIVE_BP_PERIOD]);
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_period_create: alloc failed");
        return NULL;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    period->next = NULL;
    period->duration = 0;
    period->segment_count = 0;

    ngx_live_segment_iter_last(&cctx->segment_list, &period->segment_iter);

    return period;
}

static void
ngx_live_period_free(ngx_live_channel_t *channel, ngx_live_period_t *period)
{
    ngx_live_timeline_preset_conf_t  *tpcf;

    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    ngx_block_pool_free(channel->block_pool, tpcf->bp_idx[NGX_LIVE_BP_PERIOD],
        period);
}

static void
ngx_live_period_add_segment(ngx_live_period_t *period, uint32_t duration)
{
    period->segment_count++;
    period->duration += duration;
}

static void
ngx_live_period_pop_segment(ngx_live_period_t *period, uint32_t *duration)
{
    if (period->segment_count <= 0) {
        *duration = 0;
        return;
    }

    ngx_live_segment_iter_get_one(&period->segment_iter, duration);

    period->segment_count--;
    period->time += *duration;
    period->duration -= *duration;

    /* won't break tree structure since there is no overlap between periods */
    period->node.key++;
}

static void
ngx_live_period_get_max_duration(ngx_live_period_t *period,
    uint32_t *max_duration)
{
    uint32_t                   i;
    ngx_live_segment_iter_t    iter;
    ngx_live_segment_repeat_t  segment_duration;

    iter = period->segment_iter;

    for (i = period->segment_count; ; i -= segment_duration.count) {

        ngx_live_segment_iter_get_element(&iter, &segment_duration);

        if (segment_duration.duration > *max_duration) {
            *max_duration = segment_duration.duration;
        }

        if (i <= segment_duration.count) {
            break;
        }
    }
}

static ngx_int_t
ngx_live_period_reset_duration(ngx_live_channel_t *channel,
    ngx_live_period_t *period)
{
    int64_t                           end_time;
    uint32_t                          last_index;
    ngx_live_timeline_channel_ctx_t  *cctx;

    if (period->segment_count <= 0) {
        period->duration = 0;
        return NGX_OK;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    last_index = period->node.key + period->segment_count - 1;

    if (ngx_live_segment_list_get_period_end_time(&cctx->segment_list,
        &period->segment_iter, last_index, &end_time) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_period_reset_duration: "
            "failed to get period end time, first: %ui, last: %uD",
            period->node.key, last_index);
        return NGX_ERROR;
    }

    period->duration = end_time - period->time;

    return NGX_OK;
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_period_validate(ngx_live_period_t *period, ngx_log_t *log)
{
    uint32_t                   i;
    uint64_t                   duration;
    ngx_live_segment_iter_t    iter;
    ngx_live_segment_repeat_t  segment_duration;

    iter = period->segment_iter;
    duration = 0;

    for (i = period->segment_count;
        i > 0;
        i -= segment_duration.count)
    {
        ngx_live_segment_iter_get_element(&iter, &segment_duration);

        if (segment_duration.count > i) {
            segment_duration.count = i;
        }

        duration += (uint64_t) segment_duration.duration *
            segment_duration.count;
    }

    if (period->duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_period_validate: "
            "invalid period duration %uL expected %uL",
            period->duration, duration);
        ngx_debug_point();
    }
}
#else
#define ngx_live_period_validate(period, log)
#endif


/* manifest timeline */

static void
ngx_live_manifest_timeline_remove_segment(
    ngx_live_manifest_timeline_t *timeline)
{
    uint32_t            duration;
    ngx_live_period_t  *period = &timeline->first_period;

    ngx_live_period_pop_segment(period, &duration);

    timeline->segment_count--;
    timeline->duration -= duration;

    timeline->last_modified = ngx_time();

    if (period->segment_count > 0) {
        return;
    }

    timeline->period_count--;
    timeline->first_period_index++;

    if (period->next == NULL) {
        timeline->first_period.node.key = NGX_LIVE_INVALID_SEGMENT_INDEX;
        return;
    }

    *period = *period->next;

    timeline->first_period_initial_time = period->time;
    timeline->first_period_initial_segment_index = period->node.key;
}

static void
ngx_live_manifest_timeline_remove_segments(
    ngx_live_manifest_timeline_t *timeline, uint32_t base_count,
    uint64_t base_duration)
{
    ngx_live_timeline_manifest_conf_t  *conf = &timeline->conf;

    while (timeline->segment_count > 0) {

        if (timeline->segment_count + base_count <= conf->max_segments &&
            timeline->duration + base_duration <= conf->max_duration)
        {
            break;
        }

        ngx_live_manifest_timeline_remove_segment(timeline);
    }
}

static void
ngx_live_manifest_timeline_add_first_period(
    ngx_live_timeline_channel_ctx_t *cctx,
    ngx_live_manifest_timeline_t *timeline, int64_t time,
    uint32_t segment_index)
{
    ngx_live_period_t  *period = &timeline->first_period;

    period->node.key = segment_index;
    period->next = NULL;
    period->time = time;
    period->duration = 0;
    period->segment_count = 0;

    ngx_live_segment_iter_last(&cctx->segment_list,
        &period->segment_iter);

    if (timeline->availability_start_time == 0) {
        timeline->availability_start_time = time;
    }
    timeline->first_period_initial_time = time;
    timeline->first_period_initial_segment_index = segment_index;

    timeline->period_count = 1;
}

static void
ngx_live_manifest_timeline_add_period(ngx_live_timeline_channel_ctx_t *cctx,
    ngx_live_manifest_timeline_t *timeline, ngx_live_period_t *period)
{
    switch (timeline->period_count) {

    case 0:
        ngx_live_manifest_timeline_add_first_period(cctx, timeline,
            period->time, period->node.key);
        return;

    case 1:
        timeline->first_period.next = period;
        break;
    }

    timeline->period_count++;
}

static void
ngx_live_manifest_timeline_add_segment(ngx_live_manifest_timeline_t *timeline,
    uint32_t duration)
{
    if (timeline->period_count == 1) {
        ngx_live_period_add_segment(&timeline->first_period, duration);
    }

    timeline->segment_count++;
    timeline->duration += duration;

    timeline->last_modified = ngx_time();
}

static void
ngx_live_manifest_timeline_post_add_segment(
    ngx_live_manifest_timeline_t *timeline, uint32_t duration)
{
    if (timeline->target_duration_segments <
            timeline->conf.target_duration_segments)
    {
        timeline->target_duration_segments++;

        if (duration > timeline->target_duration) {
            timeline->target_duration = duration;
        }
    }

    timeline->sequence++;

    timeline->last_durations[timeline->sequence %
        ngx_array_entries(timeline->last_durations)] = duration;
}

static void
ngx_live_manifest_timeline_truncate(
    ngx_live_manifest_timeline_t *timeline, uint32_t segment_index)
{
    while (timeline->segment_count > 0 &&
        timeline->first_period.node.key <= segment_index)
    {
        ngx_live_manifest_timeline_remove_segment(timeline);
    }
}

static void
ngx_live_timeline_manifest_copy(ngx_live_timeline_t *dest,
    ngx_live_timeline_t *source, uint32_t max_duration)
{
    dest->manifest.first_period = *dest->head_period;
    dest->manifest.availability_start_time = dest->manifest.first_period.time;
    dest->manifest.first_period_initial_time =
        dest->manifest.first_period.time;
    dest->manifest.first_period_initial_segment_index =
        dest->manifest.first_period.node.key;

    dest->manifest.duration = dest->duration;
    dest->manifest.segment_count = dest->segment_count;
    dest->manifest.period_count = dest->period_count;

    dest->manifest.target_duration = max_duration;
    dest->manifest.target_duration_segments = dest->segment_count;

    /* Note: if the end of dest timeline is different than source, the below
        is incorrect. however, since last_durations is only used to estimate
        the segment duration, it's probably good enough */
    ngx_memcpy(dest->manifest.last_durations, source->manifest.last_durations,
        sizeof(dest->manifest.last_durations));

    dest->manifest.last_modified = ngx_time();
}


/* timeline */

void
ngx_live_timeline_conf_default(ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf)
{
    ngx_memzero(conf, sizeof(*conf));
    ngx_memzero(manifest_conf, sizeof(*manifest_conf));

    conf->active = 1;    /* active by default */
    conf->period_gap = -1;
    manifest_conf->target_duration_segments = 3;
}

static ngx_int_t
ngx_live_timeline_conf_validate(ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log)
{
    if (!conf->end) {
        conf->end = LLONG_MAX;
    }

    if (conf->start >= conf->end) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_conf_validate: "
            "start offset %L must be lower than end offset %L",
            conf->start, conf->end);
        return NGX_ERROR;
    }

    if (!conf->max_segments) {
        conf->max_segments = NGX_MAX_UINT32_VALUE;
    }

    if (!manifest_conf->max_segments) {
        manifest_conf->max_segments = conf->max_segments;

    } else if (manifest_conf->max_segments > conf->max_segments) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_conf_validate: "
            "manifest max segments %uD larger than max segments %uD",
            manifest_conf->max_segments, conf->max_segments);
        return NGX_ERROR;
    }

    if (!conf->max_duration) {
        conf->max_duration = ULLONG_MAX;
    }

    if (!manifest_conf->max_duration) {
        manifest_conf->max_duration = conf->max_duration;

    } else if (manifest_conf->max_duration > conf->max_duration) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_conf_validate: "
            "manifest max duration %uL larger than max duration %uL",
            manifest_conf->max_duration, conf->max_duration);
        return NGX_ERROR;
    }

    if (manifest_conf->target_duration_segments <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_conf_validate: "
            "invalid target_duration_segments %uD",
            manifest_conf->target_duration_segments);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static u_char *
ngx_live_timeline_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char               *p;
    ngx_live_channel_t   *channel;
    ngx_live_timeline_t  *timeline;

    p = buf;

    timeline = log->data;

    if (timeline != NULL) {

        channel = timeline->channel;

        p = ngx_snprintf(buf, len, ", nsi: %uD, timeline: %V, channel: %V",
            channel->next_segment_index, &timeline->sn.str, &channel->sn.str);
        len -= p - buf;
        buf = p;
    }

    return p;
}

ngx_int_t
ngx_live_timeline_create(ngx_live_channel_t *channel, ngx_str_t *id,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log,
    ngx_live_timeline_t **result)
{
    uint32_t                          hash;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    if (id->len > sizeof(timeline->id_buf)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_create: timeline id \"%V\" too long", id);
        return NGX_INVALID_ARG;
    }

    if (ngx_live_timeline_conf_validate(conf, manifest_conf, log) != NGX_OK) {
        return NGX_INVALID_ARG;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);
    hash = ngx_crc32_short(id->data, id->len);
    timeline = (ngx_live_timeline_t *) ngx_str_rbtree_lookup(&cctx->rbtree, id,
        hash);
    if (timeline != NULL) {
        *result = timeline;
        return NGX_EXISTS;
    }

    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    timeline = ngx_block_pool_calloc(channel->block_pool,
        tpcf->bp_idx[NGX_LIVE_BP_TIMELINE]);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_timeline_create: alloc failed");
        return NGX_ERROR;
    }

    if (conf->end <= cctx->last_segment_middle) {
        conf->active = 0;
    }

    timeline->sn.str.data = timeline->id_buf;
    timeline->sn.str.len = id->len;
    ngx_memcpy(timeline->sn.str.data, id->data, timeline->sn.str.len);
    timeline->sn.node.key = hash;
    timeline->int_id = ++cctx->last_id;

    timeline->log = channel->log;
    timeline->log.handler = ngx_live_timeline_log_error;
    timeline->log.data = timeline;
    timeline->channel = channel;

    timeline->conf = *conf;

    timeline->manifest.conf = *manifest_conf;
    timeline->manifest.first_period.node.key = NGX_LIVE_INVALID_SEGMENT_INDEX;
    timeline->manifest.sequence = channel->next_segment_index;
    timeline->manifest.last_modified = ngx_time();

    ngx_rbtree_init(&timeline->rbtree, &timeline->sentinel,
        ngx_rbtree_insert_value);

    ngx_rbtree_insert(&cctx->rbtree, &timeline->sn.node);
    ngx_queue_insert_tail(&cctx->queue, &timeline->queue);
    cctx->count++;

    ngx_log_error(NGX_LOG_INFO, &timeline->log, 0,
        "ngx_live_timeline_create: created %p", timeline);

    ngx_live_channel_setup_changed(channel);

    *result = timeline;

    return NGX_OK;
}

void
ngx_live_timeline_free(ngx_live_timeline_t *timeline)
{
    ngx_live_period_t                *next;
    ngx_live_period_t                *period;
    ngx_live_channel_t               *channel;
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    ngx_log_error(NGX_LOG_INFO, &timeline->log, 0,
        "ngx_live_timeline_free: freeing %p", timeline);

    channel = timeline->channel;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);
    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    /* free the periods (no reason to remove from tree/queue) */
    for (period = timeline->head_period; period; period = next) {
        next = period->next;
        ngx_live_period_free(channel, period);
    }

    ngx_rbtree_delete(&cctx->rbtree, &timeline->sn.node);
    ngx_queue_remove(&timeline->queue);
    cctx->count--;

    ngx_block_pool_free(channel->block_pool,
        tpcf->bp_idx[NGX_LIVE_BP_TIMELINE], timeline);

    if (!channel->active && !cctx->cleanup.timer_set) {
        ngx_add_timer(&cctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    ngx_live_channel_setup_changed(channel);
}

ngx_live_timeline_t *
ngx_live_timeline_get(ngx_live_channel_t *channel, ngx_str_t *id)
{
    uint32_t                          hash;
    uint32_t                          ignore;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    hash = ngx_crc32_short(id->data, id->len);
    timeline = (void *) ngx_str_rbtree_lookup(&cctx->rbtree, id, hash);
    if (timeline == NULL) {
        return NULL;
    }

    if (!timeline->conf.active || !channel->active) {
        ignore = 0;
        ngx_live_timeline_inactive_remove_segments(timeline, &ignore);
    }

    return timeline;
}

ngx_flag_t
ngx_live_timeline_get_segment_info(ngx_live_timeline_t *timeline,
    uint32_t segment_index, uint32_t flags, int64_t *correction)
{
    ngx_rbtree_t       *rbtree = &timeline->rbtree;
    ngx_rbtree_node_t  *node;
    ngx_rbtree_node_t  *sentinel;
    ngx_live_period_t  *period;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    for ( ;; ) {

        if (node == sentinel) {
            return 0;
        }

        if (segment_index < node->key) {
            node = node->left;

        } else {
            period = (ngx_live_period_t *) node;
            if (segment_index < node->key + period->segment_count) {
                break;
            }

            node = node->right;
        }
    }

    if (flags & NGX_KSMP_FLAG_RELATIVE_DTS) {
        if (period == timeline->head_period) {
            *correction = -timeline->first_period_initial_time;

        } else {
            *correction = -period->time;
        }

    } else {
        *correction = period->correction;
    }

    return 1;
}

ngx_flag_t
ngx_live_timeline_is_expired(ngx_live_timeline_t *timeline)
{
    uint32_t                     *cur, *end;
    uint32_t                      max;
    uint32_t                      expiry;
    uint32_t                      expiry_threshold;
    ngx_live_core_preset_conf_t  *cpcf;

    expiry_threshold = timeline->manifest.conf.expiry_threshold;
    if (expiry_threshold <= 0) {
        return 0;
    }

    max = 0;
    end = timeline->manifest.last_durations +
        ngx_array_entries(timeline->manifest.last_durations);
    for (cur = timeline->manifest.last_durations; cur < end; cur++) {
        if (*cur > max) {
            max = *cur;
        }
    }

    cpcf = ngx_live_get_module_preset_conf(timeline->channel,
        ngx_live_core_module);

    expiry = ((uint64_t) max * expiry_threshold) / (cpcf->timescale * 100);

    return ngx_time() > (time_t) (timeline->last_segment_created + expiry);
}

ngx_int_t
ngx_live_timeline_update(ngx_live_timeline_t *timeline,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log)
{
    ngx_live_channel_t               *channel;
    ngx_live_timeline_channel_ctx_t  *cctx;

    if (ngx_live_timeline_conf_validate(conf, manifest_conf, log) != NGX_OK) {
        return NGX_ERROR;
    }

    channel = timeline->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    if (conf->end <= cctx->last_segment_middle) {
        conf->active = 0;
    }

    timeline->conf = *conf;
    timeline->manifest.conf = *manifest_conf;

    if (!channel->active && !cctx->cleanup.timer_set) {
        ngx_add_timer(&cctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    ngx_live_channel_setup_changed(channel);

    return NGX_OK;
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_timeline_validate(ngx_live_timeline_t *timeline)
{
    ngx_log_t          *log = &timeline->log;
    uint64_t            duration;
    uint32_t            period_count;
    uint32_t            segment_count;
    ngx_live_period_t  *period;
    ngx_live_period_t  *prev_period;

    duration = 0;
    period_count = 0;
    segment_count = 0;
    prev_period = NULL;

    for (period = timeline->head_period; period; period = period->next) {

        ngx_live_period_validate(period, log);

        duration += period->duration;
        segment_count += period->segment_count;
        period_count++;

        prev_period = period;
    }

    if (timeline->duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid timeline duration %uL expected %uL",
            timeline->duration, duration);
        ngx_debug_point();
    }

    if (timeline->segment_count != segment_count) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid timeline segment count %uD expected %uD",
            timeline->segment_count, segment_count);
        ngx_debug_point();
    }

    if (timeline->period_count != period_count) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid period count %uD expected %uD",
            timeline->period_count, period_count);
        ngx_debug_point();
    }

    if (timeline->last_period != prev_period) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid last period %p expected %p",
            timeline->last_period, prev_period);
        ngx_debug_point();
    }

    duration = 0;
    period_count = 0;
    segment_count = 0;
    prev_period = NULL;

    if (timeline->manifest.first_period.segment_count > 0) {

        for (period = &timeline->manifest.first_period;
            period;
            period = period->next) {

            ngx_live_period_validate(period, log);

            duration += period->duration;
            segment_count += period->segment_count;
            period_count++;

            prev_period = period;
        }

    } else if (timeline->manifest.first_period.node.key
        != NGX_LIVE_INVALID_SEGMENT_INDEX)
    {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest first segment index %ui when empty",
            timeline->manifest.first_period.node.key);
        ngx_debug_point();
    }

    if (timeline->manifest.duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest duration %uL expected %uL",
            timeline->manifest.duration, duration);
        ngx_debug_point();
    }

    if (timeline->manifest.segment_count != segment_count) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest segment count %uD expected %uD",
            timeline->manifest.segment_count, segment_count);
        ngx_debug_point();
    }

    if (timeline->manifest.period_count != period_count) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest period count %uD expected %uD",
            timeline->manifest.period_count, period_count);
        ngx_debug_point();
    }

    if (period_count > 1 && timeline->last_period != prev_period) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest last period %p expected %p",
            timeline->last_period, prev_period);
        ngx_debug_point();
    }
}
#else
#define ngx_live_timeline_validate(timeline)
#endif

static void
ngx_live_timeline_remove_segment(ngx_live_timeline_t *timeline)
{
    uint32_t            duration;
    ngx_live_period_t  *period = timeline->head_period;

    ngx_live_period_pop_segment(period, &duration);

    timeline->segment_count--;
    timeline->duration -= duration;

    if (period->segment_count > 0) {
        return;
    }

    ngx_rbtree_delete(&timeline->rbtree, &period->node);

    timeline->head_period = period->next;
    if (timeline->head_period == NULL) {
        timeline->last_period = NULL;

    } else {
        timeline->first_period_initial_time = timeline->head_period->time;
    }
    timeline->period_count--;

    ngx_live_period_free(timeline->channel, period);
}

static void
ngx_live_timeline_remove_segments(ngx_live_timeline_t *timeline,
    uint32_t base_count, uint64_t base_duration, uint32_t *min_segment_index)
{
    ngx_live_period_t         *period;
    ngx_live_timeline_conf_t  *conf;

    ngx_live_manifest_timeline_remove_segments(&timeline->manifest,
        base_count, base_duration);

    conf = &timeline->conf;

    while (timeline->head_period != NULL) {

        if (timeline->segment_count + base_count <= conf->max_segments &&
            timeline->duration + base_duration <= conf->max_duration)
        {
            period = timeline->head_period;
            if (period->node.key < *min_segment_index) {
                *min_segment_index = period->node.key;
            }

            break;
        }

        ngx_live_timeline_remove_segment(timeline);
    }

    ngx_live_timeline_validate(timeline);
}

static void
ngx_live_timeline_inactive_remove_segments(ngx_live_timeline_t *timeline,
    uint32_t *min_segment_index)
{
    uint32_t                      base_count;
    uint64_t                      base_duration;
    ngx_live_period_t            *period;
    ngx_live_core_preset_conf_t  *cpcf;

    if (ngx_time() <= timeline->last_segment_created ||
        timeline->duration <= 0)
    {
        period = timeline->head_period;
        if (period != NULL && period->node.key < *min_segment_index) {
            *min_segment_index = period->node.key;
        }

        return;
    }

    cpcf = ngx_live_get_module_preset_conf(timeline->channel,
        ngx_live_core_module);

    base_duration = (uint64_t) (ngx_time() - timeline->last_segment_created) *
        cpcf->timescale;

    base_count = (base_duration * timeline->segment_count) /
        timeline->duration;

    ngx_live_timeline_remove_segments(timeline, base_count, base_duration,
        min_segment_index);

    ngx_live_timeline_validate(timeline);
}

static void
ngx_live_timeline_add_segment(ngx_live_timeline_t *timeline, uint32_t duration)
{
    ngx_live_period_add_segment(timeline->last_period, duration);

    timeline->segment_count++;
    timeline->duration += duration;

    ngx_live_manifest_timeline_add_segment(&timeline->manifest, duration);
}

ngx_int_t
ngx_live_timeline_get_time(ngx_live_timeline_t *timeline, int64_t offset,
    ngx_log_t *log, int64_t *time)
{
    int64_t             duration;
    ngx_live_period_t  *period;

    if (timeline->conf.period_gap == -1) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_timeline_get_time: period_gap not set, timeline: %V",
            &timeline->sn.str);
        return NGX_ERROR;
    }

    period = timeline->head_period;
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_timeline_get_time: no periods, timeline: %V",
            &timeline->sn.str);
        return NGX_ERROR;
    }

    for ( ;; ) {
        duration = period->duration + timeline->conf.period_gap;
        if (offset < duration || period->next == NULL) {
            break;
        }

        offset -= duration;
        period = period->next;
    }

    *time = period->time + offset;
    return NGX_OK;
}

static ngx_live_period_t *
ngx_live_timeline_get_period_by_index(ngx_live_timeline_t *timeline,
    uint32_t segment_index, ngx_flag_t strict)
{
    ngx_rbtree_t       *rbtree;
    ngx_rbtree_node_t  *node;
    ngx_rbtree_node_t  *sentinel;
    ngx_live_period_t  *period;

    rbtree = &timeline->rbtree;
    node = rbtree->root;
    sentinel = rbtree->sentinel;

    if (node == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        period = (ngx_live_period_t *) node;

        if (segment_index < period->node.key) {

            node = node->left;
            if (node != sentinel) {
                continue;
            }

            return strict ? NULL : period;

        } else if (segment_index >= period->node.key + period->segment_count) {

            node = node->right;
            if (node != sentinel) {
                continue;
            }

            return strict ? NULL : period->next;

        } else {
            return period;
        }
    }
}

static ngx_live_period_t *
ngx_live_timeline_get_period_by_time(ngx_live_timeline_t *timeline,
    int64_t time)
{
    ngx_rbtree_t       *rbtree = &timeline->rbtree;
    ngx_rbtree_node_t  *node;
    ngx_rbtree_node_t  *sentinel;
    ngx_live_period_t  *period;

    /* Note: this functions returns the period that contains 'time', if one
        exists. otherwise, it will return the first segment that starts after
        'time'. if 'time' is larger than the end time of the last segment,
        null is returned. */

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    if (node == sentinel) {
        return NULL;
    }

    for ( ;; ) {

        period = (ngx_live_period_t *) node;
        if (time < period->time) {
            if (node->left == sentinel) {
                return period;
            }
            node = node->left;

        } else if (time >= (int64_t) (period->time + period->duration)) {
            if (node->right == sentinel) {
                return period->next;
            }
            node = node->right;

        } else {
            return period;
        }
    }
}

ngx_int_t
ngx_live_timeline_copy(ngx_live_timeline_t *dest, ngx_live_timeline_t *source,
    ngx_log_t *log)
{
    int64_t                           segment_time;
    int64_t                           src_period_end;
    uint32_t                          ignore;
    uint32_t                          max_duration;
    uint32_t                          segment_index;
    ngx_live_period_t                *src_period;
    ngx_live_period_t                *dest_period;
    ngx_live_channel_t               *channel = dest->channel;
    ngx_live_segment_iter_t           dummy_iter;
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    /* Note: assuming dest is an empty, freshly-created timeline */

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);
    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    src_period = ngx_live_timeline_get_period_by_time(source,
        dest->conf.start);

    max_duration = 0;

    for ( ; src_period; src_period = src_period->next) {

        if (src_period->time >= dest->conf.end) {
            break;
        }

        dest_period = ngx_block_pool_alloc(channel->block_pool,
            tpcf->bp_idx[NGX_LIVE_BP_PERIOD]);
        if (dest_period == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_timeline_copy: alloc failed");
            return NGX_ERROR;
        }

        if (dest->conf.start <= src_period->time) {
            dest_period->node.key = src_period->node.key;
            dest_period->time = src_period->time;
            dest_period->segment_iter = src_period->segment_iter;

        } else {
            if (ngx_live_segment_list_get_closest_segment(&cctx->segment_list,
                dest->conf.start, &segment_index, &dest_period->time,
                &dest_period->segment_iter) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                    "ngx_live_timeline_copy: "
                    "get closest segment failed (1)");
                ngx_live_period_free(channel, dest_period);
                return NGX_ERROR;
            }
            dest_period->node.key = segment_index;
        }

        src_period_end = src_period->time + src_period->duration;
        if (dest->conf.end >= src_period_end) {
            segment_index = src_period->node.key + src_period->segment_count;
            segment_time = src_period->time + src_period->duration;

        } else {
            if (ngx_live_segment_list_get_closest_segment(&cctx->segment_list,
                dest->conf.end, &segment_index, &segment_time,
                &dummy_iter) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                    "ngx_live_timeline_copy: "
                    "get closest segment failed (2)");
                ngx_live_period_free(channel, dest_period);
                return NGX_ERROR;
            }
        }

        dest_period->segment_count = segment_index - dest_period->node.key;
        if (dest_period->segment_count <= 0) {
            ngx_live_period_free(channel, dest_period);
            continue;
        }

        dest_period->duration = segment_time - dest_period->time;
        dest_period->next = NULL;

        if (dest->conf.period_gap != -1 && dest->last_time) {
            dest_period->correction = dest->last_time + dest->conf.period_gap -
                dest_period->time;

        } else {
            dest_period->correction = 0;
        }

        ngx_rbtree_insert(&dest->rbtree, &dest_period->node);

        if (dest->head_period == NULL) {
            dest->head_period = dest_period;

        } else {
            dest->last_period->next = dest_period;
        }
        dest->period_count++;

        dest->last_time = dest_period->time + dest_period->duration +
            dest_period->correction;
        dest->last_period = dest_period;

        dest->segment_count += dest_period->segment_count;
        dest->duration += dest_period->duration;

        ngx_live_period_get_max_duration(dest_period, &max_duration);
    }

    if (dest->period_count <= 0) {
        return NGX_OK;
    }

    dest->first_period_initial_time = dest->head_period->time;
    dest->last_segment_created = source->last_segment_created;

    ngx_live_timeline_manifest_copy(dest, source, max_duration);

    ignore = 0;
    if (dest->conf.active) {
        ngx_live_timeline_remove_segments(dest, 0, 0, &ignore);

    } else {
        ngx_live_timeline_inactive_remove_segments(dest, &ignore);
    }

    if (!channel->active && !cctx->cleanup.timer_set) {
        ngx_add_timer(&cctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    ngx_live_timeline_validate(dest);

    ngx_live_channel_setup_changed(channel);

    return NGX_OK;
}

static void
ngx_live_timeline_truncate(ngx_live_timeline_t *timeline,
    uint32_t segment_index)
{
    if (timeline->conf.no_truncate) {
        return;
    }

    ngx_live_manifest_timeline_truncate(&timeline->manifest,
        segment_index);

    while (timeline->head_period &&
        timeline->head_period->node.key <= segment_index)
    {
        ngx_live_timeline_remove_segment(timeline);
    }
}


/* channel timelines */

static void
ngx_live_timelines_free_old_segments(ngx_live_channel_t *channel,
    uint32_t min_segment_index)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_timelines_free_old_segments: index: %uD", min_segment_index);

    channel->min_segment_index = min_segment_index;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    ngx_live_segment_list_free_nodes(&cctx->segment_list, min_segment_index);

    (void) ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE,
        (void *) (uintptr_t) min_segment_index);
}

ngx_int_t
ngx_live_timelines_add_segment(ngx_live_channel_t *channel,
    int64_t time, uint32_t duration, ngx_flag_t force_new_period)
{
    uint32_t                          segment_index;
    uint32_t                          min_segment_index;
    ngx_int_t                         rc;
    ngx_flag_t                        added;
    ngx_queue_t                      *q;
    ngx_live_period_t                *period;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    /* add to segment list */
    segment_index = channel->next_segment_index;

    rc = ngx_live_segment_list_add(&cctx->segment_list, segment_index, time,
        duration);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timelines_add_segment: add failed");
        return rc;
    }

    cctx->last_segment_middle = time + duration / 2;

    min_segment_index = NGX_MAX_UINT32_VALUE;
    added = 0;

    /* add to active timelines */
    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        if (!timeline->conf.active ||
            cctx->last_segment_middle < timeline->conf.start)
        {
            ngx_live_timeline_inactive_remove_segments(timeline,
                &min_segment_index);
            continue;
        }

        if (cctx->last_segment_middle >= timeline->conf.end) {
            timeline->conf.active = 0;
            ngx_live_timeline_inactive_remove_segments(timeline,
                &min_segment_index);
            continue;
        }

        period = timeline->last_period;
        if (period == NULL ||
            time != (int64_t) (period->time + period->duration) ||
            segment_index != period->node.key + period->segment_count ||
            force_new_period)
        {
            /* create a new period */
            period = ngx_live_period_create(channel);
            if (period == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
                    "ngx_live_timelines_add_segment: failed to create period");
                return NGX_ERROR;
            }

            period->node.key = segment_index;
            period->time = time;

            if (timeline->conf.period_gap != -1 && timeline->last_time) {
                period->correction = timeline->last_time +
                    timeline->conf.period_gap - time;

            } else {
                period->correction = 0;
            }

            ngx_rbtree_insert(&timeline->rbtree, &period->node);

            if (timeline->head_period == NULL) {
                timeline->head_period = period;
                timeline->first_period_initial_time = time;

            } else {
                timeline->last_period->next = period;
            }
            timeline->period_count++;

            timeline->last_period = period;

            ngx_live_manifest_timeline_add_period(cctx, &timeline->manifest,
                period);

        } else if (timeline->manifest.period_count == 0) {
            ngx_live_manifest_timeline_add_first_period(
                cctx, &timeline->manifest, time, segment_index);
        }

        /* add the segment */
        timeline->last_time = time + duration + period->correction;

        ngx_live_timeline_add_segment(timeline, duration);

        ngx_live_timeline_remove_segments(timeline, 0, 0, &min_segment_index);

        if (timeline->manifest.segment_count <= 0) {
            /* in case the timeline somehow lost all segments, not
                incrementing the sequence number - the new segment can't be
                seen by anyone. it's probably meaningless, since the stream
                stops playing in such a case, but whatever... */
            continue;
        }

        ngx_live_manifest_timeline_post_add_segment(&timeline->manifest,
            duration);

        timeline->last_segment_created = ngx_time();

        added = 1;
    }

    ngx_live_timelines_free_old_segments(channel, min_segment_index);

    /* create a segment index */
    if (ngx_live_segment_index_create(channel, added) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timelines_add_segment: "
            "failed to create segment index");
        return NGX_ERROR;
    }

    /* notify the creation */
    rc = ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_CREATED, (void *) added);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timelines_add_segment: event failed");
        return rc;
    }

    return NGX_OK;
}

void
ngx_live_timelines_truncate(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_queue_t                      *q;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    cctx->truncate = segment_index;

    ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
        "ngx_live_timelines_truncate: index: %uD", segment_index);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        ngx_live_timeline_truncate(timeline, segment_index);
    }
}

ngx_int_t
ngx_live_timelines_get_segment_time(ngx_live_channel_t *channel,
    uint32_t segment_index, int64_t *result)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_segment_list_get_segment_time(&cctx->segment_list,
        segment_index, result);
}

int64_t
ngx_live_timelines_get_last_time(ngx_live_channel_t *channel)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return cctx->segment_list.last_time;
}


ngx_flag_t
ngx_live_timelines_cleanup(ngx_live_channel_t *channel)
{
    uint32_t                          min_segment_index;
    ngx_flag_t                        add_timer;
    ngx_queue_t                      *q;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;

    if (channel->active) {
        return 1;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_timelines_cleanup: called");

    add_timer = 0;
    min_segment_index = NGX_MAX_UINT32_VALUE;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        ngx_live_timeline_inactive_remove_segments(timeline,
            &min_segment_index);

        if (timeline->duration > 0 &&
            (timeline->conf.max_segments != NGX_MAX_UINT32_VALUE ||
                timeline->conf.max_duration != ULLONG_MAX))
        {
            add_timer = 1;
        }
    }

    ngx_live_timelines_free_old_segments(channel, min_segment_index);

    if (add_timer) {
        ngx_add_timer(&cctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    return min_segment_index != NGX_MAX_UINT32_VALUE;
}

static void
ngx_live_timelines_cleanup_handler(ngx_event_t *ev)
{
    ngx_live_channel_t  *channel = ev->data;

    ngx_live_timelines_cleanup(channel);
}

static ngx_int_t
ngx_live_timeline_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_init: alloc failed");
        return NGX_ERROR;
    }

    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    if (ngx_live_segment_list_init(channel,
        tpcf->bp_idx[NGX_LIVE_BP_SEGMENT_LIST_NODE], &cctx->segment_list)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_init: segment list init failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_timeline_module);

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel,
        ngx_str_rbtree_insert_value);
    ngx_queue_init(&cctx->queue);

    cctx->cleanup.handler = ngx_live_timelines_cleanup_handler;
    cctx->cleanup.data = channel;
    cctx->cleanup.log = &channel->log;

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    if (cctx != NULL && cctx->cleanup.timer_set) {
        ngx_del_timer(&cctx->cleanup);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_channel_inactive(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    ngx_add_timer(&cctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);

    return NGX_OK;
}

static size_t
ngx_live_timeline_last_periods_json_get_size(ngx_live_timeline_t *obj)
{
    uint32_t  count;

    count = obj->period_count;
    if (count > NGX_LIVE_TIMELINE_JSON_MAX_PERIODS) {
        count = NGX_LIVE_TIMELINE_JSON_MAX_PERIODS;
    }

    return sizeof("[]") - 1 +
        (ngx_live_period_json_get_size(NULL) + sizeof(",") - 1) * count;
}

static u_char *
ngx_live_timeline_last_periods_json_write(u_char *p, ngx_live_timeline_t *obj)
{
    uint32_t            count, skip;
    ngx_flag_t          comma;
    ngx_live_period_t  *cur;

    cur = obj->head_period;
    count = obj->period_count;
    if (count > NGX_LIVE_TIMELINE_JSON_MAX_PERIODS) {

        skip = count - NGX_LIVE_TIMELINE_JSON_MAX_PERIODS;
        count = NGX_LIVE_TIMELINE_JSON_MAX_PERIODS;

        for (; cur && skip > 0; cur = cur->next) {
            skip--;
        }
    }

    *p++ = '[';

    comma = 0;
    for (; cur && count > 0; cur = cur->next, count--) {

        if (comma) {
            *p++ = ',';

        } else {
            comma = 1;
        }

        p = ngx_live_period_json_write(p, cur);
    }

    *p++ = ']';

    return p;
}

size_t
ngx_live_timeline_channel_json_get_size(ngx_live_channel_t *channel)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_json_get_size(cctx);
}

u_char *
ngx_live_timeline_channel_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_json_write(p, cctx);
}

static size_t
ngx_live_timeline_json_writer_get_size(void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_module_json_get_size(cctx);
}

static u_char *
ngx_live_timeline_json_writer_write(u_char *p, void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_module_json_write(p, cctx);
}


static ngx_int_t
ngx_live_timeline_write_setup(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_timeline_t *timeline)
{
    ngx_wstream_t  *ws;

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_TIMELINE_PERSIST_BLOCK) != NGX_OK ||
        ngx_wstream_str(ws, &timeline->sn.str) != NGX_OK ||
        ngx_persist_write(write_ctx, &timeline->conf,
            sizeof(timeline->conf)) != NGX_OK ||
        ngx_persist_write(write_ctx, &timeline->manifest.conf,
            sizeof(timeline->manifest.conf)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_timeline_write_setup: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_timelines_write_setup(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        if (ngx_live_timeline_write_setup(write_ctx, timeline) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_read_setup(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                           rc;
    ngx_str_t                           id;
    ngx_live_channel_t                 *channel = obj;
    ngx_live_timeline_t                *timeline;
    ngx_live_timeline_conf_t           *conf;
    ngx_live_timeline_manifest_conf_t  *manifest_conf;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_setup: read id failed");
        return NGX_BAD_DATA;
    }

    conf = ngx_mem_rstream_get_ptr(rs, sizeof(*conf) + sizeof(*manifest_conf));
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_setup: "
            "read data failed, timeline: %V", &id);
        return NGX_BAD_DATA;
    }

    manifest_conf = (void *) (conf + 1);

    rc = ngx_live_timeline_create(channel, &id, conf, manifest_conf,
        rs->log, &timeline);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_setup: "
            "create failed, timeline: %V", &id);

        if (rc == NGX_EXISTS || rc == NGX_INVALID_ARG) {
            return NGX_BAD_DATA;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_timeline_channel_index_snap(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                          *q;
    ngx_live_timeline_t                  *timeline;
    ngx_live_timeline_snap_t             *ts;
    ngx_live_persist_snap_index_t        *snap = ectx;
    ngx_live_timeline_channel_ctx_t      *cctx;
    ngx_live_timeline_persist_channel_t  *cp;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    cp = ngx_palloc(snap->pool, sizeof(*cp) +
        sizeof(*ts) * (cctx->count + 1));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_index_snap: alloc failed");
        return NGX_ERROR;
    }

    ts = (void *) (cp + 1);

    ngx_live_set_ctx(snap, cp, ngx_live_timeline_module);

    cp->truncate = cctx->truncate;
    cp->last_segment_middle = cctx->last_segment_middle;
    cp->reserved = 0;

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        ts->id = timeline->int_id;
        ts->last_time = timeline->last_time;
        ts->last_segment_created = timeline->last_segment_created;

        ts->target_duration = timeline->manifest.target_duration;
        ts->target_duration_segments =
            timeline->manifest.target_duration_segments;
        ts->sequence = timeline->manifest.sequence;
        ts->last_modified = timeline->manifest.last_modified;
        ngx_memcpy(ts->last_durations, timeline->manifest.last_durations,
            sizeof(ts->last_durations));
        ts++;
    }

    ts->id = NGX_LIVE_INVALID_TIMELINE_ID;

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_write_periods(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                              last_index;
    ngx_live_period_t                    *period;
    ngx_live_timeline_t                  *timeline = obj;
    ngx_live_persist_snap_t              *snap;
    ngx_live_timeline_persist_period_t    pp;
    ngx_live_timeline_persist_periods_t   header;

    snap = ngx_persist_write_ctx(write_ctx);

    if (snap->scope.min_index > 0) {
        period = ngx_live_timeline_get_period_by_index(timeline,
            snap->scope.min_index, 0);
        if (period == NULL) {
            return NGX_OK;
        }

        if (period == timeline->head_period) {
            header.first_period_initial_time =
                timeline->first_period_initial_time;

        } else {
            header.first_period_initial_time = period->time;
        }

    } else {
        period = timeline->head_period;
        if (period == NULL) {
            return NGX_OK;
        }

        header.first_period_initial_time = timeline->first_period_initial_time;
    }

    header.merge = period->time > header.first_period_initial_time ||
        snap->scope.min_index > period->node.key;
    header.reserved = 0;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_TIMELINE_PERSIST_BLOCK_PERIODS) != NGX_OK ||
        ngx_persist_write(write_ctx, &header, sizeof(header)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_timeline_write_periods: write header failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    for (; period != NULL; period = period->next) {

        last_index = period->node.key + period->segment_count - 1;
        if (last_index > snap->scope.max_index) {
            last_index = snap->scope.max_index;
        }

        pp.segment_index = ngx_max(period->node.key, snap->scope.min_index);
        if (pp.segment_index > last_index) {
            continue;
        }

        pp.segment_count = last_index - pp.segment_index + 1;
        pp.correction = period->correction;

        if (ngx_persist_write(write_ctx, &pp, sizeof(pp)) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
                "ngx_live_timeline_write_periods: write failed");
            return NGX_ERROR;
        }
    }

    ngx_persist_write_block_close(write_ctx);      /* periods */

    return NGX_OK;
}


static ngx_int_t
ngx_live_timeline_write_index(ngx_persist_write_ctx_t *write_ctx,
    ngx_live_timeline_t *timeline, ngx_live_timeline_snap_t *ts)
{
    ngx_wstream_t                         *ws;
    ngx_live_timeline_persist_t            tp;
    ngx_live_timeline_persist_manifest_t   mp;

    ws = ngx_persist_write_stream(write_ctx);

    mp.availability_start_time = timeline->manifest.availability_start_time;
    mp.first_period_segment_index = timeline->manifest.first_period.node.key;
    mp.first_period_initial_time =
        timeline->manifest.first_period_initial_time;
    mp.first_period_initial_segment_index =
        timeline->manifest.first_period_initial_segment_index;
    mp.first_period_index = timeline->manifest.first_period_index;

    mp.target_duration = ts->target_duration;
    mp.target_duration_segments = ts->target_duration_segments;
    mp.sequence = ts->sequence;
    mp.last_modified = ts->last_modified;
    ngx_memcpy(mp.last_durations, ts->last_durations,
        sizeof(mp.last_durations));
    mp.reserved = 0;

    tp.last_time = ts->last_time;
    tp.last_segment_created = ts->last_segment_created;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_LIVE_TIMELINE_PERSIST_BLOCK) != NGX_OK ||
        ngx_wstream_str(ws, &timeline->sn.str) != NGX_OK ||
        ngx_persist_write(write_ctx, &tp, sizeof(tp)) != NGX_OK ||
        ngx_persist_write(write_ctx, &mp, sizeof(mp)) != NGX_OK ||
        ngx_live_persist_write_blocks(timeline->channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_INDEX_TIMELINE, timeline) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_timeline_write_index: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_timelines_write_index(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                          *q;
    ngx_live_channel_t                   *channel = obj;
    ngx_live_timeline_t                  *timeline;
    ngx_live_timeline_snap_t             *ts;
    ngx_live_persist_snap_index_t        *snap;
    ngx_live_timeline_channel_ctx_t      *cctx;
    ngx_live_timeline_persist_channel_t  *cp;

    snap = ngx_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_timeline_module);

    ts = (void *) (cp + 1);

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        for (; ts->id != timeline->int_id; ts++) {
            if (ts->id == NGX_LIVE_INVALID_TIMELINE_ID) {
                ngx_log_error(NGX_LOG_WARN, &timeline->log, 0,
                    "ngx_live_timelines_write_index: "
                    "timeline id %uD not found in snapshot", timeline->int_id);
                return NGX_OK;
            }
        }

        if (ngx_live_timeline_write_index(write_ctx, timeline, ts) != NGX_OK) {
            return NGX_ERROR;
        }

        ts++;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_read_alloc_period(ngx_live_timeline_t *timeline,
    ngx_live_timeline_persist_period_t *pp)
{
    ngx_int_t                         rc;
    ngx_live_period_t                *period;
    ngx_live_channel_t               *channel = timeline->channel;
    ngx_live_timeline_channel_ctx_t  *cctx;
    ngx_live_timeline_preset_conf_t  *tpcf;

    tpcf = ngx_live_get_module_preset_conf(channel, ngx_live_timeline_module);

    period = ngx_block_pool_alloc(channel->block_pool,
        tpcf->bp_idx[NGX_LIVE_BP_PERIOD]);
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_timeline_read_alloc_period: alloc failed");
        return NGX_ERROR;
    }

    period->node.key = pp->segment_index;
    period->segment_count = pp->segment_count;
    period->correction = pp->correction;
    period->next = NULL;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    rc = ngx_live_segment_iter_init(&cctx->segment_list,
        &period->segment_iter, pp->segment_index, 1, &period->time);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, &timeline->log, 0,
            "ngx_live_timeline_read_alloc_period: "
            "period start index %uD not found",
            pp->segment_index);
        return NGX_BAD_DATA;
    }

    rc = ngx_live_period_reset_duration(channel, period);
    if (rc != NGX_OK) {
        return NGX_BAD_DATA;
    }

    ngx_rbtree_insert(&timeline->rbtree, &period->node);

    if (timeline->head_period == NULL) {
        timeline->head_period = period;

    } else {
        timeline->last_period->next = period;
    }

    timeline->duration += period->duration;
    timeline->segment_count += period->segment_count;
    timeline->period_count++;

    timeline->last_period = period;

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_read_periods(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                              min_index;
    ngx_int_t                             rc;
    ngx_str_t                             data;
    ngx_live_period_t                    *period;
    ngx_live_channel_t                   *channel;
    ngx_live_timeline_t                  *timeline = obj;
    ngx_live_persist_index_scope_t       *scope;
    ngx_live_timeline_persist_period_t   *cur, *end;
    ngx_live_timeline_persist_periods_t   header;

    if (ngx_mem_rstream_read(rs, &header, sizeof(header)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_periods: read failed");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    cur = (void *) data.data;
    end = cur + data.len / sizeof(*cur);

    if (cur >= end) {
        return NGX_OK;
    }

    scope = ngx_mem_rstream_scope(rs);

    min_index = scope->min_index;

    period = timeline->last_period;
    if (period != NULL) {
        if (period->node.key + period->segment_count > min_index) {
            /* can happen due to duplicate block */
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_timeline_read_periods: "
                "last index %ui exceeds min index %uD",
                period->node.key + period->segment_count, min_index);
            return NGX_BAD_DATA;
        }

    } else {
        timeline->first_period_initial_time = header.first_period_initial_time;
    }

    channel = timeline->channel;

    for (; cur < end; cur++) {

        if (cur->segment_index < min_index) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_timeline_read_periods: "
                "segment index %uD less than min segment index %uD",
                cur->segment_index, min_index);
            return NGX_BAD_DATA;
        }

        if (cur->segment_index > scope->max_index ||
            cur->segment_count > scope->max_index - cur->segment_index + 1)
        {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_timeline_read_periods: "
                "last index outside scope, index: %uD, count: %uD, max: %uD",
                cur->segment_index, cur->segment_count, scope->max_index);
            return NGX_BAD_DATA;
        }

        if (cur->segment_count <= 0) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_timeline_read_periods: zero segment count");
            return NGX_BAD_DATA;
        }

        min_index = cur->segment_index + cur->segment_count;

        if (!header.merge) {
            rc = ngx_live_timeline_read_alloc_period(timeline, cur);
            if (rc != NGX_OK) {
                return rc;
            }

            continue;
        }

        header.merge = 0;

        if (period == NULL ||
            cur->segment_index != period->node.key + period->segment_count)
        {
            rc = ngx_live_timeline_read_alloc_period(timeline, cur);
            if (rc != NGX_OK) {
                return rc;
            }

            continue;
        }

        /* append to last period */

        period->segment_count += cur->segment_count;
        timeline->segment_count += cur->segment_count;

        timeline->duration -= period->duration;

        rc = ngx_live_period_reset_duration(channel, period);
        if (rc != NGX_OK) {
            return NGX_BAD_DATA;
        }

        timeline->duration += period->duration;
    }

    return NGX_OK;
}

static void
ngx_live_manifest_timeline_reset(ngx_live_manifest_timeline_t *timeline)
{
    ngx_live_period_t  *cur;

    timeline->duration = 0;
    timeline->segment_count = 0;
    timeline->period_count = 0;

    for (cur = &timeline->first_period; cur != NULL; cur = cur->next)
    {
        timeline->duration += cur->duration;
        timeline->segment_count += cur->segment_count;
        timeline->period_count++;
    }
}

static ngx_int_t
ngx_live_manifest_timeline_read(ngx_live_timeline_t *timeline,
    ngx_live_timeline_persist_manifest_t *mp)
{
    ngx_live_period_t                *src;
    ngx_live_period_t                *dst;
    ngx_live_channel_t               *channel;
    ngx_live_manifest_timeline_t     *manifest = &timeline->manifest;
    ngx_live_timeline_channel_ctx_t  *cctx;

    channel = timeline->channel;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    /* init first period + counters */
    dst = &manifest->first_period;
    if (mp->first_period_segment_index != NGX_LIVE_INVALID_SEGMENT_INDEX) {

        src = ngx_live_timeline_get_period_by_index(timeline,
            mp->first_period_segment_index, 1);
        if (src == NULL) {
            ngx_log_error(NGX_LOG_ERR, &timeline->log, 0,
                "ngx_live_manifest_timeline_read: "
                "segment index %uD not found in any period",
                mp->first_period_segment_index);
            return NGX_BAD_DATA;
        }

        if (ngx_live_segment_iter_init(&cctx->segment_list, &dst->segment_iter,
            mp->first_period_segment_index, 1, &dst->time) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, &timeline->log, 0,
                "ngx_live_manifest_timeline_read: "
                "segment index %uD not found in segment list",
                mp->first_period_segment_index);
            return NGX_ERROR;
        }

        dst->node.key = mp->first_period_segment_index;
        dst->duration = src->time + src->duration - dst->time;
        dst->segment_count = src->node.key + src->segment_count -
            dst->node.key;
        dst->next = src->next;

        ngx_live_manifest_timeline_reset(manifest);

    } else {

        ngx_memzero(dst, sizeof(*dst));
        dst->node.key = NGX_LIVE_INVALID_SEGMENT_INDEX;
        manifest->duration = 0;
        manifest->segment_count = 0;
        manifest->period_count = 0;
    }

    /* init other members */
    manifest->first_period_initial_time = mp->first_period_initial_time;
    manifest->first_period_initial_segment_index =
        mp->first_period_initial_segment_index;
    manifest->first_period_index = mp->first_period_index;
    manifest->sequence = mp->sequence;
    manifest->availability_start_time = mp->availability_start_time;
    manifest->last_modified = mp->last_modified;
    manifest->target_duration = mp->target_duration;
    manifest->target_duration_segments = mp->target_duration_segments;
    ngx_memcpy(manifest->last_durations, mp->last_durations,
        sizeof(manifest->last_durations));

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_read_index(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    uint32_t                               hash;
    ngx_int_t                              rc;
    ngx_str_t                              id;
    ngx_log_t                             *orig_log;
    ngx_live_channel_t                    *channel = obj;
    ngx_live_timeline_t                   *timeline;
    ngx_live_timeline_persist_t           *tp;
    ngx_live_timeline_channel_ctx_t       *cctx;
    ngx_live_timeline_persist_manifest_t  *mp;

    if (ngx_mem_rstream_str_get(rs, &id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_index: read id failed");
        return NGX_BAD_DATA;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    hash = ngx_crc32_short(id.data, id.len);
    timeline = (void *) ngx_str_rbtree_lookup(&cctx->rbtree, &id, hash);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_WARN, rs->log, 0,
            "ngx_live_timeline_read_index: timeline \"%V\" not found", &id);
        return NGX_OK;
    }

    orig_log = rs->log;
    rs->log = &timeline->log;

    tp = ngx_mem_rstream_get_ptr(rs, sizeof(*tp) + sizeof(*mp));
    if (tp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timeline_read_index: read failed, timeline: %V", &id);
        return NGX_BAD_DATA;
    }

    mp = (void *) (tp + 1);

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    rc = ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_INDEX_TIMELINE, rs, timeline);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_timeline_read_index: read blocks failed");
        return rc;
    }

    timeline->last_time = tp->last_time;
    timeline->last_segment_created = tp->last_segment_created;

    rc = ngx_live_manifest_timeline_read(timeline, mp);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_live_timeline_validate(timeline);

    rs->log = orig_log;

    return NGX_OK;
}


static ngx_int_t
ngx_live_timelines_channel_write_index(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_channel_t                   *channel = obj;
    ngx_live_persist_snap_index_t        *snap;
    ngx_live_timeline_persist_channel_t  *cp;

    snap = ngx_persist_write_ctx(write_ctx);

    cp = ngx_live_get_module_ctx(snap, ngx_live_timeline_module);

    /* Note: the full index file may contain segments that were truncated,
        need to save the truncate index in order to remove them when loading
        the delta */

    if (ngx_persist_write(write_ctx, cp, sizeof(*cp)) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timelines_channel_write_index: write failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_timelines_channel_read_index(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_channel_t                   *channel = obj;
    ngx_live_timeline_channel_ctx_t      *cctx;
    ngx_live_timeline_persist_channel_t  *cp;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    cp = ngx_mem_rstream_get_ptr(rs, sizeof(*cp));
    if (cp == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_timelines_channel_read_index: read failed");
        return NGX_BAD_DATA;
    }

    cctx->truncate = cp->truncate;
    cctx->last_segment_middle = cp->last_segment_middle;

    if (cctx->truncate > 0) {
        ngx_live_timelines_truncate(channel, cctx->truncate);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_timeline_write_segment_list(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_persist_write_blocks(channel, write_ctx,
        NGX_LIVE_PERSIST_CTX_INDEX_SEGMENT_LIST, &cctx->segment_list);
}

static ngx_int_t
ngx_live_timeline_read_segment_list(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        return NGX_BAD_DATA;
    }


    cctx->segment_list.is_first = 1;

    return ngx_live_persist_read_blocks(channel,
        NGX_LIVE_PERSIST_CTX_INDEX_SEGMENT_LIST, rs, &cctx->segment_list);
}


static ngx_int_t
ngx_live_timeline_serve_write(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t                   *ws;
    ngx_live_timeline_t             *timeline;
    ngx_ksmp_timeline_header_t       sp;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_TIMELINE)) {
        return NGX_OK;
    }

    timeline = scope->timeline;

    ws = ngx_persist_write_stream(write_ctx);

    sp.availability_start_time = timeline->manifest.availability_start_time;
    sp.period_count = timeline->manifest.period_count;
    sp.first_period_index = timeline->manifest.first_period_index;
    sp.first_period_initial_time =
        timeline->manifest.first_period_initial_time;
    sp.first_period_initial_segment_index =
        timeline->manifest.first_period_initial_segment_index;

    sp.sequence = timeline->manifest.sequence;
    sp.last_modified = timeline->manifest.last_modified;
    sp.target_duration = timeline->manifest.target_duration;
    sp.end_list = timeline->conf.end_list;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_TIMELINE) != NGX_OK ||
        ngx_wstream_str(ws, &timeline->sn.str) != NGX_OK ||
        ngx_persist_write(write_ctx, &sp, sizeof(sp)) != NGX_OK ||
        ngx_live_persist_write_blocks(timeline->channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_TIMELINE, timeline) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
            "ngx_live_timeline_serve_write: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_serve_write_periods(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                         i;
    ngx_live_period_t               *period;
    ngx_live_timeline_t             *timeline;
    ngx_live_segment_iter_t          iter;
    ngx_ksmp_period_header_t         pp;
    ngx_live_segment_repeat_t        sd;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_PERIODS)) {
        return NGX_OK;
    }

    timeline = obj;
    pp.reserved = 0;

    for (period = &timeline->manifest.first_period;
        period != NULL;
        period = period->next)
    {
        pp.time = period->time;
        pp.segment_index = period->node.key;

        if (ngx_persist_write_block_open(write_ctx,
                NGX_KSMP_BLOCK_PERIOD) != NGX_OK ||
            ngx_persist_write(write_ctx, &pp, sizeof(pp)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
                "ngx_live_timeline_serve_write_periods: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_set_header(write_ctx, 0);

        /* TODO: optimize - write whole segment list nodes if possible */

        iter = period->segment_iter;

        for (i = period->segment_count; i > 0; i -= sd.count) {
            ngx_live_segment_iter_get_element(&iter, &sd);

            if (sd.count > i) {
                sd.count = i;
            }

            if (ngx_persist_write(write_ctx, &sd, sizeof(sd)) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &timeline->log, 0,
                    "ngx_live_timeline_serve_write_periods: write failed");
                return NGX_ERROR;
            }
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_timeline_blocks[] = {
    /*
     * persist data:
     *   ngx_str_t                          id;
     *   ngx_live_timeline_conf_t           conf;
     *   ngx_live_timeline_manifest_conf_t  manifest_conf;
     */
    { NGX_LIVE_TIMELINE_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL, 0,
      ngx_live_timelines_write_setup,
      ngx_live_timeline_read_setup },

    { NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK,
      NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, NGX_PERSIST_FLAG_SINGLE,
      ngx_live_timeline_write_segment_list,
      ngx_live_timeline_read_segment_list },

    /*
     * persist header:
     *   ngx_live_segment_list_period_t  p;
     *
     * persist data:
     *   ngx_live_segment_repeat_t       sr[];
     */
    { NGX_LIVE_SEGMENT_LIST_PERSIST_BLOCK_PERIOD,
      NGX_LIVE_PERSIST_CTX_INDEX_SEGMENT_LIST, 0,
      ngx_live_segment_list_write_periods,
      ngx_live_segment_list_read_period },

    /*
     * persist header:
     *   ngx_str_t                             id;
     *   ngx_live_timeline_persist_t           p;
     *   ngx_live_timeline_persist_manifest_t  mp;
     */
    { NGX_LIVE_TIMELINE_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, 0,
      ngx_live_timelines_write_index,
      ngx_live_timeline_read_index },

    /*
     * persist header:
     *   ngx_live_timeline_persist_periods_t  p;
     *
     * persist data:
     *   ngx_live_timeline_persist_period_t   pp[];
     */
    { NGX_LIVE_TIMELINE_PERSIST_BLOCK_PERIODS,
      NGX_LIVE_PERSIST_CTX_INDEX_TIMELINE, 0,
      ngx_live_timeline_write_periods,
      ngx_live_timeline_read_periods },

    /*
     * persist data:
     *   ngx_live_timeline_persist_channel_t  p;
     */
    { NGX_LIVE_TIMELINE_PERSIST_BLOCK_CHANNEL,
      NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL, NGX_PERSIST_FLAG_SINGLE,
      ngx_live_timelines_channel_write_index,
      ngx_live_timelines_channel_read_index },

    /*
     * persist header:
     *   ngx_str_t                   id;
     *   ngx_ksmp_timeline_header_t  p;
     */
    { NGX_KSMP_BLOCK_TIMELINE, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
      ngx_live_timeline_serve_write, NULL },

    /*
     * persist header:
     *   ngx_ksmp_period_header_t  p;
     *
     * persist data:
     *   ngx_ksmp_segment_repeat_t  sd[];
     */
    { NGX_KSMP_BLOCK_PERIOD, NGX_LIVE_PERSIST_CTX_SERVE_TIMELINE, 0,
      ngx_live_timeline_serve_write_periods, NULL },

    ngx_null_persist_block
};

static ngx_int_t
ngx_live_timeline_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_timeline_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t    ngx_live_timeline_channel_events[] = {
    { ngx_live_timeline_channel_init,     NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_timeline_channel_free,     NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_timeline_channel_inactive, NGX_LIVE_EVENT_CHANNEL_INACTIVE },
    { ngx_live_timeline_channel_index_snap,
        NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_timeline_json_writers[] = {
    { { ngx_live_timeline_json_writer_get_size,
        ngx_live_timeline_json_writer_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_timeline_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_timeline_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_timeline_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_live_timeline_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_timeline_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_timeline_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_live_timeline_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_timeline_preset_conf_t  *conf = child;

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_PERIOD],
        sizeof(ngx_live_period_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_TIMELINE],
        sizeof(ngx_live_timeline_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_core_add_block_pool_index(cf,
        &conf->bp_idx[NGX_LIVE_BP_SEGMENT_LIST_NODE],
        ngx_live_segment_list_get_node_size()) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
