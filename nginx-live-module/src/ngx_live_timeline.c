#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include "ngx_live_timeline.h"


#define NGX_LIVE_TIMELINE_CLEANUP_INTERVAL  60000


enum {
    NGX_LIVE_BP_PERIOD,
    NGX_LIVE_BP_TIMELINE,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    ngx_block_pool_t         *block_pool;
    ngx_live_segment_list_t   segment_list;
    ngx_rbtree_t              tree;
    ngx_rbtree_node_t         sentinel;
    ngx_queue_t               queue;        /* ngx_live_timeline_t */
    ngx_event_t               cleanup;
    int64_t                   last_segment_middle;
} ngx_live_timeline_channel_ctx_t;


#include "ngx_live_timeline_json.h"


static ngx_int_t ngx_live_timeline_postconfiguration(ngx_conf_t *cf);

static void ngx_live_timeline_inactive_remove_segments(
    ngx_live_timeline_t *timeline, uint32_t *min_segment_index);


static ngx_live_module_t  ngx_live_timeline_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_timeline_postconfiguration,      /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    NULL,                                     /* merge preset configuration */
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
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    period = ngx_block_pool_alloc(ctx->block_pool, NGX_LIVE_BP_PERIOD);
    if (period == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_period_create: alloc failed");
        return NULL;
    }

    period->next = NULL;
    period->duration = 0;
    period->segment_count = 0;

    ngx_live_segment_iter_last(&ctx->segment_list, &period->segment_iter);

    return period;
}

static void
ngx_live_period_free(ngx_live_timeline_channel_ctx_t *ctx,
    ngx_live_period_t *period)
{
    ngx_block_pool_free(ctx->block_pool, NGX_LIVE_BP_PERIOD, period);
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

    for (i = period->segment_count; ; i -= segment_duration.repeat_count) {

        ngx_live_segment_iter_get_element(&iter, &segment_duration);

        if (segment_duration.duration > *max_duration) {
            *max_duration = segment_duration.duration;
        }

        if (i <= segment_duration.repeat_count) {
            break;
        }
    }
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
        i -= segment_duration.repeat_count)
    {
        ngx_live_segment_iter_get_element(&iter, &segment_duration);

        if (segment_duration.repeat_count > i) {
            segment_duration.repeat_count = i;
        }

        duration += (uint64_t) segment_duration.duration *
            segment_duration.repeat_count;
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

    if (period->segment_count > 0) {
        return;
    }

    timeline->period_count--;
    timeline->first_period_index++;

    if (period->next == NULL) {
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
    ngx_live_timeline_channel_ctx_t *ctx,
    ngx_live_manifest_timeline_t *timeline, int64_t time,
    uint32_t segment_index)
{
    ngx_live_period_t  *period = &timeline->first_period;

    period->node.key = segment_index;
    period->next = NULL;
    period->time = time;
    period->duration = 0;
    period->segment_count = 0;

    ngx_live_segment_iter_last(&ctx->segment_list,
        &period->segment_iter);

    if (timeline->availability_start_time == 0) {
        timeline->availability_start_time = time;
    }
    timeline->first_period_initial_time = time;
    timeline->first_period_initial_segment_index = segment_index;

    timeline->period_count = 1;
}

static void
ngx_live_manifest_timeline_add_period(ngx_live_timeline_channel_ctx_t *ctx,
    ngx_live_manifest_timeline_t *timeline, ngx_live_period_t *period)
{
    switch (timeline->period_count) {

    case 0:
        ngx_live_manifest_timeline_add_first_period(ctx, timeline,
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
    if (timeline->sequence < timeline->conf.target_duration_segments &&
        duration > timeline->target_duration) {
        timeline->target_duration = duration;
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
    ngx_live_timeline_t *source, uint32_t period_count, uint32_t max_duration)
{
    dest->manifest.first_period = *dest->head_period;
    dest->manifest.availability_start_time = dest->manifest.first_period.time;
    dest->manifest.first_period_initial_time =
        dest->manifest.first_period.time;
    dest->manifest.first_period_initial_segment_index =
        dest->manifest.first_period.node.key;
    dest->manifest.sequence = dest->segment_count;

    dest->manifest.duration = dest->duration;
    dest->manifest.segment_count = dest->segment_count;
    dest->manifest.period_count = period_count;

    dest->manifest.target_duration = max_duration;

    /* Note: if the end of dest timeline is different than source, the below
        is incorrect. however, since last_durations is only used to estimate
        the segment duration, it's probably good enough */
    ngx_memcpy(dest->manifest.last_durations, source->manifest.last_durations,
        sizeof(dest->manifest.last_durations));

    dest->manifest.last_modified = ngx_time();
}


/* timeline */

static ngx_int_t
ngx_live_timeline_validate_conf(ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log)
{
    if (!conf->end) {
        conf->end = LLONG_MAX;
    }

    if (conf->start >= conf->end) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_validate_conf: "
            "start offset must be lower than end offset",
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
            "ngx_live_timeline_validate_conf: "
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
            "ngx_live_timeline_validate_conf: "
            "manifest max duration %uL larger than max duration %uL",
            manifest_conf->max_duration, conf->max_duration);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_timeline_create(ngx_live_channel_t *channel, ngx_str_t *id,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log,
    ngx_live_timeline_t **result)
{
    uint32_t                          hash;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *ctx;

    if (id->len > sizeof(timeline->id_buf)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_timeline_create: timeline id \"%V\" too long", id);
        return NGX_DECLINED;
    }

    if (ngx_live_timeline_validate_conf(conf, manifest_conf, log) != NGX_OK) {
        return NGX_DECLINED;
    }

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);
    hash = ngx_crc32_short(id->data, id->len);
    timeline = (ngx_live_timeline_t *) ngx_str_rbtree_lookup(&ctx->tree, id,
        hash);
    if (timeline != NULL) {
        *result = timeline;
        return NGX_BUSY;
    }

    timeline = ngx_block_pool_calloc(ctx->block_pool, NGX_LIVE_BP_TIMELINE);
    if (timeline == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_timeline_create: alloc failed");
        return NGX_ERROR;
    }

    if (conf->end <= ctx->last_segment_middle) {
        conf->active = 0;
    }

    timeline->sn.str.data = timeline->id_buf;
    timeline->sn.str.len = id->len;
    ngx_memcpy(timeline->sn.str.data, id->data, timeline->sn.str.len);
    timeline->sn.node.key = hash;
    timeline->channel = channel;

    timeline->conf = *conf;

    timeline->manifest.conf = *manifest_conf;
    timeline->manifest.last_modified = ngx_time();

    ngx_rbtree_init(&timeline->rbtree, &timeline->sentinel,
        ngx_rbtree_insert_value);

    ngx_rbtree_insert(&ctx->tree, &timeline->sn.node);

    ngx_queue_insert_tail(&ctx->queue, &timeline->queue);

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_timeline_create: created %p, timeline: %V",
        timeline, &timeline->sn.str);

    *result = timeline;

    return NGX_OK;
}

void
ngx_live_timeline_free(ngx_live_timeline_t *timeline)
{
    ngx_live_period_t                *period;
    ngx_live_channel_t               *channel = timeline->channel;
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    /* free the periods (no reason to remove from tree/queue) */
    for (period = timeline->head_period; period; period = period->next) {
        ngx_live_period_free(ctx, period);
    }

    ngx_rbtree_delete(&ctx->tree, &timeline->sn.node);
    ngx_queue_remove(&timeline->queue);
    ngx_block_pool_free(ctx->block_pool, NGX_LIVE_BP_TIMELINE, timeline);

    if (!channel->active && !ctx->cleanup.timer_set) {
        ngx_add_timer(&ctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }
}

ngx_live_timeline_t *
ngx_live_timeline_get(ngx_live_channel_t *channel, ngx_str_t *id)
{
    uint32_t                          hash;
    uint32_t                          ignore;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    hash = ngx_crc32_short(id->data, id->len);
    timeline = (void*) ngx_str_rbtree_lookup(&ctx->tree, id, hash);
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
ngx_live_timeline_contains_segment(ngx_live_timeline_t *timeline,
    uint32_t segment_index)
{
    ngx_rbtree_t       *rbtree = &timeline->rbtree;
    ngx_rbtree_node_t  *node;
    ngx_rbtree_node_t  *sentinel;
    ngx_live_period_t  *period;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (segment_index < node->key) {
            node = node->left;

        } else {
            period = (ngx_live_period_t*) node;
            if (segment_index < node->key + period->segment_count) {
                return 1;
            }

            node = node->right;
        }
    }

    return 0;
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

    return ngx_time() > (time_t)(timeline->last_segment_created + expiry);
}

ngx_int_t
ngx_live_timeline_update(ngx_live_timeline_t *timeline,
    ngx_live_timeline_conf_t *conf,
    ngx_live_timeline_manifest_conf_t *manifest_conf, ngx_log_t *log)
{
    ngx_live_channel_t               *channel;
    ngx_live_timeline_channel_ctx_t  *ctx;

    if (ngx_live_timeline_validate_conf(conf, manifest_conf, log) != NGX_OK) {
        return NGX_ERROR;
    }

    channel = timeline->channel;
    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    if (conf->end <= ctx->last_segment_middle) {
        conf->active = 0;
    }

    timeline->conf = *conf;
    timeline->manifest.conf = *manifest_conf;

    if (!channel->active && !ctx->cleanup.timer_set) {
        ngx_add_timer(&ctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    return NGX_OK;
}

#if (NGX_LIVE_VALIDATIONS)
static void
ngx_live_timeline_validate(ngx_live_timeline_t *timeline)
{
    ngx_log_t          *log = &timeline->channel->log;
    uint64_t            duration;
    uint32_t            period_count;
    uint32_t            segment_count;
    ngx_live_period_t  *period;
    ngx_live_period_t  *prev_period;

    duration = 0;
    segment_count = 0;
    prev_period = NULL;

    for (period = timeline->head_period; period; period = period->next) {

        ngx_live_period_validate(period, log);

        duration += period->duration;
        segment_count += period->segment_count;

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
    }

    if (timeline->manifest.duration != duration) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest timeline duration %uL expected %uL",
            timeline->manifest.duration, duration);
        ngx_debug_point();
    }

    if (timeline->manifest.segment_count != segment_count) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ngx_live_timeline_validate: "
            "invalid manifest timeline segment count %uD expected %uD",
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
    uint32_t                          duration;
    ngx_live_period_t                *period = timeline->head_period;
    ngx_live_timeline_channel_ctx_t  *ctx;

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
    }

    ctx = ngx_live_get_module_ctx(timeline->channel, ngx_live_timeline_module);

    ngx_live_period_free(ctx, period);
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
    ngx_live_core_preset_conf_t  *cpcf;

    if (ngx_time() <= timeline->last_segment_created ||
        timeline->duration <= 0)
    {
        return;
    }

    cpcf = ngx_live_get_module_preset_conf(timeline->channel,
        ngx_live_core_module);

    base_duration = (uint64_t)(ngx_time() - timeline->last_segment_created) *
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

        period = (ngx_live_period_t*) node;
        if (time < period->time) {
            if (node->left == sentinel) {
                return period;
            }
            node = node->left;

        } else if (time >= (int64_t)(period->time + period->duration)) {
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
ngx_live_timeline_copy(ngx_live_timeline_t *dest, ngx_live_timeline_t *source)
{
    int64_t                           segment_time;
    int64_t                           src_period_end;
    uint32_t                          ignore;
    uint32_t                          max_duration;
    uint32_t                          period_count;
    uint32_t                          segment_index;
    ngx_live_period_t                *src_period;
    ngx_live_period_t                *dest_period;
    ngx_live_channel_t               *channel = dest->channel;
    ngx_live_segment_iter_t           dummy_iter;
    ngx_live_timeline_channel_ctx_t  *ctx;

    /* Note: assuming dest is an empty, freshly-created timeline */

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    src_period = ngx_live_timeline_get_period_by_time(source,
        dest->conf.start);

    period_count = 0;
    max_duration = 0;

    for ( ; src_period; src_period = src_period->next) {

        if (src_period->time >= dest->conf.end) {
            break;
        }

        dest_period = ngx_block_pool_alloc(ctx->block_pool,
            NGX_LIVE_BP_PERIOD);
        if (dest_period == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_timeline_copy: alloc failed");
            return NGX_ERROR;
        }

        if (dest->conf.start <= src_period->time) {
            dest_period->node.key = src_period->node.key;
            dest_period->time = src_period->time;
            dest_period->segment_iter = src_period->segment_iter;

        } else {
            if (ngx_live_segment_list_get_closest_segment(&ctx->segment_list,
                dest->conf.start, &segment_index, &dest_period->time,
                &dest_period->segment_iter) != NGX_OK) {
                ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                    "ngx_live_timeline_copy: "
                    "get closest segment failed (1)");
                ngx_live_period_free(ctx, dest_period);
                return NGX_ERROR;
            }
            dest_period->node.key = segment_index;
        }

        src_period_end = src_period->time + src_period->duration;
        if (dest->conf.end >= src_period_end) {
            segment_index = src_period->node.key + src_period->segment_count;
            segment_time = src_period->time + src_period->duration;

        } else {
            if (ngx_live_segment_list_get_closest_segment(&ctx->segment_list,
                dest->conf.end, &segment_index, &segment_time,
                &dummy_iter) != NGX_OK) {
                ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                    "ngx_live_timeline_copy: "
                    "get closest segment failed (2)");
                ngx_live_period_free(ctx, dest_period);
                return NGX_ERROR;
            }
        }

        dest_period->segment_count = segment_index - dest_period->node.key;
        if (dest_period->segment_count <= 0) {
            ngx_live_period_free(ctx, dest_period);
            continue;
        }

        dest_period->duration = segment_time - dest_period->time;
        dest_period->next = NULL;

        ngx_rbtree_insert(&dest->rbtree, &dest_period->node);

        if (dest->head_period == NULL) {
            dest->head_period = dest_period;

        } else {
            dest->last_period->next = dest_period;
        }

        dest->last_period = dest_period;

        dest->segment_count += dest_period->segment_count;
        dest->duration += dest_period->duration;

        period_count++;
        ngx_live_period_get_max_duration(dest_period, &max_duration);
    }

    if (period_count <= 0) {
        return NGX_OK;
    }

    dest->last_segment_created = source->last_segment_created;

    ngx_live_timeline_manifest_copy(dest, source, period_count, max_duration);

    ignore = 0;
    if (dest->conf.active) {
        ngx_live_timeline_remove_segments(dest, 0, 0, &ignore);

    } else {
        ngx_live_timeline_inactive_remove_segments(dest, &ignore);
    }

    if (!channel->active && !ctx->cleanup.timer_set) {
        ngx_add_timer(&ctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }

    ngx_live_timeline_validate(dest);

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
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    ngx_live_segment_list_free_nodes(&ctx->segment_list, min_segment_index);

    (void) ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE,
        (void*) (uintptr_t) min_segment_index);
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
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    segment_index = channel->next_segment_index;

    rc = ngx_live_segment_list_add(&ctx->segment_list, segment_index, time,
        duration);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_add_segment: add failed");
        return rc;
    }

    ctx->last_segment_middle = time + duration / 2;

    min_segment_index = NGX_MAX_UINT32_VALUE;
    added = 0;

    /* add to active timelines */
    for (q = ngx_queue_head(&ctx->queue);
        q != ngx_queue_sentinel(&ctx->queue);
        q = ngx_queue_next(q))
    {
        timeline = ngx_queue_data(q, ngx_live_timeline_t, queue);

        if (!timeline->conf.active ||
            ctx->last_segment_middle < timeline->conf.start)
        {
            ngx_live_timeline_inactive_remove_segments(timeline,
                &min_segment_index);
            continue;
        }

        if (ctx->last_segment_middle >= timeline->conf.end) {
            timeline->conf.active = 0;
            ngx_live_timeline_inactive_remove_segments(timeline,
                &min_segment_index);
            continue;
        }

        period = timeline->last_period;
        if (period == NULL ||
            time != (int64_t)(period->time + period->duration) ||
            segment_index != period->node.key + period->segment_count ||
            force_new_period)
        {
            /* create a new period */
            period = ngx_live_period_create(channel);
            if (period == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                    "ngx_live_timeline_add_segment: failed to create period");
                return NGX_ERROR;
            }

            period->node.key = segment_index;
            period->time = time;

            ngx_rbtree_insert(&timeline->rbtree, &period->node);

            if (timeline->head_period == NULL) {
                timeline->head_period = period;

            } else {
                timeline->last_period->next = period;
            }

            timeline->last_period = period;

            ngx_live_manifest_timeline_add_period(ctx, &timeline->manifest,
                period);

        } else if (timeline->manifest.period_count == 0) {
            ngx_live_manifest_timeline_add_first_period(
                ctx, &timeline->manifest, time, segment_index);
        }

        /* add the segment */
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

    /* notify the creation */
    rc = ngx_live_core_channel_event(channel,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_CREATED, (void *) added);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_add_segment: event failed");
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
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    for (q = ngx_queue_head(&ctx->queue);
        q != ngx_queue_sentinel(&ctx->queue);
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
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_segment_list_get_segment_time(&ctx->segment_list,
        segment_index, result);
}

static void
ngx_live_timelines_cleanup_handler(ngx_event_t *ev)
{
    uint32_t                          min_segment_index;
    ngx_flag_t                        add_timer;
    ngx_queue_t                      *q;
    ngx_live_channel_t               *channel = ev->data;
    ngx_live_timeline_t              *timeline;
    ngx_live_timeline_channel_ctx_t  *ctx;

    if (channel->active) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_timelines_cleanup_handler: called");

    add_timer = 0;
    min_segment_index = NGX_MAX_UINT32_VALUE;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    for (q = ngx_queue_head(&ctx->queue);
        q != ngx_queue_sentinel(&ctx->queue);
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
        ngx_add_timer(&ctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);
    }
}

static ngx_int_t
ngx_live_timeline_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    size_t                            block_sizes[NGX_LIVE_BP_COUNT];
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_pcalloc(channel->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_init: alloc failed");
        return NGX_ERROR;
    }

    block_sizes[NGX_LIVE_BP_PERIOD] = sizeof(ngx_live_period_t);
    block_sizes[NGX_LIVE_BP_TIMELINE] = sizeof(ngx_live_timeline_t);

    ctx->block_pool = ngx_live_channel_create_block_pool(channel, block_sizes,
        NGX_LIVE_BP_COUNT);
    if (ctx->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_init: create pool failed");
        return NGX_ERROR;
    }

    if (ngx_live_segment_list_init(channel, &ctx->segment_list) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_timeline_channel_init: segment list init failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, ctx, ngx_live_timeline_module);

    ngx_rbtree_init(&ctx->tree, &ctx->sentinel, ngx_str_rbtree_insert_value);
    ngx_queue_init(&ctx->queue);

    ctx->cleanup.handler = ngx_live_timelines_cleanup_handler;
    ctx->cleanup.data = channel;
    ctx->cleanup.log = &channel->log;

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    if (ctx->cleanup.timer_set) {
        ngx_del_timer(&ctx->cleanup);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_timeline_channel_inactive(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    ngx_add_timer(&ctx->cleanup, NGX_LIVE_TIMELINE_CLEANUP_INTERVAL);

    return NGX_OK;
}

size_t
ngx_live_timeline_channel_json_get_size(ngx_live_channel_t *channel)
{
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_json_get_size(ctx);
}

u_char *
ngx_live_timeline_channel_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_json_write(p, ctx);
}

static size_t
ngx_live_timeline_json_writer_get_size(void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_module_json_get_size(ctx);
}

static u_char *
ngx_live_timeline_json_writer_write(u_char *p, void *obj)
{
    ngx_live_channel_t               *channel = obj;
    ngx_live_timeline_channel_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(channel, ngx_live_timeline_module);

    return ngx_live_timelines_module_json_write(p, ctx);
}


static ngx_live_channel_event_t    ngx_live_timeline_channel_events[] = {
    { ngx_live_timeline_channel_init,     NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_timeline_channel_free,     NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_timeline_channel_inactive, NGX_LIVE_EVENT_CHANNEL_INACTIVE },
      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_timeline_json_writers[] = {
    { { ngx_live_timeline_json_writer_get_size,
        ngx_live_timeline_json_writer_write},
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_timeline_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_timeline_channel_events) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_timeline_json_writers) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
