#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "../ngx_live_timeline.h"
#include "../ngx_live_segment_cache.h"
#include "ngx_live_persist_core.h"


typedef struct {
    ngx_live_variant_t           *variant;
    ngx_ksmp_rendition_report_t   elts[KMP_MEDIA_COUNT];
    ngx_uint_t                    nelts;
} ngx_live_persist_variant_rr_t;


static ngx_int_t ngx_live_persist_serve_preconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_persist_serve_module_ctx = {
    ngx_live_persist_serve_preconfiguration,  /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    NULL                                      /* merge preset configuration */
};


ngx_module_t  ngx_live_persist_serve_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_serve_module_ctx,       /* module context */
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


static ngx_int_t
ngx_live_persist_serve_write_variant(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_uint_t                       i;
    ngx_wstream_t                   *ws;
    ngx_live_channel_t              *channel = obj;
    ngx_live_variant_t              *cur_variant;
    ngx_ksmp_variant_t               v;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);

    ws = ngx_persist_write_stream(write_ctx);

    for (i = 0; i < scope->header.variant_count; i++) {

        cur_variant = scope->variants[i];

        v.role = cur_variant->conf.role;
        v.is_default = cur_variant->conf.is_default;

        if (ngx_persist_write_block_open(write_ctx,
                NGX_KSMP_BLOCK_VARIANT) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &v, sizeof(v)) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.label.s) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.lang.s) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_SERVE_VARIANT, cur_variant) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_serve_write_variant: "
                "write failed, variant: %V", &cur_variant->sn.str);
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_serve_write_track(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    uint32_t                         min_index;
    ngx_uint_t                       i;
    ngx_live_track_t                *cur_track;
    ngx_live_channel_t              *channel;
    ngx_live_variant_t              *variant = obj;
    ngx_ksmp_track_header_t          tp;
    ngx_live_persist_serve_scope_t  *scope;

    channel = variant->channel;

    scope = ngx_persist_write_ctx(write_ctx);

    min_index = scope->min_index;

    for (i = 0; i < KMP_MEDIA_COUNT; i++) {

        if (!(variant->output_media_types & (1 << i))) {
            continue;
        }

        cur_track = variant->tracks[i];

        tp.id = cur_track->in.key;
        tp.media_type = cur_track->media_type;

        scope->min_index = min_index;
        if (!(scope->flags & NGX_KSMP_FLAG_BACK_FILL) &&
            cur_track->initial_segment_index > min_index &&
            cur_track->initial_segment_index > variant->initial_segment_index)
        {
            scope->min_index = cur_track->initial_segment_index;
        }

        if (ngx_persist_write_block_open(write_ctx,
                NGX_KSMP_BLOCK_TRACK) != NGX_OK ||
            ngx_persist_write(write_ctx, &tp, sizeof(tp)) != NGX_OK ||
            ngx_live_persist_write_blocks(channel, write_ctx,
                NGX_LIVE_PERSIST_CTX_SERVE_TRACK, cur_track) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                "ngx_live_persist_serve_write_track: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);

        scope->header.track_count++;
    }

    scope->min_index = min_index;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_serve_write_segment_index(
    ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_channel_t              *channel = obj;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);
    if (scope->si.index == NGX_LIVE_INVALID_SEGMENT_INDEX) {
        return NGX_OK;
    }

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_SEGMENT_INDEX) != NGX_OK ||
        ngx_persist_write(write_ctx, &scope->si, sizeof(scope->si)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_serve_write_segment_index: write failed");
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}


/* rendition reports */

static ngx_flag_t
ngx_live_persist_serve_get_track_rr(ngx_live_timeline_t *timeline,
    ngx_live_track_t *track, ngx_ksmp_rendition_report_t *rr)
{
    uint32_t             sequence;
    uint32_t             last_index;
    uint32_t             segment_index;
    ngx_queue_t         *q;
    ngx_live_period_t   *period;
    ngx_live_channel_t  *channel;

    channel = timeline->channel;

    segment_index = channel->next_segment_index + track->pending_index;
    if (track->next_part_index == 0) {
        segment_index--;
    }

    sequence = timeline->manifest.sequence;

    /* assuming the timeline has at least one period */

    q = ngx_queue_last(&timeline->periods);

    for ( ;; ) {

        period = ngx_queue_data(q, ngx_live_period_t, queue);

        last_index = period->node.key + period->segment_count;
        if (segment_index >= last_index) {
            rr->last_sequence = sequence - 1;
            segment_index = last_index - 1;
            break;
        }

        if (segment_index >= period->node.key) {
            rr->last_sequence = sequence - (last_index - segment_index);
            break;
        }

        sequence -= period->segment_count;

        q = ngx_queue_prev(q);
        if (q == ngx_queue_sentinel(&timeline->periods)) {
            return 0;
        }
    }

    rr->last_part_index = ngx_live_segment_cache_get_last_part(track,
        segment_index);

    if (rr->last_part_index == NGX_LIVE_INVALID_PART_INDEX) {
        return 0;
    }

    return 1;
}


static void
ngx_live_persist_serve_get_variant_rrs(ngx_live_persist_variant_rr_t *var_rr,
    ngx_live_timeline_t *timeline, ngx_ksmp_rendition_report_t *skip_rr)
{
    ngx_uint_t                    media_type;
    ngx_live_track_t             *cur_track;
    ngx_live_variant_t           *variant;
    ngx_ksmp_rendition_report_t  *rr;

    variant = var_rr->variant;

    var_rr->nelts = 0;
    rr = var_rr->elts;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {

        cur_track = variant->tracks[media_type];
        if (cur_track == NULL) {
            continue;
        }

        if (!ngx_live_persist_serve_get_track_rr(timeline, cur_track, rr)) {
            continue;
        }

        if (rr->last_sequence == skip_rr->last_sequence
            && rr->last_part_index == skip_rr->last_part_index)
        {
            continue;
        }

        rr->media_type = media_type;

        var_rr->nelts++;
        rr++;
    }
}


static ngx_int_t
ngx_live_persist_serve_write_variant_rrs(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_wstream_t                  *ws;
    ngx_live_variant_t             *variant;
    ngx_live_persist_variant_rr_t  *rr = obj;

    variant = rr->variant;

    ws = ngx_persist_write_stream(write_ctx);

    if (ngx_wstream_str(ws, &variant->sn.str) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &variant->channel->log, 0,
            "ngx_live_persist_serve_write_variant_rrs: "
            "write failed (1), variant: %V", &variant->sn.str);
        return NGX_ERROR;
    }

    ngx_persist_write_block_set_header(write_ctx, 0);

    if (ngx_persist_write(write_ctx, rr->elts,
        sizeof(rr->elts[0]) * rr->nelts) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &variant->channel->log, 0,
            "ngx_live_persist_serve_write_variant_rrs: "
            "write failed (2), variant: %V", &variant->sn.str);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_serve_write_rrs(ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_queue_t                          *q;
    ngx_live_channel_t                   *channel = obj;
    ngx_live_timeline_t                  *timeline;
    ngx_persist_write_marker_t            marker;
    ngx_ksmp_rendition_report_t           skip_rr;
    ngx_live_persist_variant_rr_t         rr;
    ngx_live_persist_serve_scope_t       *scope;
    ngx_ksmp_rendition_reports_header_t   header;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_RENDITION_REPORTS)) {
        return NGX_OK;
    }

    timeline = scope->timeline;
    if (scope->track != NULL) {
        if (!ngx_live_persist_serve_get_track_rr(scope->timeline, scope->track,
            &skip_rr))
        {
            return NGX_OK;
        }

    } else {
        ngx_memset(&skip_rr, 0xff, sizeof(skip_rr));
    }

    header.count = 0;

    for (q = ngx_queue_head(&channel->variants.queue);
        q != ngx_queue_sentinel(&channel->variants.queue);
        q = ngx_queue_next(q))
    {
        rr.variant = ngx_queue_data(q, ngx_live_variant_t, queue);
        if (!rr.variant->active) {
            continue;
        }

        ngx_live_persist_serve_get_variant_rrs(&rr, timeline, &skip_rr);
        if (rr.nelts <= 0) {
            continue;
        }

        if (header.count <= 0) {
            if (ngx_persist_write_block_open(write_ctx,
                    NGX_KSMP_BLOCK_RENDITION_REPORT) != NGX_OK ||
                ngx_persist_write_reserve(write_ctx, sizeof(header), &marker)
                    != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                    "ngx_live_persist_serve_write_rrs: write failed");
                return NGX_ERROR;
            }
        }

        if (ngx_live_persist_write_blocks(channel, write_ctx,
            NGX_LIVE_PERSIST_CTX_SERVE_VARIANT_RR, &rr) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_persist_serve_write_rrs: write blocks failed");
            return NGX_ERROR;
        }

        header.count++;
    }

    if (header.count <= 0) {
        return NGX_OK;
    }

    ngx_persist_write_marker_write(&marker, &header, sizeof(header));

    ngx_persist_write_block_close(write_ctx);

    return NGX_OK;
}


static ngx_persist_block_t  ngx_live_persist_serve_blocks[] = {
    /*
     * persist header:
     *   ngx_str_t                  id;
     *   ngx_ksmp_channel_header_t  p;
     */
    { NGX_KSMP_BLOCK_CHANNEL, NGX_LIVE_PERSIST_CTX_SERVE_MAIN,
      0, NULL, NULL },

    /*
     * persist header:
     *   ngx_ksmp_track_header_t  p;
     */
    { NGX_KSMP_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_SERVE_VARIANT, 0,
      ngx_live_persist_serve_write_track, NULL },

    /*
     * persist data:
     *   ngx_str_t           id;
     *   ngx_ksmp_variant_t  p;
     *   ngx_str_t           label;
     *   ngx_str_t           lang;
     *   uint32_t            track_id[p.track_count];
     */
    { NGX_KSMP_BLOCK_VARIANT, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
      ngx_live_persist_serve_write_variant, NULL },

    /*
     * persist data:
     *   ngx_ksmp_segment_index_t  p;
     */
    { NGX_KSMP_BLOCK_SEGMENT_INDEX, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
      ngx_live_persist_serve_write_segment_index, NULL },

    /*
     * persist header:
     *   ngx_str_t  variant_id;
     *
     * persist data:
     *   ngx_ksmp_rendition_report_t  elts[];
     */
    { NGX_KSMP_BLOCK_VARIANT_RR, NGX_LIVE_PERSIST_CTX_SERVE_VARIANT_RR,
      NGX_PERSIST_FLAG_SINGLE,
      ngx_live_persist_serve_write_variant_rrs, NULL },

    /*
     * persist header:
     *   ngx_ksmp_rendition_reports_header_t  header;
     */
    { NGX_KSMP_BLOCK_RENDITION_REPORT, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
      ngx_live_persist_serve_write_rrs, NULL },

    /*
     * persist data:
     *   uint32_t   code;
     *   ngx_str_t  message;
     */
    { NGX_KSMP_BLOCK_ERROR, NGX_LIVE_PERSIST_CTX_SERVE_MAIN,
      0, NULL, NULL },

      ngx_null_persist_block
};


static ngx_int_t
ngx_live_persist_serve_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_persist_add_blocks(cf, ngx_live_persist_serve_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
