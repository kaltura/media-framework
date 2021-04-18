#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_persist_internal.h"


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
    uint32_t                        *cur_id;
    uint32_t                         track_ids[KMP_MEDIA_COUNT];
    ngx_uint_t                       i, j;
    ngx_wstream_t                   *ws;
    ngx_live_track_t                *cur_track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_variant_t              *cur_variant;
    ngx_ksmp_variant_t               v;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);

    ws = ngx_persist_write_stream(write_ctx);

    for (i = 0; i < scope->variant_count; i++) {

        cur_variant = scope->variants[i];

        cur_id = track_ids;
        for (j = 0; j < KMP_MEDIA_COUNT; j++) {
            cur_track = cur_variant->tracks[j];
            if (cur_track == NULL || !cur_track->output) {
                continue;
            }

            *cur_id++ = cur_track->in.key;
        }

        v.role = cur_variant->conf.role;
        v.is_default = cur_variant->conf.is_default;
        v.track_count = cur_id - track_ids;

        if (ngx_persist_write_block_open(write_ctx,
                NGX_KSMP_BLOCK_VARIANT) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->sn.str) != NGX_OK ||
            ngx_persist_write(write_ctx, &v, sizeof(v)) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.label) != NGX_OK ||
            ngx_wstream_str(ws, &cur_variant->conf.lang) != NGX_OK ||
            ngx_persist_write(write_ctx, track_ids,
                (u_char *) cur_id - (u_char *) track_ids) != NGX_OK)
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
    ngx_uint_t                       i, j;
    ngx_live_track_t                *cur_track;
    ngx_live_channel_t              *channel = obj;
    ngx_live_variant_t              *cur_variant;
    ngx_ksmp_track_header_t          tp;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);

    for (i = 0; i < scope->variant_count; i++) {

        cur_variant = scope->variants[i];

        for (j = 0; j < KMP_MEDIA_COUNT; j++) {

            cur_track = cur_variant->tracks[j];
            if (cur_track == NULL
                || !cur_track->output
                || cur_track->written)
            {
                continue;
            }

            tp.id = cur_track->in.key;
            tp.media_type = cur_track->media_type;

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

            cur_track->written = 1;     /* avoid writing more than once */
            scope->track_count++;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_serve_write_segment_index(
    ngx_persist_write_ctx_t *write_ctx, void *obj)
{
    ngx_live_channel_t              *channel = obj;
    ngx_ksmp_segment_index_t         si;
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);
    if (scope->segment_index == NGX_LIVE_INVALID_SEGMENT_INDEX) {
        return NGX_OK;
    }

    si.segment_index = scope->segment_index;
    si.reserved = 0;
    si.correction = scope->correction;

    if (ngx_persist_write_block_open(write_ctx,
            NGX_KSMP_BLOCK_SEGMENT_INDEX) != NGX_OK ||
        ngx_persist_write(write_ctx, &si, sizeof(si)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_serve_write_segment_index: write failed");
        return NGX_ERROR;
    }

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
    { NGX_KSMP_BLOCK_TRACK, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
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
