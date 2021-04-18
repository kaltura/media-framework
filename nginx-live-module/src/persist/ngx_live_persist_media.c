#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_kmp.h>
#include "../ngx_live.h"
#include "../ngx_live_segment_index.h"
#include "../ngx_live_media_info.h"
#include "../ngx_live_segmenter.h"
#include "../ngx_live_timeline.h"
#include "ngx_live_persist_internal.h"


#define NGX_LIVE_PERSIST_INVALID_BUCKET_ID  NGX_MAX_INT32_VALUE

#define NGX_LIVE_PERSIST_MEDIA_DATE_LEN     64


#define NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY_LIST   (0x6c746e73)    /* sntl */
#define NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY        (0x72746e73)    /* sntr */


static ngx_int_t ngx_live_persist_media_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_persist_media_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_persist_media_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_persist_media_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_live_persist_media_bucket_id_variable(
    ngx_live_variables_ctx_t *ctx, ngx_live_variable_value_t *v,
    uintptr_t data);

static char *ngx_live_persist_media_bucket_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


typedef struct {
    uint32_t                       track_id;
    uint32_t                       segment_index;
    uint32_t                       size;
} ngx_live_persist_media_entry_t;


typedef struct {
    ngx_uint_t                     bucket_size;
    size_t                         initial_read_size;
} ngx_live_persist_media_preset_conf_t;


typedef struct {
    uint32_t                       last_bucket_id;
    uint32_t                       bucket_id;

    ngx_queue_t                    reads;
    ngx_live_persist_file_stats_t  read_stats;
    uint32_t                       read_cancel;
} ngx_live_persist_media_channel_ctx_t;


typedef struct {
    ngx_uint_t                     gmt;
    ngx_str_t                      timefmt;
} ngx_live_persist_media_bucket_time_ctx_t;


static ngx_command_t  ngx_live_persist_media_commands[] = {
    { ngx_string("persist_bucket_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_media_preset_conf_t, bucket_size),
      NULL },

    { ngx_string("persist_media_initial_read_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_persist_media_preset_conf_t, initial_read_size),
      NULL },

    { ngx_string("persist_bucket_time"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_TAKE23,
      ngx_live_persist_media_bucket_time,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_persist_media_module_ctx = {
    ngx_live_persist_media_preconfiguration,  /* preconfiguration */
    ngx_live_persist_media_postconfiguration, /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_persist_media_create_preset_conf,/* create preset configuration */
    ngx_live_persist_media_merge_preset_conf  /* merge preset configuration */
};

ngx_module_t  ngx_live_persist_media_module = {
    NGX_MODULE_V1,
    &ngx_live_persist_media_module_ctx,       /* module context */
    ngx_live_persist_media_commands,          /* module directives */
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


static ngx_live_variable_t  ngx_live_persist_media_vars[] = {

    { ngx_string("persist_bucket_id"), NULL,
      ngx_live_persist_media_bucket_id_variable, 0, 0, 0 },

      ngx_live_null_variable
};


/* read */

typedef struct {
    ngx_log_t  *log;
    u_char     *pos;
    size_t      left;
    size_t      frame_size;
} ngx_live_persist_media_read_source_t;

typedef struct {
    uint32_t    id;
    uint32_t    size;
    uint64_t    offset;
} ngx_live_persist_media_read_track_ctx_t;

typedef struct {
    ngx_queue_t                               queue;
    ngx_pool_t                               *pool;
    ngx_live_channel_t                       *channel;
    uint32_t                                  channel_id_hash;

    ngx_live_persist_main_conf_t             *pmcf;
    ngx_live_read_segment_callback_pt         callback;
    void                                     *arg;

    ngx_live_store_read_pt                    read;
    void                                     *read_ctx;

    ngx_msec_t                                start;
    size_t                                    size;

    media_segment_t                          *segment;
    uint32_t                                  read_tracks;
    ngx_live_persist_media_read_track_ctx_t   tracks[KMP_MEDIA_COUNT];
} ngx_live_persist_media_read_ctx_t;


static void *
ngx_live_persist_media_source_init(ngx_pool_t *pool, ngx_str_t *buffer)
{
    ngx_live_persist_media_read_source_t  *state;

    state = ngx_palloc(pool, sizeof(*state));
    if (state == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_source_init: ngx_palloc failed");
        return NULL;
    }

    state->log = pool->log;
    state->pos = buffer->data;
    state->left = buffer->len;

    return state;
}

static vod_status_t
ngx_live_persist_media_source_start_frame(void *ctx, input_frame_t *frame)
{
    ngx_live_persist_media_read_source_t  *state = ctx;

    state->frame_size = frame->size;

    return VOD_OK;
}

static vod_status_t
ngx_live_persist_media_source_read(void *ctx, u_char **buffer, uint32_t *size,
    bool_t *frame_done)
{
    ngx_live_persist_media_read_source_t  *state = ctx;

    if (state->left < state->frame_size) {
        ngx_log_error(NGX_LOG_ERR, state->log, 0,
            "ngx_live_persist_media_source_read: "
            "frame size %uz overflows input buffer", state->frame_size);
        return VOD_BAD_DATA;
    }

    *buffer = state->pos;
    *size = state->frame_size;
    *frame_done = TRUE;

    state->pos += state->frame_size;
    state->left -= state->frame_size;

    return VOD_OK;
}

static frames_source_t  ngx_live_persist_media_source = {
    ngx_live_persist_media_source_start_frame,
    ngx_live_persist_media_source_read,
};


static ngx_int_t
ngx_live_persist_media_read_parse_header(
    ngx_live_persist_media_read_ctx_t *ctx, ngx_str_t *buf)
{
    uint32_t                         i;
    uint32_t                         found_tracks;
    uint32_t                         channel_id_hash;
    uint64_t                         offset;
    ngx_log_t                       *log = ctx->pool->log;
    ngx_str_t                        channel_id;
    ngx_mem_rstream_t                rs;
    ngx_mem_rstream_t                block_rs;
    ngx_persist_block_header_t      *block;
    ngx_live_persist_media_entry_t  *entry;

    if (ngx_persist_read_file_header(buf, NGX_LIVE_PERSIST_TYPE_MEDIA,
        log, NULL, &rs) == NULL)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_read_parse_header: "
            "read file header failed");
        return NGX_HTTP_BAD_GATEWAY;
    }

    block = ngx_persist_read_block(&rs, &rs);
    if (block == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_read_parse_header: read block failed (1)");
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (block->id != NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY_LIST) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_read_parse_header: "
            "unexpected block, id: 0x%uxD", block->id);
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (ngx_mem_rstream_str_get(&rs, &channel_id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_read_parse_header: "
            "read channel id failed");
        return NGX_HTTP_BAD_GATEWAY;
    }

    channel_id_hash = ngx_crc32_short(channel_id.data, channel_id.len);
    if (channel_id_hash != ctx->channel_id_hash) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_read_parse_header: "
            "channel id \"%V\" mismatch", &channel_id);
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (ngx_persist_read_skip_block_header(&rs, block) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_read_parse_header: skip header failed");
        return NGX_HTTP_BAD_GATEWAY;
    }


    offset = ngx_mem_rstream_end(&rs) - buf->data;
    found_tracks = 0;

    while (!ngx_mem_rstream_eof(&rs)) {

        block = ngx_persist_read_block(&rs, &block_rs);
        if (block == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_persist_media_read_parse_header: "
                "read block failed (2)");
            return NGX_HTTP_BAD_GATEWAY;
        }

        if (block->id != NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY) {
            continue;
        }

        entry = ngx_mem_rstream_get_ptr(&block_rs, sizeof(*entry));
        if (entry == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_persist_media_read_parse_header: "
                "read segment entry failed");
            return NGX_HTTP_BAD_GATEWAY;
        }

        if (entry->segment_index != ctx->segment->segment_index) {
            offset += entry->size;
            continue;
        }

        for (i = 0; i < ctx->segment->track_count; i++) {

            if (ctx->tracks[i].id != entry->track_id) {
                continue;
            }

            if (found_tracks & (1 << i)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_live_persist_media_read_parse_header: "
                    "track %uD found more than once", entry->track_id);
                return NGX_HTTP_BAD_GATEWAY;
            }

            ctx->tracks[i].offset = offset;
            ctx->tracks[i].size = entry->size;
            found_tracks |= (1 << i);
        }

        offset += entry->size;
    }

    if (!found_tracks) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_read_parse_header: "
            "segment %uD not found on any track",
            ctx->segment->segment_index);
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_media_read_frame_list(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    media_segment_track_t  *track = obj;

    if (track->frames.part.elts) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_frame_list: duplicate frame list");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_media_read_frame_list: skip header failed");
        return NGX_BAD_DATA;
    }


    track->frames.part.elts = ngx_mem_rstream_get_ptr(rs,
        track->frame_count * sizeof(input_frame_t));
    if (track->frames.part.elts == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_frame_list: read frame list failed");
        return NGX_BAD_DATA;
    }

    track->frames.part.nelts = track->frame_count;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_media_read_frame_data(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_str_t                           data;
    media_segment_track_t              *track = obj;
    ngx_live_persist_media_read_ctx_t  *ctx;

    if (track->frames_source) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_frame_data: duplicate frame data");
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, header) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_media_read_frame_data: skip header failed");
        return NGX_BAD_DATA;
    }


    ngx_mem_rstream_get_left(rs, &data);

    ctx = rs->scope;

    track->frames_source_context = ngx_live_persist_media_source_init(
        ctx->pool, &data);
    if (track->frames_source_context == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_media_read_frame_data: "
            "frame source init failed");
        return NGX_ERROR;
    }

    track->frames_source = &ngx_live_persist_media_source;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_media_read_segment(ngx_persist_block_header_t *block,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_int_t                           rc;
    ngx_mem_rstream_t                   save;
    media_segment_track_t              *track = obj;
    ngx_live_persist_segment_header_t  *header;
    ngx_live_persist_media_read_ctx_t  *ctx;

    if (track->frame_count) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_segment: duplicate segment");
        return NGX_BAD_DATA;
    }

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_media_read_segment: "
            "read segment header failed");
        return NGX_BAD_DATA;
    }

    if (header->frame_count <= 0 ||
        header->frame_count > NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT)
    {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_segment: invalid frame count %uD",
            header->frame_count);
        return NGX_BAD_DATA;
    }

    if (ngx_persist_read_skip_block_header(rs, block) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_persist_media_read_segment: skip header failed");
        return NGX_BAD_DATA;
    }

    track->frame_count = header->frame_count;
    track->start_dts = header->start_dts;


    ctx = rs->scope;

    save = *rs;

    rc = ngx_live_persist_read_blocks_internal(ctx->pmcf,
        NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER, rs, track);
    if (rc != NGX_OK) {
        return rc;
    }

    *rs = save;

    rc = ngx_live_persist_read_blocks_internal(ctx->pmcf,
        NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_DATA, rs, track);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!track->frames.part.elts) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_segment: missing frame list");
        return NGX_BAD_DATA;
    }

    if (!track->frames_source) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_media_read_segment: missing frame data");
        return NGX_BAD_DATA;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_read_init_track(ngx_live_persist_media_read_ctx_t *ctx,
    ngx_str_t *buf)
{
    ngx_int_t               rc;
    ngx_log_t              *log;
    ngx_mem_rstream_t       rs;
    media_segment_track_t  *track;

    log = ctx->pool->log;

    ngx_mem_rstream_set(&rs, buf->data, buf->data + buf->len, log, ctx);

    track = &ctx->segment->tracks[ctx->read_tracks - 1];

    rc = ngx_live_persist_read_blocks_internal(ctx->pmcf,
        NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET, &rs, track);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_read_init_track: "
            "read blocks failed %i", rc);

        if (rc == NGX_BAD_DATA) {
            return NGX_HTTP_BAD_GATEWAY;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

static void
ngx_live_persist_media_read_complete(void *arg, ngx_int_t rc,
    ngx_buf_t *response)
{
    ngx_str_t                                 buf;
    ngx_live_persist_media_read_ctx_t        *ctx = arg;
    ngx_live_persist_media_channel_ctx_t     *cctx;
    ngx_live_persist_media_read_track_ctx_t  *tctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_media_read_complete: read failed %i", rc);
        goto done;
    }

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    if (ctx->read_tracks <= 0) {

        rc = ngx_live_persist_media_read_parse_header(ctx, &buf);
        if (rc != NGX_OK) {
            if (rc != NGX_ABORT) {
                ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                    "ngx_live_persist_media_read_complete: "
                    "parse header failed %i", rc);
            }
            goto done;
        }

    } else {

        rc = ngx_live_persist_media_read_init_track(ctx, &buf);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_read_complete: "
                "init track failed %i", rc);
            goto done;
        }
    }

    while (ctx->read_tracks < ctx->segment->track_count) {

        tctx = &ctx->tracks[ctx->read_tracks];
        ctx->read_tracks++;

        if (tctx->size <= 0) {
            continue;
        }

        rc = ctx->read(ctx->read_ctx, tctx->offset, tctx->size);
        if (rc != NGX_DONE) {
            ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
                "ngx_live_persist_media_read_complete: read failed %i", rc);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        ctx->size += tctx->size;

        return;
    }

    rc = NGX_OK;

done:

    if (ctx->channel != NULL) {
        cctx = ngx_live_get_module_ctx(ctx->channel,
            ngx_live_persist_media_module);

        if (rc == NGX_OK) {
            cctx->read_stats.success++;
            cctx->read_stats.success_msec += ngx_current_msec - ctx->start;
            cctx->read_stats.success_size += ctx->size;

        } else {
            cctx->read_stats.error++;
        }

        ngx_queue_remove(&ctx->queue);
        ctx->channel = NULL;
    }

    ctx->callback(ctx->arg, rc);
}

static void
ngx_live_persist_media_read_detach(void *data)
{
    ngx_live_persist_media_read_ctx_t     *ctx = data;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    if (ctx->channel == NULL) {
        return;
    }

    cctx = ngx_live_get_module_ctx(ctx->channel,
        ngx_live_persist_media_module);

    cctx->read_stats.started--;     /* reduce the pending count */
    cctx->read_cancel++;

    ngx_queue_remove(&ctx->queue);
}

static ngx_int_t
ngx_live_persist_media_read(ngx_live_segment_read_req_t *req)
{
    uint32_t                               i;
    uint32_t                               bucket_id;
    ngx_int_t                              rc;
    ngx_str_t                             *channel_id;
    ngx_pool_t                            *pool;
    media_segment_t                       *segment;
    ngx_live_store_t                      *store;
    ngx_pool_cleanup_t                    *cln;
    ngx_live_channel_t                    *channel;
    media_segment_track_t                 *cur_track;
    ngx_live_variables_ctx_t               vctx;
    ngx_live_store_read_request_t          request;
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_media_read_ctx_t     *ctx;
    ngx_live_persist_media_preset_conf_t  *pmpcf;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    pool = req->pool;
    channel = req->channel;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: not enabled");
        return NGX_ABORT;
    }

    cln = ngx_pool_cleanup_add(pool, sizeof(*ctx));
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: cleanup add failed");
        return NGX_ERROR;
    }

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(*ctx));

    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    segment = req->segment;
    bucket_id = segment->segment_index / pmpcf->bucket_size;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    if (ngx_live_variables_init_ctx(channel, pool, &vctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: failed to init var ctx");
        return NGX_ERROR;
    }

    cctx->bucket_id = bucket_id;

    rc = ngx_live_complex_value(&vctx,
        ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path, &request.path);

    cctx->bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: get path failed %i", rc);
        return NGX_ERROR;
    }

    request.pool = pool;
    request.channel = channel;
    request.handler = ngx_live_persist_media_read_complete;
    request.data = ctx;
    request.max_size = 0;

    store = ppcf->store;

    ctx->read_ctx = store->read_init(&request);
    if (ctx->read_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: read init failed");
        return NGX_ERROR;
    }

    store->get_info(channel, &segment->source);

    ctx->read = store->read;

    ctx->pool = pool;
    ctx->segment = segment;
    for (i = 0; i < segment->track_count; i++) {
        ctx->tracks[i].id = req->tracks[i].id;

        cur_track = &req->segment->tracks[i];
        cur_track->media_info = ngx_live_media_info_clone(pool,
            cur_track->media_info);
        if (cur_track->media_info == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_persist_media_read: failed to clone media info");
            return NGX_ERROR;
        }
    }

    channel_id = &channel->sn.str;
    ctx->channel_id_hash = ngx_crc32_short(channel_id->data, channel_id->len);

    ctx->pmcf = ngx_live_get_module_main_conf(channel,
        ngx_live_persist_module);
    ctx->callback = req->callback;
    ctx->arg = req->arg;

    cctx->read_stats.started++;
    ctx->start = ngx_current_msec;

    rc = ctx->read(ctx->read_ctx, 0, pmpcf->initial_read_size);
    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: read failed %i", rc);
        cctx->read_stats.error++;
        return NGX_ERROR;
    }

    ctx->size = pmpcf->initial_read_size;

    ctx->channel = channel;
    ngx_queue_insert_tail(&cctx->reads, &ctx->queue);

    cln->handler = ngx_live_persist_media_read_detach;

    return NGX_DONE;
}


/* copy */

typedef struct {
    ngx_queue_t                               queue;
    ngx_pool_t                               *pool;
    ngx_live_channel_t                       *channel;
    uint32_t                                  channel_id_hash;

    ngx_live_segment_writer_t                 writer;
    ngx_live_store_read_pt                    read;
    void                                     *read_ctx;

    ngx_msec_t                                start;
    size_t                                    size;

    uint32_t                                  segment_index;
    uint32_t                                  read_tracks;
    uint32_t                                  track_count;
    ngx_live_persist_media_read_track_ctx_t   tracks[1];    /* must be last */
} ngx_live_persist_media_copy_ctx_t;


static ngx_int_t
ngx_live_persist_media_copy_parse_header(
    ngx_live_persist_media_copy_ctx_t *ctx, ngx_str_t *buf)
{
    size_t                           total_size;
    uint32_t                         i;
    uint32_t                         found_tracks;
    uint32_t                         channel_id_hash;
    uint64_t                         offset;
    ngx_int_t                        rc;
    ngx_log_t                       *log = ctx->pool->log;
    ngx_str_t                        channel_id;
    ngx_mem_rstream_t                rs;
    ngx_mem_rstream_t                block_rs;
    ngx_persist_block_header_t      *block;
    ngx_live_persist_media_entry_t  *entry;

    if (ngx_persist_read_file_header(buf, NGX_LIVE_PERSIST_TYPE_MEDIA,
        log, NULL, &rs) == NULL)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "read file header failed");
        return NGX_HTTP_BAD_GATEWAY;
    }

    block = ngx_persist_read_block(&rs, &rs);
    if (block == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_copy_parse_header: read block failed (1)");
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (block->id != NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY_LIST) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "unexpected block, id: 0x%uxD", block->id);
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (ngx_mem_rstream_str_get(&rs, &channel_id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "read channel id failed");
        return NGX_HTTP_BAD_GATEWAY;
    }

    channel_id_hash = ngx_crc32_short(channel_id.data, channel_id.len);
    if (channel_id_hash != ctx->channel_id_hash) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "channel id \"%V\" mismatch", &channel_id);
        return NGX_HTTP_BAD_GATEWAY;
    }

    if (ngx_persist_read_skip_block_header(&rs, block) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_copy_parse_header: skip header failed");
        return NGX_HTTP_BAD_GATEWAY;
    }


    offset = ngx_mem_rstream_end(&rs) - buf->data;
    found_tracks = 0;
    total_size = 0;

    while (!ngx_mem_rstream_eof(&rs)) {

        block = ngx_persist_read_block(&rs, &block_rs);
        if (block == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_persist_media_copy_parse_header: "
                "read block failed (2)");
            return NGX_HTTP_BAD_GATEWAY;
        }

        if (block->id != NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY) {
            continue;
        }

        entry = ngx_mem_rstream_get_ptr(&block_rs, sizeof(*entry));
        if (entry == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_persist_media_copy_parse_header: "
                "read segment entry failed");
            return NGX_HTTP_BAD_GATEWAY;
        }

        if (entry->segment_index != ctx->segment_index) {
            offset += entry->size;
            continue;
        }

        for (i = 0; i < ctx->track_count; i++) {

            if (ctx->tracks[i].id != entry->track_id) {
                continue;
            }

            if (found_tracks & (1 << i)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_live_persist_media_copy_parse_header: "
                    "track %uD found more than once", entry->track_id);
                return NGX_HTTP_BAD_GATEWAY;
            }

            ctx->tracks[i].offset = offset;
            ctx->tracks[i].size = entry->size;
            found_tracks |= (1 << i);

            total_size += entry->size;
        }

        offset += entry->size;
    }

    if (!found_tracks) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "segment %uD not found on any track",
            ctx->segment_index);
    }

    rc = ctx->writer.set_size(ctx->writer.arg, total_size);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_live_persist_media_copy_parse_header: "
            "set size failed %i", rc);
        return rc;
    }

    return NGX_OK;
}

static void
ngx_live_persist_media_copy_complete(void *arg, ngx_int_t rc,
    ngx_buf_t *response)
{
    ngx_buf_t                                *b;
    ngx_str_t                                 buf;
    ngx_chain_t                              *cl;
    ngx_live_persist_media_copy_ctx_t        *ctx = arg;
    ngx_live_persist_media_channel_ctx_t     *cctx;
    ngx_live_persist_media_read_track_ctx_t  *tctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_media_copy_complete: read failed %i", rc);
        goto done;
    }

    if (ctx->read_tracks <= 0) {

        buf.data = response->pos;
        buf.len = response->last - response->pos;

        rc = ngx_live_persist_media_copy_parse_header(ctx, &buf);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_copy_complete: "
                "parse header failed %i", rc);
            goto done;
        }

    } else {

        b = ngx_calloc_buf(ctx->pool);
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_copy_complete: alloc buf failed");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        b->start = b->pos = response->pos;
        b->end = b->last = response->last;
        b->memory = 1;

        cl = ngx_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_copy_complete: alloc chain failed");
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        cl->buf = b;
        cl->next = NULL;

        rc = ctx->writer.write(ctx->writer.arg, cl);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_copy_complete: write failed %i", rc);
            goto done;
        }
    }

    while (ctx->read_tracks < ctx->track_count) {

        tctx = &ctx->tracks[ctx->read_tracks];
        ctx->read_tracks++;

        if (tctx->size <= 0) {
            continue;
        }

        rc = ctx->read(ctx->read_ctx, tctx->offset, tctx->size);
        if (rc != NGX_DONE) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_persist_media_copy_complete: read failed %i", rc);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        ctx->size += tctx->size;

        return;
    }

    rc = NGX_OK;

done:

    if (ctx->channel != NULL) {
        cctx = ngx_live_get_module_ctx(ctx->channel,
            ngx_live_persist_media_module);

        if (rc == NGX_OK) {
            cctx->read_stats.success++;
            cctx->read_stats.success_msec += ngx_current_msec - ctx->start;
            cctx->read_stats.success_size += ctx->size;

        } else {
            cctx->read_stats.error++;
        }

        ngx_queue_remove(&ctx->queue);
        ctx->channel = NULL;
    }

    ctx->writer.close(ctx->writer.arg, rc);
}

static void
ngx_live_persist_media_copy_detach(void *data)
{
    ngx_live_persist_media_copy_ctx_t     *ctx = data;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    if (ctx->channel == NULL) {
        return;
    }

    cctx = ngx_live_get_module_ctx(ctx->channel,
        ngx_live_persist_media_module);

    cctx->read_stats.started--;     /* reduce the pending count */
    cctx->read_cancel++;

    ngx_queue_remove(&ctx->queue);
}

static ngx_int_t
ngx_live_persist_media_copy(ngx_live_segment_copy_req_t *req)
{
    size_t                                 ctx_size;
    uint32_t                               i;
    uint32_t                               bucket_id;
    ngx_int_t                              rc;
    ngx_str_t                             *channel_id;
    ngx_pool_t                            *pool;
    ngx_live_store_t                      *store;
    ngx_pool_cleanup_t                    *cln;
    ngx_live_channel_t                    *channel;
    ngx_live_variables_ctx_t               vctx;
    ngx_live_store_read_request_t          request;
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_media_copy_ctx_t     *ctx;
    ngx_live_persist_media_preset_conf_t  *pmpcf;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    pool = req->pool;
    channel = req->channel;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_copy: not enabled");
        return NGX_OK;
    }

    ctx_size = offsetof(ngx_live_persist_media_copy_ctx_t, tracks) +
        req->track_count * sizeof(ctx->tracks[0]);
    cln = ngx_pool_cleanup_add(pool, ctx_size);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_copy: cleanup add failed");
        return NGX_ERROR;
    }

    if (ngx_live_variables_init_ctx(channel, pool, &vctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_copy: failed to init var ctx");
        return NGX_ERROR;
    }

    ctx = cln->data;
    ngx_memzero(ctx, ctx_size);

    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    bucket_id = req->segment_index / pmpcf->bucket_size;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    cctx->bucket_id = bucket_id;

    rc = ngx_live_complex_value(&vctx,
        ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path, &request.path);

    cctx->bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_copy: get path failed %i", rc);
        return NGX_ERROR;
    }

    request.pool = pool;
    request.channel = channel;
    request.handler = ngx_live_persist_media_copy_complete;
    request.data = ctx;
    request.max_size = 0;

    store = ppcf->store;

    ctx->read_ctx = store->read_init(&request);
    if (ctx->read_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: read init failed");
        return NGX_ERROR;
    }

    store->get_info(channel, &req->source);

    ctx->read = store->read;

    ctx->pool = pool;
    ctx->writer = req->writer;
    ctx->segment_index = req->segment_index;
    ctx->track_count = req->track_count;
    for (i = 0; i < req->track_count; i++) {
        ctx->tracks[i].id = req->tracks[i].id;
    }

    channel_id = &channel->sn.str;
    ctx->channel_id_hash = ngx_crc32_short(channel_id->data, channel_id->len);

    cctx->read_stats.started++;
    ctx->start = ngx_current_msec;

    rc = ctx->read(ctx->read_ctx, 0, pmpcf->initial_read_size);
    if (rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_persist_media_read: read failed %i", rc);
        cctx->read_stats.error++;
        return NGX_ERROR;
    }

    ctx->size = pmpcf->initial_read_size;

    ctx->channel = channel;
    ngx_queue_insert_tail(&cctx->reads, &ctx->queue);

    cln->handler = ngx_live_persist_media_copy_detach;

    return NGX_DONE;
}


/* write */

typedef struct {
    uint32_t                         bucket_id;
    uint32_t                         min_index;
    uint32_t                         max_index;
} ngx_live_persist_media_scope_t;


typedef struct {
    ngx_live_segment_cleanup_t      *cln;
    ngx_live_persist_media_scope_t   scope;
    ngx_persist_write_ctx_t         *write_data;
} ngx_live_persist_media_write_ctx_t;


static ngx_int_t
ngx_live_persist_media_write_segment(ngx_persist_write_ctx_t *write_idx,
    ngx_live_segment_t *segment)
{
    size_t                               start;
    uint32_t                             header_size;
    ngx_persist_block_header_t           block;
    ngx_live_persist_media_entry_t       entry;
    ngx_live_persist_media_write_ctx_t  *ctx;

    ctx = ngx_persist_write_ctx(write_idx);

    start = ngx_persist_write_get_size(ctx->write_data);

    if (ngx_live_segment_cache_write(ctx->write_data, segment, ctx->cln,
        &header_size) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* add segment entry */
    block.id = NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY;
    block.header_size = header_size | NGX_PERSIST_HEADER_FLAG_INDEX;

    entry.track_id = segment->track->in.key;
    entry.segment_index = segment->node.key;
    entry.size = ngx_persist_write_get_size(ctx->write_data) - start;

    if (ngx_persist_write_block(write_idx, &block, &entry,
        sizeof(entry)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_write_segments(ngx_persist_write_ctx_t *write_idx,
    void *obj)
{
    uint32_t                             max_segments;
    uint32_t                             segment_index;
    ngx_pool_t                          *pool;
    ngx_queue_t                         *q;
    ngx_live_channel_t                  *channel = obj;
    ngx_live_track_t                    *cur_track;
    ngx_live_segment_t                  *segment;
    ngx_live_segment_index_t            *index;
    ngx_live_persist_media_write_ctx_t  *ctx;

    ctx = ngx_persist_write_ctx(write_idx);

    for (segment_index = ctx->scope.min_index;
        segment_index < ctx->scope.max_index;
        segment_index++)
    {
        for (q = ngx_queue_head(&channel->tracks.queue);
            q != ngx_queue_sentinel(&channel->tracks.queue);
            q = ngx_queue_next(q))
        {
            cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

            segment = ngx_live_segment_cache_get(cur_track, segment_index);
            if (segment == NULL) {
                continue;
            }

            if (ctx->cln == NULL) {
                index = ngx_live_segment_index_get(channel, segment->node.key);
                if (index == NULL) {
                    ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
                        "ngx_live_persist_media_write_segments: "
                        "failed to get index %ui", segment->node.key);
                    return NGX_ERROR;
                }

                pool = ngx_persist_write_pool(write_idx);
                max_segments = (ctx->scope.max_index - ctx->scope.min_index) *
                    channel->tracks.count;

                ctx->cln = ngx_live_segment_index_cleanup_add(pool, index,
                    max_segments);
                if (ctx->cln == NULL) {
                    ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                        "ngx_live_persist_media_write_segments: "
                        "add cleanup item failed");
                    return NGX_ERROR;
                }
            }

            if (ngx_live_persist_media_write_segment(write_idx, segment)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, &cur_track->log, 0,
                    "ngx_live_persist_media_write_segments: write failed");
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_write_bucket(ngx_persist_write_ctx_t *write_idx,
    void *obj)
{
    ngx_pool_t                          *pool;
    ngx_wstream_t                       *ws;
    ngx_live_channel_t                  *channel;
    ngx_live_persist_media_write_ctx_t  *ctx;

    channel = obj;

    ws = ngx_persist_write_stream(write_idx);

    if (ngx_persist_write_block_open(write_idx,
            NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY_LIST) != NGX_OK ||
        ngx_wstream_str(ws, &channel->sn.str) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_bucket: write header failed");
        return NGX_ERROR;
    }

    pool = ngx_persist_write_pool(write_idx);

    ctx = ngx_persist_write_ctx(write_idx);

    ctx->write_data = ngx_persist_write_init(pool, 0, 0);
    if (ctx->write_data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_bucket: write init failed");
        return NGX_ERROR;
    }

    ngx_persist_write_ctx(ctx->write_data) = ctx;

    if (ngx_live_persist_write_blocks(channel, write_idx,
        NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET, channel) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_bucket: write failed");
        return NGX_ERROR;
    }

    if (ctx->cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_media_write_bucket: "
            "no segments found, bucket: %uD", ctx->scope.bucket_id);
        return NGX_ERROR;
    }

    ngx_persist_write_block_close(write_idx);  /* segment entry list */

    if (ngx_persist_write_chain(write_idx, ctx->write_data) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_bucket: chain failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

void
ngx_live_persist_media_write_complete(ngx_live_persist_write_file_ctx_t *ctx,
    ngx_int_t rc)
{
    ngx_live_channel_t              *channel;
    ngx_live_persist_media_scope_t   scope;

    channel = ctx->channel;
    scope = *(ngx_live_persist_media_scope_t *) ctx->scope;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_complete: "
            "write failed %i, bucket_id: %uD", rc, scope.bucket_id);

    } else {
        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_media_write_complete: "
            "write success, bucket_id: %uD", scope.bucket_id);
    }

    ngx_live_persist_write_file_destroy(ctx);

    ngx_live_segment_index_persisted(channel, scope.min_index,
        scope.max_index, rc);
}

static void
ngx_live_persist_media_write_cancel(void *arg)
{
    ngx_live_channel_t                 *channel;
    ngx_live_persist_media_scope_t     *scope;
    ngx_live_persist_write_file_ctx_t  *write_ctx = arg;

    channel = write_ctx->channel;
    scope = (void *) write_ctx->scope;

    ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
        "ngx_live_persist_media_write_cancel: "
        "cancelling write request, bucket_id: %uD", scope->bucket_id);

    ngx_live_persist_media_write_complete(write_ctx, NGX_ERROR);
}

static void
ngx_live_persist_media_write_file(ngx_live_channel_t *channel,
    uint32_t bucket_id)
{
    ngx_live_persist_write_file_ctx_t     *write_ctx;
    ngx_live_persist_media_write_ctx_t     ctx;
    ngx_live_persist_media_preset_conf_t  *pmpcf;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    if (channel->mem_left < channel->mem_high_watermark) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_media_write_file: "
            "memory too low, aborting write, bucket_id: %uD", bucket_id);
        ngx_live_persist_write_error(channel, NGX_LIVE_PERSIST_FILE_MEDIA);
        goto error;
    }

    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    ctx.cln = NULL;
    ctx.scope.bucket_id = bucket_id;
    ctx.scope.min_index = bucket_id * pmpcf->bucket_size;
    ctx.scope.max_index = ctx.scope.min_index + pmpcf->bucket_size;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    cctx->bucket_id = bucket_id;

    write_ctx = ngx_live_persist_write_file(channel,
        NGX_LIVE_PERSIST_FILE_MEDIA, &ctx, &ctx.scope, sizeof(ctx.scope));

    cctx->bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;

    if (write_ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_write_file: "
            "write failed, bucket_id: %uD", bucket_id);
        goto error;
    }

    ctx.cln->handler = ngx_live_persist_media_write_cancel;
    ctx.cln->data = write_ctx;

    /* Note: if the channel is freed, the segment index module will call
        ngx_live_persist_media_write_cancel, which will free the pool */

    return;

error:

    ngx_live_segment_index_persisted(channel, ctx.scope.min_index,
        ctx.scope.max_index, NGX_ERROR);
}

static ngx_int_t
ngx_live_persist_media_write_segment_created(ngx_live_channel_t *channel,
    void *ectx)
{
    uint32_t                               bucket_id;
    uint32_t                               segment_index;
    ngx_flag_t                             exists;
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_media_channel_ctx_t  *cctx;
    ngx_live_persist_media_preset_conf_t  *pmpcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL ||
        !ppcf->write)
    {
        return NGX_OK;
    }

    exists = (intptr_t) ectx;
    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    segment_index = channel->next_segment_index;

    bucket_id = segment_index / pmpcf->bucket_size;

    if (cctx->last_bucket_id != NGX_LIVE_PERSIST_INVALID_BUCKET_ID &&
        cctx->last_bucket_id != bucket_id)
    {
        /* bucket changed since last time, write previous bucket */
        ngx_live_persist_media_write_file(channel, cctx->last_bucket_id);

        cctx->last_bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;
    }

    if ((segment_index + 1) % pmpcf->bucket_size != 0) {
        /* more segments are expected in this bucket */
        if (exists) {
            cctx->last_bucket_id = bucket_id;
        }
        return NGX_OK;
    }

    /* last segment in the bucket, write it */
    if (!exists && cctx->last_bucket_id == NGX_LIVE_PERSIST_INVALID_BUCKET_ID)
    {
        return NGX_OK;
    }

    ngx_live_persist_media_write_file(channel, bucket_id);

    cctx->last_bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;

    return NGX_OK;
}


static ngx_int_t
ngx_live_persist_media_bucket_id_variable(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    u_char                                *p;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(ctx->ch, ngx_live_persist_media_module);

    if (cctx->bucket_id == NGX_LIVE_PERSIST_INVALID_BUCKET_ID) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(ctx->pool, NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uD", cctx->bucket_id) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_bucket_time_variable(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    time_t                                     sec;
    int64_t                                    time;
    uint32_t                                   segment_index;
    uint32_t                                   limit;
    ngx_tm_t                                   tm;
    ngx_live_channel_t                        *channel;
    ngx_live_core_preset_conf_t               *cpcf;
    ngx_live_persist_media_channel_ctx_t      *cctx;
    ngx_live_persist_media_preset_conf_t      *pmpcf;
    ngx_live_persist_media_bucket_time_ctx_t  *var = (void *) data;

    char  buf[NGX_LIVE_PERSIST_MEDIA_DATE_LEN];

    channel = ctx->ch;
    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    if (cctx->bucket_id == NGX_LIVE_PERSIST_INVALID_BUCKET_ID) {
        v->not_found = 1;
        return NGX_OK;
    }

    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    segment_index = cctx->bucket_id * pmpcf->bucket_size;
    limit = segment_index + pmpcf->bucket_size;
    for ( ;; ) {

        if (segment_index >= limit) {
            ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
                "ngx_live_persist_media_bucket_time_variable: "
                "failed to get the timestamp of all segments in bucket %uD",
                cctx->bucket_id);
            return NGX_ERROR;
        }

        if (ngx_live_timelines_get_segment_time(channel, segment_index, &time)
            == NGX_OK)
        {
            break;
        }

        segment_index++;
    }

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    sec = time / cpcf->timescale;

    if (var->gmt) {
        ngx_libc_gmtime(sec, &tm);

    } else {
        ngx_libc_localtime(sec, &tm);
    }

    v->len = strftime(buf, NGX_LIVE_PERSIST_MEDIA_DATE_LEN,
        (char *) var->timefmt.data, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_persist_media_bucket_time_variable: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(ctx->pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_bucket_time_variable: alloc failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static char *
ngx_live_persist_media_bucket_time(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                                 *value;
    ngx_str_t                                  name;
    ngx_str_t                                  zone;
    ngx_live_variable_t                       *var;
    ngx_live_persist_media_bucket_time_ctx_t  *ctx;

    ctx = ngx_pcalloc(cf->pool,
        sizeof(ngx_live_persist_media_bucket_time_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    name = value[1];

    if (name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    if (cf->args->nelts > 3) {
        zone = value[3];

        if (zone.len == 3 &&
            ngx_strncasecmp(zone.data, (u_char *) "gmt", 3) == 0)
        {
            ctx->gmt = 1;

        } else if (zone.len == 5 &&
            ngx_strncasecmp(zone.data, (u_char *) "local", 5) == 0)
        {
            ctx->gmt = 0;

        } else {
            return "invalid timezone";
        }
    }

    ctx->timefmt = value[2];

    var = ngx_live_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_live_persist_media_bucket_time_variable;
    var->data = (uintptr_t) ctx;

    return NGX_CONF_OK;
}


size_t
ngx_live_persist_media_read_json_get_size(ngx_live_channel_t *channel)
{
    ngx_live_persist_file_stats_t         *stats;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);
    stats = &cctx->read_stats;

    size_t  result =
        ngx_live_persist_base_obj_json_get_size(stats) +
        sizeof(",\"cancel\":") - 1 + NGX_INT32_LEN +
        sizeof("{}") - 1;

    return result;
}

u_char *
ngx_live_persist_media_read_json_write(u_char *p, ngx_live_channel_t *channel)
{
    ngx_live_persist_file_stats_t         *stats;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);
    stats = &cctx->read_stats;

    *p++ = '{';
    p = ngx_live_persist_base_obj_json_write(p, stats);
    p = ngx_copy_fix(p, ",\"cancel\":");
    p = ngx_sprintf(p, "%uD", cctx->read_cancel);
    *p++ = '}';

    return p;
}


static ngx_int_t
ngx_live_persist_media_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_media_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_media_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_persist_media_module);

    cctx->bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;
    cctx->last_bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;

    ngx_queue_init(&cctx->reads);

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                           *q;
    ngx_live_persist_media_read_ctx_t     *ctx;
    ngx_live_persist_media_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(&cctx->reads);
        q != ngx_queue_sentinel(&cctx->reads);
        q = ngx_queue_next(q))
    {
        ctx = ngx_queue_data(q, ngx_live_persist_media_read_ctx_t, queue);

        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_persist_media_channel_free: detaching from channel");

        ctx->channel = NULL;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_channel_inactive(ngx_live_channel_t *channel,
    void *ectx)
{
    uint32_t                               next_segment_index;
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_media_channel_ctx_t  *cctx;
    ngx_live_persist_media_preset_conf_t  *pmpcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);

    if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL ||
        !ppcf->write)
    {
        return NGX_OK;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_persist_media_module);

    if (cctx->last_bucket_id != NGX_LIVE_PERSIST_INVALID_BUCKET_ID) {
        ngx_live_persist_media_write_file(channel, cctx->last_bucket_id);

        cctx->last_bucket_id = NGX_LIVE_PERSIST_INVALID_BUCKET_ID;
    }

    /* make sure the next segment will use a new bucket if the stream becomes
        active later */
    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    next_segment_index = channel->next_segment_index;
    if (next_segment_index < NGX_LIVE_INVALID_SEGMENT_INDEX -
        pmpcf->bucket_size)
    {
        channel->next_segment_index = ngx_round_up_to_multiple(
            next_segment_index, pmpcf->bucket_size);

        ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
            "ngx_live_persist_media_channel_inactive: "
            "aligned next segment index to bucket, prev: %uD",
            next_segment_index);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_persist_media_channel_read(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_persist_preset_conf_t        *ppcf;
    ngx_live_persist_media_preset_conf_t  *pmpcf;

    ppcf = ngx_live_get_module_preset_conf(channel, ngx_live_persist_module);
    if (ppcf->files[NGX_LIVE_PERSIST_FILE_MEDIA].path == NULL) {
        return NGX_OK;
    }

    pmpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_persist_media_module);

    /* make sure the next segment will use a new bucket if the stream becomes
        active later */
    if (channel->next_segment_index < NGX_LIVE_INVALID_SEGMENT_INDEX -
        pmpcf->bucket_size)
    {
        channel->next_segment_index = ngx_round_up_to_multiple(
            channel->next_segment_index, pmpcf->bucket_size);
    }

    return NGX_OK;
}

static void *
ngx_live_persist_media_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_persist_media_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_persist_media_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bucket_size = NGX_CONF_UNSET_UINT;
    conf->initial_read_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_live_persist_media_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_persist_media_preset_conf_t  *prev = parent;
    ngx_live_persist_media_preset_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->bucket_size, prev->bucket_size, 2);

    ngx_conf_merge_size_value(conf->initial_read_size,
                              prev->initial_read_size, 4 * 1024);

    return NGX_CONF_OK;
}


static ngx_persist_block_t  ngx_live_persist_media_blocks[] = {
    /*
     * persist header:
     *   ngx_str_t  channel_id;
     */
    { NGX_LIVE_PERSIST_MEDIA_BLOCK_ENTRY_LIST, NGX_LIVE_PERSIST_CTX_MEDIA_MAIN,
      0, ngx_live_persist_media_write_bucket, NULL },

    /*
     * persist header:
     *   ngx_live_persist_segment_header_t  header;
     */
    { NGX_LIVE_PERSIST_BLOCK_SEGMENT, NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET, 0,
      ngx_live_persist_media_write_segments,
      ngx_live_persist_media_read_segment },

    /*
     * persist data:
     *   input_frame_t  frame[];
     */
    { NGX_LIVE_PERSIST_BLOCK_FRAME_LIST,
      NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER,
      NGX_PERSIST_FLAG_SINGLE,
      NULL,
      ngx_live_persist_media_read_frame_list },

    { NGX_LIVE_PERSIST_BLOCK_FRAME_DATA,
      NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_DATA,
      NGX_PERSIST_FLAG_SINGLE,
      NULL,
      ngx_live_persist_media_read_frame_data },

      ngx_null_persist_block
};

static ngx_int_t
ngx_live_persist_media_preconfiguration(ngx_conf_t *cf)
{
    ngx_live_read_segment = ngx_live_persist_media_read;
    ngx_live_copy_segment = ngx_live_persist_media_copy;

    if (ngx_live_variable_add_multi(cf, ngx_live_persist_media_vars)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_persist_add_blocks(cf, ngx_live_persist_media_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t    ngx_live_persist_media_channel_events[] = {
    { ngx_live_persist_media_channel_init,     NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_persist_media_channel_free,     NGX_LIVE_EVENT_CHANNEL_FREE },
    { ngx_live_persist_media_channel_read,     NGX_LIVE_EVENT_CHANNEL_READ },
    { ngx_live_persist_media_channel_inactive,
        NGX_LIVE_EVENT_CHANNEL_INACTIVE },
    { ngx_live_persist_media_write_segment_created,
        NGX_LIVE_EVENT_CHANNEL_SEGMENT_CREATED },
      ngx_live_null_event
};

static ngx_int_t
ngx_live_persist_media_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_persist_media_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
