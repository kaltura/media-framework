#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_dvr.h"
#include "ngx_live_dvr_format.h"
#include "../ngx_live_segment_cache.h"
#include "../ngx_live_media_info.h"
#include "../ngx_live_segmenter.h"
#include "../ngx_live_timeline.h"
#include "../ngx_live_input_bufs.h"


#define NGX_LIVE_DVR_INVALID_BUCKET_ID  NGX_MAX_INT32_VALUE
#define NGX_LIVE_DVR_DATE_LEN           64


static ngx_int_t ngx_live_dvr_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_dvr_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_dvr_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_dvr_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_dvr_bucket_id_variable(ngx_live_channel_t *channel,
    ngx_pool_t *pool, ngx_live_variable_value_t *v, uintptr_t data);

static char *ngx_live_dvr_bucket_time(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


typedef struct {
    uint32_t    segments_mask_start;
    uint32_t    saved_segments_mask;
    uint32_t    failed_segments_mask;
    uint32_t    last_bucket_id;
    uint32_t    bucket_id;

    uint32_t    save_started;
    uint32_t    save_error;
    uint32_t    save_success;
    uint64_t    save_success_msec;
    uint64_t    save_success_size;
    uint32_t    read_segments;
} ngx_live_dvr_channel_ctx_t;

typedef struct {
    ngx_uint_t  gmt;
    ngx_str_t   timefmt;
} ngx_live_dvr_bucket_time_ctx_t;


static ngx_conf_num_bounds_t  ngx_live_dvr_bucket_size_bounds = {
    ngx_conf_check_num_bounds, 1, 32
};

static ngx_conf_num_bounds_t  ngx_live_dvr_force_memory_segments_bounds = {
    ngx_conf_check_num_bounds, 1, 32
};

static ngx_command_t  ngx_live_dvr_commands[] = {
    { ngx_string("dvr_path"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_set_complex_value_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_preset_conf_t, path),
      NULL },

    { ngx_string("dvr_bucket_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_preset_conf_t, bucket_size),
      &ngx_live_dvr_bucket_size_bounds },

    { ngx_string("dvr_force_memory_segments"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_preset_conf_t, force_memory_segments),
      &ngx_live_dvr_force_memory_segments_bounds },

    { ngx_string("dvr_initial_read_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dvr_preset_conf_t, initial_read_size),
      NULL },

    { ngx_string("dvr_bucket_time"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_TAKE23,
      ngx_live_dvr_bucket_time,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_dvr_module_ctx = {
    ngx_live_dvr_preconfiguration,          /* preconfiguration */
    ngx_live_dvr_postconfiguration,         /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_live_dvr_create_preset_conf,        /* create preset configuration */
    ngx_live_dvr_merge_preset_conf          /* merge preset configuration */
};

ngx_module_t  ngx_live_dvr_module = {
    NGX_MODULE_V1,
    &ngx_live_dvr_module_ctx,               /* module context */
    ngx_live_dvr_commands,                  /* module directives */
    NGX_LIVE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_live_variable_t  ngx_live_dvr_vars[] = {

    { ngx_string("dvr_bucket_id"), NULL,
      ngx_live_dvr_bucket_id_variable, 0, 0, 0 },

      ngx_live_null_variable
};


/* read */

typedef struct {
    ngx_log_t  *log;
    size_t      frame_size;
    u_char     *pos;
    size_t      left;
} ngx_live_dvr_source_state_t;

typedef struct {
    uint32_t    id;
    uint32_t    size;
    uint64_t    offset;
} ngx_live_dvr_read_track_ctx_t;

typedef struct {
    ngx_pool_t                         *pool;
    media_segment_t                    *segment;
    ngx_live_dvr_read_track_ctx_t       tracks[KMP_MEDIA_COUNT];
    uint32_t                            read_tracks;
    ngx_live_dvr_read_pt                read;
    void                               *read_ctx;
    ngx_live_read_segment_callback_pt   callback;
    void                               *arg;
} ngx_live_dvr_read_ctx_t;


static ngx_int_t
ngx_live_dvr_source_init(ngx_pool_t *pool, ngx_str_t *buffer, void **result)
{
    ngx_live_dvr_source_state_t  *state;

    state = ngx_palloc(pool, sizeof(*state));
    if (state == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_source_init: ngx_palloc failed");
        return NGX_ERROR;
    }

    state->log = pool->log;
    state->pos = buffer->data;
    state->left = buffer->len;

    *result = state;

    return NGX_OK;
}

static vod_status_t
ngx_live_dvr_source_start_frame(void *ctx, input_frame_t *frame)
{
    ngx_live_dvr_source_state_t  *state = ctx;

    state->frame_size = frame->size;

    return VOD_OK;
}

static vod_status_t
ngx_live_dvr_source_read(void *ctx, u_char **buffer, uint32_t *size,
    bool_t *frame_done)
{
    ngx_live_dvr_source_state_t  *state = ctx;

    if (state->left < state->frame_size) {
        ngx_log_error(NGX_LOG_ERR, state->log, 0,
            "ngx_live_dvr_source_read: "
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

static frames_source_t  ngx_live_dvr_source = {
    ngx_live_dvr_source_start_frame,
    ngx_live_dvr_source_read,
};


/* Returns: NGX_ERROR = bad data, NGX_ABORT = alloc error */
static ngx_int_t
ngx_live_dvr_read_init_track(ngx_pool_t *pool, ngx_str_t *buf,
    media_segment_track_t *track)
{
    uint32_t                        frames_size;
    ngx_int_t                       rc;
    ngx_str_t                       frame_data;
    ngx_buf_chain_t                 extra_data;
    ngx_live_dvr_segment_header_t  *header;

    /* validate the header */
    if (buf->len < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: read size %uz too small",
            buf->len);
        return NGX_ERROR;
    }

    header = (void*)buf->data;
    if (header->magic != NGX_LIVE_DVR_SEGMENT_MAGIC) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: invalid magic 0x%uxD",
            header->magic);
        return NGX_ERROR;
    }

    if (buf->len < header->header_size) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: "
            "read size %uz smaller than header size %uD",
            buf->len, header->header_size);
        return NGX_ERROR;
    }


    if (header->extra_data_len > NGX_LIVE_MEDIA_INFO_MAX_EXTRA_DATA_LEN) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: extra data len %uD too big",
            header->extra_data_len);
        return NGX_ERROR;
    }

    if (header->frame_count > NGX_LIVE_SEGMENTER_MAX_FRAME_COUNT) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: frame count %uD too big",
            header->frame_count);
        return NGX_ERROR;
    }

    if (header->frames_start < sizeof(*header) + header->extra_data_len) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: frame start offset %uD too small",
            header->frames_start);
        return NGX_ERROR;
    }

    frames_size = header->frame_count * sizeof(input_frame_t);
    if (header->frames_start > NGX_MAX_INT32_VALUE - frames_size) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: frame start offset %uD too big",
            header->frames_start);
        return NGX_ERROR;
    }

    if (header->header_size < header->frames_start + frames_size) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read_init_track: header size %uD too small",
            header->header_size);
        return NGX_ERROR;
    }

    /* allocate and parse the media info */
    track->media_info = ngx_palloc(pool, sizeof(*track->media_info) +
        MAX_CODEC_NAME_SIZE);
    if (track->media_info == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read_init_track: alloc failed");
        return NGX_ABORT;
    }

    track->media_info->codec_name.data = (void*)(track->media_info + 1);

    extra_data.size = header->extra_data_len;
    extra_data.data = buf->data + header->frames_start - extra_data.size;
    extra_data.next = NULL;

    rc = ngx_live_media_info_parse(pool->log,
        (ngx_live_media_info_alloc_pt) ngx_palloc, pool, &header->media_info,
        &extra_data, extra_data.size, track->media_info);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read_init_track: failed to parse media info");
        return rc;
    }

    /* initialize the frames */
    frame_data.data = buf->data + header->header_size;
    frame_data.len = buf->len - header->header_size;

    rc = ngx_live_dvr_source_init(pool, &frame_data,
        &track->frames_source_context);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read_init_track: frame source init failed");
        return NGX_ABORT;
    }

    track->frames_source = &ngx_live_dvr_source;

    ngx_memzero(&track->frames, sizeof(track->frames));
    track->frames.part.elts = (void*)(buf->data + header->frames_start);
    track->frames.part.nelts = header->frame_count;
    track->frames.part.next = NULL;

    track->start_dts = header->start_dts;
    track->frame_count = header->frame_count;

    return NGX_OK;
}

void
ngx_live_dvr_read_complete(void *arg, ngx_int_t rc, ngx_buf_t *response)
{
    uint64_t                        offset;
    uint32_t                        i;
    uint32_t                        found_tracks;
    ngx_int_t                       code;
    ngx_str_t                       buf;
    ngx_live_dvr_read_ctx_t        *ctx = arg;
    ngx_live_dvr_file_header_t     *header;
    ngx_live_dvr_segment_entry_t   *cur_entry;
    ngx_live_dvr_segment_entry_t   *last_entry;
    ngx_live_dvr_read_track_ctx_t  *tctx;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: read failed %i", rc);
        code = rc;
        goto failed;
    }

    buf.data = response->pos;
    buf.len = response->last - response->pos;

    if (ctx->read_tracks > 0) {

        rc = ngx_live_dvr_read_init_track(ctx->pool, &buf,
            &ctx->segment->tracks[ctx->read_tracks - 1]);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->pool->log, 0,
                "ngx_live_dvr_read_complete: init track failed %i", rc);
            code = rc == NGX_ABORT ? NGX_HTTP_INTERNAL_SERVER_ERROR :
                NGX_HTTP_BAD_GATEWAY;
            goto failed;
        }

        if (ctx->read_tracks < ctx->segment->track_count) {
            goto read_next;
        }

        ctx->callback(ctx->arg, NGX_OK);
        return;
    }

    if (buf.len < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: read size %uz too small", buf.len);
        code = NGX_HTTP_BAD_GATEWAY;
        goto failed;
    }

    header = (void*) buf.data;

    if (header->magic != NGX_LIVE_DVR_FILE_MAGIC) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: invalid magic 0x%uxD", header->magic);
        code = NGX_HTTP_BAD_GATEWAY;
        goto failed;
    }

    if (buf.len < header->header_size) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: "
            "read size %uz smaller than header size %uD",
            buf.len, header->header_size);
        code = NGX_HTTP_BAD_GATEWAY;
        goto failed;
    }

    if (header->header_size < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: header size %uD too small",
            header->header_size);
        code = NGX_HTTP_BAD_GATEWAY;
        goto failed;
    }

    if (header->segment_count > (header->header_size - sizeof(*header)) /
        sizeof(*cur_entry))
    {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: segment count %uD too big",
            header->segment_count);
        code = NGX_HTTP_BAD_GATEWAY;
        goto failed;
    }

    found_tracks = 0;
    cur_entry = (void*)(header + 1);
    last_entry = cur_entry + header->segment_count;

    for (offset = header->header_size;
        cur_entry < last_entry;
        offset += cur_entry->size, cur_entry++)
    {
        if (cur_entry->segment_id != ctx->segment->segment_index) {
            continue;
        }

        for (i = 0; i < ctx->segment->track_count; i++) {

            if (ctx->tracks[i].id != cur_entry->track_id) {
                continue;
            }

            if (found_tracks & (1 << i)) {
                ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
                    "ngx_live_dvr_read_complete: "
                    "track %uD found more than once",
                    cur_entry->track_id);
                code = NGX_HTTP_BAD_GATEWAY;
                goto failed;
            }

            ctx->tracks[i].offset = offset;
            ctx->tracks[i].size = cur_entry->size;
            found_tracks |= (1 << i);
        }
    }

    if (found_tracks != (uint32_t)(1 << ctx->segment->track_count) - 1) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: "
            "some tracks are missing, found 0x%uxD",
            found_tracks);
        code = NGX_HTTP_NOT_FOUND;
        goto failed;
    }

read_next:

    tctx = &ctx->tracks[ctx->read_tracks];

    rc = ctx->read(ctx->read_ctx, tctx->offset, tctx->size);
    if (rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_ERR, ctx->pool->log, 0,
            "ngx_live_dvr_read_complete: read failed %i", rc);
        code = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    ctx->read_tracks++;

    return;

failed:

    ctx->callback(ctx->arg, code);
}

static ngx_int_t
ngx_live_dvr_read(ngx_live_segment_read_req_t *req)
{
    uint32_t                     i;
    uint32_t                     bucket_id;
    ngx_int_t                    rc;
    ngx_str_t                    path;
    ngx_pool_t                  *pool;
    media_segment_t             *segment;
    ngx_live_channel_t          *channel;
    ngx_live_dvr_read_ctx_t     *ctx;
    ngx_live_dvr_preset_conf_t  *dpcf;
    ngx_live_dvr_channel_ctx_t  *cctx;

    pool = req->pool;
    channel = req->channel;

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);
    if (dpcf->store == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_read: dvr not enabled");
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read: alloc failed");
        return NGX_ERROR;
    }

    segment = req->segment;
    bucket_id = segment->segment_index / dpcf->bucket_size;

    rc = ngx_live_dvr_get_path(channel, pool, bucket_id, &path);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read: get path failed %i", rc);
        return NGX_ERROR;
    }

    rc = dpcf->store->read_init(pool, channel, &path, ctx, &segment->source,
        &ctx->read_ctx);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read: read init failed %i", rc);
        return NGX_ERROR;
    }

    ctx->read = dpcf->store->read;

    ctx->pool = pool;
    ctx->segment = segment;
    for (i = 0; i < segment->track_count; i++) {
        ctx->tracks[i].id = req->tracks[i].id;
    }

    ctx->callback = req->callback;
    ctx->arg = req->arg;

    rc = ctx->read(ctx->read_ctx, 0, dpcf->initial_read_size);
    if (rc != NGX_AGAIN) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_read: read failed %i", rc);
        return NGX_ERROR;
    }

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);

    cctx->read_segments++;

    return NGX_AGAIN;
}


/* write */

static void
ngx_live_dvr_save_release_locks(void *data)
{
    ngx_live_input_bufs_lock_t  **cur;

    for (cur = data; *cur; cur++) {
        ngx_live_input_bufs_unlock(*cur);
    }
}

static ngx_chain_t **
ngx_live_dvr_save_append_segment(ngx_pool_t *pool, ngx_chain_t **ll,
    ngx_live_track_t *cur_track, ngx_live_segment_t *segment,
    ngx_live_dvr_segment_entry_t *entry)
{
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_buf_chain_t                *chain;
    ngx_list_part_t                *part;
    ngx_live_dvr_segment_header_t   header;

    header.frames_start = sizeof(header) +
        segment->media_info->extra_data.len;
    header.header_size = header.frames_start +
        segment->frame_count * sizeof(input_frame_t);

    b = ngx_create_temp_buf(pool, header.header_size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_save_append_segment: create header buf failed");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_save_append_segment: alloc chain failed");
        return NULL;
    }

    header.magic = NGX_LIVE_DVR_SEGMENT_MAGIC;
    header.flags = 0;
    header.reserved = 0;
    header.frame_count = segment->frame_count;
    header.start_dts = segment->start_dts;
    header.extra_data_len = segment->media_info->extra_data.len;
    header.media_info = *segment->kmp_media_info;

    b->last = ngx_copy(b->last, &header, sizeof(header));
    b->last = ngx_copy_str(b->last, segment->media_info->extra_data);

    for (part = &segment->frames.part; part != NULL; part = part->next) {
        b->last = ngx_copy(b->last, part->elts,
            part->nelts * sizeof(input_frame_t));
    }

    cl->buf = b;
    *ll = cl;
    ll = &cl->next;

    for (chain = segment->data_head; chain != NULL; chain = chain->next) {

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_dvr_save_append_segment: alloc chain failed");
            return NULL;
        }

        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                "ngx_live_dvr_save_append_segment: alloc buf failed");
            return NULL;
        }

        b->start = b->pos = chain->data;
        b->last = chain->data + chain->size;
        b->memory = 1;

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    entry->segment_id = segment->node.key;
    entry->track_id = cur_track->in.key;
    entry->size = header.header_size + segment->data_size;
    entry->metadata_size = header.header_size;

    return ll;
}

ngx_chain_t *
ngx_live_dvr_save_create_file(ngx_live_channel_t *channel, ngx_pool_t *pool,
    ngx_live_dvr_save_request_t *request)
{
    uint32_t                        limit;
    uint32_t                        bucket_size;
    uint32_t                        max_segments;
    uint32_t                        segment_index;
    ngx_buf_t                      *header_buf;
    ngx_queue_t                    *q;
    ngx_chain_t                    *cl;
    ngx_chain_t                    *out;
    ngx_chain_t                   **ll;
    ngx_live_track_t               *cur_track;
    ngx_live_segment_t             *segment;
    ngx_pool_cleanup_t             *cln;
    ngx_live_dvr_file_header_t     *header;
    ngx_live_dvr_preset_conf_t     *dpcf;
    ngx_live_input_bufs_lock_t    **locks;
    ngx_live_dvr_segment_entry_t   *segment_entry;

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);
    bucket_size = dpcf->bucket_size;
    max_segments = channel->tracks.count * bucket_size;

    header_buf = ngx_create_temp_buf(pool, sizeof(*header) +
        max_segments * sizeof(*segment_entry));
    if (header_buf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_create_file: alloc header buf failed");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_create_file: alloc chain failed");
        return NULL;
    }

    cln = ngx_pool_cleanup_add(pool, sizeof(*locks) * (max_segments + 1));
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_create_file: failed to add cleanup item");
        return NULL;
    }
    locks = cln->data;
    cln->handler = ngx_live_dvr_save_release_locks;

    ll = &out;
    request->size = 0;

    header = (void*) header_buf->last;
    header_buf->last += sizeof(*header);

    header->magic = NGX_LIVE_DVR_FILE_MAGIC;
    header->flags = 0;
    header->segment_count = 0;

    cl->buf = header_buf;
    *ll = cl;
    ll = &cl->next;

    limit = (request->bucket_id + 1) * bucket_size;
    for (segment_index = request->bucket_id * bucket_size;
        segment_index < limit;
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

            segment_entry = (void*) header_buf->last;
            header_buf->last += sizeof(*segment_entry);

            ll = ngx_live_dvr_save_append_segment(pool, ll, cur_track, segment,
                segment_entry);
            if (ll == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_live_dvr_create_file: append segment failed");
                *locks = NULL;
                return NULL;
            }

            *locks = ngx_live_segment_cache_lock_data(segment);
            if (*locks == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_live_dvr_create_file: lock segment failed");
                return NULL;
            }
            locks++;

            header->segment_count++;
            request->size += segment_entry->size;
        }
    }

    *locks = NULL;

    header->header_size = header_buf->last - header_buf->pos;
    request->size += header->header_size;

    *ll = NULL;

    return out;
}

void
ngx_live_dvr_save_complete(ngx_live_channel_t *channel,
    ngx_live_dvr_save_request_t *request, ngx_int_t rc)
{
    uint32_t                     limit;
    uint32_t                     segment_flag;
    uint32_t                     segment_index;
    uint32_t                     max_failed_index;
    ngx_live_dvr_channel_ctx_t  *cctx;
    ngx_live_dvr_preset_conf_t  *dpcf;

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);
    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_save_complete: save failed %i, bucket_id: %uD",
            rc, request->bucket_id);
        cctx->save_error++;

    } else {
        cctx->save_success++;
        cctx->save_success_msec += ngx_current_msec - request->start;
        cctx->save_success_size += request->size;
    }

    limit = (request->bucket_id + 1) * dpcf->bucket_size;
    max_failed_index = NGX_LIVE_INVALID_SEGMENT_INDEX;

    for (segment_index = request->bucket_id * dpcf->bucket_size;
        segment_index < limit;
        segment_index++)
    {
        if (segment_index >= cctx->segments_mask_start) {

            /* segment forced to memory, mark it as saved */
            segment_flag = 1 << (segment_index - cctx->segments_mask_start);
            cctx->saved_segments_mask |= segment_flag;

            if (rc != NGX_OK) {
                cctx->failed_segments_mask |= segment_flag;
            }
            continue;
        }

        /* segment not forced into memory, free it */
        ngx_live_segment_cache_free_by_index(channel, segment_index);

        if (rc != NGX_OK) {
            max_failed_index = segment_index;
        }
    }

    if (max_failed_index != NGX_LIVE_INVALID_SEGMENT_INDEX) {
        ngx_live_timelines_truncate(channel, max_failed_index);
    }
}

static ngx_inline void
ngx_live_dvr_save_bucket(ngx_live_channel_t *channel,
    ngx_live_dvr_channel_ctx_t *cctx, ngx_live_dvr_preset_conf_t *dpcf,
    uint32_t bucket_id)
{
    ngx_int_t                    rc;
    ngx_live_dvr_save_request_t  request;

    request.bucket_id = bucket_id;
    request.start = ngx_current_msec;
    request.size = 0;

    cctx->save_started++;

    if (channel->mem_left < channel->mem_high_watermark) {
        ngx_log_error(NGX_LOG_ERR, &channel->log, 0,
            "ngx_live_dvr_save_bucket: "
            "memory too low, aborting save, bucket_id: %uD", bucket_id);
        ngx_live_dvr_save_complete(channel, &request, NGX_ERROR);
        return;
    }

    rc = dpcf->store->save(channel, &request);
    if (rc != NGX_OK) {
        ngx_live_dvr_save_complete(channel, &request, rc);
    }
}

void
ngx_live_dvr_save_segment_created(ngx_live_channel_t *channel,
    ngx_flag_t exists)
{
    uint32_t                     i;
    uint32_t                     count;
    uint32_t                     bucket_id;
    uint32_t                     cur_index;
    uint32_t                     segment_flag;
    uint32_t                     segment_index;
    uint32_t                     new_mask_start;
    uint32_t                     max_failed_index;
    ngx_live_dvr_channel_ctx_t  *cctx;
    ngx_live_dvr_preset_conf_t  *dpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);
    if (cctx == NULL) {
        return;
    }

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);

    segment_index = channel->next_segment_index;

    if (segment_index >= cctx->segments_mask_start +
        dpcf->force_memory_segments)
    {
        new_mask_start = segment_index + 1 - dpcf->force_memory_segments;

        count = ngx_min(new_mask_start - cctx->segments_mask_start,
            dpcf->force_memory_segments);

        max_failed_index = NGX_LIVE_INVALID_SEGMENT_INDEX;

        for (i = 0; i < count; i++) {

            segment_flag = 1 << i;

            if ((cctx->saved_segments_mask & segment_flag) == 0) {
                continue;
            }

            cur_index = cctx->segments_mask_start + i;

            ngx_live_segment_cache_free_by_index(channel, cur_index);

            if (cctx->failed_segments_mask & segment_flag) {
                max_failed_index = cur_index;
            }
        }

        if (max_failed_index != NGX_LIVE_INVALID_SEGMENT_INDEX) {
            ngx_live_timelines_truncate(channel, max_failed_index);
        }

        cctx->saved_segments_mask >>= count;
        cctx->failed_segments_mask >>= count;
        cctx->segments_mask_start = new_mask_start;
    }

    bucket_id = segment_index / dpcf->bucket_size;

    if (cctx->last_bucket_id != NGX_LIVE_DVR_INVALID_BUCKET_ID &&
        cctx->last_bucket_id != bucket_id)
    {
        /* bucket changed since last time, save previous bucket */
        ngx_live_dvr_save_bucket(channel, cctx, dpcf, cctx->last_bucket_id);

        cctx->last_bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;
    }

    if ((segment_index + 1) % dpcf->bucket_size != 0) {
        /* more segments are expected in this bucket */
        if (exists) {
            cctx->last_bucket_id = bucket_id;
        }
        return;
    }

    /* last segment in the bucket, save it */
    if (!exists && cctx->last_bucket_id == NGX_LIVE_DVR_INVALID_BUCKET_ID) {
        return;
    }

    ngx_live_dvr_save_bucket(channel, cctx, dpcf, bucket_id);

    cctx->last_bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;
}


/* read + write */

ngx_int_t
ngx_live_dvr_get_path(ngx_live_channel_t *channel, ngx_pool_t *pool,
    uint32_t bucket_id, ngx_str_t *path)
{
    ngx_int_t                    rc;
    ngx_live_dvr_channel_ctx_t  *cctx;
    ngx_live_dvr_preset_conf_t  *dpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);

    cctx->bucket_id = bucket_id;

    rc = ngx_live_complex_value(channel, pool, dpcf->path, path);

    cctx->bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;

    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_dvr_bucket_id_variable(ngx_live_channel_t *channel, ngx_pool_t *pool,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    u_char                      *p;
    ngx_live_dvr_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);

    if (cctx == NULL || cctx->bucket_id == NGX_LIVE_DVR_INVALID_BUCKET_ID) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(pool, NGX_INT32_LEN);
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
ngx_live_dvr_bucket_time_variable(ngx_live_channel_t *channel,
    ngx_pool_t *pool, ngx_live_variable_value_t *v, uintptr_t data)
{
    time_t                           sec;
    int64_t                          time;
    uint32_t                         segment_index;
    uint32_t                         limit;
    ngx_tm_t                         tm;
    ngx_live_dvr_channel_ctx_t      *cctx;
    ngx_live_dvr_preset_conf_t      *dpcf;
    ngx_live_core_preset_conf_t     *cpcf;
    ngx_live_dvr_bucket_time_ctx_t  *var = (void*) data;

    char  buf[NGX_LIVE_DVR_DATE_LEN];

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);

    if (cctx == NULL || cctx->bucket_id == NGX_LIVE_DVR_INVALID_BUCKET_ID) {
        v->not_found = 1;
        return NGX_OK;
    }

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);

    limit = (cctx->bucket_id + 1) * dpcf->bucket_size;
    for (segment_index = cctx->bucket_id * dpcf->bucket_size;
        segment_index < limit;
        segment_index++)
    {
        if (segment_index >= limit) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                "ngx_live_dvr_bucket_time_variable: "
                "failed to get the timestamp of all segments in bucket %uD",
                cctx->bucket_id);
            return NGX_ERROR;
        }

        if (ngx_live_timelines_get_segment_time(channel, segment_index, &time)
            == NGX_OK) {
            break;
        }
    }

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    sec = time / cpcf->timescale;

    if (var->gmt) {
        ngx_libc_gmtime(sec, &tm);

    } else {
        ngx_libc_localtime(sec, &tm);
    }

    v->len = strftime(buf, NGX_LIVE_DVR_DATE_LEN,
        (char *) var->timefmt.data, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_dvr_bucket_time_variable: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(pool, v->len);
    if (v->data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_dvr_bucket_time_variable: alloc failed");
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static char *
ngx_live_dvr_bucket_time(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_str_t                        name;
    ngx_str_t                        zone;
    ngx_live_variable_t             *var;
    ngx_live_dvr_bucket_time_ctx_t  *ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_live_dvr_bucket_time_ctx_t));
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
        }
        else if (zone.len == 5 &&
            ngx_strncasecmp(zone.data, (u_char *) "local", 5) == 0)
        {
            ctx->gmt = 0;
        }
        else
        {
            return "invalid timezone";
        }
    }

    ctx->timefmt = value[2];

    var = ngx_live_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_live_dvr_bucket_time_variable;
    var->data = (uintptr_t) ctx;

    return NGX_CONF_OK;
}


static size_t
ngx_live_dvr_channel_json_get_size(void *obj)
{
    ngx_live_channel_t          *channel = obj;
    ngx_live_dvr_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);
    if (cctx == NULL) {
        return 0;
    }

    return sizeof("\"dvr\":{\"save_pending\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"save_error\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"save_success\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"save_success_size\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"save_success_msec\":") - 1 + NGX_INT64_LEN +
        sizeof(",\"read_segments\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_dvr_channel_json_write(u_char *p, void *obj)
{
    uint32_t                     save_pending;
    ngx_live_channel_t          *channel = obj;
    ngx_live_dvr_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);
    if (cctx == NULL) {
        return p;
    }

    save_pending = cctx->save_started - cctx->save_error - cctx->save_success;
    p = ngx_copy_fix(p, "\"dvr\":{\"save_pending\":");
    p = ngx_sprintf(p, "%uD", save_pending);
    p = ngx_copy_fix(p, ",\"save_error\":");
    p = ngx_sprintf(p, "%uD", cctx->save_error);
    p = ngx_copy_fix(p, ",\"save_success\":");
    p = ngx_sprintf(p, "%uD", cctx->save_success);
    p = ngx_copy_fix(p, ",\"save_success_size\":");
    p = ngx_sprintf(p, "%uL", cctx->save_success_size);
    p = ngx_copy_fix(p, ",\"save_success_msec\":");
    p = ngx_sprintf(p, "%uL", cctx->save_success_msec);
    p = ngx_copy_fix(p, ",\"read_segments\":");
    p = ngx_sprintf(p, "%uD", cctx->read_segments);
    *p++ = '}';
    return p;
}


static ngx_int_t
ngx_live_dvr_channel_init(ngx_live_channel_t *channel, size_t *track_ctx_size)
{
    ngx_live_dvr_channel_ctx_t  *cctx;
    ngx_live_dvr_preset_conf_t  *dpcf;

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);
    if (dpcf->store == NULL) {
        return NGX_OK;
    }

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dvr_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_dvr_module);

    cctx->bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;
    cctx->last_bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;

    return NGX_OK;
}

static ngx_int_t
ngx_live_dvr_channel_inactive(ngx_live_channel_t *channel)
{
    ngx_live_dvr_channel_ctx_t  *cctx;
    ngx_live_dvr_preset_conf_t  *dpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dvr_module);
    if (cctx == NULL ||
        cctx->last_bucket_id == NGX_LIVE_DVR_INVALID_BUCKET_ID)
    {
        return NGX_OK;
    }

    dpcf = ngx_live_get_module_preset_conf(channel, ngx_live_dvr_module);

    ngx_live_dvr_save_bucket(channel, cctx, dpcf, cctx->last_bucket_id);

    /* make sure the next segment will use a new bucket if the stream becomes
        active later */
    channel->next_segment_index = ngx_round_up_to_multiple(
        channel->next_segment_index, dpcf->bucket_size);

    cctx->last_bucket_id = NGX_LIVE_DVR_INVALID_BUCKET_ID;

    return NGX_OK;
}

static void *
ngx_live_dvr_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_dvr_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_dvr_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->store = NGX_CONF_UNSET_PTR;
    conf->bucket_size = NGX_CONF_UNSET_UINT;
    conf->force_memory_segments = NGX_CONF_UNSET_UINT;
    conf->initial_read_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_live_dvr_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_dvr_preset_conf_t  *prev = parent;
    ngx_live_dvr_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->store, prev->store, NULL);

    if (conf->path == NULL) {
        conf->path = prev->path;
    }

    ngx_conf_merge_uint_value(conf->bucket_size, prev->bucket_size, 2);

    ngx_conf_merge_uint_value(conf->force_memory_segments,
                              prev->force_memory_segments, 5);

    ngx_conf_merge_size_value(conf->initial_read_size,
                              prev->initial_read_size, 4 * 1024);

    if (conf->store != NULL && conf->path == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"dvr_path\" must be set when dvr is enabled");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_live_dvr_preconfiguration(ngx_conf_t *cf)
{
    ngx_live_variable_t  *var, *v;

    ngx_live_read_segment = ngx_live_dvr_read;

    for (v = ngx_live_dvr_vars; v->name.len; v++) {
        var = ngx_live_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_dvr_postconfiguration(ngx_conf_t *cf)
{
    ngx_live_json_writer_t            *writer;
    ngx_live_core_main_conf_t         *cmcf;
    ngx_live_channel_handler_pt       *ch;
    ngx_live_channel_init_handler_pt  *cih;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cih = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INIT]);
    if (cih == NULL) {
        return NGX_ERROR;
    }
    *cih = ngx_live_dvr_channel_init;

    ch = ngx_array_push(&cmcf->events[NGX_LIVE_EVENT_CHANNEL_INACTIVE]);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    *ch = ngx_live_dvr_channel_inactive;

    writer = ngx_array_push(&cmcf->json_writers[NGX_LIVE_JSON_CTX_CHANNEL]);
    if (writer == NULL) {
        return NGX_ERROR;
    }
    writer->get_size = ngx_live_dvr_channel_json_get_size;
    writer->write = ngx_live_dvr_channel_json_write;

    return NGX_OK;
}
