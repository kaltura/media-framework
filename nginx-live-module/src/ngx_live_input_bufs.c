#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_buf_queue.h>
#include "ngx_block_pool.h"
#include "ngx_live_input_bufs.h"


enum {
    NGX_LIVE_BP_OBJ,
    NGX_LIVE_BP_LOCK,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    ngx_queue_t             queue;
    ngx_buf_queue_t         buf_queue;
    ngx_queue_t             locks;          /* sorted by index */
    uint32_t                ref_count;
    uint32_t                lock_count;
    uint32_t                min_segment_index;
    u_char                 *min_ptr;
    unsigned                no_partial_free:1;
} ngx_live_input_bufs_t;

struct ngx_live_input_bufs_lock_s {
    ngx_queue_t             queue;
    ngx_live_input_bufs_t  *input_bufs;
    uint32_t                segment_index;
    uint32_t                ref_count;
    u_char                 *ptr;
};


typedef struct {
    ngx_live_input_bufs_t  *input_bufs;
} ngx_live_input_bufs_track_ctx_t;


/* Note: the channel level queue points to all input bufs associated with the
    channel. it is required in order to detach them when the channel is freed.
    we can't use the tracks for this - when a track is freed, the input bufs
    may still be linked to the channel if they are locked */

typedef struct {
    ngx_queue_t             queue;
} ngx_live_input_bufs_channel_ctx_t;


typedef struct {
    size_t                  buffer_size;
    ngx_uint_t              bin_count;
    ngx_uint_t              max_free_buffers;
    ngx_lba_t              *lba;
} ngx_live_input_bufs_preset_conf_t;


static ngx_int_t ngx_live_input_bufs_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_live_input_bufs_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_input_bufs_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_input_bufs_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_live_input_bufs_commands[] = {
    { ngx_string("input_bufs_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_input_bufs_preset_conf_t, buffer_size),
      NULL },

    { ngx_string("input_bufs_bin_count"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_input_bufs_preset_conf_t, bin_count),
      NULL },

    { ngx_string("input_bufs_max_free"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_input_bufs_preset_conf_t, max_free_buffers),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_input_bufs_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_live_input_bufs_postconfiguration,  /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_live_input_bufs_create_preset_conf, /* create preset configuration */
    ngx_live_input_bufs_merge_preset_conf,  /* merge preset configuration */
};

ngx_module_t  ngx_live_input_bufs_module = {
    NGX_MODULE_V1,
    &ngx_live_input_bufs_module_ctx,        /* module context */
    ngx_live_input_bufs_commands,           /* module directives */
    NGX_LIVE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_live_input_bufs_init_process,       /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_block_pool_t  *ngx_live_input_bufs_pool;
static size_t             ngx_live_input_bufs_mem_left;
static ngx_queue_t        ngx_live_input_bufs_zombie;


static ngx_int_t
ngx_live_input_bufs_init_process(ngx_cycle_t *cycle)
{
    size_t  sizes[NGX_LIVE_BP_COUNT];

    ngx_live_input_bufs_mem_left = NGX_MAX_SIZE_T_VALUE;

    sizes[NGX_LIVE_BP_OBJ] = sizeof(ngx_live_input_bufs_t);
    sizes[NGX_LIVE_BP_LOCK] = sizeof(ngx_live_input_bufs_lock_t);

    ngx_live_input_bufs_pool = ngx_block_pool_create(cycle->pool, sizes,
        NGX_LIVE_BP_COUNT, &ngx_live_input_bufs_mem_left);
    if (ngx_live_input_bufs_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
            "ngx_live_input_bufs_init_process: create block pool failed");
        return NGX_ERROR;
    }

    ngx_queue_init(&ngx_live_input_bufs_zombie);

    return NGX_OK;
}

static ngx_live_input_bufs_t *
ngx_live_input_bufs_create(ngx_live_track_t *track)
{
    ngx_int_t                           rc;
    ngx_live_channel_t                 *channel;
    ngx_live_input_bufs_t              *result;
    ngx_live_input_bufs_preset_conf_t  *conf;
    ngx_live_input_bufs_channel_ctx_t  *cctx;

    result = ngx_block_pool_calloc(ngx_live_input_bufs_pool, NGX_LIVE_BP_OBJ);
    if (result == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_input_bufs_create: alloc failed");
        return NULL;
    }

    channel = track->channel;

    conf = ngx_live_get_module_preset_conf(channel,
        ngx_live_input_bufs_module);

    rc = ngx_buf_queue_init(&result->buf_queue, &track->log, conf->lba,
        conf->max_free_buffers, &channel->mem_left);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_input_bufs_create: buf queue init failed %i", rc);
        ngx_block_pool_free(ngx_live_input_bufs_pool, NGX_LIVE_BP_OBJ, result);
        return NULL;
    }

    ngx_queue_init(&result->locks);
    result->ref_count = 1;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_input_bufs_module);

    ngx_queue_insert_tail(&cctx->queue, &result->queue);

    return result;
}

static void
ngx_live_input_bufs_free_bufs(ngx_live_input_bufs_t *input_bufs)
{
    u_char                      *ptr;
    uint32_t                     segment_index;
    ngx_queue_t                 *q;
    ngx_live_input_bufs_lock_t  *cur;

    if (input_bufs->no_partial_free) {
        return;
    }

    segment_index = input_bufs->min_segment_index;
    if (segment_index <= 0) {
        return;
    }

    ptr = input_bufs->min_ptr;

    if (!ngx_queue_empty(&input_bufs->locks)) {
        q = ngx_queue_head(&input_bufs->locks);
        cur = ngx_queue_data(q, ngx_live_input_bufs_lock_t, queue);

        if (cur->segment_index < segment_index) {
            ptr = cur->ptr;
        }
    }

    ngx_buf_queue_free(&input_bufs->buf_queue, ptr);
}

static void
ngx_live_input_bufs_free(ngx_live_input_bufs_t *input_bufs)
{
    if (input_bufs->ref_count <= 0) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
            "ngx_live_input_bufs_free: ref count is zero");
        return;
    }

    input_bufs->ref_count--;

    if (input_bufs->ref_count > 0) {
        ngx_live_input_bufs_free_bufs(input_bufs);
        return;
    }

    if (!ngx_queue_empty(&input_bufs->locks)) {
        ngx_log_error(NGX_LOG_ALERT, input_bufs->buf_queue.log, 0,
            "ngx_live_input_bufs_free: locks queue is not empty");
        return;
    }

    ngx_buf_queue_delete(&input_bufs->buf_queue);

    ngx_queue_remove(&input_bufs->queue);

    ngx_block_pool_free(ngx_live_input_bufs_pool, NGX_LIVE_BP_OBJ, input_bufs);
}

ngx_int_t
ngx_live_input_bufs_get(ngx_live_track_t *track, ngx_buf_t *b)
{
    ngx_live_channel_t               *channel;
    ngx_live_input_bufs_t            *input_bufs;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    input_bufs = ctx->input_bufs;

    b->start = ngx_buf_queue_get(&input_bufs->buf_queue);
    if (b->start == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_input_bufs_get: failed to get buffer");
        return NGX_ERROR;
    }

    b->end = b->start + input_bufs->buf_queue.used_size;

    b->pos = b->last = b->start;

    channel = track->channel;
    if (channel->mem_left < channel->mem_high_watermark) {
        (void) ngx_live_core_channel_event(channel,
            NGX_LIVE_EVENT_CHANNEL_WATERMARK, NULL);
    }

    return NGX_OK;
}

ngx_buf_chain_t *
ngx_live_input_bufs_read_chain(ngx_live_track_t *track, ngx_str_t *src,
    ngx_buf_chain_t **tail)
{
    ngx_buf_t         b;
    ngx_str_t         left = *src;
    ngx_buf_chain_t  *head, **last;
    ngx_buf_chain_t  *cur = NULL;

    last = &head;

    for ( ;; ) {

        if (ngx_live_input_bufs_get(track, &b) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_input_bufs_read_chain: get buf failed");
            return NULL;
        }

        cur = ngx_live_channel_buf_chain_alloc(track->channel);
        if (cur == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_input_bufs_read_chain: alloc buf chain failed");
            return NULL;
        }

        *last = cur;
        last = &cur->next;

        cur->data = b.last;

        cur->size = b.end - b.last;
        if (cur->size >= left.len) {
            cur->size = left.len;
            ngx_memcpy(cur->data, left.data, cur->size);
            break;
        }

        ngx_memcpy(cur->data, left.data, cur->size);
        left.data += cur->size;
        left.len -= cur->size;
    }

    *last = NULL;

    *tail = cur;
    return head;
}

ngx_live_input_bufs_lock_t *
ngx_live_input_bufs_lock(ngx_live_track_t *track, uint32_t segment_index,
    u_char *ptr)
{
    ngx_queue_t                      *q;
    ngx_live_input_bufs_t            *input_bufs;
    ngx_live_input_bufs_lock_t       *cur;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    input_bufs = ctx->input_bufs;

    /* Note: the assumption here is that there aren't many locks, otherwise
        this can be inefficient */

    for (q = ngx_queue_last(&input_bufs->locks);
        q != ngx_queue_sentinel(&input_bufs->locks);
        q = ngx_queue_prev(q))
    {
        cur = ngx_queue_data(q, ngx_live_input_bufs_lock_t, queue);

        if (input_bufs->no_partial_free) {
            cur->ref_count++;
            goto done;
        }

        if (segment_index < cur->segment_index) {
            continue;
        }

        if (segment_index > cur->segment_index) {
            break;
        }

        if (cur->ptr != ptr) {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_live_input_bufs_lock: "
                "inconsistent ptr for segment %uD",
                segment_index);
            return NULL;
        }

        cur->ref_count++;
        goto done;
    }

    cur = ngx_block_pool_alloc(ngx_live_input_bufs_pool, NGX_LIVE_BP_LOCK);
    if (cur == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_live_input_bufs_lock: alloc failed");
        return NULL;
    }

    ngx_queue_insert_after(q, &cur->queue);
    cur->input_bufs = input_bufs;
    input_bufs->ref_count++;

    cur->ptr = ptr;
    cur->segment_index = segment_index;
    cur->ref_count = 1;

done:

    input_bufs->lock_count++;
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_input_bufs_lock: "
        "locked index: %uD, lock: %p, ref_count: %uD",
        segment_index, cur, cur->ref_count);
    return cur;
}

void
ngx_live_input_bufs_unlock(ngx_live_input_bufs_lock_t *lock)
{
    if (lock->ref_count <= 0) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
            "ngx_live_input_bufs_unlock: ref count is zero");
        return;
    }

    lock->ref_count--;
    lock->input_bufs->lock_count--;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
        "ngx_live_input_bufs_unlock: "
        "unlocked index: %uD, lock: %p, ref_count: %uD",
        lock->segment_index, lock, lock->ref_count);

    if (lock->ref_count > 0) {
        return;
    }

    ngx_queue_remove(&lock->queue);

    ngx_live_input_bufs_free(lock->input_bufs);

    ngx_block_pool_free(ngx_live_input_bufs_pool, NGX_LIVE_BP_LOCK, lock);
}

ngx_int_t
ngx_live_input_bufs_lock_cleanup(ngx_pool_t *pool, ngx_live_track_t *track,
    uint32_t segment_index, u_char *ptr)
{
    ngx_pool_cleanup_t          *cln;
    ngx_live_input_bufs_lock_t  *lock;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    lock = ngx_live_input_bufs_lock(track, segment_index, ptr);
    if (lock == NULL) {
        return NGX_ERROR;
    }

    cln->handler = (ngx_pool_cleanup_pt) ngx_live_input_bufs_unlock;
    cln->data = lock;

    return NGX_OK;
}

void
ngx_live_input_bufs_set_min_used(ngx_live_track_t *track,
    uint32_t segment_index, u_char *ptr)
{
    ngx_live_input_bufs_t            *input_bufs;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_live_input_bufs_set_min_used: index: %uD ptr: %p",
        segment_index, ptr);

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    input_bufs = ctx->input_bufs;

    input_bufs->min_segment_index = segment_index;
    input_bufs->min_ptr = ptr;

    ngx_live_input_bufs_free_bufs(input_bufs);
}

void
ngx_live_input_bufs_link(ngx_live_track_t *dst, ngx_live_track_t *src)
{
    ngx_live_input_bufs_t            *input_bufs;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(src, ngx_live_input_bufs_module);

    input_bufs = ctx->input_bufs;

    ctx = ngx_live_get_module_ctx(dst, ngx_live_input_bufs_module);

    ngx_live_input_bufs_free(ctx->input_bufs);

    ctx->input_bufs = input_bufs;

    input_bufs->ref_count++;
    input_bufs->no_partial_free = 1;
}


static ngx_int_t
ngx_live_input_bufs_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_input_bufs_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_input_bufs_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_input_bufs_module);

    ngx_queue_init(&cctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_input_bufs_channel_free(ngx_live_channel_t *channel, void *ectx)
{
    ngx_queue_t                        *q, *next;
    ngx_live_input_bufs_t              *cur;
    ngx_live_input_bufs_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_input_bufs_module);
    if (cctx == NULL) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = next)
    {
        next = ngx_queue_next(q);
        cur = ngx_queue_data(q, ngx_live_input_bufs_t, queue);

        ngx_buf_queue_detach(&cur->buf_queue);

        ngx_queue_insert_tail(&ngx_live_input_bufs_zombie, q);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_input_bufs_track_init(ngx_live_track_t *track, void *ectx)
{
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    ctx->input_bufs = ngx_live_input_bufs_create(track);
    if (ctx->input_bufs == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_input_bufs_track_free(ngx_live_track_t *track, void *ectx)
{
    ngx_live_input_bufs_t            *input_bufs;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    input_bufs = ctx->input_bufs;
    if (input_bufs != NULL) {
        ngx_buf_queue_detach(&input_bufs->buf_queue);

        ngx_live_input_bufs_free(input_bufs);
        ctx->input_bufs = NULL;
    }

    return NGX_OK;
}


static size_t
ngx_live_input_bufs_global_json_get_size(void *obj)
{
    return sizeof("\"zombie_input_bufs\":{\"size\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"lock_count\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_input_bufs_global_json_write(u_char *p, void *obj)
{
    size_t                  size;
    uint32_t                count, lock_count;
    ngx_queue_t            *q;
    ngx_buf_queue_t        *buf_queue;
    ngx_live_input_bufs_t  *cur;

    size = 0;
    count = 0;
    lock_count = 0;

    for (q = ngx_queue_head(&ngx_live_input_bufs_zombie);
        q != ngx_queue_sentinel(&ngx_live_input_bufs_zombie);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_input_bufs_t, queue);

        buf_queue = &cur->buf_queue;
        size += buf_queue->nbuffers * buf_queue->alloc_size;
        lock_count += cur->lock_count;
        count++;
    }

    p = ngx_copy_fix(p, "\"zombie_input_bufs\":{\"size\":");
    p = ngx_sprintf(p, "%uz", size);
    p = ngx_copy_fix(p, ",\"count\":");
    p = ngx_sprintf(p, "%uD", count);
    p = ngx_copy_fix(p, ",\"lock_count\":");
    p = ngx_sprintf(p, "%uD", lock_count);
    *p++ = '}';

    return p;
}

static size_t
ngx_live_input_bufs_track_json_get_size(void *obj)
{
    return sizeof("\"input_bufs\":{\"size\":") - 1 + NGX_SIZE_T_LEN +
        sizeof(",\"min_used_index\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"lock_count\":") - 1 + NGX_INT32_LEN +
        sizeof(",\"min_lock_index\":") - 1 + NGX_INT32_LEN +
        sizeof("}") - 1;
}

static u_char *
ngx_live_input_bufs_track_json_write(u_char *p, void *obj)
{
    size_t                            size;
    ngx_queue_t                      *q;
    ngx_buf_queue_t                  *buf_queue;
    ngx_live_track_t                 *track = obj;
    ngx_live_input_bufs_lock_t       *first_lock;
    ngx_live_input_bufs_track_ctx_t  *ctx;

    ctx = ngx_live_get_module_ctx(track, ngx_live_input_bufs_module);

    buf_queue = &ctx->input_bufs->buf_queue;
    size = buf_queue->nbuffers * buf_queue->alloc_size;

    p = ngx_copy_fix(p, "\"input_bufs\":{\"size\":");
    p = ngx_sprintf(p, "%uz", size);

    p = ngx_copy_fix(p, ",\"min_used_index\":");
    p = ngx_sprintf(p, "%uD", ctx->input_bufs->min_segment_index);

    p = ngx_copy_fix(p, ",\"lock_count\":");
    p = ngx_sprintf(p, "%uD", ctx->input_bufs->lock_count);

    if (!ngx_queue_empty(&ctx->input_bufs->locks)) {
        q = ngx_queue_head(&ctx->input_bufs->locks);
        first_lock = ngx_queue_data(q, ngx_live_input_bufs_lock_t, queue);

        p = ngx_copy_fix(p, ",\"min_lock_index\":");
        p = ngx_sprintf(p, "%uD", first_lock->segment_index);
    }

    *p++ = '}';

    return p;
}


static ngx_live_channel_event_t    ngx_live_input_bufs_channel_events[] = {
    { ngx_live_input_bufs_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
    { ngx_live_input_bufs_channel_free, NGX_LIVE_EVENT_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_live_track_event_t      ngx_live_input_bufs_track_events[] = {
    { ngx_live_input_bufs_track_init, NGX_LIVE_EVENT_TRACK_INIT },
    { ngx_live_input_bufs_track_free, NGX_LIVE_EVENT_TRACK_FREE },
    { ngx_live_input_bufs_track_free, NGX_LIVE_EVENT_TRACK_CHANNEL_FREE },

      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_input_bufs_json_writers[] = {
    { { ngx_live_input_bufs_global_json_get_size,
        ngx_live_input_bufs_global_json_write },
      NGX_LIVE_JSON_CTX_GLOBAL },

    { { ngx_live_input_bufs_track_json_get_size,
        ngx_live_input_bufs_track_json_write },
      NGX_LIVE_JSON_CTX_TRACK },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_input_bufs_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_input_bufs_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_track_events_add(cf, ngx_live_input_bufs_track_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_input_bufs_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_live_input_bufs_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_input_bufs_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_input_bufs_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->bin_count = NGX_CONF_UNSET_UINT;
    conf->max_free_buffers = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_live_input_bufs_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_input_bufs_preset_conf_t  *prev = parent;
    ngx_live_input_bufs_preset_conf_t  *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 10240);

    ngx_conf_merge_size_value(conf->bin_count,
                              prev->bin_count, 8);

    ngx_conf_merge_uint_value(conf->max_free_buffers,
                              prev->max_free_buffers, 4);

    conf->lba = ngx_live_core_get_lba(cf, conf->buffer_size, conf->bin_count);
    if (conf->lba == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_reserve_track_ctx_size(cf, ngx_live_input_bufs_module,
        sizeof(ngx_live_input_bufs_track_ctx_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
