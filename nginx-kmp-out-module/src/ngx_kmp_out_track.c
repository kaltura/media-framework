#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_call.h>
#include <ngx_buf_queue.h>
#include <ngx_live_kmp.h>
#include <ngx_json_parser.h>

#include "ngx_kmp_out_utils.h"
#include "ngx_kmp_out_track_internal.h"
#include "ngx_kmp_out_upstream.h"


#define NGX_KMP_OUT_TRACK_STAT_PERIOD  10  /* sec */


enum {
    NGX_KMP_OUT_LOG_FRAMES_OFF,
    NGX_KMP_OUT_LOG_FRAMES_ALL,
    NGX_KMP_OUT_LOG_FRAMES_KEY,
};


ngx_conf_enum_t  ngx_kmp_out_log_frames[] = {
    { ngx_string("all"), NGX_KMP_OUT_LOG_FRAMES_ALL },
    { ngx_string("key"), NGX_KMP_OUT_LOG_FRAMES_KEY },
    { ngx_string("off"), NGX_KMP_OUT_LOG_FRAMES_OFF },
    { ngx_null_string, 0 }
};


typedef struct {
    ngx_rbtree_t          rbtree;
    ngx_rbtree_node_t     sentinel;
    ngx_queue_t           queue;
    ngx_uint_t            counter;
} ngx_kmp_out_tracks_t;


typedef struct {
    ngx_kmp_out_track_t  *track;
    ngx_uint_t            retries_left;
} ngx_kmp_out_publish_call_ctx_t;


typedef struct {
    ngx_kmp_out_track_t  *track;
} ngx_kmp_out_unpublish_call_ctx_t;


static ngx_int_t ngx_kmp_out_track_send_end_of_stream(
    ngx_kmp_out_track_t *track);

static void ngx_kmp_out_track_cleanup(ngx_kmp_out_track_t *track);


static size_t  ngx_kmp_out_track_default_buffer_size[KMP_MEDIA_COUNT] = {
    64 * 1024,
    4 * 1024,
    1 * 1024,
};


static size_t  ngx_kmp_out_track_default_mem_limit[KMP_MEDIA_COUNT] = {
    48 * 1024 * 1024,
    1 * 1024 * 1024,
    128 * 1024,
};


static ngx_kmp_out_tracks_t  ngx_kmp_out_tracks;


#include "ngx_kmp_out_track_json.h"


ngx_int_t
ngx_kmp_out_track_init_process(ngx_cycle_t *cycle)
{
    ngx_rbtree_init(&ngx_kmp_out_tracks.rbtree, &ngx_kmp_out_tracks.sentinel,
        ngx_str_rbtree_insert_value);
    ngx_queue_init(&ngx_kmp_out_tracks.queue);

    ngx_kmp_out_tracks.counter = 1;

    return NGX_OK;
}


int64_t
ngx_kmp_out_track_get_time(ngx_kmp_out_track_t *track)
{
    struct timespec  spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    return (int64_t) spec.tv_sec * track->media_info.timescale +
        (int64_t) spec.tv_nsec * track->media_info.timescale / 1000000000;
}


void
ngx_kmp_out_track_init_conf(ngx_kmp_out_track_conf_t *conf)
{
    ngx_uint_t  media_type;

    conf->ctrl_publish_url = NGX_CONF_UNSET_PTR;
    conf->ctrl_unpublish_url = NGX_CONF_UNSET_PTR;
    conf->ctrl_republish_url = NGX_CONF_UNSET_PTR;
    conf->ctrl_timeout = NGX_CONF_UNSET_MSEC;
    conf->ctrl_read_timeout = NGX_CONF_UNSET_MSEC;
    conf->ctrl_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->ctrl_retries = NGX_CONF_UNSET_UINT;
    conf->ctrl_retry_interval = NGX_CONF_UNSET_MSEC;

    conf->timescale = NGX_CONF_UNSET_UINT;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->max_free_buffers = NGX_CONF_UNSET_UINT;
    conf->buffer_bin_count = NGX_CONF_UNSET_UINT;
    conf->mem_high_watermark = NGX_CONF_UNSET_UINT;
    conf->mem_low_watermark = NGX_CONF_UNSET_UINT;
    conf->flush_timeout = NGX_CONF_UNSET_MSEC;
    conf->keepalive_interval = NGX_CONF_UNSET_MSEC;
    conf->log_frames = NGX_CONF_UNSET_UINT;

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        conf->buffer_size[media_type] = NGX_CONF_UNSET_SIZE;
        conf->mem_limit[media_type] = NGX_CONF_UNSET_SIZE;
    }

    conf->republish_interval = NGX_CONF_UNSET_MSEC;
    conf->max_republishes = NGX_CONF_UNSET_UINT;
}


ngx_int_t
ngx_kmp_out_track_merge_conf(ngx_conf_t *cf, ngx_kmp_out_track_conf_t *conf,
    ngx_kmp_out_track_conf_t *prev)
{
    ngx_uint_t  media_type;

    ngx_conf_merge_ptr_value(conf->ctrl_publish_url,
                             prev->ctrl_publish_url, NULL);

    ngx_conf_merge_ptr_value(conf->ctrl_unpublish_url,
                             prev->ctrl_unpublish_url, NULL);

    ngx_conf_merge_ptr_value(conf->ctrl_republish_url,
                             prev->ctrl_republish_url, NULL);

    if (conf->ctrl_headers == NULL) {
        conf->ctrl_headers = prev->ctrl_headers;
    }

    ngx_conf_merge_msec_value(conf->ctrl_timeout,
                              prev->ctrl_timeout, 2000);

    ngx_conf_merge_msec_value(conf->ctrl_read_timeout,
                              prev->ctrl_read_timeout, 20000);

    ngx_conf_merge_size_value(conf->ctrl_buffer_size,
                              prev->ctrl_buffer_size, 4 * 1024);

    ngx_conf_merge_uint_value(conf->ctrl_retries,
                              prev->ctrl_retries, 5);

    ngx_conf_merge_msec_value(conf->ctrl_retry_interval,
                              prev->ctrl_retry_interval, 2000);

    ngx_conf_merge_uint_value(conf->timescale, prev->timescale, 90000);

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 10000);

    ngx_conf_merge_uint_value(conf->max_free_buffers,
                              prev->max_free_buffers, 4);

    ngx_conf_merge_size_value(conf->buffer_bin_count,
                              prev->buffer_bin_count, 8);

    ngx_conf_merge_uint_value(conf->mem_high_watermark,
                              prev->mem_high_watermark, 75);

    ngx_conf_merge_uint_value(conf->mem_low_watermark,
                              prev->mem_low_watermark, 50);

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        ngx_conf_merge_size_value(conf->buffer_size[media_type],
            prev->buffer_size[media_type],
            ngx_kmp_out_track_default_buffer_size[media_type]);

        ngx_conf_merge_size_value(conf->mem_limit[media_type],
            prev->mem_limit[media_type],
            ngx_kmp_out_track_default_mem_limit[media_type]);
    }

    ngx_conf_merge_msec_value(conf->flush_timeout, prev->flush_timeout, 1000);

    ngx_conf_merge_msec_value(conf->keepalive_interval,
                              prev->keepalive_interval, 0);

    ngx_conf_merge_uint_value(conf->log_frames, prev->log_frames,
                              NGX_KMP_OUT_LOG_FRAMES_OFF);

    ngx_conf_merge_msec_value(conf->republish_interval,
                              prev->republish_interval, 1000);

    ngx_conf_merge_uint_value(conf->max_republishes,
                              prev->max_republishes, 15);

    for (media_type = 0; media_type < KMP_MEDIA_COUNT; media_type++) {
        conf->lba[media_type] = ngx_lba_get_global(cf,
            conf->buffer_size[media_type], conf->buffer_bin_count);
        if (conf->lba[media_type] == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_http_call_ctx_t *
ngx_kmp_out_track_http_call_create(ngx_kmp_out_track_t *track,
    ngx_http_call_init_t *ci)
{
    ngx_kmp_out_track_conf_t  *conf = track->conf;

    ci->timeout = conf->ctrl_timeout;
    ci->read_timeout = conf->ctrl_read_timeout;
    ci->retry_interval = conf->ctrl_retry_interval;
    ci->buffer_size = conf->ctrl_buffer_size;

    return ngx_http_call_create(ci);
}


size_t
ngx_kmp_out_track_media_info_json_get_size(ngx_kmp_out_track_t *track)
{
    size_t  size;

    size = sizeof("\"media_info\":{") - 1 + sizeof("}") - 1;

    switch (track->media_info.media_type) {

    case KMP_MEDIA_VIDEO:
        size += ngx_kmp_out_track_video_json_get_size(track);
        break;

    case KMP_MEDIA_AUDIO:
        size += ngx_kmp_out_track_audio_json_get_size(track);
        break;

    case KMP_MEDIA_SUBTITLE:
        size += ngx_kmp_out_track_subtitle_json_get_size(track);
        break;
    }

    return size;
}


u_char *
ngx_kmp_out_track_media_info_json_write(u_char *p,
    ngx_kmp_out_track_t *track)
{
    p = ngx_copy_fix(p, "\"media_info\":{");

    switch (track->media_info.media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_kmp_out_track_video_json_write(p, track);
        break;

    case KMP_MEDIA_AUDIO:
        p = ngx_kmp_out_track_audio_json_write(p, track);
        break;

    case KMP_MEDIA_SUBTITLE:
        p = ngx_kmp_out_track_subtitle_json_write(p, track);
        break;
    }

    *p++ = '}';

    return p;
}


void
ngx_kmp_out_track_set_error_reason(ngx_kmp_out_track_t *track, char *code)
{
    if (track->unpublish_reason.s.len == 0) {
        track->unpublish_reason.s.data = (u_char *) code;
        track->unpublish_reason.s.len = ngx_strlen(code);

        ngx_json_str_set_escape(&track->unpublish_reason);
    }
}


ngx_int_t
ngx_kmp_out_track_publish_json(ngx_kmp_out_track_t *track,
    ngx_json_object_t *obj, ngx_pool_t *temp_pool)
{
    ngx_str_t                  track_id;
    ngx_str_t                  channel_id;
    ngx_array_part_t          *part;
    ngx_json_array_t          *upstreams;
    ngx_json_object_t         *cur;
    kmp_connect_packet_t      *header;
    ngx_kmp_out_track_json_t   json;

    /* parse and validate the json */

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(temp_pool, obj, ngx_kmp_out_track_json,
        ngx_array_entries(ngx_kmp_out_track_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_publish_json: failed to parse object");
        return NGX_ERROR;
    }

    if (json.channel_id.data == NGX_CONF_UNSET_PTR ||
        json.track_id.data == NGX_CONF_UNSET_PTR ||
        json.upstreams == NGX_CONF_UNSET_PTR)
    {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_track_publish_json: missing required params in json");
        return NGX_ERROR;
    }

    channel_id = json.channel_id;
    if (channel_id.len > sizeof(header->c.channel_id)) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_track_publish_json: channel id \"%V\" too long",
            &channel_id);
        return NGX_ERROR;
    }

    track_id = json.track_id;
    if (track_id.len > sizeof(header->c.track_id)) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_track_publish_json: track id \"%V\" too long",
            &track_id);
        return NGX_ERROR;
    }

    upstreams = json.upstreams;
    if (upstreams->count != 0 && upstreams->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_track_publish_json: "
            "invalid upstreams element type %d", upstreams->type);
        return NGX_ERROR;
    }

    /* init the header */

    header = &track->connect;
    header->header.packet_type = KMP_PACKET_CONNECT;
    header->header.header_size = sizeof(*header);
    ngx_memcpy(header->c.channel_id, channel_id.data, channel_id.len);
    ngx_memcpy(header->c.track_id, track_id.data, track_id.len);
    header->c.flags = KMP_CONNECT_FLAG_CONSISTENT;

    track->channel_id.s.data = header->c.channel_id;
    track->channel_id.s.len = channel_id.len;

    ngx_json_str_set_escape(&track->channel_id);

    track->track_id.s.data = header->c.track_id;
    track->track_id.s.len = track_id.len;

    ngx_json_str_set_escape(&track->track_id);

    /* create the upstreams */

    if (upstreams->count == 0) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_kmp_out_track_publish_json: no upstreams");
        track->state = NGX_KMP_TRACK_INACTIVE;
        ngx_kmp_out_track_cleanup(track);
        return NGX_OK;
    }

    part = &upstreams->part;
    for (cur = part->first; ; cur++) {
        if ((void *) cur >= part->last) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            cur = part->first;
        }

        if (ngx_kmp_out_upstream_from_json(temp_pool, track, NULL, cur)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_out_track_publish_json: failed to create upstream");
            ngx_kmp_out_track_error(track, "create_upstream_failed");
            return NGX_OK;
        }
    }

    if (track->conf->keepalive_interval > 0) {
        ngx_add_timer(&track->keepalive, track->conf->keepalive_interval);
    }

    track->state = NGX_KMP_TRACK_ACTIVE;

    return NGX_OK;
}


static ngx_chain_t *
ngx_kmp_out_track_publish_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    size_t                           size;
    u_char                          *p;
    ngx_buf_t                       *b;
    ngx_chain_t                     *cl;
    ngx_kmp_out_track_t             *track;
    ngx_kmp_out_track_conf_t        *conf;
    ngx_kmp_out_publish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    size = sizeof("{,,}") +
        ngx_kmp_out_track_publish_json_get_size(track) +
        track->json_info.len +
        ngx_kmp_out_track_media_info_json_get_size(track);

    cl = ngx_http_call_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_out_track_publish_create: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;
    p = b->last;

    *p++ = '{';
    p = ngx_kmp_out_track_publish_json_write(p, track);
    if (track->json_info.len > 0) {
        *p++ = ',';
        p = ngx_copy(p, track->json_info.data, track->json_info.len);
    }

    *p++ = ',';
    p = ngx_kmp_out_track_media_info_json_write(p, track);
    *p++ = '}';

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_out_track_publish_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NULL;
    }

    b->last = p;

    conf = ctx->track->conf;

    return ngx_http_call_format_json_post(pool,
        &conf->ctrl_publish_url->host, &conf->ctrl_publish_url->uri,
        conf->ctrl_headers, cl);
}


static ngx_int_t
ngx_kmp_out_publish_handle(ngx_pool_t *temp_pool, void *arg, ngx_uint_t code,
    ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_int_t                        rc;
    ngx_str_t                        message;
    ngx_str_t                        code_str;
    ngx_json_value_t                 obj;
    ngx_kmp_out_track_t             *track;
    ngx_http_call_ctx_t             *publish_call;
    ngx_kmp_out_publish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    publish_call = track->publish_call;
    track->publish_call = NULL;

    if (ngx_kmp_out_parse_json_response(temp_pool, &track->log, code,
        content_type, body, &obj) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_publish_handle: parse response failed");
        goto retry;
    }

    rc = ngx_kmp_out_status_parse(temp_pool, &track->log, &obj.v.obj,
        &code_str, &message);
    switch (rc) {

    case NGX_OK:
        break;

    case NGX_DECLINED:
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_publish_handle: "
            "bad code \"%V\" in json, message=\"%V\"", &code_str, &message);
        goto retry;

    default:
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_publish_handle: failed to parse status");
        goto retry;
    }

    rc = ngx_kmp_out_track_publish_json(track, &obj.v.obj, temp_pool);
    if (rc == NGX_OK) {
        return NGX_OK;
    }

retry:

    if (ctx->retries_left > 0) {
        ctx->retries_left--;
        track->publish_call = publish_call;
        return NGX_AGAIN;
    }

    ngx_kmp_out_track_error(track, "parse_publish_failed");
    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_publish(ngx_kmp_out_track_t *track)
{
    ngx_url_t                       *url;
    ngx_http_call_init_t             ci;
    ngx_kmp_out_publish_call_ctx_t   ctx;

    track->state = NGX_KMP_TRACK_WAIT_PUBLISH_RESPONSE;

    url = track->conf->ctrl_publish_url;
    if (url == NULL) {
        ngx_log_error(NGX_LOG_CRIT, &track->log, 0,
            "ngx_kmp_out_track_publish: no publish url set in conf");
        return NGX_ERROR;
    }

    ctx.track = track;
    ctx.retries_left = track->conf->ctrl_retries;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_out_track_publish_create;
    ci.handle = ngx_kmp_out_publish_handle;
    ci.handler_pool = track->pool;
    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_out_track_publish: sending publish request to \"%V\"",
        &url->url);

    track->log.action = "sending publish request";

    track->publish_call = ngx_kmp_out_track_http_call_create(track, &ci);
    if (track->publish_call == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_publish: http call create failed");
        ngx_kmp_out_track_set_error_reason(track, "create_publish_failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_chain_t *
ngx_kmp_out_unpublish_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    size_t                             size;
    u_char                            *p;
    ngx_buf_t                         *b;
    ngx_chain_t                       *pl;
    ngx_kmp_out_track_t               *track;
    ngx_kmp_out_track_conf_t          *conf;
    ngx_kmp_out_unpublish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    size = sizeof("{,}") +
        ngx_kmp_out_track_unpublish_json_get_size(track) +
        track->json_info.len;

    pl = ngx_http_call_alloc_chain_temp_buf(pool, size);
    if (pl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_out_unpublish_create: alloc chain buf failed");
        return NULL;
    }

    b = pl->buf;
    p = b->last;

    *p++ = '{';
    p = ngx_kmp_out_track_unpublish_json_write(p, track);
    if (track->json_info.len > 0) {
        *p++ = ',';
        p = ngx_copy(p, track->json_info.data, track->json_info.len);
    }

    *p++ = '}';

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_out_unpublish_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NULL;
    }

    b->last = p;

    conf = ctx->track->conf;

    return ngx_http_call_format_json_post(pool,
        &conf->ctrl_unpublish_url->host, &conf->ctrl_unpublish_url->uri,
        conf->ctrl_headers, pl);
}


static void
ngx_kmp_out_track_unpublish(ngx_kmp_out_track_t *track)
{
    ngx_url_t                         *url;
    ngx_http_call_init_t               ci;
    ngx_kmp_out_unpublish_call_ctx_t   ctx;

    url = track->conf->ctrl_unpublish_url;
    if (url == NULL || track->state == NGX_KMP_TRACK_INITIAL) {
        return;
    }

    ctx.track = track;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_out_unpublish_create;
    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_out_track_unpublish: sending unpublish request to \"%V\"",
        &url->url);

    track->log.action = "sending unpublish request";

    if (ngx_kmp_out_track_http_call_create(track, &ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_unpublish: http call create failed");
    }
}


static void
ngx_kmp_out_track_cleanup(ngx_kmp_out_track_t *track)
{
    if (track->flush.timer_set) {
        ngx_del_timer(&track->flush);
    }

    if (track->keepalive.timer_set) {
        ngx_del_timer(&track->keepalive);
    }

    if (!ngx_queue_empty(&track->upstreams)) {
        return;
    }

    ngx_buf_queue_delete(&track->buf_queue);

    if (!track->detached) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_out_track_cleanup: freeing %p", track);

    ngx_kmp_out_track_unpublish(track);

    ngx_queue_remove(&track->queue);
    ngx_rbtree_delete(&ngx_kmp_out_tracks.rbtree, &track->sn.node);

    ngx_destroy_pool(track->pool);
}


void
ngx_kmp_out_track_error(ngx_kmp_out_track_t *track, char *code)
{
    ngx_uint_t                    level;
    ngx_kmp_out_track_handler_pt  handler;

    level = track->state == NGX_KMP_TRACK_INACTIVE ? NGX_LOG_INFO :
        NGX_LOG_NOTICE;

    ngx_log_error(level, &track->log, 0,
        "ngx_kmp_out_track_error: called, code: %s", code);

    ngx_kmp_out_track_set_error_reason(track, code);

    if (track->detached) {
        ngx_kmp_out_track_cleanup(track);
        return;
    }

    handler = track->handler;
    if (handler) {
        track->handler = NULL;
        handler(track->ctx);
    }
}


static void
ngx_kmp_out_track_free_upstreams(ngx_kmp_out_track_t *track)
{
    ngx_queue_t             *q;
    ngx_kmp_out_upstream_t  *u;

    while (!ngx_queue_empty(&track->upstreams)) {

        q = ngx_queue_head(&track->upstreams);
        u = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        ngx_kmp_out_upstream_free(u);
    }
}


void
ngx_kmp_out_track_detach(ngx_kmp_out_track_t *track, char *reason)
{
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_out_track_detach: called, reason: %s", reason);

    track->detached = 1;

    ngx_kmp_out_track_set_error_reason(track, reason);

    if (track->publish_call != NULL) {
        ngx_http_call_cancel(track->publish_call);
        track->publish_call = NULL;
    }

    if (!ngx_queue_empty(&track->upstreams)) {
        if (ngx_kmp_out_track_send_end_of_stream(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_out_track_detach: send eos failed");
            ngx_kmp_out_track_free_upstreams(track);
        }
    }

    ngx_kmp_out_track_cleanup(track);
}


static ngx_int_t
ngx_kmp_out_track_append_all(ngx_kmp_out_track_t *track)
{
    u_char                  *min_used_ptr;
    uint64_t                 min_acked_frame_id;
    ngx_queue_t             *q;
    ngx_kmp_out_upstream_t  *u;

    if (track->active_buf.last <= track->active_buf.pos) {
        return NGX_OK;
    }

    min_used_ptr = NULL;
    min_acked_frame_id = ULLONG_MAX;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        if (ngx_kmp_out_upstream_append_buffer(u, &track->active_buf)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_out_track_append_all: append failed");
            ngx_kmp_out_track_set_error_reason(track, "append_failed");
            return NGX_ERROR;
        }

        if (u->acked_frame_id < min_acked_frame_id) {
            min_used_ptr = ngx_buf_queue_stream_pos(&u->acked_reader);
            min_acked_frame_id = u->acked_frame_id;
        }

        if (u->peer.connection && u->peer.connection->write->ready) {
            track->send_pending = 1;
        }
    }

    track->active_buf.pos = track->active_buf.last;

    if (min_used_ptr != NULL) {
        ngx_buf_queue_free(&track->buf_queue, min_used_ptr);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_out_track_send_all(ngx_kmp_out_track_t *track)
{
    ngx_int_t                rc;
    ngx_queue_t             *q;
    ngx_kmp_out_upstream_t  *u;

    if (!track->send_pending || track->send_blocked) {
        return NGX_OK;
    }

    track->send_pending = 0;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        rc = ngx_kmp_out_upstream_send(u);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_out_track_send_all: send failed");
            ngx_kmp_out_track_set_error_reason(track, "upstream_error");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_out_track_flush(ngx_kmp_out_track_t *track)
{
    if (ngx_kmp_out_track_append_all(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_flush: append failed");
        return NGX_ERROR;
    }

    if (ngx_kmp_out_track_send_all(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_flush: send failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_out_track_flush_handler(ngx_event_t *ev)
{
    ngx_kmp_out_track_t  *track;

    track = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_KMP, &track->log, 0,
        "ngx_kmp_out_track_flush_handler: called");

    if (ngx_kmp_out_track_flush(track) != NGX_OK) {
        ngx_kmp_out_track_error(track, "unexpected");
    }
}


static ngx_kmp_out_upstream_t *
ngx_kmp_out_track_min_acked_upstream(ngx_kmp_out_track_t *track)
{
    ngx_queue_t             *q;
    ngx_kmp_out_upstream_t  *cur, *min;

    min = NULL;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        if (min == NULL || cur->acked_frame_id < min->acked_frame_id) {
            min = cur;
        }
    }

    return min;
}


static ngx_kmp_out_upstream_t *
ngx_kmp_out_track_get_upstream(ngx_kmp_out_track_t *track, ngx_str_t *id)
{
    ngx_queue_t             *q;
    ngx_kmp_out_upstream_t  *u;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        if (u->id.s.len == id->len
            && ngx_strncmp(u->id.s.data, id->data, id->len) == 0)
        {
            return u;
        }
    }

    return NULL;
}


ngx_int_t
ngx_kmp_out_track_add_upstream(ngx_pool_t *temp_pool,
    ngx_kmp_out_track_t *track, ngx_str_t *src_id, ngx_json_object_t *obj)
{
    ngx_kmp_out_upstream_t  *src;

    if (src_id != NULL) {
        src = ngx_kmp_out_track_get_upstream(track, src_id);
        if (src == NULL) {
            ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
                "ngx_kmp_out_track_add_upstream: "
                "unknown upstream \"%V\" in track \"%V\"",
                src_id, &track->sn.str);
            return NGX_DECLINED;
        }

    } else {
        src = ngx_kmp_out_track_min_acked_upstream(track);
        if (src == NULL) {
            ngx_log_error(NGX_LOG_ERR, temp_pool->log, 0,
                "ngx_kmp_out_track_add_upstream: "
                "track \"%V\" has no upstreams", &track->sn.str);
            return NGX_DECLINED;
        }
    }

    return ngx_kmp_out_upstream_from_json(temp_pool, track, src, obj);
}


ngx_int_t
ngx_kmp_out_track_del_upstream(ngx_kmp_out_track_t *track, ngx_str_t *id,
    ngx_log_t *log)
{
    ngx_kmp_out_upstream_t  *u;

    u = ngx_kmp_out_track_get_upstream(track, id);
    if (u == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_kmp_out_track_del_upstream: "
            "unknown upstream \"%V\" in track \"%V\"", id, &track->sn.str);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_kmp_out_track_del_upstream: "
        "deleting upstream \"%V\" in track \"%V\"", id, &track->sn.str);

    ngx_kmp_out_upstream_free(u);

    if (ngx_queue_empty(&track->upstreams)) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_kmp_out_track_del_upstream: no upstreams");
        track->state = NGX_KMP_TRACK_INACTIVE;
        ngx_kmp_out_track_cleanup(track);
    }

    return NGX_OK;
}


static void
ngx_kmp_out_track_free_bufs(ngx_kmp_out_track_t *track)
{
    ngx_kmp_out_upstream_t  *u;

    u = ngx_kmp_out_track_min_acked_upstream(track);
    if (u == NULL) {
        return;
    }

    ngx_buf_queue_free(&track->buf_queue,
        ngx_buf_queue_stream_pos(&u->acked_reader));
}


static ngx_int_t
ngx_kmp_out_track_mem_watermark(ngx_kmp_out_track_t *track)
{
    size_t                   mem_left;
    ngx_int_t                rc;
    ngx_kmp_out_upstream_t  *u;

    while (track->mem_left < track->mem_low_watermark) {
        u = ngx_kmp_out_track_min_acked_upstream(track);
        if (u == NULL) {
            break;
        }

        rc = ngx_kmp_out_upstream_auto_ack(u,
            track->mem_low_watermark - track->mem_left, 1);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
                "ngx_kmp_out_track_mem_watermark: auto ack failed");
            return NGX_ERROR;
        }

        if (rc == 0) {
            break;
        }

        mem_left = track->mem_left;

        ngx_kmp_out_track_free_bufs(track);

        ngx_log_error(NGX_LOG_NOTICE, &u->log, 0,
            "ngx_kmp_out_track_mem_watermark: "
            "memory too low, acked frames, count: %i, before: %uz, after: %uz",
            rc, mem_left, track->mem_left);
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_alloc_extra_data(ngx_kmp_out_track_t *track, size_t size)
{
    if (track->extra_data_size >= size) {
        return NGX_OK;
    }

    if (size < track->extra_data_size * 2) {
        size = track->extra_data_size * 2;
    }

    if (track->mem_left < size) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_out_track_alloc_extra_data: "
            "memory limit exceeded");
        ngx_kmp_out_track_set_error_reason(track, "alloc_failed");
        return NGX_ERROR;
    }

    track->extra_data.data = ngx_pnalloc(track->pool, size);
    if (track->extra_data.data == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_alloc_extra_data: alloc failed");
        ngx_kmp_out_track_set_error_reason(track, "alloc_failed");
        return NGX_ERROR;
    }

    track->extra_data_size = size;
    track->mem_left -= size;

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_out_track_write_chain(ngx_kmp_out_track_t *track, ngx_chain_t *in,
    u_char *p)
{
    size_t       size;
    ngx_int_t    rc;
    ngx_buf_t   *active_buf = &track->active_buf;
    ngx_flag_t   appended = 0;

    if (track->mem_left < track->mem_high_watermark) {
        rc = ngx_kmp_out_track_mem_watermark(track);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    for ( ;; ) {

        while (p >= in->buf->last) {

            in = in->next;
            if (in == NULL) {

                if (ngx_kmp_out_track_send_all(track) != NGX_OK) {
                    ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                        "ngx_kmp_out_track_write_chain: send failed");
                    goto error;
                }

                if (!track->flush.timer_set || appended) {
                    ngx_log_debug0(NGX_LOG_DEBUG_KMP, &track->log, 0,
                        "ngx_kmp_out_track_write_chain: "
                        "resetting flush timer");

                    ngx_add_timer(&track->flush, track->conf->flush_timeout);
                }

                return NGX_OK;
            }

            p = in->buf->pos;
        }

        size = ngx_min(active_buf->end - active_buf->last, in->buf->last - p);
        if (size > 0) {
            active_buf->last = ngx_copy(active_buf->last, p, size);

            p += size;
            track->stats.written += size;
        }

        if (active_buf->last >= active_buf->end) {

            appended = 1;

            if (ngx_kmp_out_track_append_all(track) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_kmp_out_track_write_chain: append failed");
                goto error;
            }

            active_buf->start = ngx_buf_queue_get(&track->buf_queue);
            if (active_buf->start == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_kmp_out_track_write_chain: "
                    "ngx_buf_queue_get failed");
                ngx_kmp_out_track_set_error_reason(track, "alloc_failed");
                goto error;
            }

            active_buf->end = active_buf->start + track->buf_queue.used_size;

            active_buf->pos = active_buf->last = active_buf->start;
        }
    }

error:

    track->write_error = 1;
    return NGX_ERROR;
}


static ngx_int_t
ngx_kmp_out_track_write(ngx_kmp_out_track_t *track, u_char *data,
    size_t size)
{
    ngx_buf_t    buf;
    ngx_chain_t  in;

    buf.last = data + size;

    in.next = NULL;
    in.buf = &buf;

    return ngx_kmp_out_track_write_chain(track, &in, data);
}


ngx_int_t
ngx_kmp_out_track_write_media_info(ngx_kmp_out_track_t *track)
{
    kmp_packet_header_t  header;

    header.packet_type = KMP_PACKET_MEDIA_INFO;
    header.header_size = sizeof(header) + sizeof(track->media_info);
    header.data_size = track->extra_data.len;
    header.reserved = 0;

    if (ngx_kmp_out_track_write(track, (u_char *) &header, sizeof(header))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_kmp_out_track_write(track, (u_char *) &track->media_info,
        sizeof(track->media_info)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_kmp_out_track_write(track, track->extra_data.data,
        track->extra_data.len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_out_track_chain_md5_hex(u_char dst[32], ngx_chain_t *in, u_char *p)
{
    u_char     hash[16];
    ngx_md5_t  md5;

    ngx_md5_init(&md5);

    for ( ;; ) {

        ngx_md5_update(&md5, p, in->buf->last - p);

        in = in->next;
        if (in == NULL) {
            break;
        }

        p = in->buf->pos;
    }

    ngx_md5_final(hash, &md5);
    ngx_hex_dump(dst, hash, sizeof(hash));
}


static void
ngx_kmp_out_track_update_frame_stats(ngx_kmp_out_track_stats_t *stats,
    kmp_frame_packet_t *frame)
{
    size_t      size;
    ngx_uint_t  frames;

    stats->sent_frames++;
    if (frame->f.flags & KMP_FRAME_FLAG_KEY) {
        stats->sent_key_frames++;
    }

    stats->last_created = frame->f.created;
    stats->last_frame_written = stats->written;

    if (ngx_cached_time->sec < stats->period_end) {
        return;
    }

    if (ngx_cached_time->sec < stats->period_end
        + NGX_KMP_OUT_TRACK_STAT_PERIOD / 2)
    {
        frames = stats->sent_frames - stats->initial_sent_frames;
        size = stats->written - stats->initial_written
            - frames * sizeof(kmp_frame_packet_t);

        stats->frame_rate = 100 * frames / NGX_KMP_OUT_TRACK_STAT_PERIOD;
        stats->bitrate = 8 * size / NGX_KMP_OUT_TRACK_STAT_PERIOD;
    }

    stats->initial_sent_frames = stats->sent_frames;
    stats->initial_written = stats->written;
    stats->period_end = ngx_cached_time->sec + NGX_KMP_OUT_TRACK_STAT_PERIOD;
}


ngx_int_t
ngx_kmp_out_track_write_frame(ngx_kmp_out_track_t *track,
    kmp_frame_packet_t *frame, ngx_chain_t *in, u_char *p)
{
    u_char      data_md5[32];
    ngx_int_t   rc;
    ngx_uint_t  log_frame;

    log_frame = track->conf->log_frames;
    if (log_frame == NGX_KMP_OUT_LOG_FRAMES_KEY) {
        log_frame = track->media_info.media_type == KMP_MEDIA_VIDEO
            && (frame->f.flags & KMP_FRAME_FLAG_KEY);
    }

    if (log_frame) {
        ngx_kmp_out_track_chain_md5_hex(data_md5, in, p);

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_kmp_out_track_write_frame: created: %L, dts: %L, "
            "flags: 0x%uxD, ptsDelay: %uD, size: %uD, md5: %*s",
            frame->f.created, frame->f.dts, frame->f.flags, frame->f.pts_delay,
            frame->header.data_size, (size_t) sizeof(data_md5), data_md5);

    } else {
        ngx_log_debug6(NGX_LOG_DEBUG_KMP, &track->log, 0,
            "ngx_kmp_out_track_write_frame: input: %V, created: %L, "
            "size: %uD, dts: %L, flags: 0x%uxD, ptsDelay: %uD",
            &track->input_id.s, frame->f.created, frame->header.data_size,
            frame->f.dts, frame->f.flags, frame->f.pts_delay);
    }

    rc = ngx_kmp_out_track_write(track, (u_char *) frame, sizeof(*frame));
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_kmp_out_track_write_chain(track, in, p);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_kmp_out_track_update_frame_stats(&track->stats, frame);

    return NGX_OK;
}


void
ngx_kmp_out_track_write_marker_start(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker)
{
    ngx_buf_queue_stream_init_tail(&marker->reader, &track->buf_queue,
        track->active_buf.last);

    marker->written = track->stats.written;

    track->send_blocked++;  /* must not send anything until marker ends */
}


ngx_int_t
ngx_kmp_out_track_write_marker_end(ngx_kmp_out_track_t *track,
    ngx_kmp_out_track_marker_t *marker, void *data, size_t size)
{
    if (ngx_buf_queue_stream_write(&marker->reader, data, size) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
            "ngx_kmp_out_track_write_marker_end: write failed");
        return NGX_ERROR;
    }

    track->send_blocked--;

    return ngx_kmp_out_track_send_all(track);
}


ngx_int_t
ngx_kmp_out_track_write_frame_start(ngx_kmp_out_track_t *track)
{
    kmp_frame_packet_t  frame;

    ngx_kmp_out_track_write_marker_start(track, &track->cur_frame);

    ngx_memzero(&frame, sizeof(frame));

    if (ngx_kmp_out_track_write(track, (u_char *) &frame, sizeof(frame))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_kmp_out_track_write_frame_data(ngx_kmp_out_track_t *track, u_char *data,
    size_t size)
{
    return ngx_kmp_out_track_write(track, data, size);
}


ngx_int_t
ngx_kmp_out_track_write_frame_end(ngx_kmp_out_track_t *track,
    kmp_frame_packet_t *frame)
{
    u_char      hash[16];
    u_char      hash_hex[32];
    ngx_int_t   rc;
    ngx_uint_t  log_frame;

    frame->header.data_size = ngx_kmp_out_track_marker_get_size(
        track, &track->cur_frame) - sizeof(*frame);

    rc = ngx_kmp_out_track_write_marker_end(track, &track->cur_frame,
        frame, sizeof(*frame));
    if (rc != NGX_OK) {
        return rc;
    }

    log_frame = track->conf->log_frames;
    if (log_frame == NGX_KMP_OUT_LOG_FRAMES_KEY) {
        log_frame = track->media_info.media_type == KMP_MEDIA_VIDEO
            && (frame->f.flags & KMP_FRAME_FLAG_KEY);
    }

    if (log_frame) {
        if (ngx_buf_queue_stream_md5(&track->cur_frame.reader,
            frame->header.data_size, hash) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ALERT, &track->log, 0,
                "ngx_kmp_out_track_write_frame_end: failed to calc frame md5");
            return NGX_ERROR;
        }

        ngx_hex_dump(hash_hex, hash, sizeof(hash));

        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_kmp_out_track_write_frame_end: created: %L, dts: %L, "
            "flags: 0x%uxD, ptsDelay: %uD, size: %uD, md5: %*s",
            frame->f.created, frame->f.dts, frame->f.flags, frame->f.pts_delay,
            frame->header.data_size, (size_t) sizeof(hash_hex), hash_hex);

    } else {
        ngx_log_debug6(NGX_LOG_DEBUG_KMP, &track->log, 0,
            "ngx_kmp_out_track_write_frame_end: input: %V, created: %L, "
            "size: %uD, dts: %L, flags: 0x%uxD, ptsDelay: %uD",
            &track->input_id.s, frame->f.created, frame->header.data_size,
            frame->f.dts, frame->f.flags, frame->f.pts_delay);
    }

    ngx_kmp_out_track_update_frame_stats(&track->stats, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_kmp_out_track_send_end_of_stream(ngx_kmp_out_track_t *track)
{
    ngx_queue_t             *q;
    kmp_packet_header_t      header;
    ngx_kmp_out_upstream_t  *u;

    if (track->write_error) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_send_end_of_stream: error state");
        return NGX_ERROR;
    }

    track->state = NGX_KMP_TRACK_INACTIVE;

    ngx_memzero(&header, sizeof(header));
    header.packet_type = KMP_PACKET_END_OF_STREAM;
    header.header_size = sizeof(header);

    if (ngx_kmp_out_track_write(track, (u_char *) &header, sizeof(header))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_out_track_send_end_of_stream: write failed");
        return NGX_ERROR;
    }

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_out_upstream_t, queue);

        u->sent_end = 1;
    }

    if (ngx_kmp_out_track_flush(track) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_kmp_out_track_keepalive_handler(ngx_event_t *ev)
{
    ngx_kmp_out_track_t  *track;
    kmp_packet_header_t   packet;

    track = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_KMP, &track->log, 0,
        "ngx_kmp_out_track_keepalive_handler: called");

    packet.packet_type = KMP_PACKET_NULL;
    packet.header_size = sizeof(packet);
    packet.data_size = 0;
    packet.reserved = 0;

    if (ngx_kmp_out_track_write(track, (u_char *) &packet, sizeof(packet))
        != NGX_OK)
    {
        ngx_kmp_out_track_error(track, "unexpected");
    }

    ngx_add_timer(ev, track->conf->keepalive_interval);
}


static u_char *
ngx_kmp_out_track_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char               *p;
    ngx_kmp_out_track_t  *track;

    p = buf;

    track = log->data;

    if (track != NULL) {
        p = ngx_snprintf(buf, len, ", track: %V", &track->sn.str);
        len -= p - buf;
        buf = p;

        if (track->input_id.s.len) {
            p = ngx_snprintf(buf, len, ", input: %V", &track->input_id.s);
            len -= p - buf;
            buf = p;
        }
    }

    return p;
}


ngx_kmp_out_track_t *
ngx_kmp_out_track_get(ngx_str_t *id)
{
    uint32_t  hash;

    hash = ngx_crc32_short(id->data, id->len);

    return (ngx_kmp_out_track_t *) ngx_str_rbtree_lookup(
        &ngx_kmp_out_tracks.rbtree, id, hash);
}


ngx_kmp_out_track_t *
ngx_kmp_out_track_create(ngx_kmp_out_track_conf_t *conf,
    ngx_uint_t media_type)
{
    u_char               *p;
    uint32_t              hash;
    ngx_lba_t            *lba;
    ngx_log_t            *log = ngx_cycle->log;
    ngx_pool_t           *pool;
    ngx_kmp_out_track_t  *track;

    pool = ngx_create_pool(2048, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_out_track_create: ngx_create_pool failed");
        return NULL;
    }

    track = ngx_pcalloc(pool, sizeof(*track));
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_out_track_create: ngx_palloc failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    track->log = *ngx_cycle->log;
    pool->log = &track->log;

    track->log.handler = ngx_kmp_out_track_log_error;
    track->log.data = track;
    track->log.action = NULL;

    track->mem_limit = conf->mem_limit[media_type];
    lba = conf->lba[media_type];

    track->mem_left = track->mem_limit;
    track->mem_high_watermark = (100 - conf->mem_high_watermark) *
        track->mem_limit / 100;
    track->mem_low_watermark = (100 - conf->mem_low_watermark) *
        track->mem_limit / 100;

    if (ngx_buf_queue_init(&track->buf_queue, pool->log, lba,
        conf->max_free_buffers, &track->mem_left) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_out_track_create: ngx_buf_queue_init failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    track->pool = pool;
    ngx_queue_init(&track->upstreams);

    track->conf = conf;
    track->media_info.media_type = media_type;
    track->media_info.timescale = conf->timescale;
    track->connect.c.initial_frame_id = ngx_kmp_out_track_get_time(track);

    track->flush.handler = ngx_kmp_out_track_flush_handler;
    track->flush.data = track;
    track->flush.log = &track->log;

    track->keepalive.handler = ngx_kmp_out_track_keepalive_handler;
    track->keepalive.data = track;
    track->keepalive.log = &track->log;

    p = track->id_buf;
    track->sn.str.data = p;
    p = ngx_sprintf(p, "%ui", ngx_kmp_out_tracks.counter++);
    track->sn.str.len = p - track->id_buf;
    track->id_escape = 0;

    hash = ngx_crc32_short(track->sn.str.data, track->sn.str.len);
    track->sn.node.key = hash;

    ngx_rbtree_insert(&ngx_kmp_out_tracks.rbtree, &track->sn.node);
    ngx_queue_insert_tail(&ngx_kmp_out_tracks.queue, &track->queue);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_out_track_create: created %p", track);

    return track;
}
