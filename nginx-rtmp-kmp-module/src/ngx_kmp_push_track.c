#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_call.h>
#include <ngx_buf_queue.h>
#include <ngx_live_kmp.h>
#include <ngx_json_parser.h>

#include "ngx_kmp_push_utils.h"
#include "ngx_kmp_push_track_internal.h"
#include "ngx_kmp_push_upstream.h"
#include "ngx_kmp_push_track_json.h"


enum {
    NGX_KMP_TRACK_CHANNEL_ID,
    NGX_KMP_TRACK_TRACK_ID,
    NGX_KMP_TRACK_UPSTREAMS,
    NGX_KMP_TRACK_PARAM_COUNT
};

static ngx_json_object_key_def_t  ngx_kmp_track_json_params[] = {
    { ngx_string("channel_id"),  NGX_JSON_STRING,  NGX_KMP_TRACK_CHANNEL_ID },
    { ngx_string("track_id"),    NGX_JSON_STRING,  NGX_KMP_TRACK_TRACK_ID },
    { ngx_string("upstreams"),   NGX_JSON_ARRAY,   NGX_KMP_TRACK_UPSTREAMS },
    { ngx_null_string, 0, 0 }
};

typedef struct {
    ngx_kmp_push_track_t  *track;
    ngx_uint_t             retries_left;
} ngx_kmp_push_publish_call_ctx_t;

typedef struct {
    ngx_kmp_push_track_t  *track;
} ngx_kmp_push_unpublish_call_ctx_t;


static ngx_int_t ngx_kmp_push_track_send_end_of_stream(
    ngx_kmp_push_track_t *track);

static void ngx_kmp_push_track_cleanup(ngx_kmp_push_track_t *track);


int64_t
ngx_kmp_push_track_get_time(ngx_kmp_push_track_t *track)
{
    struct timespec  spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    return (int64_t) spec.tv_sec * track->media_info.timescale +
        (int64_t) spec.tv_nsec * track->media_info.timescale / 1000000000;
}

void
ngx_kmp_push_track_init_conf(ngx_kmp_push_track_conf_t *conf)
{
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
    conf->video_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->video_mem_limit = NGX_CONF_UNSET_SIZE;
    conf->audio_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->audio_mem_limit = NGX_CONF_UNSET_SIZE;
    conf->flush_timeout = NGX_CONF_UNSET_MSEC;

    conf->republish_interval = NGX_CONF_UNSET;
    conf->max_republishes = NGX_CONF_UNSET_UINT;
}

void
ngx_kmp_push_track_merge_conf(ngx_kmp_push_track_conf_t *conf,
    ngx_kmp_push_track_conf_t *prev)
{
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

    ngx_conf_merge_size_value(conf->video_buffer_size,
                              prev->video_buffer_size, 64 * 1024);

    ngx_conf_merge_size_value(conf->video_mem_limit,
                              prev->video_mem_limit, 16 * 1024 * 1024);

    ngx_conf_merge_size_value(conf->audio_buffer_size,
                              prev->audio_buffer_size, 4 * 1024);

    ngx_conf_merge_size_value(conf->audio_mem_limit,
                              prev->audio_mem_limit, 1 * 1024 * 1024);

    ngx_conf_merge_msec_value(conf->flush_timeout, prev->flush_timeout, 1000);

    ngx_conf_merge_value(conf->republish_interval,
                         prev->republish_interval, 1);

    ngx_conf_merge_uint_value(conf->max_republishes,
                              prev->max_republishes, 10);
}

ngx_http_call_ctx_t *
ngx_kmp_push_track_http_call_create(ngx_kmp_push_track_t *track,
    ngx_http_call_init_t *ci)
{
    ngx_kmp_push_track_conf_t  *conf = track->conf;

    ci->timeout = conf->ctrl_timeout;
    ci->read_timeout = conf->ctrl_read_timeout;
    ci->retry_interval = conf->ctrl_retry_interval;
    ci->buffer_size = conf->ctrl_buffer_size;

    return ngx_http_call_create(ci);
}

size_t
ngx_kmp_push_track_media_info_json_get_size(ngx_kmp_push_track_t *track)
{
    size_t  size;

    size = sizeof("\"media_info\":{}") - 1;

    switch (track->media_info.media_type) {

    case KMP_MEDIA_VIDEO:
        size += ngx_kmp_push_track_video_json_get_size(track);
        break;

    case KMP_MEDIA_AUDIO:
        size += ngx_kmp_push_track_audio_json_get_size(track);
        break;
    }

    return size;
}

u_char *
ngx_kmp_push_track_media_info_json_write(u_char *p,
    ngx_kmp_push_track_t *track)
{
    p = ngx_copy_fix(p, "\"media_info\":{");

    switch (track->media_info.media_type) {

    case KMP_MEDIA_VIDEO:
        p = ngx_kmp_push_track_video_json_write(p, track);
        break;

    case KMP_MEDIA_AUDIO:
        p = ngx_kmp_push_track_audio_json_write(p, track);
        break;
    }
    *p++ = '}';

    return p;
}

static ngx_chain_t *
ngx_kmp_push_track_publish_create(void *arg, ngx_pool_t *pool,
    ngx_chain_t **body)
{
    size_t                            size;
    u_char                           *p;
    ngx_buf_t                        *b;
    ngx_chain_t                      *cl;
    ngx_kmp_push_track_t             *track;
    ngx_kmp_push_track_conf_t        *conf;
    ngx_kmp_push_publish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    size = sizeof("{,,}") +
        ngx_kmp_push_track_publish_json_get_size(track) +
        track->json_info.len +
        ngx_kmp_push_track_media_info_json_get_size(track);

    cl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_track_publish_create: alloc chain buf failed");
        return NULL;
    }

    b = cl->buf;
    p = b->last;

    *p++ = '{';
    p = ngx_kmp_push_track_publish_json_write(p, track);
    if (track->json_info.len > 0) {
        *p++ = ',';
        p = ngx_copy(p, track->json_info.data, track->json_info.len);
    }
    *p++ = ',';
    p = ngx_kmp_push_track_media_info_json_write(p, track);
    *p++ = '}';

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_push_track_publish_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NULL;
    }

    b->last = p;

    conf = ctx->track->conf;

    return ngx_kmp_push_format_json_http_request(pool,
        &conf->ctrl_publish_url->host, &conf->ctrl_publish_url->uri,
        conf->ctrl_headers, cl);
}

static ngx_int_t
ngx_kmp_push_publish_handle(ngx_pool_t *temp_pool, void *arg, ngx_uint_t code,
    ngx_str_t *content_type, ngx_buf_t *body)
{
    ngx_str_t                         track_id;
    ngx_str_t                         channel_id;
    ngx_array_part_t                 *part;
    ngx_json_array_t                 *upstreams;
    ngx_json_value_t                  json;
    ngx_json_value_t                 *values[NGX_KMP_TRACK_PARAM_COUNT];
    ngx_json_object_t                *cur;
    ngx_kmp_push_track_t             *track;
    kmp_connect_packet_t             *header;
    ngx_kmp_push_publish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    /* parse and validate the json */
    if (ngx_kmp_push_parse_json_response(temp_pool, &track->log, code,
        content_type, body, &json) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_publish_handle: parse response failed");
        goto retry;
    }

    ngx_memzero(values, sizeof(values));
    ngx_json_get_object_values(&json.v.obj, ngx_kmp_track_json_params, values);

    if (values[NGX_KMP_TRACK_CHANNEL_ID] == NULL ||
        values[NGX_KMP_TRACK_TRACK_ID] == NULL ||
        values[NGX_KMP_TRACK_UPSTREAMS] == NULL) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_push_publish_handle: missing required params in json");
        goto retry;
    }

    channel_id = values[NGX_KMP_TRACK_CHANNEL_ID]->v.str;
    if (channel_id.len > sizeof(header->channel_id)) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_push_publish_handle: channel id \"%V\" too long",
            &channel_id);
        goto retry;
    }

    track_id = values[NGX_KMP_TRACK_TRACK_ID]->v.str;
    if (track_id.len > sizeof(header->track_id)) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_push_publish_handle: track id \"%V\" too long",
            &track_id);
        goto retry;
    }

    upstreams = &values[NGX_KMP_TRACK_UPSTREAMS]->v.arr;
    if (upstreams->type != NGX_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_ERR, &track->log, 0,
            "ngx_kmp_push_publish_handle: invalid upstreams element type %d",
            upstreams->type);
        goto retry;
    }

    /* init the header */
    header = &track->connect;
    header->header.packet_type = KMP_PACKET_CONNECT;
    header->header.header_size = sizeof(*header);
    ngx_memcpy(header->channel_id, channel_id.data, channel_id.len);
    ngx_memcpy(header->track_id, track_id.data, track_id.len);

    track->channel_id.data = header->channel_id;
    track->channel_id.len = channel_id.len;
    track->track_id.data = header->track_id;
    track->track_id.len = track_id.len;

    /* create the upstreams */
    if (upstreams->count == 0) {
        ngx_log_error(NGX_LOG_INFO, &track->log, 0,
            "ngx_kmp_push_publish_handle: no upstreams");
        track->state = NGX_KMP_TRACK_INACTIVE;
        ngx_kmp_push_track_cleanup(track);
        goto done;
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

        if (ngx_kmp_push_upstream_from_json(temp_pool, track, cur) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_push_publish_handle: failed to create upstream");
            ngx_kmp_push_track_error(track, "create_upstream_failed");
            goto done;
        }
    }

    track->state = NGX_KMP_TRACK_ACTIVE;

done:

    track->publish_call = NULL;
    return NGX_OK;

retry:

    if (ctx->retries_left > 0) {
        ctx->retries_left--;
        return NGX_AGAIN;
    }

    ngx_kmp_push_track_error(track, "parse_publish_failed");

    track->publish_call = NULL;
    return NGX_OK;
}

ngx_int_t
ngx_kmp_push_track_publish(ngx_kmp_push_track_t *track)
{
    ngx_url_t                        *url;
    ngx_http_call_init_t              ci;
    ngx_kmp_push_publish_call_ctx_t   ctx;

    track->state = NGX_KMP_TRACK_WAIT_PUBLISH_RESPONSE;

    url = track->conf->ctrl_publish_url;

    ctx.track = track;
    ctx.retries_left = track->conf->ctrl_retries;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_push_track_publish_create;
    ci.handle = ngx_kmp_push_publish_handle;
    ci.handler_pool = track->pool;
    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_push_track_publish: sending publish request to \"%V\"",
        &url->url);

    track->log.action = "sending publish request";

    track->publish_call = ngx_kmp_push_track_http_call_create(track, &ci);
    if (track->publish_call == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_publish: http call create failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_chain_t *
ngx_kmp_push_unpublish_create(void *arg, ngx_pool_t *pool, ngx_chain_t **body)
{
    size_t                              size;
    u_char                             *p;
    ngx_buf_t                          *b;
    ngx_chain_t                        *pl;
    ngx_kmp_push_track_t               *track;
    ngx_kmp_push_track_conf_t          *conf;
    ngx_kmp_push_unpublish_call_ctx_t  *ctx = arg;

    track = ctx->track;

    size = sizeof("{,}") +
        ngx_kmp_push_track_unpublish_json_get_size(track) +
        track->json_info.len;

    pl = ngx_kmp_push_alloc_chain_temp_buf(pool, size);
    if (pl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_kmp_push_unpublish_create: alloc chain buf failed");
        return NULL;
    }

    b = pl->buf;
    p = b->last;

    *p++ = '{';
    p = ngx_kmp_push_track_unpublish_json_write(p, track);
    if (track->json_info.len > 0) {
        *p++ = ',';
        p = ngx_copy(p, track->json_info.data, track->json_info.len);
    }
    *p++ = '}';

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_kmp_push_unpublish_create: "
            "result length %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NULL;
    }

    b->last = p;

    conf = ctx->track->conf;

    return ngx_kmp_push_format_json_http_request(pool,
        &conf->ctrl_unpublish_url->host, &conf->ctrl_unpublish_url->uri,
        conf->ctrl_headers, pl);
}

static void
ngx_kmp_push_track_unpublish(ngx_kmp_push_track_t *track)
{
    ngx_url_t                          *url;
    ngx_http_call_init_t                ci;
    ngx_kmp_push_unpublish_call_ctx_t   ctx;

    url = track->conf->ctrl_unpublish_url;
    if (url == NULL) {
        return;
    }

    ctx.track = track;

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_kmp_push_unpublish_create;
    ci.arg = &ctx;
    ci.argsize = sizeof(ctx);

    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_push_track_unpublish: sending unpublish request to \"%V\"",
        &url->url);

    track->log.action = "sending unpublish request";

    if (ngx_kmp_push_track_http_call_create(track, &ci) == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_unpublish: http call create failed");
    }
}

static void
ngx_kmp_push_track_cleanup(ngx_kmp_push_track_t *track)
{
    if (track->flush.timer_set) {
        ngx_del_timer(&track->flush);
    }

    if (!ngx_queue_empty(&track->upstreams)) {
        return;
    }

    ngx_buf_queue_delete(&track->buf_queue);

    if (!track->detached) {
        return;
    }

    ngx_kmp_push_track_unpublish(track);

    ngx_destroy_pool(track->pool);
}

void
ngx_kmp_push_track_error(ngx_kmp_push_track_t *track, char *code)
{
    ngx_uint_t                     level;
    ngx_kmp_push_track_handler_pt  handler;

    level = track->state == NGX_KMP_TRACK_INACTIVE ? NGX_LOG_INFO :
        NGX_LOG_NOTICE;

    ngx_log_error(level, &track->log, 0,
        "ngx_kmp_push_track_error: called");

    if (track->unpublish_reason.len == 0) {
        track->unpublish_reason.data = (u_char *) code;
        track->unpublish_reason.len = ngx_strlen(code);
    }

    if (track->detached) {
        ngx_kmp_push_track_cleanup(track);
        return;
    }

    handler = track->handler;
    if (handler) {
        track->handler = NULL;
        handler(track->ctx);
    }
}

static void
ngx_kmp_push_track_free_upstreams(ngx_kmp_push_track_t *track)
{
    ngx_queue_t              *q;
    ngx_kmp_push_upstream_t  *u;

    while (!ngx_queue_empty(&track->upstreams)) {

        q = ngx_queue_head(&track->upstreams);
        u = ngx_queue_data(q, ngx_kmp_push_upstream_t, queue);

        ngx_kmp_push_upstream_free(u);
    }
}

void
ngx_kmp_push_track_detach(ngx_kmp_push_track_t *track, char *reason)
{
    ngx_log_error(NGX_LOG_INFO, &track->log, 0,
        "ngx_kmp_push_track_detach: called");

    track->detached = 1;

    if (track->unpublish_reason.len == 0) {
        track->unpublish_reason.data = (u_char *) reason;
        track->unpublish_reason.len = ngx_strlen(reason);
    }

    if (track->publish_call != NULL) {
        ngx_http_call_cancel(track->publish_call);
        track->publish_call = NULL;
    }

    if (!ngx_queue_empty(&track->upstreams)) {
        if (ngx_kmp_push_track_send_end_of_stream(track) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_push_track_detach: send eos failed");
            ngx_kmp_push_track_free_upstreams(track);
        }
    }

    ngx_kmp_push_track_cleanup(track);
}

static ngx_int_t
ngx_kmp_push_track_append_all(ngx_kmp_push_track_t *track, ngx_flag_t *send)
{
    u_char                   *min_used_ptr;
    uint64_t                  min_acked_frame_id;
    ngx_queue_t              *q;
    ngx_kmp_push_upstream_t  *u;

    if (track->active_buf.last <= track->active_buf.pos) {
        return NGX_OK;
    }

    min_used_ptr = NULL;
    min_acked_frame_id = ULLONG_MAX;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_push_upstream_t, queue);

        if (ngx_kmp_push_upstream_append_buffer(u, &track->active_buf)
            != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_push_track_append_all: append failed");
            return NGX_ERROR;
        }

        if (u->acked_frame_id < min_acked_frame_id) {
            min_used_ptr = u->acked_reader.start;
            min_acked_frame_id = u->acked_frame_id;
        }

        if (u->peer.connection && u->peer.connection->write->ready) {
            *send = 1;
        }
    }

    track->active_buf.pos = track->active_buf.last;

    if (min_used_ptr != NULL) {
        ngx_buf_queue_free(&track->buf_queue, min_used_ptr);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_track_send_all(ngx_kmp_push_track_t *track)
{
    ngx_int_t                 rc;
    ngx_queue_t              *q;
    ngx_kmp_push_upstream_t  *u;

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_push_upstream_t, queue);

        rc = ngx_kmp_push_upstream_send(u);
        if (rc != NGX_OK && rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_kmp_push_track_send_all: send failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_kmp_push_track_flush(ngx_kmp_push_track_t *track)
{
    ngx_flag_t  send = 0;

    if (ngx_kmp_push_track_append_all(track, &send) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_flush: append failed");
        return NGX_ERROR;
    }

    if (!send) {
        return NGX_OK;
    }

    if (ngx_kmp_push_track_send_all(track) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_flush: send failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
ngx_kmp_push_track_flush_handler(ngx_event_t *ev)
{
    ngx_kmp_push_track_t  *track;

    track = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_KMP, &track->log, 0,
        "ngx_kmp_push_track_flush_handler: called");

    if (ngx_kmp_push_track_flush(track) != NGX_OK) {
        ngx_kmp_push_track_error(track, "flush_failed");
    }
}

ngx_int_t
ngx_kmp_push_track_write_chain(ngx_kmp_push_track_t *track, ngx_chain_t *in,
    u_char *p)
{
    size_t       size;
    ngx_buf_t   *active_buf = &track->active_buf;
    ngx_flag_t   send = 0;
    ngx_flag_t   appended = 0;

    for ( ;; ) {

        while (p >= in->buf->last) {

            in = in->next;
            if (in == NULL) {

                if (send) {

                    if (ngx_kmp_push_track_send_all(track) != NGX_OK) {
                        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                            "ngx_kmp_push_track_write_chain: send failed");
                        goto error;
                    }
                }

                if (!track->flush.timer_set || appended) {
                    ngx_log_debug0(NGX_LOG_DEBUG_KMP, &track->log, 0,
                        "ngx_kmp_push_track_write_chain: "
                        "resetting flush timer");

                    ngx_add_timer(&track->flush, track->conf->flush_timeout);
                }

                return NGX_OK;
            }
            p = in->buf->pos;
        }

        size = ngx_min(active_buf->end - active_buf->last, in->buf->last - p);
        active_buf->last = ngx_copy(active_buf->last, p, size);

        p += size;
        track->written += size;

        if (active_buf->last >= active_buf->end) {

            appended = 1;

            if (ngx_kmp_push_track_append_all(track, &send) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_kmp_push_track_write_chain: append failed");
                goto error;
            }

            active_buf->start = ngx_buf_queue_get(&track->buf_queue);
            if (active_buf->start == NULL) {
                ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                    "ngx_kmp_push_track_write_chain: "
                    "ngx_buf_queue_get failed");
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
ngx_kmp_push_track_write(ngx_kmp_push_track_t *track, u_char *data,
    size_t size)
{
    ngx_buf_t    buf;
    ngx_chain_t  in;

    buf.last = data + size;

    in.next = NULL;
    in.buf = &buf;

    return ngx_kmp_push_track_write_chain(track, &in, data);
}

ngx_int_t
ngx_kmp_push_track_write_media_info(ngx_kmp_push_track_t *track)
{
    kmp_packet_header_t  header;

    header.packet_type = KMP_PACKET_MEDIA_INFO;
    header.header_size = sizeof(header) + sizeof(track->media_info);
    header.data_size = track->extra_data.len;
    header.reserved = 0;

    if (ngx_kmp_push_track_write(track, (u_char *) &header, sizeof(header))
        != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_kmp_push_track_write(track, (u_char *) &track->media_info,
        sizeof(track->media_info)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_kmp_push_track_write(track, track->extra_data.data,
        track->extra_data.len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_kmp_push_track_write_frame(ngx_kmp_push_track_t *track,
    kmp_frame_packet_t *frame)
{
    track->sent_frames++;
    if (frame->f.flags & KMP_FRAME_FLAG_KEY) {
        track->sent_key_frames++;
    }
    track->last_created = frame->f.created;

    return ngx_kmp_push_track_write(track, (u_char *) frame, sizeof(*frame));
}

static ngx_int_t
ngx_kmp_push_track_send_end_of_stream(ngx_kmp_push_track_t *track)
{
    ngx_queue_t              *q;
    kmp_packet_header_t       header;
    ngx_kmp_push_upstream_t  *u;

    if (track->write_error) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_send_end_of_stream: error state");
        return NGX_ERROR;
    }

    track->state = NGX_KMP_TRACK_INACTIVE;

    ngx_memzero(&header, sizeof(header));
    header.packet_type = KMP_PACKET_END_OF_STREAM;
    header.header_size = sizeof(header);

    if (ngx_kmp_push_track_write(track, (u_char *) &header, sizeof(header)) !=
        NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
            "ngx_kmp_push_track_send_end_of_stream: write failed");
        return NGX_ERROR;
    }

    for (q = ngx_queue_head(&track->upstreams);
        q != ngx_queue_sentinel(&track->upstreams);
        q = ngx_queue_next(q))
    {
        u = ngx_queue_data(q, ngx_kmp_push_upstream_t, queue);

        u->sent_end = 1;
    }

    if (ngx_kmp_push_track_flush(track) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static u_char *
ngx_kmp_push_track_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_kmp_push_track_t  *track;

    p = buf;

    track = log->data;

    if (track != NULL) {
        if (track->input_id.len) {
            p = ngx_snprintf(buf, len, ", input: %V", &track->input_id);
            len -= p - buf;
            buf = p;
        }
    }

    return p;
}

ngx_kmp_push_track_t *
ngx_kmp_push_track_create(ngx_kmp_push_track_conf_t *conf,
    ngx_uint_t media_type)
{
    size_t                 buffer_size;
    ngx_log_t             *log = ngx_cycle->log;
    ngx_pool_t            *pool;
    ngx_kmp_push_track_t  *track;

    pool = ngx_create_pool(2048, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_push_track_create: ngx_create_pool failed");
        return NULL;
    }

    track = ngx_pcalloc(pool, sizeof(*track));
    if (track == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_push_track_create: ngx_palloc failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    track->log = *ngx_cycle->log;
    pool->log = &track->log;

    track->log.handler = ngx_kmp_push_track_log_error;
    track->log.data = track;
    track->log.action = NULL;

    if (media_type == KMP_MEDIA_VIDEO) {
        track->mem_limit = conf->video_mem_limit;
        buffer_size = conf->video_buffer_size;

    } else {
        track->mem_limit = conf->audio_mem_limit;
        buffer_size = conf->audio_buffer_size;
    }

    track->mem_left = track->mem_limit;

    if (ngx_buf_queue_init(&track->buf_queue, pool->log, buffer_size,
        conf->max_free_buffers, &track->mem_left) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_kmp_push_track_create: ngx_buf_queue_init failed");
        ngx_destroy_pool(pool);
        return NULL;
    }

    track->pool = pool;
    ngx_queue_init(&track->upstreams);

    track->conf = conf;
    track->media_info.media_type = media_type;
    track->media_info.timescale = conf->timescale;
    track->connect.initial_frame_id = ngx_kmp_push_track_get_time(track);

    track->flush.handler = ngx_kmp_push_track_flush_handler;
    track->flush.data = track;
    track->flush.log = &track->log;

    return track;
}
