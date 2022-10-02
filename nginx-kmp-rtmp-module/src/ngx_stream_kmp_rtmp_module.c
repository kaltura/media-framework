#include <ngx_json_parser.h>
#include <ngx_kmp_in.h>


#include "ngx_stream_kmp_rtmp_module.h"
#include "ngx_kmp_rtmp_build.h"
#include "ngx_kmp_rtmp_connect_data_json.h"


typedef struct {
    ngx_array_t                 lba_array;
} ngx_stream_kmp_rtmp_main_conf_t;

typedef struct {
    ngx_msec_t                  read_timeout;
    ngx_msec_t                  send_timeout;
    size_t                      buffer_size;
    ngx_uint_t                  bin_count;
    ngx_uint_t                  max_free_buffers;
    size_t                      mem_limit;
    ngx_msec_t                  wait_frame_timeout;
    ngx_uint_t                  chunk_size;
    ngx_lba_t                  *lba;
    ngx_kmp_in_conf_t           in;
} ngx_stream_kmp_rtmp_srv_conf_t;

typedef struct {
    ngx_rbtree_t                rbtree;
    ngx_rbtree_node_t           sentinel;
} ngx_stream_kmp_rtmp_upstreams_t;


static ngx_stream_kmp_rtmp_upstreams_t ngx_stream_kmp_rtmp_upstreams;

static void *ngx_stream_kmp_rtmp_create_srv_conf(ngx_conf_t *cf);
static void *ngx_stream_kmp_rtmp_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_kmp_rtmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_kmp_rtmp(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_stream_kmp_rtmp_process_handler(
    ngx_stream_kmp_rtmp_upstream_t *upstream);


static ngx_int_t
ngx_kmp_rtmp_frame_list_init(ngx_rtmp_kmp_frame_list_t *list, ngx_pool_t *pool)
{
    ngx_rtmp_kmp_frame_part_t  *part;

    list->pool = pool;
    part = ngx_palloc(pool, sizeof(ngx_rtmp_kmp_frame_part_t));
    if (part == NULL) {
        return NGX_ERROR;
    }

    part->nelts = 0;
    part->next = NULL;

    list->last = list->part = part;

    return NGX_OK;
}

static ngx_rtmp_kmp_frame_t *
ngx_kmp_rtmp_frame_list_push(ngx_rtmp_kmp_frame_list_t *list,
    ngx_buf_chain_t *data_head, ngx_buf_chain_t *data_tail)
{
    ngx_rtmp_kmp_frame_t       *frame;
    ngx_rtmp_kmp_frame_part_t  *last;

    last = list->last;

    if (last->nelts >= NGX_RTMP_KMP_FRAME_PART_COUNT) {

        last = ngx_palloc(list->pool, sizeof(ngx_rtmp_kmp_frame_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        list->last->next = last;
        list->last = last;
    }

    frame = &last->elts[last->nelts];
    last->nelts++;

    list->count++;

    frame->data = data_head;

    if (list->last_data_part != NULL) {
        list->last_data_part->next = data_head;
    }

    list->last_data_part = data_tail;

    return frame;
}

static void
ngx_kmp_rtmp_frame_list_pop(ngx_rtmp_kmp_frame_list_t *list)
{
    ngx_rtmp_kmp_frame_part_t  *part;

    list->count--;

    list->offset++;
    if (list->offset < NGX_RTMP_KMP_FRAME_PART_COUNT) {
        goto done;
    }

    list->offset = 0;

    part = list->part;
    if (part->next == NULL) {
        part->nelts = 0;
        goto done;
    }

    list->part = part->next;

    /* TODO free ???? */

done:

}

static ngx_rtmp_kmp_frame_t *
ngx_kmp_rtmp_frame_list_head(ngx_rtmp_kmp_frame_list_t *list)
{
    return list->part->elts + list->offset;
}

ngx_int_t
ngx_stream_kmp_rtmp_init_process(ngx_cycle_t *cycle)
{
    ngx_rbtree_init(&ngx_stream_kmp_rtmp_upstreams.rbtree,
        &ngx_stream_kmp_rtmp_upstreams.sentinel, ngx_str_rbtree_insert_value);

    return NGX_OK;
}

static ngx_command_t  ngx_stream_kmp_rtmp_commands[] = {

    { ngx_string("kmp_rtmp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_kmp_rtmp,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("live_kmp_rtmp_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, read_timeout),
      NULL },

    { ngx_string("live_kmp_rtmp_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("input_bufs_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("input_bufs_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, bin_count),
      NULL },

    { ngx_string("input_bufs_max_free"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, max_free_buffers),
      NULL },

   { ngx_string("mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, mem_limit),
      NULL },

    { ngx_string("wait_frame_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, wait_frame_timeout),
      NULL },

    { ngx_string("chunk_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, chunk_size),
      NULL },

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_kmp_rtmp_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */
    ngx_stream_kmp_rtmp_create_main_conf,     /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_stream_kmp_rtmp_create_srv_conf,      /* create server configuration */
    ngx_stream_kmp_rtmp_merge_srv_conf        /* merge server configuration */
};

ngx_module_t  ngx_stream_kmp_rtmp_module = {
    NGX_MODULE_V1,
    &ngx_stream_kmp_rtmp_module_ctx,          /* module context */
    ngx_stream_kmp_rtmp_commands,             /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    ngx_stream_kmp_rtmp_init_process,         /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};

static void
ngx_stream_kmp_rtmp_free(void *data)
{
}



static void
ngx_stream_kmp_rtmp_dummy_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, wev->log, 0,
        "ngx_stream_kmp_rtmp_dummy_handler: called");
}

static ngx_int_t
ngx_stream_kmp_rtmp_get_output_buf(ngx_stream_kmp_rtmp_upstream_t  *upstream,
    size_t size)
{
    ngx_buf_t *b;
    ngx_buf_queue_t *buf_queue;

    buf_queue = &upstream->buf_queue;
    b = &upstream->active_buf;

    if (size > (size_t)(b->end - b->pos)) {
        b->start = ngx_buf_queue_get(buf_queue);
        if (b->start == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, upstream->log, 0,
                "ngx_stream_kmp_rtmp_get_output_buf: alloc buf failed");
            return NGX_ERROR;
        }

        if (size > buf_queue->used_size) {
            ngx_log_error(NGX_LOG_NOTICE, upstream->log, 0,
                "ngx_stream_kmp_rtmp_get_output_buf: not enough space in buf");
            return NGX_ERROR;
        }

        b->end = b->start + buf_queue->used_size;
        b->pos = b->last = b->start;
    }

    return NGX_OK;
}

ngx_int_t
ngx_stream_kmp_rtmp_send_chain(ngx_stream_kmp_rtmp_upstream_t *upstream)
{
    ngx_chain_t       *cl, *free;
    ngx_chain_t       *next;
    ngx_chain_t       *chain;
    ngx_connection_t  *c;

    c = upstream->connection;
    chain = c->send_chain(c, upstream->busy, 0);

    if (chain == NGX_CHAIN_ERROR) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_kmp_rtmp_send_chain: send_chain failed");
        c->error = 1;
        return NGX_ERROR;
    }

    /* move sent buffers to free */
    free = upstream->busy;
    for (cl = upstream->busy; cl && cl != chain; cl = next) {
        free = cl;
        next = cl->next;

        cl->next = upstream->free;
        upstream->free = cl;
    }

   if (free != NULL) {
        ngx_buf_queue_free(&upstream->buf_queue, free->buf->start);
    }

    upstream->busy = chain;

    if (upstream->busy == NULL) {
        upstream->last = &upstream->busy;
    }

    return NGX_AGAIN;
}

static void
ngx_stream_kmp_rtmp_timer(ngx_event_t *ev)
{
    ngx_stream_kmp_rtmp_upstream_t  *upstream = ev->data;

    ngx_stream_kmp_rtmp_process_handler(upstream);
}

static void
ngx_stream_kmp_rtmp_process_handler(ngx_stream_kmp_rtmp_upstream_t *upstream)
{
    ngx_msec_t                     timer;
    ngx_queue_t                   *q;
    ngx_rbtree_node_t             *root, *sentinel, *node;
    ngx_chain_t                   *ch;
    ngx_rtmp_kmp_frame_t          *frame;
    ngx_stream_kmp_rtmp_track_t   *ctx;
    ngx_stream_kmp_rtmp_stream_t  *cur_stream;

    for (q = ngx_queue_head(&upstream->streams.queue);
        q != ngx_queue_sentinel(&upstream->streams.queue);
        q = ngx_queue_next(q))
    {
        cur_stream = ngx_queue_data(q, ngx_stream_kmp_rtmp_stream_t, queue);
        if (cur_stream->media_info_sent) {
            continue;
        }

        if (cur_stream->track_count < 2 &&
            ngx_time() < cur_stream->created + 5)
        {
            ngx_log_error(NGX_LOG_INFO, upstream->log, 0,
                "ngx_stream_kmp_rtmp_process_handler: media info not ready %d",
                    cur_stream->track_count);
            ngx_add_timer(&upstream->process, 500);
            continue;
        }

        if (ngx_stream_kmp_rtmp_get_output_buf(upstream,
            ngx_kmp_rtmp_meta_data_get_size(cur_stream->tracks_list[0],
            cur_stream->tracks_list[1]) != NGX_OK))
        {
            ngx_log_error(NGX_LOG_NOTICE, upstream->log, 0,
                "ngx_stream_kmp_rtmp_process_handler: "
                "buf alloc failed");
        }

        ngx_kmp_rtmp_build_meta_data(&upstream->active_buf,
            cur_stream->tracks_list[0], cur_stream->tracks_list[1]);
        ch = ngx_kmp_rtmp_build_get_chain(upstream,
            cur_stream->tracks_list[0] ? cur_stream->tracks_list[0]->pool
            : cur_stream->tracks_list[1]->pool,
            upstream->active_buf.pos, upstream->active_buf.last);
        *upstream->last = ch;
        upstream->last = &ch->next;
        ngx_stream_kmp_rtmp_send_chain(upstream);
        upstream->active_buf.pos = upstream->active_buf.last;
        cur_stream->media_info_sent = 1;
        ngx_log_error(NGX_LOG_INFO, upstream->log, 0,
            "ngx_stream_kmp_rtmp_process_handler: media info build");
    }

    sentinel = upstream->tracks.rbtree.sentinel;

    for ( ;;) {
        root = upstream->tracks.rbtree.root;
        if (root == sentinel) {
            break;
        }

        node = ngx_rbtree_min(root, sentinel);

        ctx = (void *) node;
        if (ctx->stream->media_info_sent) {
            frame = ngx_kmp_rtmp_frame_list_head(&ctx->frames);

            if (ngx_current_msec < frame->added + upstream->wait_frame_timeout) {
                timer = frame->added + 1 - ngx_current_msec;
                if (timer > 1000) {
                    ngx_log_error(NGX_LOG_INFO, upstream->log, 0,
                        "ngx_stream_kmp_rtmp_process_handler: delay %d %d %d",
                        ngx_current_msec, frame->added, timer);
                }

                ngx_add_timer(&upstream->process, timer);
                break;
            }

            u_char *h = frame->data->data;
            if (ngx_kmp_rtmp_build_rtmp(upstream, ctx, frame, upstream->chunk_size, ctx->timescale) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_INFO, upstream->log, 0,
                    "ngx_stream_kmp_rtmp_process_handler: "
                    "ngx_kmp_rtmp_build_rtmp failed");
                break;
            }

            ngx_stream_kmp_rtmp_send_chain(upstream);
            ngx_rbtree_delete(&upstream->tracks.rbtree, &ctx->in);
            ngx_kmp_rtmp_frame_list_pop(&ctx->frames);
            ngx_buf_queue_free(&ctx->buf_queue, h);
            if (ctx->frames.count <= 0 ) {
                continue;
            }
            frame = ngx_kmp_rtmp_frame_list_head(&ctx->frames);
            ctx->in.key = frame->dts;
            ngx_rbtree_insert(&upstream->tracks.rbtree, &ctx->in);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
               "ngx_stream_kmp_rtmp_process_handler: no media info");
            break;
        }
    }
}

static void
ngx_stream_kmp_rtmp_peer_read_handler(ngx_event_t *rev)
{
    u_char                           buf[10];
    ssize_t                          n;
    ngx_queue_t                     *q;
    ngx_connection_t                *c;
    ngx_stream_kmp_rtmp_track_t     *cur_ctx;
    ngx_stream_kmp_rtmp_stream_t    *cur_stream;
    ngx_stream_kmp_rtmp_upstream_t  *upstream;

    c = rev->data;
    upstream = c->data;

    for ( ;; ) {

        n = ngx_recv(c, buf, 10);
        if (n > 0) {
            continue;
        }

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }

            return;
        }

        break;
    }

    ngx_log_error(NGX_LOG_INFO, rev->log, 0,
        "ngx_stream_kmp_rtmp_peer_read_handler: closed connection");

    for (q = ngx_queue_head(&upstream->streams.queue);
        q != ngx_queue_sentinel(&upstream->streams.queue);
        q = ngx_queue_next(q))
    {
        cur_stream = ngx_queue_data(q, ngx_stream_kmp_rtmp_stream_t, queue);
        for (int i = 0 ; i < 2 ; i++) {
            cur_ctx = cur_stream->tracks_list[i];
            if (cur_ctx != NULL) {
                ngx_stream_finalize_session(cur_ctx->s, NGX_STREAM_OK);
            }
        }
    }

}

static void
ngx_stream_kmp_rtmp_peer_write_handler(ngx_event_t *wev)
{
    ngx_connection_t                *c;
    ngx_stream_kmp_rtmp_upstream_t  *upstream;

    c = wev->data;
    upstream = c->data;

    if (upstream) {
        ngx_stream_kmp_rtmp_send_chain(upstream);
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
           "ngx_stream_kmp_rtmp_peer_write_handler: handle write event failed");
    }

    return;
}

static void
ngx_stream_kmp_rtmp_get_stream_params(ngx_log_t *log, ngx_str_t *id,
    ngx_str_t *host, ngx_str_t *app, ngx_str_t *tc_url, ngx_str_t *flash_ver,
    ngx_str_t *stream_name)
{
    char  *start, *end;

    end = ngx_strchr((u_char *)id->data, '/') + 1;

    host->data = id->data;
    host->len = (u_char *)end - id->data - 1;


    start = end;
    end = ngx_strchr(start, '/') + 1;

    app->data = (u_char *)start;
    app->len = end - start - 1;

    start = end;
    end = ngx_strchr(start, '/') + 1;

    stream_name->data = (u_char *)start;
    stream_name->len = id->data + id->len  - (u_char *)start;

    tc_url->len = start - (char *)id->data - 1;
    tc_url->data = id->data;

    flash_ver->data = (u_char *)"FMLE/3.0 (compatible; Lavf58.76.100)";
    flash_ver->len = sizeof("FMLE/3.0 (compatible; Lavf58.76.100)") - 1;
}

static ngx_int_t
ngx_stream_kmp_rtmp_init_upstream_and_stream(ngx_stream_kmp_rtmp_track_t *ctx,
    ngx_stream_session_t *s, ngx_kmp_rtmp_connect_data_json_t  *connect_data)
{
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_str_t                        id, host;
    ngx_str_t                        app, tc_url, flash_ver, stream_name;
    ngx_url_t                        url;
    ngx_chain_t                     *ch;
    ngx_connection_t                *peer_c;
    ngx_peer_connection_t            peer;
    ngx_stream_kmp_rtmp_srv_conf_t  *conf;
    ngx_stream_kmp_rtmp_upstream_t  *upstream;

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_rtmp_module);

    id = connect_data->url;
    ngx_stream_kmp_rtmp_get_stream_params(ctx->log, &id, &host, &app, &tc_url,
        &flash_ver, &stream_name);

    hash = ngx_crc32_short(id.data, id.len);
    upstream = (ngx_stream_kmp_rtmp_upstream_t *) ngx_str_rbtree_lookup(
        &ngx_stream_kmp_rtmp_upstreams.rbtree, &id, hash);
    if (upstream == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_init_upstream_and_stream: create upstream");
        upstream = ngx_pcalloc(ctx->pool, sizeof(ngx_stream_kmp_rtmp_upstream_t)
            + id.len);
        upstream->mem_left = conf->mem_limit;
        upstream->wait_frame_timeout = conf->wait_frame_timeout;
        upstream->chunk_size = conf->chunk_size;
        upstream->sn.str.data = (void *) (upstream + 1);
        upstream->sn.str.len = id.len;
        ngx_memcpy(upstream->sn.str.data, id.data, upstream->sn.str.len);
        upstream->sn.node.key = hash;
        ngx_rbtree_insert(&ngx_stream_kmp_rtmp_upstreams.rbtree,
            &upstream->sn.node);
        ngx_queue_init(&upstream->streams.queue);
        ngx_rbtree_init(&upstream->streams.rbtree, &upstream->streams.sentinel,
            ngx_str_rbtree_insert_value);
        ngx_rbtree_init(&upstream->tracks.rbtree, &upstream->tracks.sentinel,
            ngx_rbtree_insert_value);

        ngx_memzero(&url, sizeof(url));
        ngx_memzero(&peer, sizeof(peer));

        url.url = host;

        if (ngx_parse_url(ctx->pool, &url) != NGX_OK) {
            if (url.err) {
                ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                    "ngx_stream_kmp_rtmp_init_upstream_and_stream: %s i \"%V\"",
                    url.err, &host);
            }
            return NGX_ERROR;
        }

        if (url.naddrs == 0) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "ngx_stream_kmp_rtmp_init_upstream_and_stream:"
                 "no addresses in \"%V\"", &host);
            return NGX_ERROR;
        }

        u_char sockaddr_buf[NGX_SOCKADDRLEN];
        peer.socklen = url.addrs[0].socklen;
        peer.sockaddr = (void *) sockaddr_buf;
        ngx_memcpy(peer.sockaddr, url.addrs[0].sockaddr, peer.socklen);
        peer.name = &id;
        peer.get = ngx_event_get_peer;
        peer.log = ctx->log;
        peer.log_error = NGX_ERROR_ERR;
        rc = ngx_event_connect_peer(&peer);

        if (rc != NGX_OK && rc != NGX_AGAIN) {
            return NGX_ERROR;
        }

        peer_c = peer.connection;
        peer_c->data = upstream;
        peer_c->log->connection = peer_c->number;
        peer_c->read->handler = ngx_stream_kmp_rtmp_peer_read_handler;
        peer_c->write->handler = ngx_stream_kmp_rtmp_peer_write_handler;
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "ngx_stream_kmp_rtmp_init_upstream_and_stream: connecting to %V",
             &host);

        if (ngx_buf_queue_init(&upstream->buf_queue, ctx->log, conf->lba,
            conf->max_free_buffers, &upstream->mem_left) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_kmp_rtmp_init_upstream_and_stream: ngx_buf_queue_init failed");
            return NGX_STREAM_INTERNAL_SERVER_ERROR;
        }

        upstream->log = ctx->log;
        upstream->connection = peer.connection;
        upstream->free = NULL;

        if (ngx_stream_kmp_rtmp_get_output_buf(upstream,
            ngx_kmp_rtmp_handshake_init_get_size(&app, &tc_url, &flash_ver))
                != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_kmp_rtmp_init_upstream_and_stream: "
                "buf alloc failed");
        }

        if (connect_data->header.len > 0) {
            upstream->active_buf.last = ngx_copy(upstream->active_buf.last,
                connect_data->header.data, connect_data->header.len);
        }

        ngx_kmp_rtmp_build_handshake_init(&upstream->active_buf,
            &connect_data->header, &app, &tc_url, &flash_ver, conf->chunk_size);
        ch = ngx_kmp_rtmp_build_get_chain(upstream, ctx->pool,
            upstream->active_buf.pos, upstream->active_buf.last);
        upstream->busy = ch;
        upstream->last = &ch->next;

        ngx_stream_kmp_rtmp_send_chain(upstream);
        upstream->active_buf.pos = upstream->active_buf.last;
        upstream->process.handler = ngx_stream_kmp_rtmp_timer;
        upstream->process.log = ctx->log;
        upstream->process.data = upstream;
    }

    ctx->s = s;
    ctx->cln.data = ctx;
    ctx->cln.handler = ngx_stream_kmp_rtmp_free; /* TODO is needed ask Eran?? */
    ctx->cln.next = ctx->pool->cleanup;
    ctx->pool->cleanup = &ctx->cln;

    hash = ngx_crc32_short(stream_name.data, stream_name.len);
    ngx_stream_kmp_rtmp_stream_t *stream =
        (ngx_stream_kmp_rtmp_stream_t *)
        ngx_str_rbtree_lookup(&upstream->streams.rbtree,
        &stream_name, hash);

    if (stream == NULL) {
       ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_init_upstream_and_stream: create stream");
        stream = ngx_pcalloc(ctx->pool, sizeof(ngx_stream_kmp_rtmp_stream_t) +
            stream_name.len);
        stream->created = ngx_time();
        stream->sn.str.data = (void *) (stream + 1);
        stream->sn.str.len = stream_name.len;
        ngx_memcpy(stream->sn.str.data, stream_name.data, stream->sn.str.len);
        stream->sn.node.key = hash;
        ngx_rbtree_insert(&upstream->streams.rbtree, &stream->sn.node);
        ngx_queue_insert_tail(&upstream->streams.queue, &stream->queue);
        if (ngx_stream_kmp_rtmp_get_output_buf(upstream,
            ngx_kmp_rtmp_stream_init_get_size(&stream_name)) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_kmp_rtmp_init_upstream_and_stream: "
                "buf alloc failed");
        }
        ngx_kmp_rtmp_build_stream_init(&upstream->active_buf, &stream_name);
        ch = ngx_kmp_rtmp_build_get_chain(upstream, ctx->pool,
            upstream->active_buf.pos, upstream->active_buf.last);
        *upstream->last = ch;
        upstream->last = &ch->next;
        ngx_stream_kmp_rtmp_send_chain(upstream);
        upstream->active_buf.pos = upstream->active_buf.last;
    }

    ctx->upstream = upstream;
    ctx->stream = stream;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_kmp_rtmp_media_info(void *data, ngx_kmp_in_evt_media_info_t* evt)
{
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;
    ctx->media_info = evt->media_info;
    ctx->media_info_data.data = ngx_pcalloc(ctx->pool, evt->extra_data_size);
    ctx->media_info_data.len = evt->extra_data_size;


    if (ngx_buf_chain_copy(&evt->extra_data, ctx->media_info_data.data,
        evt->extra_data_size) == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
            "ngx_stream_kmp_rtmp_media_info: failed to copy extra data");
        return NGX_ERROR;
    }

    ctx->media_type = ctx->media_info.media_type;
    ctx->timescale = ctx->media_info.timescale;
    ctx->stream->tracks_list[ctx->media_info.media_type] = ctx;
    ctx->stream->track_count++;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_kmp_rtmp_frame(void *data, ngx_kmp_in_evt_frame_t *evt)
{
    ngx_rtmp_kmp_frame_t         *frame;
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;
    ngx_flag_t empty = ctx->frames.count <= 0;

    frame = ngx_kmp_rtmp_frame_list_push(&ctx->frames, evt->data_head,
        evt->data_tail);
    frame->created = evt->frame.created;
    frame->added = ngx_current_msec;
    frame->id = evt->frame_id;
    frame->dts = evt->frame.dts;
    frame->pts = evt->frame.pts_delay;
    frame->flags = evt->frame.flags;
    frame->size = evt->size;

    if (empty) {
        ctx->in.key = evt->frame.dts;
        ngx_rbtree_insert(&ctx->upstream->tracks.rbtree, &ctx->in);
        ngx_stream_kmp_rtmp_process_handler(ctx->upstream);
    }

    return NGX_OK;
}

static void
ngx_stream_kmp_rtmp_end_stream(void *data)
{
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_end_stream");
}

static ngx_int_t
ngx_stream_kmp_rtmp_connect_data(ngx_kmp_in_ctx_t *ictx,
    ngx_kmp_in_evt_connect_data_t *evt)
{
    ngx_int_t                         rc;
    ngx_json_value_t                  obj;
    ngx_connection_t                 *c;
    ngx_stream_session_t             *s;
    ngx_stream_kmp_rtmp_track_t      *ctx;
    ngx_kmp_rtmp_connect_data_json_t  json;

    ictx->connect_data = NULL;
    c = ictx->connection;
    s = c->data;
    ctx = ictx->data;

    rc = ngx_kmp_in_parse_json_chain(ctx->pool, evt->data, evt->header->header.data_size, &obj);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_connect_data: failed to parse json chain");

        return rc;
    }

    ngx_memset(&json, 0xff, sizeof(json));

    if (ngx_json_object_parse(ctx->pool, &obj.v.obj,
        ngx_kmp_rtmp_connect_data_json,
        ngx_array_entries(ngx_kmp_rtmp_connect_data_json), &json)
        != NGX_JSON_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_connect_data: failed to parse object");

        return NGX_ERROR;
    }

    ngx_stream_kmp_rtmp_init_upstream_and_stream(ctx, s, &json);

    ictx->media_info = ngx_stream_kmp_rtmp_media_info;
    ictx->frame = ngx_stream_kmp_rtmp_frame;
    ictx->end_stream = ngx_stream_kmp_rtmp_end_stream;

    return NGX_OK;
}

static ngx_buf_chain_t *
ngx_stream_kmp_rtmp_alloc_chain(void *data)
{
    ngx_buf_chain_t          *chain;
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;

    chain = ctx->free;
    if (chain) {
        ctx->free = chain->next;
        return chain;
    }

    return ngx_palloc(ctx->pool, sizeof(*chain));
}

static ngx_int_t
ngx_stream_kmp_rtmp_get_input_buf(void *data, ngx_buf_t *b)
{
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;

    b->start = ngx_buf_queue_get(&ctx->buf_queue);
    if (b->start == NULL) {
        return NGX_ERROR;
    }

    b->end = b->start + ctx->buf_queue.used_size;
    b->pos = b->last = b->start;

    return NGX_OK;
}

static void
ngx_stream_kmp_rtmp_free_chain_list(void *data, ngx_buf_chain_t *head,
    ngx_buf_chain_t *tail)
{
    ngx_stream_kmp_rtmp_track_t  *ctx;

    ctx = data;
    tail->next = ctx->free;
    ctx->free = head;
}

static ngx_int_t
ngx_stream_kmp_rtmp_connected(ngx_kmp_in_ctx_t *ictx,
    ngx_kmp_in_evt_connected_t *evt)
{
    ngx_log_t                       *log;
    ngx_pool_t                      *pool;
    ngx_connection_t                *c;
    ngx_stream_session_t            *s;
    ngx_stream_kmp_rtmp_track_t     *ctx;
    ngx_stream_kmp_rtmp_srv_conf_t  *conf;

    c = ictx->connection;
    pool = c->pool;
    s = c->data;
    log = ictx->log;

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_rtmp_module);

    ctx = ngx_pcalloc(pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_stream_kmp_rtmp_connected: alloc ctx failed");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    ctx->mem_left = conf->mem_limit;
    ctx->pool = pool;
    ctx->log = log;
    ngx_kmp_rtmp_frame_list_init(&ctx->frames, pool);

    if (ngx_buf_queue_init(&ctx->buf_queue, log, conf->lba,
        conf->max_free_buffers, &ctx->mem_left) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "ngx_stream_kmp_rtmp_connected: ngx_buf_queue_init failed");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    ictx->connect_data = ngx_stream_kmp_rtmp_connect_data;
    ictx->alloc_chain = ngx_stream_kmp_rtmp_alloc_chain;
    ictx->get_input_buf = ngx_stream_kmp_rtmp_get_input_buf;
    ictx->free_chain_list = ngx_stream_kmp_rtmp_free_chain_list;
    ictx->data = ctx;

    return NGX_OK;
}

static void
ngx_stream_kmp_rtmp_disconnect(ngx_kmp_in_ctx_t *ictx, ngx_uint_t rc)
{

     ngx_log_error(NGX_LOG_NOTICE, ictx->log, 0,
            "ngx_stream_kmp_rtmp_disconnect: start");
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ictx->connection;
    s = c->data;

    ngx_stream_finalize_session(s, rc);
}

static void
ngx_stream_kmp_rtmp_disconnected(ngx_kmp_in_ctx_t *ictx)
{
    ngx_log_error(NGX_LOG_NOTICE, ictx->log, 0,
            "ngx_stream_kmp_rtmp_disconnected: start");
    ngx_stream_kmp_rtmp_track_t     *ctx;
    ngx_stream_kmp_rtmp_stream_t    *stream;
    ngx_stream_kmp_rtmp_upstream_t  *upstream;

    ctx = ictx->data;
    stream = ctx->stream;
    upstream = ctx->upstream;
    stream->tracks_list[ctx->media_type] = NULL;
    stream->track_count--;

    if (stream->track_count == 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_disconnected: delete stream");
        ngx_queue_remove(&stream->queue);
    }

   if (ngx_queue_empty(&upstream->streams.queue)) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_kmp_rtmp_disconnected: delete upstream");
        ngx_rbtree_delete(&ngx_stream_kmp_rtmp_upstreams.rbtree,
            &upstream->sn.node);
        upstream->busy = NULL;
        upstream->connection->read->handler = NULL;
        upstream->connection->write->handler = NULL;
        if (upstream->process.timer_set) {
            ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                "ngx_stream_kmp_rtmp_disconnected: delete timer");
            ngx_del_timer(&upstream->process);
        }
    }
}

static u_char *
ngx_stream_kmp_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                       *p;
    ngx_kmp_in_ctx_t             *ictx;
    ngx_stream_session_t         *s;
    ngx_stream_kmp_rtmp_track_t  *ctx;

    s = log->data;
    p = buf;
    ictx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_rtmp_module);

    ctx = ictx->data;
    if (ctx != NULL) {
        p = ngx_snprintf(buf, len, "");
    }

    return p;
}

static void
ngx_stream_kmp_rtmp_read_handler(ngx_event_t *rev)
{
    ngx_int_t              rc;
    ngx_kmp_in_ctx_t      *ctx;
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = rev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_rtmp_module);

    rc = ngx_kmp_in_read_handler(ctx);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}

static void
ngx_stream_kmp_rtmp_handler(ngx_stream_session_t *s)
{
    ngx_connection_t                *c;
    ngx_kmp_in_ctx_t                *ctx;
    ngx_stream_kmp_rtmp_srv_conf_t  *conf;

    c = s->connection;

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_rtmp_module);

    ctx = ngx_kmp_in_create(c, &conf->in);
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_kmp_rtmp_module);

    ctx->connected = ngx_stream_kmp_rtmp_connected;
    ctx->disconnect = ngx_stream_kmp_rtmp_disconnect;
    ctx->disconnected = ngx_stream_kmp_rtmp_disconnected;

    s->log_handler = ngx_stream_kmp_rtmp_log_error;

    c->read->handler = ngx_stream_kmp_rtmp_read_handler;
    c->write->handler = ngx_stream_kmp_rtmp_dummy_handler;
    ngx_stream_kmp_rtmp_read_handler(c->read);
}

static void *
ngx_stream_kmp_rtmp_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_kmp_rtmp_main_conf_t  *kmcf;

    kmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_kmp_rtmp_main_conf_t));
    if (kmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&kmcf->lba_array, cf->temp_pool, 1, sizeof(void *))
        != NGX_OK)
    {
        return NULL;
    }

    return kmcf;
}

static ngx_lba_t *
ngx_stream_kmp_rtmp_get_lba(ngx_conf_t *cf, size_t buffer_size,
    ngx_uint_t bin_count)
{
    ngx_lba_t                        *lba, **plba;
    ngx_uint_t                        i;
    ngx_stream_kmp_rtmp_main_conf_t  *kmcf;

    kmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_kmp_rtmp_module);
    plba = kmcf->lba_array.elts;

    for (i = 0; i < kmcf->lba_array.nelts; i++) {
        lba = plba[i];
        if (ngx_lba_match(lba, buffer_size, bin_count)) {
            return lba;
        }
    }

    lba = ngx_lba_create(cf->pool, buffer_size, bin_count);
    if (lba == NULL) {
        return NULL;
    }

    plba = ngx_array_push(&kmcf->lba_array);
    if (plba == NULL) {
        return NULL;
    }

    *plba = lba;

    return lba;
}

static void *
ngx_stream_kmp_rtmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_kmp_rtmp_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_kmp_rtmp_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->bin_count = NGX_CONF_UNSET_UINT;
    conf->max_free_buffers = NGX_CONF_UNSET_UINT;
    conf->mem_limit = NGX_CONF_UNSET_UINT;
    conf->wait_frame_timeout = NGX_CONF_UNSET_MSEC;
    conf->chunk_size = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_stream_kmp_rtmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_kmp_rtmp_srv_conf_t  *prev = parent;
    ngx_stream_kmp_rtmp_srv_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 20 * 1000);

    ngx_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 10 * 1000);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 10240);

    ngx_conf_merge_size_value(conf->bin_count,
                              prev->bin_count, 8);

    ngx_conf_merge_uint_value(conf->max_free_buffers,
                              prev->max_free_buffers, 4);

    ngx_conf_merge_size_value(conf->mem_limit,
                              prev->mem_limit, 64 * 1024 * 1024);

    ngx_conf_merge_msec_value(conf->wait_frame_timeout,
                              prev->wait_frame_timeout, 1);

    ngx_conf_merge_msec_value(conf->chunk_size,
                              prev->chunk_size, 65536);

    conf->lba = ngx_stream_kmp_rtmp_get_lba(cf, conf->buffer_size,
        conf->bin_count);

    if (conf->lba == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_stream_kmp_rtmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_stream_kmp_rtmp_handler;

    return NGX_CONF_OK;
}