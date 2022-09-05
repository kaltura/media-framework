#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "../ngx_live.h"
#include "../ngx_live_input_bufs.h"
#include "../ngx_live_segmenter.h"
#include "../ngx_live_media_info.h"


typedef struct {
    ngx_kmp_in_conf_t  in;
} ngx_stream_live_kmp_srv_conf_t;


static void *ngx_stream_live_kmp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_live_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_live_kmp(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_stream_live_kmp_commands[] = {

    { ngx_string("live_kmp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_live_kmp,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("live_kmp_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, in.read_timeout),
      NULL },

    { ngx_string("live_kmp_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, in.send_timeout),
      NULL },

    { ngx_string("live_kmp_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, in.dump_folder),
      NULL },

    { ngx_string("live_kmp_log_frames"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_live_kmp_srv_conf_t, in.log_frames),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_live_kmp_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_live_kmp_create_srv_conf,      /* create server configuration */
    ngx_stream_live_kmp_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_stream_live_kmp_module = {
    NGX_MODULE_V1,
    &ngx_stream_live_kmp_module_ctx,          /* module context */
    ngx_stream_live_kmp_commands,             /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_buf_chain_t *
ngx_stream_live_kmp_alloc_chain(void *data)
{
    ngx_buf_chain_t     *chain;
    ngx_live_track_t    *track;
    ngx_live_channel_t  *channel;

    track = data;
    channel = track->channel;

    chain = ngx_live_channel_buf_chain_alloc(channel);
    if (chain == NULL) {
        ngx_live_channel_finalize(channel, ngx_live_free_alloc_chain_failed);
        return NULL;
    }

    return chain;
}


static void
ngx_stream_live_kmp_free_chain_list(void *data, void *head, void *tail)
{
    ngx_live_track_t    *track;
    ngx_live_channel_t  *channel;

    track = data;
    channel = track->channel;

    ngx_live_channel_buf_chain_free_list(channel, head, tail);
}


static ngx_int_t
ngx_stream_live_kmp_get_input_buf(void *data, ngx_buf_t *b)
{
    ngx_int_t          rc;
    ngx_live_track_t  *track;

    track = data;

    rc = ngx_live_input_bufs_get(track, b);
    if (rc != NGX_OK) {
        ngx_live_channel_finalize(track->channel,
            ngx_live_free_alloc_buf_failed);
        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_live_kmp_connected(ngx_kmp_in_ctx_t *ctx,
    ngx_kmp_in_evt_connected_t *evt)
{
    ngx_int_t                      rc;
    ngx_str_t                      track_id;
    ngx_str_t                      channel_id;
    ngx_live_track_t              *track;
    ngx_live_channel_t            *channel;
    kmp_connect_packet_t          *header;
    ngx_live_core_preset_conf_t   *cpcf;
    ngx_live_stream_stream_req_t   req;

    header = evt->header;

    /* get the channel */
    channel_id.data = header->channel_id;
    channel_id.len = ngx_kmp_in_strnlen(channel_id.data,
        sizeof(header->channel_id));

    channel = ngx_live_channel_get(&channel_id);
    if (channel == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_connected: unknown channel \"%V\"",
            &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (channel->blocked) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_connected: channel \"%V\" is blocked",
            &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    /* get the track */
    track_id.data = header->track_id;
    track_id.len = ngx_kmp_in_strnlen(track_id.data, sizeof(header->track_id));

    track = ngx_live_track_get(channel, &track_id);
    if (track == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_connected: "
            "unknown track \"%V\" in channel \"%V\"",
            &track_id, &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (track->type == ngx_live_track_type_filler) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_connected: "
            "track \"%V\" in channel \"%V\" is a filler track",
            &track_id, &channel_id);
        return NGX_STREAM_BAD_REQUEST;
    }

    if (track->input != NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "ngx_stream_live_kmp_connected: "
            "track \"%V\" in channel \"%V\" already connected to %uA",
            &track_id, &channel_id, track->input->connection->number);
        return NGX_STREAM_BAD_REQUEST;
    }

    /* connect to the track */
    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    ctx->data = track;
    ctx->track_id = track_id;
    track->input = ctx;

    ctx->media_info = cpcf->segmenter.add_media_info;
    ctx->frame = cpcf->segmenter.add_frame;
    ctx->end_stream = cpcf->segmenter.end_stream;

    ctx->alloc_chain = ngx_stream_live_kmp_alloc_chain;
    ctx->free_chain_list = ngx_stream_live_kmp_free_chain_list;
    ctx->get_input_buf = ngx_stream_live_kmp_get_input_buf;

    ngx_memzero(&req, sizeof(req));
    req.track = track;
    req.header = header;

    rc = cpcf->segmenter.start_stream(&req);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
            "ngx_stream_live_kmp_connected: failed to start stream");
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    evt->skip_count = req.skip_count;
    evt->skip_wait_key = req.skip_wait_key;

    return NGX_OK;
}


static void
ngx_stream_live_kmp_disconnected(ngx_kmp_in_ctx_t *ctx)
{
    ngx_live_track_t  *track = ctx->data;

    if (track != NULL) {
        track->input = NULL;
    }
}


static void
ngx_stream_live_kmp_disconnect(ngx_kmp_in_ctx_t *ctx, ngx_uint_t rc)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ctx->connection;
    s = c->data;

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_live_kmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_kmp_in_ctx_t      *ctx;
    ngx_live_track_t      *track;
    ngx_live_channel_t    *channel;
    ngx_stream_session_t  *s;

    s = log->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);
    track = ctx->data;

    p = buf;

    if (track != NULL) {
        channel = track->channel;

        p = ngx_snprintf(buf, len, ", nsi: %uD, track: %V, channel: %V",
            channel->next_segment_index, &track->sn.str, &channel->sn.str);
    }

    return p;
}


static void
ngx_stream_live_kmp_read_handler(ngx_event_t *rev)
{
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_kmp_in_ctx_t      *ctx;
    ngx_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    rc = ngx_kmp_in_read_handler(ctx);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_live_kmp_write_handler(ngx_event_t *wev)
{
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_kmp_in_ctx_t      *ctx;
    ngx_stream_session_t  *s;

    c = wev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_live_kmp_module);

    rc = ngx_kmp_in_write_handler(ctx);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_live_kmp_handler(ngx_stream_session_t *s)
{
    ngx_connection_t                *c;
    ngx_kmp_in_ctx_t                *ctx;
    ngx_stream_live_kmp_srv_conf_t  *lscf;

    c = s->connection;

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_live_kmp_module);

    ctx = ngx_kmp_in_create(c, &lscf->in);
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_live_kmp_module);

    ctx->connected = ngx_stream_live_kmp_connected;
    ctx->disconnected = ngx_stream_live_kmp_disconnected;

    ctx->disconnect = ngx_stream_live_kmp_disconnect;

    s->log_handler = ngx_stream_live_kmp_log_error;

    c->read->handler = ngx_stream_live_kmp_read_handler;
    c->write->handler = ngx_stream_live_kmp_write_handler;

    ngx_stream_live_kmp_read_handler(c->read);
}


static void *
ngx_stream_live_kmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_live_kmp_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_live_kmp_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_kmp_in_init_conf(&conf->in);

    return conf;
}


static char *
ngx_stream_live_kmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_live_kmp_srv_conf_t  *prev = parent;
    ngx_stream_live_kmp_srv_conf_t  *conf = child;

    ngx_kmp_in_merge_conf(&prev->in, &conf->in);

    return NGX_CONF_OK;
}


static char *
ngx_stream_live_kmp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_stream_live_kmp_handler;

    return NGX_CONF_OK;
}
