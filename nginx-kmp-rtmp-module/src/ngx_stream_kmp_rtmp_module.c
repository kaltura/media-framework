#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_buf_queue.h>
#include <ngx_kmp_in.h>

#include "ngx_kmp_rtmp_track.h"


typedef struct {
    ngx_kmp_in_conf_t              in;
    size_t                         in_mem_limit;
    size_t                         in_buffer_size;
    ngx_uint_t                     in_buffer_bin_count;
    ngx_uint_t                     in_max_free_buffers;
    ngx_lba_t                     *in_lba;

    ngx_kmp_rtmp_upstream_conf_t   out;
    size_t                         out_buffer_size;
    ngx_uint_t                     out_buffer_bin_count;
} ngx_stream_kmp_rtmp_srv_conf_t;


typedef struct {
    ngx_kmp_in_ctx_t              *input;

    ngx_pool_t                    *pool;
    ngx_buf_chain_t               *free;
    ngx_json_value_t               json;

    ngx_buf_queue_t                buf_queue;
    size_t                         mem_left;

    ngx_kmp_rtmp_track_t          *track;
} ngx_stream_kmp_rtmp_ctx_t;


static char *ngx_conf_check_size_bounds(ngx_conf_t *cf, void *post,
    void *data);

static void *ngx_stream_kmp_rtmp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_kmp_rtmp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_kmp_rtmp(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_num_bounds_t  ngx_stream_kmp_rtmp_chunk_size_bounds = {
    ngx_conf_check_size_bounds, 128, 0xffffff
};


static ngx_command_t  ngx_stream_kmp_rtmp_commands[] = {

    { ngx_string("kmp_rtmp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_kmp_rtmp,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },


    { ngx_string("kmp_rtmp_in_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in.read_timeout),
      NULL },

    { ngx_string("kmp_rtmp_in_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in.send_timeout),
      NULL },

    { ngx_string("kmp_rtmp_in_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in.dump_folder),
      NULL },

    { ngx_string("kmp_rtmp_in_log_frames"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in.log_frames),
      NULL },

    { ngx_string("kmp_rtmp_in_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in_mem_limit),
      NULL },

    { ngx_string("kmp_rtmp_in_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in_buffer_size),
      NULL },

    { ngx_string("kmp_rtmp_in_buffer_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in_buffer_bin_count),
      NULL },

    { ngx_string("kmp_rtmp_in_max_free_buffers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, in_max_free_buffers),
      NULL },


    { ngx_string("kmp_rtmp_out_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.mem_limit),
      NULL },

    { ngx_string("kmp_rtmp_out_max_free_buffers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.max_free_buffers),
      NULL },

    { ngx_string("kmp_rtmp_out_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.timeout),
      NULL },

    { ngx_string("kmp_rtmp_out_flush_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.flush_timeout),
      NULL },

    { ngx_string("kmp_rtmp_out_flash_ver"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.flash_ver),
      NULL },

    { ngx_string("kmp_rtmp_out_chunk_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.chunk_size),
      &ngx_stream_kmp_rtmp_chunk_size_bounds },

    { ngx_string("kmp_rtmp_out_write_meta_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.write_meta_timeout),
      NULL },

    { ngx_string("kmp_rtmp_out_min_process_delay"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.min_process_delay),
      NULL },

    { ngx_string("kmp_rtmp_out_max_process_delay"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.max_process_delay),
      NULL },

    { ngx_string("kmp_rtmp_out_onfi_period"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.onfi_period),
      NULL },

    { ngx_string("kmp_rtmp_out_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out.dump_folder),
      NULL },

    { ngx_string("kmp_rtmp_out_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out_buffer_size),
      NULL },

    { ngx_string("kmp_rtmp_out_buffer_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_rtmp_srv_conf_t, out_buffer_bin_count),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_kmp_rtmp_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
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
    ngx_kmp_rtmp_init_process,                /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_conf_check_size_bounds(ngx_conf_t *cf, void *post, void *data)
{
    ssize_t                *sp = data;
    ngx_conf_num_bounds_t  *bounds = post;

    if (bounds->high == -1) {
        if (*sp >= bounds->low) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "value must be equal to or greater than %i",
            bounds->low);

        return NGX_CONF_ERROR;
    }

    if (*sp >= bounds->low && *sp <= bounds->high) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "value must be between %i and %i",
        bounds->low, bounds->high);

    return NGX_CONF_ERROR;
}


/* temporary handlers until input is connected to a track */

static ngx_buf_chain_t *
ngx_stream_kmp_rtmp_alloc_chain(void *data)
{
    ngx_buf_chain_t            *chain;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = data;

    chain = ctx->free;
    if (chain) {
        ctx->free = chain->next;
        return chain;
    }

    return ngx_palloc(ctx->pool, sizeof(*chain));
}


static void
ngx_stream_kmp_rtmp_free_chain_list(void *data, ngx_buf_chain_t *head,
    ngx_buf_chain_t *tail)
{
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = data;

    tail->next = ctx->free;
    ctx->free = head;
}


static ngx_int_t
ngx_stream_kmp_rtmp_get_input_buf(void *data, ngx_buf_t *b)
{
    u_char                     *p;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = data;

    p = ngx_buf_queue_get(&ctx->buf_queue);
    if (p == NULL) {
        return NGX_ERROR;
    }

    b->start = p;
    b->end = p + ctx->buf_queue.used_size;

    b->pos = b->last = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_kmp_rtmp_media_info(void *data, ngx_kmp_in_evt_media_info_t *evt)
{
    ngx_int_t                        rc;
    ngx_connection_t                *c;
    ngx_kmp_in_ctx_t                *input;
    ngx_stream_session_t            *s;
    ngx_stream_kmp_rtmp_ctx_t       *ctx;
    ngx_kmp_rtmp_track_connect_t     connect;
    ngx_stream_kmp_rtmp_srv_conf_t  *kscf;

    ctx = data;
    input = ctx->input;

    c = input->connection;
    s = c->data;
    kscf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_rtmp_module);

    connect.temp_pool = ctx->pool;
    connect.conf = &kscf->out;
    connect.input = input;
    connect.buf_queue = &ctx->buf_queue;
    connect.value = &ctx->json;
    connect.media_info = evt;

    rc = ngx_kmp_rtmp_track_connect(&connect);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_kmp_rtmp_media_info: connect track failed %i", rc);
        return rc;
    }

    ctx->track = connect.track;

    ngx_destroy_pool(ctx->pool);
    ctx->pool = NULL;
    ctx->free = NULL;

    /* buf queue ownership passed to the track */
    ngx_memzero(&ctx->buf_queue, sizeof(ctx->buf_queue));

    return NGX_OK;      /* caller must not free the chains (pool destroyed) */
}


static void
ngx_stream_kmp_rtmp_end_stream(void *data)
{
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = data;

    ngx_log_error(NGX_LOG_NOTICE, ctx->input->log, 0,
        "ngx_stream_kmp_rtmp_end_stream: called");
}


static ngx_int_t
ngx_stream_kmp_rtmp_connect_data(ngx_kmp_in_ctx_t *input,
    ngx_kmp_in_evt_connect_data_t *evt)
{
    ngx_int_t                   rc;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    input->connect_data = NULL;      /* run only once */

    ctx = input->data;

    rc = ngx_kmp_in_parse_json_chain(ctx->pool, evt->data,
        evt->header->header.data_size, &ctx->json);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, input->log, 0,
            "ngx_stream_kmp_rtmp_connect_data: parse json failed %i", rc);
        return rc;
    }

    input->media_info = ngx_stream_kmp_rtmp_media_info;
    input->end_stream = ngx_stream_kmp_rtmp_end_stream;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_kmp_rtmp_connected(ngx_kmp_in_ctx_t *input,
    ngx_kmp_in_evt_connected_t *evt)
{
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = input->data;

    ctx->pool = ngx_create_pool(1024, input->log);
    if (ctx->pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, input->log, 0,
            "ngx_stream_kmp_rtmp_connected: create pool failed");
        return NGX_ERROR;
    }

    input->alloc_chain = ngx_stream_kmp_rtmp_alloc_chain;
    input->free_chain_list = ngx_stream_kmp_rtmp_free_chain_list;
    input->get_input_buf = ngx_stream_kmp_rtmp_get_input_buf;

    input->connect_data = ngx_stream_kmp_rtmp_connect_data;

    return NGX_OK;
}


static void
ngx_stream_kmp_rtmp_disconnected(ngx_kmp_in_ctx_t *input)
{
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    ctx = input->data;

    ngx_log_error(NGX_LOG_INFO, input->log, 0,
        "ngx_stream_kmp_rtmp_disconnected: called");

    if (ctx->pool != NULL) {
        ngx_destroy_pool(ctx->pool);
    }

    ngx_buf_queue_delete(&ctx->buf_queue);
}


static void
ngx_stream_kmp_rtmp_disconnect(ngx_kmp_in_ctx_t *input, ngx_uint_t rc)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = input->connection;
    s = c->data;

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_kmp_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_kmp_in_ctx_t           *input;
    ngx_stream_session_t       *s;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    s = log->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_rtmp_module);
    input = ctx->input;

    p = buf;

    if (input->track_id.s.len > 0) {
        p = ngx_snprintf(buf, len, ", track: %V, channel: %V",
            &input->track_id.s, &input->channel_id.s);
    }

    return p;
}


static void
ngx_stream_kmp_rtmp_read_handler(ngx_event_t *rev)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c;
    ngx_stream_session_t       *s;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_rtmp_module);

    rc = ngx_kmp_in_read_handler(ctx->input);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_kmp_rtmp_write_handler(ngx_event_t *wev)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c;
    ngx_stream_session_t       *s;
    ngx_stream_kmp_rtmp_ctx_t  *ctx;

    c = wev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_rtmp_module);

    rc = ngx_kmp_in_write_handler(ctx->input);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_kmp_rtmp_handler(ngx_stream_session_t *s)
{
    ngx_connection_t                *c;
    ngx_kmp_in_ctx_t                *input;
    ngx_stream_kmp_rtmp_ctx_t       *ctx;
    ngx_stream_kmp_rtmp_srv_conf_t  *kscf;

    c = s->connection;
    kscf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_rtmp_module);

    /* init ctx */

    ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
    if (ctx == NULL) {
        goto failed;
    }

    ctx->mem_left = kscf->in_mem_limit;

    if (ngx_buf_queue_init(&ctx->buf_queue, c->log, kscf->in_lba,
        kscf->in_max_free_buffers, &ctx->mem_left) != NGX_OK)
    {
        goto failed;
    }

    /* init kmp in */

    input = ngx_kmp_in_create(c, &kscf->in);
    if (input == NULL) {
        goto failed;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_kmp_rtmp_module);

    input->connected = ngx_stream_kmp_rtmp_connected;
    input->disconnected = ngx_stream_kmp_rtmp_disconnected;

    input->disconnect = ngx_stream_kmp_rtmp_disconnect;

    input->data = ctx;
    ctx->input = input;

    /* set session handlers */

    s->log_handler = ngx_stream_kmp_rtmp_log_error;

    c->read->handler = ngx_stream_kmp_rtmp_read_handler;
    c->write->handler = ngx_stream_kmp_rtmp_write_handler;

    ngx_stream_kmp_rtmp_read_handler(c->read);

    return;

failed:

    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}


static void *
ngx_stream_kmp_rtmp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_kmp_rtmp_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_kmp_rtmp_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_kmp_in_init_conf(&conf->in);

    conf->in_mem_limit = NGX_CONF_UNSET_SIZE;
    conf->in_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->in_buffer_bin_count = NGX_CONF_UNSET_UINT;
    conf->in_max_free_buffers = NGX_CONF_UNSET_UINT;

    ngx_kmp_rtmp_upstream_conf_init(&conf->out);

    conf->out_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->out_buffer_bin_count = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_kmp_rtmp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_core_srv_conf_t      *cscf;
    ngx_stream_kmp_rtmp_srv_conf_t  *prev = parent;
    ngx_stream_kmp_rtmp_srv_conf_t  *conf = child;

    ngx_kmp_in_merge_conf(&prev->in, &conf->in);

    ngx_conf_merge_size_value(conf->in_mem_limit,
                              prev->in_mem_limit, 256 * 1024);

    ngx_conf_merge_size_value(conf->in_buffer_size,
                              prev->in_buffer_size, 64 * 1024);

    ngx_conf_merge_uint_value(conf->in_buffer_bin_count,
                              prev->in_buffer_bin_count, 8);

    ngx_conf_merge_uint_value(conf->in_max_free_buffers,
                              prev->in_max_free_buffers, 4);

    if (ngx_kmp_rtmp_upstream_conf_merge(cf, &prev->out, &conf->out)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->out_buffer_size,
                              prev->out_buffer_size, 64 * 1024);

    ngx_conf_merge_uint_value(conf->out_buffer_bin_count,
                              prev->out_buffer_bin_count, 8);

    conf->in_lba = ngx_lba_get_global(cf, conf->in_buffer_size,
        conf->in_buffer_bin_count);
    if (conf->in_lba == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->out.lba = ngx_lba_get_global(cf, conf->out_buffer_size,
        conf->out_buffer_bin_count);
    if (conf->out.lba == NULL) {
        return NGX_CONF_ERROR;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    conf->out.resolver = cscf->resolver;
    conf->out.resolver_timeout = cscf->resolver_timeout;

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
