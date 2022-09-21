#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_buf_queue.h>
#include <ngx_kmp_in.h>
#include <ngx_kmp_out_track.h>
#include <ngx_kmp_out_utils.h>

#include "ngx_kmp_cc.h"


#define NGX_STREAM_KMP_CC_FREE_PERIOD  10


typedef struct {
    ngx_kmp_in_conf_t          in;
    size_t                     in_mem_limit;
    size_t                     in_buffer_size;
    ngx_uint_t                 in_buffer_bin_count;
    ngx_uint_t                 in_max_free_buffers;
    ngx_lba_t                 *in_lba;

    ngx_kmp_cc_conf_t          cc;

    ngx_kmp_out_track_conf_t   out;

    ngx_queue_t                sessions;    /* ngx_stream_kmp_cc_ctx_t */
} ngx_stream_kmp_cc_srv_conf_t;


typedef struct {
    ngx_queue_t                queue;
    ngx_kmp_in_ctx_t          *input;
    ngx_pool_t                *pool;
    ngx_buf_chain_t           *free;
    ngx_buf_queue_t            buf_queue;
    size_t                     mem_left;
    size_t                     mem_limit;
    ngx_kmp_cc_ctx_t          *cc;
} ngx_stream_kmp_cc_ctx_t;


static void ngx_stream_kmp_cc_handler(ngx_stream_session_t *s);

static void *ngx_stream_kmp_cc_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_kmp_cc_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_kmp_cc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_stream_core_main_conf_t *ngx_stream_kmp_cc_get_core_main_conf(void);


static ngx_command_t  ngx_stream_kmp_cc_commands[] = {

    { ngx_string("kmp_cc"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_kmp_cc,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("kmp_cc_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, cc.dump_folder),
      NULL },

    { ngx_string("kmp_cc_max_pending_packets"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, cc.max_pending_packets),
      NULL },


    { ngx_string("kmp_cc_in_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in.read_timeout),
      NULL },

    { ngx_string("kmp_cc_in_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in.send_timeout),
      NULL },

    { ngx_string("kmp_cc_in_dump_folder"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in.dump_folder),
      NULL },

    { ngx_string("kmp_cc_in_log_frames"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in.log_frames),
      NULL },

    { ngx_string("kmp_cc_in_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in_mem_limit),
      NULL },

    { ngx_string("kmp_cc_in_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in_buffer_size),
      NULL },

    { ngx_string("kmp_cc_in_buffer_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in_buffer_bin_count),
      NULL },

    { ngx_string("kmp_cc_in_max_free_buffers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, in_max_free_buffers),
      NULL },


    { ngx_string("kmp_cc_out_ctrl_publish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_kmp_out_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_publish_url),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_unpublish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_kmp_out_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_unpublish_url),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_republish_url"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_kmp_out_url_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_republish_url),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_add_header"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_headers),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_timeout),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_read_timeout),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_buffer_size),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_retries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_retries),
      NULL },

    { ngx_string("kmp_cc_out_ctrl_retry_interval"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.ctrl_retry_interval),
      NULL },


    { ngx_string("kmp_cc_out_timescale"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.timescale),
      NULL },

    { ngx_string("kmp_cc_out_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.timeout),
      NULL },

    { ngx_string("kmp_cc_out_max_free_buffers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.max_free_buffers),
      NULL },

    { ngx_string("kmp_cc_out_buffer_bin_count"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.buffer_bin_count),
      NULL },

    { ngx_string("kmp_cc_out_mem_high_watermark"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.mem_high_watermark),
      NULL },

    { ngx_string("kmp_cc_out_mem_low_watermark"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.mem_low_watermark),
      NULL },

#if 0   /* TODO: support video output (with 608/708 SEI payloads stripped) */
    { ngx_string("kmp_cc_out_video_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.buffer_size[KMP_MEDIA_VIDEO]),
      NULL },

    { ngx_string("kmp_cc_out_video_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.mem_limit[KMP_MEDIA_VIDEO]),
      NULL },
#endif

    { ngx_string("kmp_cc_out_subtitle_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t,
          out.buffer_size[KMP_MEDIA_SUBTITLE]),
      NULL },

    { ngx_string("kmp_cc_out_subtitle_mem_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t,
          out.mem_limit[KMP_MEDIA_SUBTITLE]),
      NULL },

    { ngx_string("kmp_cc_out_flush_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.flush_timeout),
      NULL },

    { ngx_string("kmp_cc_out_log_frames"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.log_frames),
      NULL },

    { ngx_string("kmp_cc_out_republish_interval"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.republish_interval),
      NULL },

    { ngx_string("kmp_cc_out_max_republishes"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_kmp_cc_srv_conf_t, out.max_republishes),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_kmp_cc_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_kmp_cc_create_srv_conf,        /* create server configuration */
    ngx_stream_kmp_cc_merge_srv_conf          /* merge server configuration */
};


ngx_module_t  ngx_stream_kmp_cc_module = {
    NGX_MODULE_V1,
    &ngx_stream_kmp_cc_module_ctx,            /* module context */
    ngx_stream_kmp_cc_commands,               /* module directives */
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


#include "ngx_stream_kmp_cc_module_json.h"


static ngx_buf_chain_t *
ngx_stream_kmp_cc_alloc_chain(void *data)
{
    ngx_buf_chain_t          *chain;
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    chain = ctx->free;
    if (chain) {
        ctx->free = chain->next;
        return chain;
    }

    return ngx_palloc(ctx->pool, sizeof(*chain));
}


static void
ngx_stream_kmp_cc_free_chain_list(void *data, ngx_buf_chain_t *head,
    ngx_buf_chain_t *tail)
{
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    tail->next = ctx->free;
    ctx->free = head;
}


static ngx_int_t
ngx_stream_kmp_cc_get_input_buf(void *data, ngx_buf_t *b)
{
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    b->start = ngx_buf_queue_get(&ctx->buf_queue);
    if (b->start == NULL) {
        return NGX_ERROR;
    }

    b->end = b->start + ctx->buf_queue.used_size;

    b->pos = b->last = b->start;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_kmp_cc_media_info(void *data, ngx_kmp_in_evt_media_info_t *evt)
{
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    return ngx_kmp_cc_add_media_info(ctx->cc, evt);
}


static ngx_int_t
ngx_stream_kmp_cc_frame(void *data, ngx_kmp_in_evt_frame_t *evt)
{
    u_char                   *limit;
    ngx_int_t                 rc;
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    rc = ngx_kmp_cc_add_frame(ctx->cc, evt);
    if (rc != NGX_OK) {
        return rc;
    }

    if ((evt->frame_id % NGX_STREAM_KMP_CC_FREE_PERIOD) == 0) {
        limit = ngx_kmp_cc_get_min_used(ctx->cc);
        ngx_buf_queue_free(&ctx->buf_queue, limit);
    }

    return NGX_DONE;    /* caller can free the chains */
}


static void
ngx_stream_kmp_cc_end_stream(void *data)
{
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = data;

    ngx_kmp_cc_end_stream(ctx->cc);
}


static ngx_int_t
ngx_stream_kmp_cc_connect_data(ngx_kmp_in_ctx_t *input,
    ngx_kmp_in_evt_connect_data_t *evt)
{
    ngx_int_t                      rc;
    ngx_pool_t                    *temp_pool;
    ngx_json_value_t               json;
    ngx_connection_t              *c;
    ngx_kmp_cc_input_t             cc_input;
    ngx_stream_session_t          *s;
    ngx_stream_kmp_cc_ctx_t       *ctx;
    ngx_stream_kmp_cc_srv_conf_t  *kscf;

    input->connect_data = NULL;      /* run only once */

    c = input->connection;
    ctx = input->data;

    s = c->data;
    kscf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_cc_module);

    if (evt->header->header.data_size > 0) {
        temp_pool = ngx_create_pool(1024, c->log);
        if (temp_pool == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_stream_kmp_cc_connect_data: create pool failed");
            return NGX_ABORT;
        }

        rc = ngx_kmp_in_parse_json_chain(temp_pool, evt->data,
            evt->header->header.data_size, &json);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                "ngx_stream_kmp_cc_connect_data: parse json failed %i", rc);
            ngx_destroy_pool(temp_pool);
            return rc;
        }

    } else {
        temp_pool = NULL;
        json.type = NGX_JSON_NULL;
    }

    cc_input.channel_id = input->channel_id;
    cc_input.track_id = input->track_id;

    rc = ngx_kmp_cc_create(ctx->pool, temp_pool, &kscf->cc, &cc_input, &json,
        &kscf->out, &ctx->cc);

    if (temp_pool != NULL) {
        ngx_destroy_pool(temp_pool);
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
            "ngx_stream_kmp_cc_connect_data: create ctx failed %i", rc);
        return rc;
    }

    input->media_info = ngx_stream_kmp_cc_media_info;
    input->frame = ngx_stream_kmp_cc_frame;
    input->end_stream = ngx_stream_kmp_cc_end_stream;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_kmp_cc_connected(ngx_kmp_in_ctx_t *input,
    ngx_kmp_in_evt_connected_t *evt)
{
    input->alloc_chain = ngx_stream_kmp_cc_alloc_chain;
    input->free_chain_list = ngx_stream_kmp_cc_free_chain_list;
    input->get_input_buf = ngx_stream_kmp_cc_get_input_buf;

    input->connect_data = ngx_stream_kmp_cc_connect_data;

    return NGX_OK;
}


static void
ngx_stream_kmp_cc_disconnected(ngx_kmp_in_ctx_t *input)
{
    ngx_stream_kmp_cc_ctx_t  *ctx;

    ctx = input->data;

    if (ctx->cc != NULL) {
        ngx_kmp_cc_close(ctx->cc, "disconnected");
    }

    ngx_buf_queue_delete(&ctx->buf_queue);

    ngx_queue_remove(&ctx->queue);
}


static void
ngx_stream_kmp_cc_disconnect(ngx_kmp_in_ctx_t *input, ngx_uint_t rc)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = input->connection;
    s = c->data;

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_kmp_cc_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                   *p;
    ngx_kmp_in_ctx_t         *input;
    ngx_stream_session_t     *s;
    ngx_stream_kmp_cc_ctx_t  *ctx;

    s = log->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_cc_module);
    input = ctx->input;

    p = buf;

    if (input->track_id.s.len > 0) {
        p = ngx_snprintf(buf, len, ", track: %V, channel: %V",
            &input->track_id.s, &input->channel_id.s);
    }

    return p;
}


static void
ngx_stream_kmp_cc_read_handler(ngx_event_t *rev)
{
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_kmp_cc_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_cc_module);

    rc = ngx_kmp_in_read_handler(ctx->input);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_kmp_cc_write_handler(ngx_event_t *wev)
{
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_kmp_cc_ctx_t  *ctx;

    c = wev->data;
    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_kmp_cc_module);

    rc = ngx_kmp_in_write_handler(ctx->input);
    if (rc != NGX_OK) {
        ngx_stream_finalize_session(s, rc);
    }
}


static void
ngx_stream_kmp_cc_handler(ngx_stream_session_t *s)
{
    ngx_connection_t              *c;
    ngx_kmp_in_ctx_t              *input;
    ngx_stream_kmp_cc_ctx_t       *ctx;
    ngx_stream_kmp_cc_srv_conf_t  *kscf;

    c = s->connection;
    kscf = ngx_stream_get_module_srv_conf(s, ngx_stream_kmp_cc_module);

    /* init ctx */

    ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->pool = c->pool;
    ctx->mem_left = kscf->in_mem_limit;
    ctx->mem_limit = kscf->in_mem_limit;

    if (ngx_buf_queue_init(&ctx->buf_queue, c->log, kscf->in_lba,
        kscf->in_max_free_buffers, &ctx->mem_left) != NGX_OK)
    {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    /* init kmp in */

    input = ngx_kmp_in_create(c, &kscf->in);
    if (input == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_kmp_cc_module);

    input->connected = ngx_stream_kmp_cc_connected;
    input->disconnected = ngx_stream_kmp_cc_disconnected;

    input->disconnect = ngx_stream_kmp_cc_disconnect;

    input->data = ctx;
    ctx->input = input;

    ngx_queue_insert_tail(&kscf->sessions, &ctx->queue);

    /* set session handlers */

    s->log_handler = ngx_stream_kmp_cc_log_error;

    c->read->handler = ngx_stream_kmp_cc_read_handler;
    c->write->handler = ngx_stream_kmp_cc_write_handler;

    ngx_stream_kmp_cc_read_handler(c->read);
}


static ngx_stream_core_main_conf_t *
ngx_stream_kmp_cc_get_core_main_conf(void)
{
    ngx_stream_conf_ctx_t        *stream_ctx;
    ngx_stream_core_main_conf_t  *cmcf;

    stream_ctx = (ngx_stream_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
        ngx_stream_module);
    if (stream_ctx == NULL) {
        return NULL;
    }

    cmcf = ngx_stream_get_module_main_conf(stream_ctx, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NULL;
    }

    return cmcf;
}


static ngx_stream_session_t *
ngx_stream_kmp_cc_server_get_session(ngx_stream_conf_ctx_t *conf,
    ngx_uint_t connection)
{
    ngx_queue_t                   *q;
    ngx_connection_t              *c;
    ngx_stream_kmp_cc_ctx_t       *ctx;
    ngx_stream_kmp_cc_srv_conf_t  *kscf;

    kscf = ngx_stream_get_module_srv_conf(conf, ngx_stream_kmp_cc_module);

    for (q = ngx_queue_head(&kscf->sessions);
        q != ngx_queue_sentinel(&kscf->sessions);
        q = ngx_queue_next(q))
    {
        ctx = ngx_queue_data(q, ngx_stream_kmp_cc_ctx_t, queue);

        c = ctx->input->connection;
        if (c->number == connection) {
            return c->data;
        }
    }

    return NULL;
}


static ngx_stream_session_t *
ngx_stream_kmp_cc_get_session(ngx_stream_core_main_conf_t *cmcf,
    ngx_uint_t connection)
{
    ngx_uint_t                    n;
    ngx_stream_session_t         *s;
    ngx_stream_core_srv_conf_t  **cscfp;

    cscfp = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; n++) {
        s = ngx_stream_kmp_cc_server_get_session(cscfp[n]->ctx, connection);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


ngx_int_t
ngx_stream_kmp_cc_finalize_session(ngx_uint_t connection, ngx_log_t *log)
{
    ngx_stream_session_t         *s;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_kmp_cc_get_core_main_conf();
    if (cmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_stream_kmp_cc_finalize_session: "
            "failed to get stream conf");
        return NGX_ERROR;
    }

    s = ngx_stream_kmp_cc_get_session(cmcf, connection);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_stream_kmp_cc_finalize_session: "
            "connection %ui not found", connection);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_stream_kmp_cc_finalize_session: "
        "dropping connection %ui", connection);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);

    return NGX_OK;
}


static void *
ngx_stream_kmp_cc_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_kmp_cc_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_kmp_cc_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_kmp_in_init_conf(&conf->in);

    conf->in_mem_limit = NGX_CONF_UNSET_SIZE;
    conf->in_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->in_buffer_bin_count = NGX_CONF_UNSET_UINT;
    conf->in_max_free_buffers = NGX_CONF_UNSET_UINT;

    conf->cc.max_pending_packets = NGX_CONF_UNSET_UINT;

    ngx_kmp_out_track_init_conf(&conf->out);

    ngx_queue_init(&conf->sessions);

    return conf;
}


static char *
ngx_stream_kmp_cc_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_kmp_cc_srv_conf_t  *prev = parent;
    ngx_stream_kmp_cc_srv_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->cc.max_pending_packets,
                              prev->cc.max_pending_packets, 128);

    ngx_conf_merge_str_value(conf->cc.dump_folder,
                             prev->cc.dump_folder, "");


    ngx_kmp_in_merge_conf(&prev->in, &conf->in);

    ngx_conf_merge_size_value(conf->in_mem_limit,
                              prev->in_mem_limit, 16 * 1024 * 1024);

    ngx_conf_merge_size_value(conf->in_buffer_size,
                              prev->in_buffer_size, 64 * 1024);

    ngx_conf_merge_uint_value(conf->in_buffer_bin_count,
                              prev->in_buffer_bin_count, 8);

    ngx_conf_merge_uint_value(conf->in_max_free_buffers,
                              prev->in_max_free_buffers, 4);


    conf->in_lba = ngx_lba_get_global(cf, conf->in_buffer_size,
        conf->in_buffer_bin_count);
    if (conf->in_lba == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_kmp_out_track_merge_conf(cf, &conf->out, &prev->out) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_kmp_cc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    if (cscf->handler) {
        return "is duplicate";
    }

    cscf->handler = ngx_stream_kmp_cc_handler;

    return NGX_CONF_OK;
}
