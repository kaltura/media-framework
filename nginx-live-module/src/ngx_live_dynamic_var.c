#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


#define NGX_LIVE_DYNAMIC_VAR_PERSIST_BLOCK       NGX_KSMP_BLOCK_DYNAMIC_VAR


enum {
    NGX_LIVE_BP_VAR,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    size_t                  max_size;
    ngx_uint_t              bp_idx[NGX_LIVE_BP_COUNT];
} ngx_live_dynamic_var_preset_conf_t;


typedef struct {
    ngx_str_node_t          sn;        /* must be first */
    uintptr_t               id_escape;
    ngx_queue_t             queue;
    ngx_json_str_t          value;
} ngx_live_dynamic_var_t;


typedef struct {
    ngx_rbtree_t            rbtree;
    ngx_rbtree_node_t       sentinel;
    ngx_queue_t             queue;
} ngx_live_dynamic_var_channel_ctx_t;


#include "ngx_live_dynamic_var_json.h"


static ngx_int_t ngx_live_dynamic_var_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_dynamic_var_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_dynamic_var_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_dynamic_var_merge_preset_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_live_dynamic_var_get(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_live_dynamic_var_set_vars(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value);


static ngx_command_t  ngx_live_dynamic_var_commands[] = {
    { ngx_string("dynamic_var_max_size"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_dynamic_var_preset_conf_t, max_size),
      NULL },

      ngx_null_command
};

static ngx_live_module_t  ngx_live_dynamic_var_module_ctx = {
    ngx_live_dynamic_var_preconfiguration,    /* preconfiguration */
    ngx_live_dynamic_var_postconfiguration,   /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_dynamic_var_create_preset_conf,  /* create preset configuration */
    ngx_live_dynamic_var_merge_preset_conf,   /* merge preset configuration */
};

ngx_module_t  ngx_live_dynamic_var_module = {
    NGX_MODULE_V1,
    &ngx_live_dynamic_var_module_ctx,         /* module context */
    ngx_live_dynamic_var_commands,            /* module directives */
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


static ngx_live_variable_t  ngx_live_dynamic_var_vars[] = {

    { ngx_string("var_"), NULL, ngx_live_dynamic_var_get,
      0, NGX_LIVE_VAR_PREFIX, 0 },

      ngx_live_null_variable
};

static ngx_live_json_cmd_t  ngx_live_dynamic_var_dyn_cmds[] = {

    { ngx_string("vars"), NGX_JSON_OBJECT,
      ngx_live_dynamic_var_set_vars },

      ngx_live_null_json_cmd
};


static ngx_int_t
ngx_live_dynamic_var_set_vars(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value)
{
    uint32_t                             hash;
    ngx_queue_t                         *q, *next;
    ngx_queue_t                          new_vars;
    ngx_json_object_t                   *obj = &value->v.obj;
    ngx_live_channel_t                  *channel = jctx->obj;
    ngx_json_key_value_t                *cur;
    ngx_json_key_value_t                *last;
    ngx_live_dynamic_var_t              *var;
    ngx_live_dynamic_var_preset_conf_t  *dpcf;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    dpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_dynamic_var_module);

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dynamic_var_module);

    /* load new vars to a temp queue */
    ngx_queue_init(&new_vars);

    cur = obj->elts;
    last = cur + obj->nelts;
    for (; cur < last; cur++) {

        if (cur->value.type != NGX_JSON_STRING) {
            ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "invalid value type for key \"%V\"", &cur->key);
            goto failed;
        }

        if (cur->key.len + cur->value.v.str.s.len > dpcf->max_size) {
            ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "key \"%V\" exceeds max size", &cur->key);
            goto failed;
        }

        var = ngx_block_pool_alloc(channel->block_pool,
            dpcf->bp_idx[NGX_LIVE_BP_VAR]);
        if (var == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
                "ngx_live_dynamic_var_set_vars: alloc failed");
            goto failed;
        }

        ngx_queue_insert_tail(&new_vars, &var->queue);

        var->sn.str.data = (void *) (var + 1);
        var->sn.str.len = 0;

        if (ngx_json_decode_string(&var->sn.str, &cur->key) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "failed to decode key \"%V\"", &cur->key);
            goto failed;
        }
        var->id_escape = ngx_json_str_get_escape(&var->sn.str);

        var->value.s.data = var->sn.str.data + var->sn.str.len;

        if (cur->value.v.str.escape) {
            var->value.s.len = 0;
            if (ngx_json_decode_string(&var->value.s, &cur->value.v.str.s)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
                    "ngx_live_dynamic_var_set_vars: "
                    "failed to decode the value of key \"%V\"", &cur->key);
                goto failed;
            }

        } else {
            var->value.s.len = cur->value.v.str.s.len;
            ngx_memcpy(var->value.s.data, cur->value.v.str.s.data,
                var->value.s.len);
        }
        ngx_json_str_set_escape(&var->value);
    }

    /* remove existing vars */
    q = ngx_queue_head(&cctx->queue);
    while (q != ngx_queue_sentinel(&cctx->queue)) {

        var = ngx_queue_data(q, ngx_live_dynamic_var_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_block_pool_free(channel->block_pool, dpcf->bp_idx[NGX_LIVE_BP_VAR],
            var);
    }

    ngx_rbtree_reset(&cctx->rbtree);
    ngx_queue_init(&cctx->queue);

    /* load new vars */
    for (q = ngx_queue_head(&new_vars);
        q != ngx_queue_sentinel(&new_vars);
        q = next)
    {
        next = ngx_queue_next(q);
        var = ngx_queue_data(q, ngx_live_dynamic_var_t, queue);

        ngx_queue_insert_tail(&cctx->queue, q);

        hash = ngx_crc32_short(var->sn.str.data, var->sn.str.len);
        var->sn.node.key = hash;
        ngx_rbtree_insert(&cctx->rbtree, &var->sn.node);
    }

    return NGX_OK;

failed:

    /* free temp queue */
    q = ngx_queue_head(&new_vars);
    while (q != ngx_queue_sentinel(&new_vars)) {

        var = ngx_queue_data(q, ngx_live_dynamic_var_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_block_pool_free(channel->block_pool, dpcf->bp_idx[NGX_LIVE_BP_VAR],
            var);
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_live_dynamic_var_get(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    uint32_t                             hash;
    ngx_str_t                            name = *(ngx_str_t *) data;
    ngx_live_dynamic_var_t              *var;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(ctx->ch, ngx_live_dynamic_var_module);

    name.data += sizeof("var_") - 1;
    name.len -= sizeof("var_") - 1;

    hash = ngx_crc32_short(name.data, name.len);
    var = (ngx_live_dynamic_var_t *) ngx_str_rbtree_lookup(&cctx->rbtree,
        &name, hash);
    if (var == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = var->value.s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = var->value.s.data;

    return NGX_OK;
}

static size_t
ngx_live_dynamic_var_channel_json_get_size(void *obj)
{
    ngx_live_channel_t                  *channel = obj;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dynamic_var_module);

    return ngx_live_dynamic_vars_json_get_size(cctx);
}

static u_char *
ngx_live_dynamic_var_channel_json_write(u_char *p, void *obj)
{
    ngx_live_channel_t                  *channel = obj;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dynamic_var_module);

    return ngx_live_dynamic_vars_json_write(p, cctx);
}

static ngx_int_t
ngx_live_dynamic_var_channel_init(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dynamic_var_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_dynamic_var_module);

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel,
        ngx_str_rbtree_insert_value);
    ngx_queue_init(&cctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_dynamic_var_write_setup(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_queue_t                         *q;
    ngx_wstream_t                       *ws;
    ngx_live_channel_t                  *channel = obj;
    ngx_live_dynamic_var_t              *cur;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dynamic_var_module);

    ws = ngx_persist_write_stream(write_ctx);

    for (q = ngx_queue_head(&cctx->queue);
        q != ngx_queue_sentinel(&cctx->queue);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_live_dynamic_var_t, queue);

        if (ngx_persist_write_block_open(write_ctx,
                NGX_LIVE_DYNAMIC_VAR_PERSIST_BLOCK) != NGX_OK ||
            ngx_wstream_str(ws, &cur->sn.str) != NGX_OK ||
            ngx_wstream_str(ws, &cur->value.s) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_dynamic_var_write_setup: write failed");
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_live_dynamic_var_read_setup(ngx_persist_block_header_t *header,
    ngx_mem_rstream_t *rs, void *obj)
{
    size_t                               left;
    uint32_t                             hash;
    ngx_live_channel_t                  *channel = obj;
    ngx_live_dynamic_var_t              *var;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;
    ngx_live_dynamic_var_preset_conf_t  *dpcf;

    cctx = ngx_live_get_module_ctx(channel, ngx_live_dynamic_var_module);

    dpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_dynamic_var_module);

    var = ngx_block_pool_alloc(channel->block_pool,
        dpcf->bp_idx[NGX_LIVE_BP_VAR]);
    if (var == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
            "ngx_live_dynamic_var_read_setup: alloc failed");
        return NGX_ERROR;
    }

    left = dpcf->max_size;

    var->sn.str.data = (void *) (var + 1);
    if (ngx_mem_rstream_str_fixed(rs, &var->sn.str, left) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_dynamic_var_read_setup: read key failed");
        return NGX_BAD_DATA;
    }
    var->id_escape = ngx_json_str_get_escape(&var->sn.str);

    var->value.s.data = var->sn.str.data + var->sn.str.len;
    left -= var->sn.str.len;

    if (ngx_mem_rstream_str_fixed(rs, &var->value.s, left) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_dynamic_var_read_setup: read value failed");
        return NGX_BAD_DATA;
    }
    ngx_json_str_set_escape(&var->value);

    ngx_queue_insert_tail(&cctx->queue, &var->queue);

    hash = ngx_crc32_short(var->sn.str.data, var->sn.str.len);
    var->sn.node.key = hash;
    ngx_rbtree_insert(&cctx->rbtree, &var->sn.node);

    return NGX_OK;
}


static ngx_int_t
ngx_live_dynamic_var_serve_write(ngx_persist_write_ctx_t *write_ctx,
    void *obj)
{
    ngx_live_persist_serve_scope_t  *scope;

    scope = ngx_persist_write_ctx(write_ctx);
    if (!(scope->flags & NGX_KSMP_FLAG_DYNAMIC_VAR)) {
        return NGX_OK;
    }

    return ngx_live_dynamic_var_write_setup(write_ctx, obj);
}


static ngx_persist_block_t  ngx_live_dynamic_var_blocks[] = {
    /*
     * persist data:
     *   ngx_str_t  key;
     *   ngx_str_t  value;
     */
    { NGX_LIVE_DYNAMIC_VAR_PERSIST_BLOCK, NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL,
      0,
      ngx_live_dynamic_var_write_setup,
      ngx_live_dynamic_var_read_setup },

    /*
     * persist data:
     *   ngx_str_t  key;
     *   ngx_str_t  value;
     */
    { NGX_KSMP_BLOCK_DYNAMIC_VAR, NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL, 0,
      ngx_live_dynamic_var_serve_write, NULL },

    ngx_null_persist_block
};


static ngx_int_t
ngx_live_dynamic_var_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_variable_add_multi(cf, ngx_live_dynamic_var_vars) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_live_persist_add_blocks(cf, ngx_live_dynamic_var_blocks)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_json_cmds_add_multi(cf, ngx_live_dynamic_var_dyn_cmds,
        NGX_LIVE_JSON_CTX_CHANNEL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* required for supporting dynamic vars as part of the persist path */
    if (ngx_live_json_cmds_add_multi(cf, ngx_live_dynamic_var_dyn_cmds,
        NGX_LIVE_JSON_CTX_PRE_CHANNEL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_live_channel_event_t    ngx_live_dynamic_var_channel_events[] = {
    { ngx_live_dynamic_var_channel_init, NGX_LIVE_EVENT_CHANNEL_INIT },
      ngx_live_null_event
};

static ngx_live_json_writer_def_t  ngx_live_dynamic_var_json_writers[] = {
    { { ngx_live_dynamic_var_channel_json_get_size,
        ngx_live_dynamic_var_channel_json_write },
      NGX_LIVE_JSON_CTX_CHANNEL },

      ngx_live_null_json_writer
};

static ngx_int_t
ngx_live_dynamic_var_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf,
        ngx_live_dynamic_var_channel_events) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_core_json_writers_add(cf,
        ngx_live_dynamic_var_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_live_dynamic_var_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_dynamic_var_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_dynamic_var_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_live_dynamic_var_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_live_dynamic_var_preset_conf_t  *prev = parent;
    ngx_live_dynamic_var_preset_conf_t  *conf = child;

    ngx_conf_merge_size_value(conf->max_size,
                              prev->max_size, 128);

    if (ngx_live_core_add_block_pool_index(cf, &conf->bp_idx[NGX_LIVE_BP_VAR],
        sizeof(ngx_live_dynamic_var_t) + conf->max_size) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
