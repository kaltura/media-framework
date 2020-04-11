#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


enum {
    NGX_LIVE_BP_VAR,

    NGX_LIVE_BP_COUNT
};


typedef struct {
    size_t                  max_size;
} ngx_live_dynamic_var_preset_conf_t;


typedef struct {
    ngx_str_node_t          sn;        /* must be first */
    ngx_queue_t             queue;
    ngx_str_t               value;
} ngx_live_dynamic_var_t;


typedef struct {
    ngx_block_pool_t       *block_pool;

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

static ngx_int_t ngx_live_dynamic_var_get(ngx_live_channel_t *ch,
    ngx_pool_t *pool, ngx_live_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_live_dynamic_var_set_vars(void *ctx,
    ngx_live_json_command_t *cmd, ngx_json_value_t *value, ngx_log_t *log);


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

static ngx_live_json_command_t  ngx_live_dynamic_var_dyn_cmds[] = {

    { ngx_string("vars"), NGX_JSON_OBJECT,
      ngx_live_dynamic_var_set_vars },

      ngx_live_null_json_command
};


static ngx_int_t
ngx_live_dynamic_var_set_vars(void *ctx, ngx_live_json_command_t *cmd,
    ngx_json_value_t *value, ngx_log_t *log)
{
    uint32_t                             hash;
    ngx_queue_t                         *q, *next;
    ngx_queue_t                          new_vars;
    ngx_json_object_t                   *obj = &value->v.obj;
    ngx_live_channel_t                  *channel = ctx;
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
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "invalid value type for key \"%V\"", &cur->key);
            goto failed;
        }

        if (cur->key.len + cur->value.v.str.len > dpcf->max_size) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "key \"%V\" exceeds max size", &cur->key);
            goto failed;
        }

        var = ngx_block_pool_alloc(cctx->block_pool, NGX_LIVE_BP_VAR);
        if (var == NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_dynamic_var_set_vars: alloc failed");
            goto failed;
        }

        ngx_queue_insert_tail(&new_vars, &var->queue);

        var->sn.str.data = (void *) (var + 1);
        var->sn.str.len = 0;

        if (ngx_json_decode_string(&var->sn.str, &cur->key) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "failed to decode key \"%V\"", &cur->key);
            goto failed;
        }

        var->value.data = var->sn.str.data + var->sn.str.len;
        var->value.len = 0;

        if (ngx_json_decode_string(&var->value, &cur->value.v.str) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "ngx_live_dynamic_var_set_vars: "
                "failed to decode the value of key \"%V\"", &cur->key);
            goto failed;
        }
    }

    /* remove existing vars */
    q = ngx_queue_head(&cctx->queue);
    while (q != ngx_queue_sentinel(&cctx->queue)) {

        var = ngx_queue_data(q, ngx_live_dynamic_var_t, queue);

        q = ngx_queue_next(q);      /* move to next before freeing */

        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_VAR, var);
    }

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel,
        ngx_str_rbtree_insert_value);
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

        ngx_block_pool_free(cctx->block_pool, NGX_LIVE_BP_VAR, var);
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_live_dynamic_var_get(ngx_live_channel_t *ch, ngx_pool_t *pool,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    uint32_t                             hash;
    ngx_str_t                            name = *(ngx_str_t *) data;
    ngx_live_dynamic_var_t              *var;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_live_get_module_ctx(ch, ngx_live_dynamic_var_module);

    name.data += sizeof("var_") - 1;
    name.len -= sizeof("var_") - 1;

    hash = ngx_crc32_short(name.data, name.len);
    var = (ngx_live_dynamic_var_t *) ngx_str_rbtree_lookup(&cctx->rbtree,
        &name, hash);
    if (var == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = var->value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = var->value.data;

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
    size_t                               block_sizes[NGX_LIVE_BP_COUNT];
    ngx_live_dynamic_var_preset_conf_t  *dpcf;
    ngx_live_dynamic_var_channel_ctx_t  *cctx;

    cctx = ngx_pcalloc(channel->pool, sizeof(*cctx));
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dynamic_var_channel_init: alloc failed");
        return NGX_ERROR;
    }

    ngx_live_set_ctx(channel, cctx, ngx_live_dynamic_var_module);

    dpcf = ngx_live_get_module_preset_conf(channel,
        ngx_live_dynamic_var_module);

    block_sizes[NGX_LIVE_BP_VAR] = sizeof(ngx_live_dynamic_var_t) +
        dpcf->max_size;

    cctx->block_pool = ngx_live_channel_create_block_pool(channel, block_sizes,
        NGX_LIVE_BP_COUNT);
    if (cctx->block_pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_dynamic_var_channel_init: create block pool failed");
        return NGX_ERROR;
    }

    ngx_rbtree_init(&cctx->rbtree, &cctx->sentinel,
        ngx_str_rbtree_insert_value);
    ngx_queue_init(&cctx->queue);

    return NGX_OK;
}

static ngx_int_t
ngx_live_dynamic_var_preconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_variable_add_multi(cf, ngx_live_dynamic_var_vars) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_live_json_commands_add_multi(cf, ngx_live_dynamic_var_dyn_cmds,
        NGX_LIVE_JSON_CTX_CHANNEL) != NGX_OK)
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
        ngx_live_dynamic_var_channel_json_write},
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

    return NGX_CONF_OK;
}
