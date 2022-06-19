#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


#define NGX_LIVE_CORE_STR_BLOCK_SIZE  (128)


static char *ngx_live_core_preset(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);

static char *ngx_live_block_sizes_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_live_core_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_live_core_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_live_core_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_live_core_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_core_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_live_core_set_mem_limit(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value);


typedef struct {
    size_t       size;
    ngx_uint_t  *index;
} ngx_live_core_block_size_t;


static ngx_conf_num_bounds_t  ngx_live_core_percent_bounds = {
    ngx_conf_check_num_bounds, 0, 100
};


static ngx_command_t  ngx_live_core_commands[] = {

    { ngx_string("variables_hash_max_size"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_MAIN_CONF_OFFSET,
      offsetof(ngx_live_core_main_conf_t, variables_hash_max_size),
      NULL },

    { ngx_string("variables_hash_bucket_size"),
      NGX_LIVE_MAIN_CONF |NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_MAIN_CONF_OFFSET,
      offsetof(ngx_live_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { ngx_string("preset_names_hash_max_size"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_MAIN_CONF_OFFSET,
      offsetof(ngx_live_core_main_conf_t, preset_names_hash_max_size),
      NULL },

    { ngx_string("preset_names_hash_bucket_size"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_MAIN_CONF_OFFSET,
      offsetof(ngx_live_core_main_conf_t, preset_names_hash_bucket_size),
      NULL },

    { ngx_string("preset"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_live_core_preset,
      0,
      0,
      NULL },

    { ngx_string("mem_limit"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, mem_limit),
      NULL },

    { ngx_string("mem_high_watermark"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, mem_high_watermark),
      &ngx_live_core_percent_bounds },

    { ngx_string("mem_low_watermark"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, mem_low_watermark),
      &ngx_live_core_percent_bounds },

    { ngx_string("mem_block_sizes"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_1MORE,
      ngx_live_block_sizes_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, mem_conf_blocks),
      NULL },

    { ngx_string("timescale"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, timescale),
      NULL },

    { ngx_string("segment_duration"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, segment_duration),
      NULL },

    { ngx_string("part_duration"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_core_preset_conf_t, part_duration),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_core_module_ctx = {
    ngx_live_core_preconfiguration,           /* preconfiguration */
    ngx_live_core_postconfiguration,          /* postconfiguration */

    ngx_live_core_create_main_conf,           /* create main configuration */
    ngx_live_core_init_main_conf,             /* init main configuration */

    ngx_live_core_create_preset_conf,         /* create preset configuration */
    ngx_live_core_merge_preset_conf           /* merge preset configuration */
};


ngx_module_t  ngx_live_core_module = {
    NGX_MODULE_V1,
    &ngx_live_core_module_ctx,                /* module context */
    ngx_live_core_commands,                   /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    ngx_live_channel_init_process,            /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_live_json_cmd_t  ngx_live_core_dyn_cmds[] = {

    { ngx_string("mem_limit"), NGX_JSON_INT, ngx_live_core_set_mem_limit },

      ngx_live_null_json_cmd
};


/* must match NGX_LIVE_CORE_BP_XXX in order */
static size_t  ngx_live_core_block_sizes[NGX_LIVE_CORE_BP_COUNT] = {
    0,      /* dynamic */
    sizeof(ngx_live_variant_t),
    sizeof(ngx_buf_chain_t),
    NGX_LIVE_CORE_STR_BLOCK_SIZE
};


static size_t  ngx_live_core_default_block_sizes[] = {
    ngx_block_pool_auto(64),
    ngx_block_pool_auto(128),
    ngx_block_pool_auto(640),
    ngx_block_pool_auto(2240),
};


static char *
ngx_live_block_sizes_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    size_t             size;
    size_t            *sizep;
    ngx_str_t         *value;
    ngx_uint_t         i;
    ngx_array_t      **sizes;
    ngx_conf_post_t   *post;

    sizes = (ngx_array_t **) (p + cmd->offset);

    if (*sizes == NULL) {
        *sizes = ngx_array_create(cf->pool, 5, sizeof(size_t));
        if (*sizes == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        size = ngx_parse_size(&value[i]);
        if (size == (size_t) NGX_ERROR) {
            return "invalid value";
        }

        sizep = ngx_array_push(*sizes);
        if (sizep == NULL) {
            return NGX_CONF_ERROR;
        }

        *sizep = ngx_block_pool_auto(size);
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sizes);
    }

    return NGX_CONF_OK;
}

static char *
ngx_live_core_preset(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                         *rv;
    void                         *mconf;
    ngx_str_t                    *value;
    ngx_uint_t                    i;
    ngx_conf_t                    pcf;
    ngx_live_module_t            *module;
    ngx_live_conf_ctx_t          *ctx, *live_ctx;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_core_preset_conf_t  *cpcf, **cpcfp;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_live_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    live_ctx = cf->ctx;
    ctx->main_conf = live_ctx->main_conf;

    /* the preset{}'s preset_conf */

    ctx->preset_conf = ngx_pcalloc(cf->pool,
                                   sizeof(void *) * ngx_live_max_module);
    if (ctx->preset_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_LIVE_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_preset_conf) {
            mconf = module->create_preset_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->preset_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }


    /* the preset configuration context */

    value = cf->args->elts;

    cpcf = ngx_live_get_module_preset_conf(ctx, ngx_live_core_module);
    cpcf->ctx = ctx;
    cpcf->name.s = value[1];
    ngx_json_str_set_escape(&cpcf->name);


    cmcf = ngx_live_get_module_main_conf(ctx, ngx_live_core_module);

    cpcfp = ngx_array_push(&cmcf->presets);
    if (cpcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cpcfp = cpcf;


    /* parse inside preset{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_LIVE_PRESET_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}

static void *
ngx_live_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_live_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->presets, cf->pool, 4,
        sizeof(ngx_live_core_preset_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

    cmcf->preset_names_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->preset_names_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}

static char *
ngx_live_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_live_core_main_conf_t  *cmcf = conf;

    ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
        ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    ngx_conf_init_uint_value(cmcf->preset_names_hash_max_size, 512);
    ngx_conf_init_uint_value(cmcf->preset_names_hash_bucket_size,
        ngx_cacheline_size);

    cmcf->preset_names_hash_bucket_size =
        ngx_align(cmcf->preset_names_hash_bucket_size, ngx_cacheline_size);

    return NGX_CONF_OK;
}


ngx_int_t
ngx_live_core_reserve_track_ctx_size(ngx_conf_t *cf, ngx_uint_t index,
    size_t size)
{
    ngx_live_core_ctx_offset_t   *elt;
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_core_module);

    elt = ngx_array_push(&cpcf->track_ctx_offset);
    if (elt == NULL) {
        return NGX_ERROR;
    }

    elt->index = index;
    elt->offset = cpcf->track_ctx_size;

    cpcf->track_ctx_size += size;

    return NGX_OK;
}


ngx_int_t
ngx_live_core_add_block_pool_index(ngx_conf_t *cf, ngx_uint_t *index,
    size_t size)
{
    ngx_live_core_block_size_t   *bs;
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_conf_get_module_preset_conf(cf, ngx_live_core_module);

    bs = ngx_array_push(cpcf->mem_temp_blocks);
    if (bs == NULL) {
        return NGX_ERROR;
    }

    bs->size = size;
    bs->index = index;

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_live_core_compare_block_sizes(const void *one, const void *two)
{
    ngx_live_core_block_size_t  *first, *second;

    first = (ngx_live_core_block_size_t *) one;
    second = (ngx_live_core_block_size_t *) two;

    return (int) first->size - (int) second->size;
}


ngx_int_t
ngx_live_core_prepare_preset(ngx_conf_t *cf, ngx_live_core_preset_conf_t *cpcf)
{
    size_t                      *size;
    size_t                      *elts;
    ngx_uint_t                   i, n;
    ngx_live_core_block_size_t  *bs;

    /* add core blocks */
    bs = ngx_array_push_n(cpcf->mem_temp_blocks, NGX_LIVE_CORE_BP_COUNT);
    if (bs == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < NGX_LIVE_CORE_BP_COUNT; i++) {
        bs[i].size = ngx_live_core_block_sizes[i];
        bs[i].index = &cpcf->bp_idx[i];
    }

    bs[NGX_LIVE_CORE_BP_TRACK].size = cpcf->track_ctx_size;

    /* add conf blocks */
    if (cpcf->mem_conf_blocks != NULL) {
        elts = cpcf->mem_conf_blocks->elts;
        n = cpcf->mem_conf_blocks->nelts;

    } else {
        elts = ngx_live_core_default_block_sizes;
        n = sizeof(ngx_live_core_default_block_sizes) /
            sizeof(ngx_live_core_default_block_sizes[0]);
    }

    bs = ngx_array_push_n(cpcf->mem_temp_blocks, n);
    if (bs == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        bs[i].size = elts[i];
        bs[i].index = NULL;
    }

    /* sort and compact the block list */
    bs = cpcf->mem_temp_blocks->elts;
    n = cpcf->mem_temp_blocks->nelts;

    ngx_qsort(bs, n, sizeof(ngx_live_core_block_size_t),
        ngx_live_core_compare_block_sizes);

    if (ngx_array_init(&cpcf->mem_blocks, cf->pool, n, sizeof(size_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {

        if (i == 0 || bs[i].size != bs[i - 1].size) {
            size = ngx_array_push(&cpcf->mem_blocks);
            if (size == NULL) {
                return NGX_ERROR;
            }

            *size = bs[i].size;
        }

        if (bs[i].index != NULL) {
            *bs[i].index = cpcf->mem_blocks.nelts - 1;
        }
    }

    cpcf->mem_temp_blocks = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_live_core_channel_read(ngx_live_channel_t *channel, void *ectx)
{
    ngx_live_variants_update_active(channel);

    return NGX_OK;
}

static void *
ngx_live_core_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_core_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_core_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mem_limit = NGX_CONF_UNSET_SIZE;
    conf->mem_high_watermark = NGX_CONF_UNSET_UINT;
    conf->mem_low_watermark = NGX_CONF_UNSET_UINT;
    conf->timescale = NGX_CONF_UNSET_UINT;
    conf->segment_duration = NGX_CONF_UNSET_MSEC;
    conf->part_duration = NGX_CONF_UNSET_MSEC;

    conf->mem_temp_blocks = ngx_array_create(cf->temp_pool, 10,
        sizeof(ngx_live_core_block_size_t));
    if (conf->mem_temp_blocks == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->track_ctx_offset, cf->pool, 8,
                       sizeof(ngx_live_core_ctx_offset_t))
        != NGX_OK)
    {
        return NULL;
    }

    conf->track_ctx_size = sizeof(ngx_live_track_t) +
        sizeof(void *) * ngx_live_max_module;

    return conf;
}


static char *
ngx_live_core_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_core_preset_conf_t  *prev = parent;
    ngx_live_core_preset_conf_t  *conf = child;

    if (!conf->segmenter.id) {
        conf->segmenter = prev->segmenter;
    }

    ngx_conf_merge_size_value(conf->mem_limit,
                              prev->mem_limit, 64 * 1024 * 1024);

    ngx_conf_merge_uint_value(conf->mem_high_watermark,
                              prev->mem_high_watermark, 75);

    ngx_conf_merge_uint_value(conf->mem_low_watermark,
                              prev->mem_low_watermark, 50);

    ngx_conf_merge_uint_value(conf->timescale,
                              prev->timescale, 90000);

    ngx_conf_merge_msec_value(conf->segment_duration,
                              prev->segment_duration, 6000);

    ngx_conf_merge_msec_value(conf->part_duration,
                              prev->part_duration, 1000);

    if (conf->mem_conf_blocks == NULL) {
        conf->mem_conf_blocks = prev->mem_conf_blocks;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_live_core_preconfiguration(ngx_conf_t *cf)
{
    ngx_array_t                *cur;
    ngx_array_t                *last;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    if (ngx_live_variables_add_core_vars(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cur = cmcf->json_writers;
    last = cur + NGX_LIVE_JSON_CTX_MAX;
    for (; cur < last; cur++) {
        if (ngx_array_init(cur, cf->pool, 1, sizeof(ngx_live_json_writer_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_array_init(&cmcf->lba_array, cf->temp_pool, 1, sizeof(void *))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_json_cmds_prepare(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_live_json_cmds_add_multi(cf, ngx_live_core_dyn_cmds,
        NGX_LIVE_JSON_CTX_CHANNEL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_live_channel_event_t  ngx_live_core_channel_events[] = {
    { ngx_live_core_channel_read, NGX_LIVE_EVENT_CHANNEL_READ },

      ngx_live_null_event
};

static ngx_int_t
ngx_live_core_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_channel_events_add(cf, ngx_live_core_channel_events)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_live_core_main_conf_t *
ngx_live_core_get_main_conf(ngx_cycle_t *cycle)
{
    ngx_live_conf_ctx_t *live_conf;

    live_conf = (ngx_live_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx,
        ngx_live_module);
    if (live_conf == NULL) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
            "ngx_live_core_get_main_conf: no live conf");
        return NULL;
    }

    return ngx_live_get_module_main_conf(live_conf, ngx_live_core_module);
}

ngx_live_conf_ctx_t *
ngx_live_core_get_preset_conf(ngx_cycle_t *cycle, ngx_str_t *preset_name)
{
    ngx_uint_t                    key;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_core_preset_conf_t  *cpcf;

    cmcf = ngx_live_core_get_main_conf(cycle);
    if (cmcf == NULL) {
        return NULL;
    }

    key = ngx_hash_key_lc(preset_name->data, preset_name->len);

    cpcf = ngx_hash_find(&cmcf->presets_hash, key, preset_name->data,
        preset_name->len);
    if (cpcf == NULL) {
        return NULL;
    }

    return cpcf->ctx;
}


static ngx_int_t
ngx_live_core_set_mem_limit(ngx_live_json_cmds_ctx_t *jctx,
    ngx_live_json_cmd_t *cmd, ngx_json_value_t *value)
{
    size_t               mem_limit;
    ngx_live_channel_t  *channel = jctx->obj;

    mem_limit = value->v.num.num;

    if (mem_limit >= channel->mem_limit) {
        channel->mem_left += mem_limit - channel->mem_limit;

    } else if (mem_limit >= channel->mem_limit - channel->mem_left) {
        channel->mem_left -= channel->mem_limit - mem_limit;

    } else {
        ngx_log_error(NGX_LOG_ERR, jctx->pool->log, 0,
            "ngx_live_core_set_mem_limit: "
            "new limit lower than used mem, new: %uz, old: %uz, left: %uz",
            mem_limit, channel->mem_limit, channel->mem_left);
        return NGX_ERROR;
    }

    channel->mem_limit = mem_limit;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_core_set_mem_limit: set to %uz", mem_limit);

    return NGX_OK;
}


void
ngx_live_core_channel_init(ngx_live_channel_t *channel)
{
    ngx_live_core_preset_conf_t  *cpcf;

    cpcf = ngx_live_get_module_preset_conf(channel, ngx_live_core_module);

    channel->mem_limit = cpcf->mem_limit;
    channel->mem_left = channel->mem_limit;
    channel->mem_high_watermark = (100 - cpcf->mem_high_watermark) *
        cpcf->mem_limit / 100;
    channel->mem_low_watermark = (100 - cpcf->mem_low_watermark) *
        cpcf->mem_limit / 100;

    channel->timescale = cpcf->timescale;

    channel->conf.segment_duration = cpcf->segment_duration;
    channel->segment_duration = ngx_live_rescale_time(
        channel->conf.segment_duration, 1000, channel->timescale);

    if (cpcf->segmenter.flags & NGX_LIVE_SEGMENTER_FLAG_PARTS_CAP) {
        channel->part_duration = ngx_live_rescale_time(cpcf->part_duration,
            1000, channel->timescale);
    }
}

ngx_int_t
ngx_live_core_channel_event(ngx_live_channel_t *channel, ngx_uint_t event,
    void *ectx)
{
    ngx_int_t                     rc;
    ngx_uint_t                    i, n;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_channel_handler_pt  *handler;

    cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);

    handler = cmcf->events[event].elts;
    n = cmcf->events[event].nelts;

    ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
        "ngx_live_core_channel_event: event %ui started, ctx: %p",
        event, ectx);

    for (i = 0; i < n; i++) {
        rc = handler[i](channel, ectx);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
                "ngx_live_core_channel_event: event %ui, handler %ui failed",
                event, i);
            return rc;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, &channel->log, 0,
        "ngx_live_core_channel_event: event %ui done", event);

    return NGX_OK;
}

ngx_int_t
ngx_live_core_track_event(ngx_live_track_t *track, ngx_uint_t event,
    void *ectx)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, n;
    ngx_live_track_handler_pt  *handler;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(track->channel, ngx_live_core_module);

    handler = cmcf->events[event].elts;
    n = cmcf->events[event].nelts;

    ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_core_track_event: event %ui started, ctx: %p", event, ectx);

    for (i = 0; i < n; i++) {

        rc = handler[i](track, ectx);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, &track->log, 0,
                "ngx_live_core_track_event: event %ui, handler %ui failed",
                event, i);
            return rc;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, &track->log, 0,
        "ngx_live_core_track_event: event %ui done", event);

    return NGX_OK;
}

ngx_lba_t *
ngx_live_core_get_lba(ngx_conf_t *cf, size_t buffer_size, ngx_uint_t bin_count)
{
    ngx_lba_t                  *lba, **plba;
    ngx_uint_t                  i;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    plba = cmcf->lba_array.elts;
    for (i = 0; i < cmcf->lba_array.nelts; i++) {
        lba = plba[i];
        if (ngx_lba_match(lba, buffer_size, bin_count)) {
            return lba;
        }
    }

    lba = ngx_lba_create(cf->pool, buffer_size, bin_count);
    if (lba == NULL) {
        return NULL;
    }

    plba = ngx_array_push(&cmcf->lba_array);
    if (plba == NULL) {
        return NULL;
    }

    *plba = lba;

    return lba;
}

ngx_int_t
ngx_live_core_channel_events_add(ngx_conf_t *cf,
    ngx_live_channel_event_t *events)
{
    ngx_live_channel_event_t     *cur;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_channel_handler_pt  *ch;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    for (cur = events; cur->handler != NULL; cur++) {

        ch = ngx_array_push(&cmcf->events[cur->event]);
        if (ch == NULL) {
            return NGX_ERROR;
        }

        *ch = cur->handler;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_core_track_events_add(ngx_conf_t *cf,
    ngx_live_track_event_t *events)
{
    ngx_live_track_event_t     *cur;
    ngx_live_core_main_conf_t  *cmcf;
    ngx_live_track_handler_pt  *th;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    for (cur = events; cur->handler != NULL; cur++) {

        th = ngx_array_push(&cmcf->events[cur->event]);
        if (th == NULL) {
            return NGX_ERROR;
        }

        *th = cur->handler;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_core_json_writers_add(ngx_conf_t *cf,
    ngx_live_json_writer_def_t *writers)
{
    ngx_live_json_writer_t      *writer;
    ngx_live_core_main_conf_t   *cmcf;
    ngx_live_json_writer_def_t  *cur;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    for (cur = writers; cur->writer.get_size != NULL; cur++) {

        writer = ngx_array_push(&cmcf->json_writers[cur->ctx]);
        if (writer == NULL) {
            return NGX_ERROR;
        }

        *writer = cur->writer;
    }

    return NGX_OK;
}

size_t
ngx_live_core_json_get_size(void *obj, ngx_live_channel_t *channel,
    ngx_uint_t ctx)
{
    size_t                      result = 0;
    ngx_uint_t                  i, n;
    ngx_live_json_writer_t     *elts;
    ngx_live_core_main_conf_t  *cmcf;

    if (channel == NULL) {
        cmcf = ngx_live_core_get_main_conf((ngx_cycle_t *) ngx_cycle);

    } else {
        cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);
    }

    elts = cmcf->json_writers[ctx].elts;
    n = cmcf->json_writers[ctx].nelts;

    for (i = 0; i < n; i++) {
        result += elts[i].get_size(obj) + sizeof(",") - 1;
    }

    return result;
}

u_char *
ngx_live_core_json_write(u_char *p, void *obj, ngx_live_channel_t *channel,
    ngx_uint_t ctx)
{
    u_char                     *first = p;
    u_char                     *next;
    ngx_uint_t                  i, n;
    ngx_live_json_writer_t     *elts;
    ngx_live_core_main_conf_t  *cmcf;

    if (channel == NULL) {
        cmcf = ngx_live_core_get_main_conf((ngx_cycle_t *) ngx_cycle);

    } else {
        cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);
    }

    elts = cmcf->json_writers[ctx].elts;
    n = cmcf->json_writers[ctx].nelts;

    for (i = 0; i < n; i++) {

        if (p != first) {
            *p++ = ',';
        }

        next = elts[i].write(p, obj);

        /* revert the comma if didn't write anything */
        p = p != first && next == p ? p - 1 : next;
    }

    return p;
}
