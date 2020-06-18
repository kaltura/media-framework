#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


static char *ngx_live_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_uint_t  ngx_live_max_module;


static ngx_command_t  ngx_live_commands[] = {

    { ngx_string("live"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_live_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_live_module_ctx = {
    ngx_string("live"),
    NULL,
    NULL
};


ngx_module_t  ngx_live_module = {
    NGX_MODULE_V1,
    &ngx_live_module_ctx,                  /* module context */
    ngx_live_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t  argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7
};


static ngx_int_t
ngx_live_preset_names(ngx_conf_t *cf, ngx_live_core_main_conf_t *cmcf)
{
    ngx_int_t                   rc;
    ngx_uint_t                  s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_live_core_preset_conf_t  **cscfp;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    cscfp = cmcf->presets.elts;

    for (s = 0; s < cmcf->presets.nelts; s++) {

        rc = ngx_hash_add_key(&ha, &cscfp[s]->name, cscfp[s], 0);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_BUSY) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                "conflicting preset name \"%V\", ignored",
                &cscfp[s]->name);
        }
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->preset_names_hash_max_size;
    hash.bucket_size = cmcf->preset_names_hash_bucket_size;
    hash.name = "preset_names_hash";
    hash.pool = cf->pool;
    hash.hash = &cmcf->presets_hash;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
        goto failed;
    }

    ngx_destroy_pool(ha.temp_pool);

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}

static char *
ngx_live_merge_presets(ngx_conf_t *cf, ngx_live_core_main_conf_t *cmcf,
    ngx_live_module_t *module, ngx_uint_t ctx_index)
{
    char                          *rv;
    ngx_uint_t                     s;
    ngx_live_conf_ctx_t           *ctx, saved;
    ngx_live_core_preset_conf_t  **cscfp;

    cscfp = cmcf->presets.elts;
    ctx = (ngx_live_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = NGX_CONF_OK;

    for (s = 0; s < cmcf->presets.nelts; s++) {

        /* merge the preset{}s' preset_conf's */

        ctx->preset_conf = cscfp[s]->ctx->preset_conf;

        if (module->merge_preset_conf) {
            rv = module->merge_preset_conf(cf, saved.preset_conf[ctx_index],
                cscfp[s]->ctx->preset_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}

static ngx_int_t
ngx_live_init_events(ngx_conf_t *cf, ngx_live_core_main_conf_t *cmcf)
{
    ngx_uint_t  n;

    for (n = 0; n < NGX_LIVE_EVENT_MAX; n++) {

        if (ngx_array_init(&cmcf->events[n], cf->pool, 1, sizeof(void *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static char *
ngx_live_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   mi, m;
    ngx_conf_t                   pcf;
    ngx_live_module_t           *module;
    ngx_live_conf_ctx_t         *ctx;
    ngx_live_core_main_conf_t   *cmcf;

    if (*(ngx_live_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main live context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_live_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_live_conf_ctx_t **) conf = ctx;


    /* count the number of the live modules and set up their indices */

    ngx_live_max_module = ngx_count_modules(cf->cycle, NGX_LIVE_MODULE);


    /* the live main_conf context, it is the same in the all live contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_live_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the live null loc_conf context, it is used to merge
     * the preset{}s' preset_conf's
     */

    ctx->preset_conf = ngx_pcalloc(cf->pool, sizeof(void *) *
        ngx_live_max_module);
    if (ctx->preset_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all live modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_LIVE_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_preset_conf) {
            ctx->preset_conf[mi] = module->create_preset_conf(cf);
            if (ctx->preset_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_LIVE_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the live{} block */

    cf->module_type = NGX_LIVE_MODULE;
    cf->cmd_type = NGX_LIVE_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    /*
     * init live{} main_conf's, merge the preset{}s' preset_conf's
     */

    cmcf = ngx_live_get_module_main_conf(ctx, ngx_live_core_module);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_LIVE_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init live{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        rv = ngx_live_merge_presets(cf, cmcf, module, mi);
        if (rv != NGX_CONF_OK) {
            goto failed;
        }
    }

    if (ngx_live_init_events(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_LIVE_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_live_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_json_commands_init(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * live{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    *cf = pcf;

    if (ngx_live_preset_names(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}

/* copied from ngx_conf_handler, removed support for modules */
char *
ngx_live_block_command_handler(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf)
{
    ngx_live_block_conf_ctx_t  *ctx;
    ngx_command_t              *cmd;
    ngx_str_t                  *name;
    char                       *rv;

    ctx = cf->ctx;
    cmd = ctx->cmds;

    name = cf->args->elts;

    for ( /* void */; cmd->name.len; cmd++) {

        if (name->len != cmd->name.len) {
            continue;
        }

        if (ngx_strcmp(name->data, cmd->name.data) != 0) {
            continue;
        }

        /* is the directive's argument count right ? */

        if (!(cmd->type & NGX_CONF_ANY)) {

            if (cmd->type & NGX_CONF_FLAG) {

                if (cf->args->nelts != 2) {
                    goto invalid;
                }

            } else if (cmd->type & NGX_CONF_1MORE) {

                if (cf->args->nelts < 2) {
                    goto invalid;
                }

            } else if (cmd->type & NGX_CONF_2MORE) {

                if (cf->args->nelts < 3) {
                    goto invalid;
                }

            } else if (cf->args->nelts > NGX_CONF_MAX_ARGS) {

                goto invalid;

            } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
            {
                goto invalid;
            }
        }

        rv = cmd->set(ctx->cf, cmd, conf);

        if (rv == NGX_CONF_OK) {
            return NGX_CONF_OK;
        }

        if (rv == NGX_CONF_ERROR) {
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"%s\" directive %s", name->data, rv);

        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "unknown directive \"%s\"", name->data);

    return NGX_CONF_ERROR;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "invalid number of arguments in \"%s\" directive",
        name->data);

    return NGX_CONF_ERROR;
}
