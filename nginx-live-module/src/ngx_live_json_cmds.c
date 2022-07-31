#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


ngx_int_t
ngx_live_json_cmds_prepare(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t  *cmcf;
    ngx_live_json_cmds_conf_t  *cur;
    ngx_live_json_cmds_conf_t  *last;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cur = cmcf->json_cmds;
    last = cur + NGX_LIVE_JSON_CTX_MAX;
    for (; cur < last; cur++) {

        cur->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (cur->keys == NULL) {
            return NGX_ERROR;
        }

        cur->keys->pool = cf->pool;
        cur->keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(cur->keys, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_array_init(&cur->post, cf->pool, 1,
                           sizeof(ngx_live_json_cmd_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_live_json_cmd_t *
ngx_live_json_cmds_add(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t ctx)
{
    ngx_int_t                   rc;
    ngx_live_json_cmd_t        *v;
    ngx_hash_keys_arrays_t     *keys;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    if (name->len == 0) {
        v = ngx_array_push(&cmcf->json_cmds[ctx].post);
        if (v == NULL) {
            return NULL;
        }

        ngx_memzero(v, sizeof(*v));
        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_live_json_cmd_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->type = 0;

    keys = cmcf->json_cmds[ctx].keys;
    rc = ngx_hash_add_key(keys, &v->name, v, 0);
    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ngx_live_json_cmds_add: conflicting name \"%V\"", name);
        return NULL;
    }

    return v;
}


ngx_int_t
ngx_live_json_cmds_add_multi(ngx_conf_t *cf, ngx_live_json_cmd_t *cmds,
    ngx_uint_t ctx)
{
    ngx_live_json_cmd_t  *cmd, *c;

    for (c = cmds; c->set_handler; c++) {
        cmd = ngx_live_json_cmds_add(cf, &c->name, ctx);
        if (cmd == NULL) {
            return NGX_ERROR;
        }

        cmd->set_handler = c->set_handler;
        cmd->type = c->type;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_json_cmds_init(ngx_conf_t *cf)
{
    ngx_hash_init_t             hash;
    ngx_live_core_main_conf_t  *cmcf;
    ngx_live_json_cmds_conf_t  *cur;
    ngx_live_json_cmds_conf_t  *last;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cur = cmcf->json_cmds;
    last = cur + NGX_LIVE_JSON_CTX_MAX;
    for (; cur < last; cur++) {

        hash.hash = &cur->hash;
        hash.key = ngx_hash_key;
        hash.max_size = 512;
        hash.bucket_size = ngx_align(64, ngx_cacheline_size);
        hash.name = "live_json_cmds_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, cur->keys->keys.elts, cur->keys->keys.nelts)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        cur->keys = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_json_cmds_post(ngx_live_channel_t *channel,
    ngx_live_json_cmds_ctx_t *jctx)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i, n;
    ngx_array_t                *post;
    ngx_live_json_cmd_t        *cmd, *cmds;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);

    post = &cmcf->json_cmds[jctx->ctx].post;
    n = post->nelts;
    cmds = post->elts;

    for (i = 0; i < n; i++) {

        cmd = &cmds[i];
        rc = cmd->set_handler(jctx, cmd, NULL);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_AGAIN:
            return NGX_AGAIN;

        default:
            ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
                "ngx_live_json_cmds_post: post handler failed %i", rc);
            return rc;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_json_cmds_exec(ngx_live_channel_t *channel,
    ngx_live_json_cmds_ctx_t *jctx, ngx_json_object_t *json)
{
    ngx_int_t                   rc;
    ngx_flag_t                  changed;
    ngx_hash_t                 *hash;
    ngx_live_json_cmd_t        *cmd;
    ngx_json_key_value_t       *cur;
    ngx_json_key_value_t       *last;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);

    changed = 0;
    hash = &cmcf->json_cmds[jctx->ctx].hash;

    cur = json->elts;
    last = cur + json->nelts;
    for (; cur < last; cur++) {

        cmd = ngx_hash_find(hash, cur->key_hash, cur->key.data, cur->key.len);
        if (cmd == NULL) {
            continue;
        }

        if (!(cmd->type & cur->value.type)) {
            continue;
        }

        rc = cmd->set_handler(jctx, cmd, &cur->value);
        switch (rc) {

        case NGX_OK:
            break;

        case NGX_AGAIN:
            return NGX_AGAIN;

        default:
            ngx_log_error(NGX_LOG_NOTICE, jctx->pool->log, 0,
                "ngx_live_json_cmds_exec: handler failed %i, key: %V",
                rc, &cur->key);
            return rc;
        }

        changed = 1;
    }

    if (changed) {
        ngx_live_channel_setup_changed(channel);
    }

    return ngx_live_json_cmds_post(channel, jctx);
}
