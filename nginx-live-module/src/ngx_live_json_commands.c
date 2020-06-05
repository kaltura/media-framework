#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


ngx_int_t
ngx_live_json_commands_prepare(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t      *cmcf;
    ngx_live_json_commands_conf_t  *cur;
    ngx_live_json_commands_conf_t  *last;

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
    }

    return NGX_OK;
}

ngx_live_json_command_t *
ngx_live_json_commands_add(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t context)
{
    ngx_int_t                   rc;
    ngx_hash_keys_arrays_t     *keys;
    ngx_live_json_command_t    *v;
    ngx_live_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ngx_live_json_commands_add: empty name");
        return NULL;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_live_json_command_t));
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
    v->type = NGX_JSON_NULL;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);
    keys = cmcf->json_cmds[context].keys;
    rc = ngx_hash_add_key(keys, &v->name, v, 0);
    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "ngx_live_json_commands_add: conflicting name \"%V\"", name);
        return NULL;
    }

    return v;
}

ngx_int_t
ngx_live_json_commands_add_multi(ngx_conf_t *cf,
    ngx_live_json_command_t *cmds, ngx_uint_t context)
{
    ngx_live_json_command_t  *cmd, *c;

    for (c = cmds; c->name.len; c++) {
        cmd = ngx_live_json_commands_add(cf, &c->name, context);
        if (cmd == NULL) {
            return NGX_ERROR;
        }

        cmd->set_handler = c->set_handler;
        cmd->type = c->type;
    }

    return NGX_OK;
}

ngx_int_t
ngx_live_json_commands_init(ngx_conf_t *cf)
{
    ngx_hash_init_t                 hash;
    ngx_live_core_main_conf_t      *cmcf;
    ngx_live_json_commands_conf_t  *cur;
    ngx_live_json_commands_conf_t  *last;

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

ngx_int_t
ngx_live_json_commands_exec(ngx_live_channel_t *channel,
    ngx_uint_t ctx, void *obj, ngx_json_object_t *json, ngx_log_t *log)
{
    ngx_int_t                   rc;
    ngx_flag_t                  changed;
    ngx_hash_t                 *hash;
    ngx_json_key_value_t       *cur;
    ngx_json_key_value_t       *last;
    ngx_live_json_command_t    *cmd;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);

    changed = 0;
    hash = &cmcf->json_cmds[ctx].hash;

    cur = json->elts;
    last = cur + json->nelts;
    for (; cur < last; cur++) {

        cmd = ngx_hash_find(hash, cur->key_hash, cur->key.data, cur->key.len);
        if (cmd == NULL) {
            continue;
        }

        if (cmd->type != cur->value.type) {
            continue;
        }

        rc = cmd->set_handler(obj, cmd, &cur->value, log);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "ngx_live_json_commands_exec: handler failed %i", rc);
            return rc;
        }

        changed = 1;
    }

    if (changed) {
        ngx_live_channel_setup_changed(channel);
    }

    return NGX_OK;
}
