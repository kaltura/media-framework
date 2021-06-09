
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"
#include <nginx.h>

static ngx_live_variable_t *ngx_live_add_prefix_variable(ngx_conf_t *cf,
    ngx_str_t *name, ngx_uint_t flags);


static ngx_int_t ngx_live_variable_nginx_version(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_live_variable_hostname(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_live_variable_pid(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_live_variable_msec(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_live_variable_channel(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_live_variable_channel_uint32(
    ngx_live_variables_ctx_t *ctx, ngx_live_variable_value_t *v,
    uintptr_t data);


static ngx_live_variable_t  ngx_live_core_variables[] = {

    { ngx_string("nginx_version"), NULL, ngx_live_variable_nginx_version,
      0, 0, 0 },

    { ngx_string("hostname"), NULL, ngx_live_variable_hostname,
      0, 0, 0 },

    { ngx_string("pid"), NULL, ngx_live_variable_pid,
      0, 0, 0 },

    { ngx_string("msec"), NULL, ngx_live_variable_msec,
      0, NGX_LIVE_VAR_NOCACHEABLE, 0 },

    { ngx_string("channel_id"), NULL, ngx_live_variable_channel,
      offsetof(ngx_live_channel_t, sn.str), 0, 0 },

    { ngx_string("next_segment_index"), NULL, ngx_live_variable_channel_uint32,
      offsetof(ngx_live_channel_t, next_segment_index), 0, 0 },

      ngx_live_null_variable
};


ngx_live_variable_value_t  ngx_live_variable_null_value =
    ngx_live_variable("");
ngx_live_variable_value_t  ngx_live_variable_true_value =
    ngx_live_variable("1");


static ngx_uint_t  ngx_live_variable_depth = 100;


ngx_live_variable_t *
ngx_live_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_hash_key_t             *key;
    ngx_live_variable_t        *v;
    ngx_live_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & NGX_LIVE_VAR_PREFIX) {
        return ngx_live_add_prefix_variable(cf, name, flags);
    }

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NGX_LIVE_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NGX_LIVE_VAR_WEAK)) {
            v->flags &= ~NGX_LIVE_VAR_WEAK;
        }

        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_live_variable_t));
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
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


static ngx_live_variable_t *
ngx_live_add_prefix_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_uint_t                  i;
    ngx_live_variable_t        *v;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & NGX_LIVE_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & NGX_LIVE_VAR_WEAK)) {
            v->flags &= ~NGX_LIVE_VAR_WEAK;
        }

        return v;
    }

    v = ngx_array_push(&cmcf->prefix_variables);
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
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}

ngx_int_t
ngx_live_variable_add_multi(ngx_conf_t *cf, ngx_live_variable_t *vars)
{
    ngx_live_variable_t  *var, *v;

    for (v = vars; v->name.len; v++) {
        var = ngx_live_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        *var = *v;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_live_variable_t        *v;
    ngx_live_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NGX_ERROR;
    }

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_live_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


ngx_live_variable_value_t *
ngx_live_get_indexed_variable(ngx_live_variables_ctx_t *ctx, ngx_uint_t index)
{
    ngx_live_variable_t        *v;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(ctx->ch, ngx_live_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, &ctx->ch->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (ctx->variables[index].not_found || ctx->variables[index].valid) {
        return &ctx->variables[index];
    }

    v = cmcf->variables.elts;

    if (ngx_live_variable_depth == 0) {
        ngx_log_error(NGX_LOG_ERR, &ctx->ch->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    ngx_live_variable_depth--;

    if (v[index].get_handler(ctx, &ctx->variables[index], v[index].data)
        == NGX_OK)
    {
        ngx_live_variable_depth++;

        if (v[index].flags & NGX_LIVE_VAR_NOCACHEABLE) {
            ctx->variables[index].no_cacheable = 1;
        }

        return &ctx->variables[index];
    }

    ngx_live_variable_depth++;

    ctx->variables[index].valid = 0;
    ctx->variables[index].not_found = 1;

    return NULL;
}


ngx_live_variable_value_t *
ngx_live_get_flushed_variable(ngx_live_variables_ctx_t *ctx, ngx_uint_t index)
{
    ngx_live_variable_value_t  *v;

    v = &ctx->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_live_get_indexed_variable(ctx, index);
}


ngx_live_variable_value_t *
ngx_live_get_variable(ngx_live_variables_ctx_t *ctx, ngx_str_t *name,
    ngx_uint_t key)
{
    size_t                      len;
    ngx_uint_t                  i, n;
    ngx_live_variable_t        *v;
    ngx_live_variable_value_t  *vv;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(ctx->ch, ngx_live_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_LIVE_VAR_INDEXED) {
            return ngx_live_get_flushed_variable(ctx, v->index);
        }

        if (ngx_live_variable_depth == 0) {
            ngx_log_error(NGX_LOG_ERR, &ctx->ch->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        ngx_live_variable_depth--;

        vv = ngx_palloc(ctx->pool,
                        sizeof(ngx_live_variable_value_t));

        if (vv && v->get_handler(ctx, vv, v->data) == NGX_OK) {
            ngx_live_variable_depth++;
            return vv;
        }

        ngx_live_variable_depth++;
        return NULL;
    }

    vv = ngx_palloc(ctx->pool, sizeof(ngx_live_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && ngx_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(ctx, vv, (uintptr_t) name) == NGX_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static ngx_int_t
ngx_live_variable_nginx_version(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NGINX_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NGINX_VERSION;

    return NGX_OK;
}


static ngx_int_t
ngx_live_variable_hostname(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    v->len = ngx_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ngx_cycle->hostname.data;

    return NGX_OK;
}


static ngx_int_t
ngx_live_variable_pid(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(ctx->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%P", ngx_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_live_variable_msec(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    ngx_time_t  *tp;

    p = ngx_pnalloc(ctx->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return NGX_ERROR;
    }

    tp = ngx_timeofday();

    v->len = ngx_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_live_variable_channel(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *s;

    s = (ngx_str_t *) ((char *) ctx->ch + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_variable_channel_uint32(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    u_char    *p;
    uint32_t  *n;

    p = ngx_pnalloc(ctx->pool, NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    n = (uint32_t *) ((char *) ctx->ch + data);

    v->len = ngx_sprintf(p, "%uD", *n) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


void *
ngx_live_map_find(ngx_live_variables_ctx_t *ctx, ngx_live_map_t *map,
    ngx_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    ngx_uint_t   key;

    len = match->len;

    if (len) {
        low = ngx_pnalloc(ctx->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = ngx_hash_strlow(low, match->data, len);

    value = ngx_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NGX_PCRE)

    if (len && map->nregex) {
        ngx_int_t              n;
        ngx_uint_t             i;
        ngx_live_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = ngx_live_regex_exec(ctx, reg[i].regex, match);

            if (n == NGX_OK) {
                return reg[i].value;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            /* NGX_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_live_variable_not_found(ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_live_regex_t *
ngx_live_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    ngx_str_t                   name;
    ngx_uint_t                  i, n;
    ngx_live_variable_t        *v;
    ngx_live_regex_t           *re;
    ngx_live_regex_variable_t  *rv;
    ngx_live_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = ngx_pcalloc(cf->pool, sizeof(ngx_live_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);
    cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

    n = (ngx_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = ngx_palloc(rc->pool, n * sizeof(ngx_live_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = ngx_strlen(name.data);

        v = ngx_live_add_variable(cf, &name, NGX_LIVE_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = ngx_live_get_variable_index(cf, &name);
        if (rv[i].index == NGX_ERROR) {
            return NULL;
        }

        v->get_handler = ngx_live_variable_not_found;

        p += size;
    }

    return re;
}


ngx_int_t
ngx_live_regex_exec(ngx_live_variables_ctx_t *ctx, ngx_live_regex_t *re,
    ngx_str_t *str)
{
    ngx_int_t                   rc, index;
    ngx_uint_t                  i, n, len;
    ngx_live_variable_value_t  *vv;
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(ctx->ch, ngx_live_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (ctx->captures == NULL) {
            ctx->captures = ngx_palloc(ctx->pool, len * sizeof(int));
            if (ctx->captures == NULL) {
                return NGX_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = ngx_regex_exec(re->regex, str, ctx->captures, len);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, &ctx->ch->log, 0,
                      ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return NGX_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &ctx->variables[index];

        vv->len = ctx->captures[n + 1] - ctx->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &str->data[ctx->captures[n]];

#if (NGX_DEBUG)
        {
        ngx_live_variable_t  *v;

        v = cmcf->variables.elts;

        ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &ctx->ch->log, 0,
                       "live regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    ctx->ncaptures = rc * 2;
    ctx->captures_data = str->data;

    return NGX_OK;
}

#endif


ngx_int_t
ngx_live_variables_init_ctx(ngx_live_channel_t *channel, ngx_pool_t *pool,
    ngx_live_variables_ctx_t *ctx)
{
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_get_module_main_conf(channel, ngx_live_core_module);

    ctx->variables = ngx_pcalloc(pool, cmcf->variables.nelts
                                 * sizeof(ngx_live_variable_value_t));

    if (ctx->variables == NULL) {
        return NGX_ERROR;
    }

    ctx->ch = channel;
    ctx->pool = pool;
    ctx->ncaptures = 0;
    ctx->captures = NULL;
    ctx->captures_data = NULL;

    return NGX_OK;
}


ngx_int_t
ngx_live_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_live_core_main_conf_t  *cmcf;

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(ngx_live_variable_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_variable_add_multi(cf, ngx_live_core_variables) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_live_variables_init_vars(ngx_conf_t *cf)
{
    size_t                      len;
    ngx_uint_t                  i, n;
    ngx_hash_key_t             *key;
    ngx_hash_init_t             hash;
    ngx_live_variable_t        *v, *av, *pv;
    ngx_live_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed live variables */

    cmcf = ngx_live_conf_get_module_main_conf(cf, ngx_live_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NGX_LIVE_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & NGX_LIVE_VAR_WEAK))
                {
                    break;
                }

                goto next;
            }
        }

        len = 0;
        av = NULL;

        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && ngx_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;
        }

        if (v[i].get_handler == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);
            return NGX_ERROR;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_LIVE_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf->variables_keys = NULL;

    return NGX_OK;
}
