
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


static ngx_int_t ngx_live_script_init_arrays(
    ngx_live_script_compile_t *sc);
static ngx_int_t ngx_live_script_done(ngx_live_script_compile_t *sc);
static ngx_int_t ngx_live_script_add_copy_code(
    ngx_live_script_compile_t *sc, ngx_str_t *value, ngx_uint_t last);
static ngx_int_t ngx_live_script_add_var_code(
    ngx_live_script_compile_t *sc, ngx_str_t *name);
static ngx_int_t ngx_live_script_add_full_name_code(
    ngx_live_script_compile_t *sc);
static size_t ngx_live_script_full_name_len_code(
    ngx_live_script_engine_t *e);
static void ngx_live_script_full_name_code(ngx_live_script_engine_t *e);


#define ngx_live_script_exit  (u_char *) &ngx_live_script_exit_code

static uintptr_t ngx_live_script_exit_code = (uintptr_t) NULL;


ngx_int_t
ngx_live_complex_value(ngx_live_channel_t *ch, ngx_pool_t *pool,
    ngx_live_complex_value_t *val, ngx_str_t *value)
{
    size_t                        len;
    ngx_live_script_code_pt       code;
    ngx_live_script_engine_t      e;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_script_len_code_pt   lcode;

    if (val->lengths == NULL) {
        *value = val->value;
        return NGX_OK;
    }

    ngx_memzero(&e, sizeof(ngx_live_script_engine_t));

    e.ip = val->lengths;
    e.channel = ch;
    e.pool = pool;
    e.flushed = 1;

    cmcf = ngx_live_get_module_main_conf(ch, ngx_live_core_module);

    e.variables = ngx_pcalloc(pool, cmcf->variables.nelts
        * sizeof(ngx_live_variable_value_t));
    if (e.variables == NULL) {
        return NGX_ERROR;
    }

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_live_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = ngx_pnalloc(pool, len);
    if (value->data == NULL) {
        return NGX_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_live_script_code_pt *) e.ip;
        code((ngx_live_script_engine_t *) &e);
    }

    *value = e.buf;

    return NGX_OK;
}


size_t
ngx_live_complex_value_size(ngx_live_channel_t *ch, ngx_pool_t *pool,
    ngx_live_complex_value_t *val, size_t default_value)
{
    size_t     size;
    ngx_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (ngx_live_complex_value(ch, pool, val, &value) != NGX_OK) {
        return default_value;
    }

    size = ngx_parse_size(&value);

    if (size == (size_t) NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


ngx_int_t
ngx_live_compile_complex_value(ngx_live_compile_complex_value_t *ccv)
{
    ngx_str_t                  *v;
    ngx_uint_t                  i, n, nv, nc;
    ngx_array_t                 lengths, values, *pl, *pv;
    ngx_live_script_compile_t   sc;

    v = ccv->value;

    nv = 0;
    nc = 0;

    for (i = 0; i < v->len; i++) {
        if (v->data[i] == '$') {
            if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
                nc++;

            } else {
                nv++;
            }
        }
    }

    if ((v->len == 0 || v->data[0] != '$')
        && (ccv->conf_prefix || ccv->root_prefix))
    {
        if (ngx_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != NGX_OK) {
            return NGX_ERROR;
        }

        ccv->conf_prefix = 0;
        ccv->root_prefix = 0;
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (nv == 0 && nc == 0) {
        return NGX_OK;
    }

    n = nv * (2 * sizeof(ngx_live_script_copy_code_t)
                  + sizeof(ngx_live_script_var_code_t))
        + sizeof(uintptr_t);

    if (ngx_array_init(&lengths, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    n = (nv * (2 * sizeof(ngx_live_script_copy_code_t)
                   + sizeof(ngx_live_script_var_code_t))
                + sizeof(uintptr_t)
                + v->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (ngx_array_init(&values, ccv->cf->pool, n, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    pl = &lengths;
    pv = &values;

    ngx_memzero(&sc, sizeof(ngx_live_script_compile_t));

    sc.cf = ccv->cf;
    sc.source = v;
    sc.lengths = &pl;
    sc.values = &pv;
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    sc.zero = ccv->zero;
    sc.conf_prefix = ccv->conf_prefix;
    sc.root_prefix = ccv->root_prefix;

    if (ngx_live_script_compile(&sc) != NGX_OK) {
        return NGX_ERROR;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return NGX_OK;
}


char *
ngx_live_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_str_t                          *value;
    ngx_live_complex_value_t          **cv;
    ngx_live_compile_complex_value_t    ccv;

    cv = (ngx_live_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = ngx_palloc(cf->pool, sizeof(ngx_live_complex_value_t));
    if (*cv == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_live_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (ngx_live_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_live_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                      *rv;
    ngx_live_complex_value_t  *cv;

    rv = ngx_live_set_complex_value_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    cv = *(ngx_live_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return NGX_CONF_OK;
    }

    cv->u.size = ngx_parse_size(&cv->value);
    if (cv->u.size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


ngx_uint_t
ngx_live_script_variables_count(ngx_str_t *value)
{
    ngx_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


ngx_int_t
ngx_live_script_compile(ngx_live_script_compile_t *sc)
{
    u_char       ch;
    ngx_str_t    name;
    ngx_uint_t   i, bracket;

    if (ngx_live_script_init_arrays(sc) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return NGX_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            if (ngx_live_script_add_var_code(sc, &name) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (ngx_live_script_add_copy_code(sc, &name, (i == sc->source->len))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return ngx_live_script_done(sc);

invalid_variable:

    ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return NGX_ERROR;
}


u_char *
ngx_live_script_run(ngx_live_channel_t *ch, ngx_pool_t *pool, ngx_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    ngx_live_script_code_pt       code;
    ngx_live_script_engine_t      e;
    ngx_live_core_main_conf_t    *cmcf;
    ngx_live_script_len_code_pt   lcode;

    cmcf = ngx_live_get_module_main_conf(ch, ngx_live_core_module);

    ngx_memzero(&e, sizeof(ngx_live_script_engine_t));

    e.ip = code_lengths;
    e.channel = ch;
    e.pool = pool;
    e.flushed = 1;

    e.variables = ngx_pcalloc(pool, cmcf->variables.nelts
        * sizeof(ngx_live_variable_value_t));
    if (e.variables == NULL) {
        return NULL;
    }

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_live_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = ngx_pnalloc(pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_live_script_code_pt *) e.ip;
        code((ngx_live_script_engine_t *) &e);
    }

    return e.pos;
}


static ngx_int_t
ngx_live_script_init_arrays(ngx_live_script_compile_t *sc)
{
    ngx_uint_t   n;

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(ngx_live_script_copy_code_t)
                             + sizeof(ngx_live_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NGX_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(ngx_live_script_copy_code_t)
                              + sizeof(ngx_live_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return NGX_ERROR;
        }
    }

    sc->variables = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_live_script_done(ngx_live_script_compile_t *sc)
{
    ngx_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (ngx_live_script_add_copy_code(sc, &zero, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (ngx_live_script_add_full_name_code(sc) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = ngx_live_script_add_code(*sc->lengths, sizeof(uintptr_t),
                                          NULL);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = ngx_live_script_add_code(*sc->values, sizeof(uintptr_t),
                                          &sc->main);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NGX_OK;
}


void *
ngx_live_script_add_code(ngx_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = ngx_array_push_n(codes, size);
    if (new == NULL) {
        return NULL;
    }

    if (code) {
        if (elts != codes->elts) {
            p = code;
            *p += (u_char *) codes->elts - elts;
        }
    }

    return new;
}


static ngx_int_t
ngx_live_script_add_copy_code(ngx_live_script_compile_t *sc,
    ngx_str_t *value, ngx_uint_t last)
{
    u_char                       *p;
    size_t                        size, len, zero;
    ngx_live_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = ngx_live_script_add_code(*sc->lengths,
                                      sizeof(ngx_live_script_copy_code_t),
                                      NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_live_script_code_pt) (void *)
                                               ngx_live_script_copy_len_code;
    code->len = len;

    size = (sizeof(ngx_live_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = ngx_live_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_live_script_copy_code;
    code->len = len;

    p = ngx_cpymem((u_char *) code + sizeof(ngx_live_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return NGX_OK;
}


size_t
ngx_live_script_copy_len_code(ngx_live_script_engine_t *e)
{
    ngx_live_script_copy_code_t  *code;

    code = (ngx_live_script_copy_code_t *) e->ip;

    e->ip += sizeof(ngx_live_script_copy_code_t);

    return code->len;
}


void
ngx_live_script_copy_code(ngx_live_script_engine_t *e)
{
    u_char                       *p;
    ngx_live_script_copy_code_t  *code;

    code = (ngx_live_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = ngx_copy(p, e->ip + sizeof(ngx_live_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(ngx_live_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    ngx_log_debug2(NGX_LOG_DEBUG_LIVE, &e->channel->log, 0,
                   "live script copy: \"%*s\"", e->pos - p, p);
}


static ngx_int_t
ngx_live_script_add_var_code(ngx_live_script_compile_t *sc, ngx_str_t *name)
{
    ngx_int_t                    index;
    ngx_live_script_var_code_t  *code;

    index = ngx_live_get_variable_index(sc->cf, name);

    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    code = ngx_live_script_add_code(*sc->lengths,
                                      sizeof(ngx_live_script_var_code_t),
                                      NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_live_script_code_pt) (void *)
                                           ngx_live_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = ngx_live_script_add_code(*sc->values,
                                      sizeof(ngx_live_script_var_code_t),
                                      &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_live_script_copy_var_code;
    code->index = (uintptr_t) index;

    return NGX_OK;
}


size_t
ngx_live_script_copy_var_len_code(ngx_live_script_engine_t *e)
{
    ngx_live_variable_value_t   *value;
    ngx_live_script_var_code_t  *code;

    code = (ngx_live_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_live_script_var_code_t);

    if (e->flushed) {
        value = ngx_live_get_indexed_variable(e->channel, e->pool,
            e->variables, code->index);

    } else {
        value = ngx_live_get_flushed_variable(e->channel, e->pool,
            e->variables, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
ngx_live_script_copy_var_code(ngx_live_script_engine_t *e)
{
    u_char                      *p;
    ngx_live_variable_value_t   *value;
    ngx_live_script_var_code_t  *code;

    code = (ngx_live_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_live_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = ngx_live_get_indexed_variable(e->channel, e->pool,
                e->variables, code->index);

        } else {
            value = ngx_live_get_flushed_variable(e->channel, e->pool,
                e->variables, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = ngx_copy(p, value->data, value->len);

            ngx_log_debug2(NGX_LOG_DEBUG_LIVE,
                           &e->channel->log, 0,
                           "live script var: \"%*s\"", e->pos - p, p);
        }
    }
}


static ngx_int_t
ngx_live_script_add_full_name_code(ngx_live_script_compile_t *sc)
{
    ngx_live_script_full_name_code_t  *code;

    code = ngx_live_script_add_code(*sc->lengths,
                                    sizeof(ngx_live_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = (ngx_live_script_code_pt) (void *)
                                          ngx_live_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = ngx_live_script_add_code(*sc->values,
                        sizeof(ngx_live_script_full_name_code_t), &sc->main);
    if (code == NULL) {
        return NGX_ERROR;
    }

    code->code = ngx_live_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return NGX_OK;
}


static size_t
ngx_live_script_full_name_len_code(ngx_live_script_engine_t *e)
{
    ngx_live_script_full_name_code_t  *code;

    code = (ngx_live_script_full_name_code_t *) e->ip;

    e->ip += sizeof(ngx_live_script_full_name_code_t);

    return code->conf_prefix ? ngx_cycle->conf_prefix.len:
                               ngx_cycle->prefix.len;
}


static void
ngx_live_script_full_name_code(ngx_live_script_engine_t *e)
{
    ngx_live_script_full_name_code_t  *code;

    ngx_str_t  value, *prefix;

    code = (ngx_live_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (ngx_str_t *) &ngx_cycle->conf_prefix:
                                 (ngx_str_t *) &ngx_cycle->prefix;

    if (ngx_get_full_name(e->pool, prefix, &value)
        != NGX_OK)
    {
        e->ip = ngx_live_script_exit;
        return;
    }

    e->buf = value;

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, &e->channel->log, 0,
                   "live script fullname: \"%V\"", &value);

    e->ip += sizeof(ngx_live_script_full_name_code_t);
}
