#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_str_t   delim;
} ngx_stream_preread_str_srv_conf_t;


typedef struct {
    u_char     *pos;
    ngx_str_t   header;
} ngx_stream_preread_str_ctx_t;


static ngx_int_t ngx_stream_preread_str_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_preread_str_add_variables(ngx_conf_t *cf);
static void *ngx_stream_preread_str_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_preread_str_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_preread_str_preread_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_preread_str_commands[] = {

    { ngx_string("preread_str_delim"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_preread_str_srv_conf_t, delim),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_preread_str_module_ctx = {
    ngx_stream_preread_str_add_variables,     /* preconfiguration */
    ngx_stream_preread_str_preread_init,      /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_stream_preread_str_create_srv_conf,   /* create server configuration */
    ngx_stream_preread_str_merge_srv_conf     /* merge server configuration */
};


ngx_module_t  ngx_stream_preread_str_module = {
    NGX_MODULE_V1,
    &ngx_stream_preread_str_module_ctx,       /* module context */
    ngx_stream_preread_str_commands,          /* module directives */
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


static ngx_stream_variable_t  ngx_stream_preread_str_vars[] = {

    { ngx_string("preread_str"), NULL,
      ngx_stream_preread_str_variable, 0, 0, 0 },

      ngx_stream_null_variable
};


static ngx_int_t
ngx_stream_preread_str_preread_handler(ngx_stream_session_t *s)
{
    u_char                              c1, c2;
    u_char                             *s2, *limit;
    size_t                              s2_len;
    ngx_connection_t                   *c;
    ngx_stream_preread_str_ctx_t       *ctx;
    ngx_stream_preread_str_srv_conf_t  *pscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "preread str handler");

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_preread_str_module);

    if (pscf->delim.len <= 0) {
        return NGX_DECLINED;
    }

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_preread_str_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_preread_str_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_preread_str_module);

        ctx->header.data = ctx->pos = c->buffer->pos;
    }

    if ((size_t) (c->buffer->last - ctx->pos) < pscf->delim.len) {
        return NGX_AGAIN;
    }

    limit = c->buffer->last - pscf->delim.len;

    c2 = pscf->delim.data[0];
    s2 = pscf->delim.data + 1;
    s2_len = pscf->delim.len - 1;

    do {
        do {
            if (ctx->pos > limit) {
                return NGX_AGAIN;
            }

            c1 = *ctx->pos++;

        } while (c1 != c2);

    } while (ngx_memcmp(ctx->pos, s2, s2_len) != 0);

    ctx->header.len = ctx->pos - 1 - ctx->header.data;
    c->buffer->pos = ctx->pos + s2_len;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_preread_str_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_preread_str_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_preread_str_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->header.len;
    v->data = ctx->header.data;

    ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
        "ngx_stream_preread_str_variable:  %s", v->data);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_preread_str_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_preread_str_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_preread_str_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_preread_str_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_preread_str_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_stream_preread_str_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_preread_str_srv_conf_t  *prev = parent;
    ngx_stream_preread_str_srv_conf_t  *conf = child;

    ngx_conf_merge_str_value(conf->delim, prev->delim, "");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_preread_str_preread_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_preread_str_preread_handler;

    return NGX_OK;
}