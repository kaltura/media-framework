
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIVE_VARIABLES_H_INCLUDED_
#define _NGX_LIVE_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef ngx_variable_value_t  ngx_live_variable_value_t;

#define ngx_live_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_live_variable_s  ngx_live_variable_t;

typedef struct ngx_live_variables_ctx_s  ngx_live_variables_ctx_t;

typedef void (*ngx_live_set_variable_pt) (ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_live_get_variable_pt) (ngx_live_variables_ctx_t *ctx,
    ngx_live_variable_value_t *v, uintptr_t data);


#define NGX_LIVE_VAR_CHANGEABLE   1
#define NGX_LIVE_VAR_NOCACHEABLE  2
#define NGX_LIVE_VAR_INDEXED      4
#define NGX_LIVE_VAR_NOHASH       8
#define NGX_LIVE_VAR_WEAK         16
#define NGX_LIVE_VAR_PREFIX       32


struct ngx_live_variable_s {
    ngx_str_t                     name;   /* must be first to build the hash */
    ngx_live_set_variable_pt      set_handler;
    ngx_live_get_variable_pt      get_handler;
    uintptr_t                     data;
    ngx_uint_t                    flags;
    ngx_uint_t                    index;
};

#define ngx_live_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }


struct ngx_live_variables_ctx_s {
    ngx_live_channel_t           *ch;
    ngx_pool_t                   *pool;
    ngx_live_variable_value_t    *variables;

#if (NGX_PCRE)
    ngx_uint_t                    ncaptures;
    int                          *captures;
    u_char                       *captures_data;
#endif
};


ngx_live_variable_t *ngx_live_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_live_variable_add_multi(ngx_conf_t *cf,
    ngx_live_variable_t *vars);
ngx_int_t ngx_live_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_live_variable_value_t *ngx_live_get_indexed_variable(
    ngx_live_variables_ctx_t *ctx, ngx_uint_t index);
ngx_live_variable_value_t *ngx_live_get_flushed_variable(
    ngx_live_variables_ctx_t *ctx, ngx_uint_t index);

ngx_live_variable_value_t *ngx_live_get_variable(ngx_live_variables_ctx_t *ctx,
    ngx_str_t *name, ngx_uint_t key);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_live_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_live_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_live_regex_t;


typedef struct {
    ngx_live_regex_t             *regex;
    void                         *value;
} ngx_live_map_regex_t;


ngx_live_regex_t *ngx_live_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_live_regex_exec(ngx_live_variables_ctx_t *ctx,
    ngx_live_regex_t *re, ngx_str_t *str);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_live_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_live_map_t;


void *ngx_live_map_find(ngx_live_variables_ctx_t *ctx, ngx_live_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_live_variables_init_ctx(ngx_live_channel_t *channel,
    ngx_pool_t *pool, ngx_live_variables_ctx_t *ctx);

ngx_int_t ngx_live_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_live_variables_init_vars(ngx_conf_t *cf);


extern ngx_live_variable_value_t  ngx_live_variable_null_value;
extern ngx_live_variable_value_t  ngx_live_variable_true_value;


#endif /* _NGX_LIVE_VARIABLES_H_INCLUDED_ */
