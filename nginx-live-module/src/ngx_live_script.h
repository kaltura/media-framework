
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIVE_SCRIPT_H_INCLUDED_
#define _NGX_LIVE_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live.h"


typedef struct {
    u_char                       *ip;
    u_char                       *pos;
    ngx_live_variable_value_t    *sp;

    ngx_str_t                     buf;
    ngx_str_t                     line;

    unsigned                      flushed:1;
    unsigned                      skip:1;

    ngx_live_variables_ctx_t     *ctx;
} ngx_live_script_engine_t;


typedef struct {
    ngx_conf_t                   *cf;
    ngx_str_t                    *source;

    ngx_array_t                 **flushes;
    ngx_array_t                 **lengths;
    ngx_array_t                 **values;

    ngx_uint_t                    variables;
    ngx_uint_t                    ncaptures;
    ngx_uint_t                    size;

    void                         *main;

    unsigned                      complete_lengths:1;
    unsigned                      complete_values:1;
    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} ngx_live_script_compile_t;


typedef struct {
    ngx_str_t                     value;
    ngx_uint_t                   *flushes;
    void                         *lengths;
    void                         *values;

    union {
        size_t                    size;
    } u;
} ngx_live_complex_value_t;


typedef struct {
    ngx_conf_t                   *cf;
    ngx_str_t                    *value;
    ngx_live_complex_value_t     *complex_value;

    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} ngx_live_compile_complex_value_t;


typedef void (*ngx_live_script_code_pt) (ngx_live_script_engine_t *e);
typedef size_t (*ngx_live_script_len_code_pt) (ngx_live_script_engine_t *e);


typedef struct {
    ngx_live_script_code_pt       code;
    uintptr_t                     len;
} ngx_live_script_copy_code_t;


typedef struct {
    ngx_live_script_code_pt       code;
    uintptr_t                     index;
} ngx_live_script_var_code_t;


typedef struct {
    ngx_live_script_code_pt       code;
    uintptr_t                     n;
} ngx_live_script_copy_capture_code_t;


typedef struct {
    ngx_live_script_code_pt       code;
    uintptr_t                     conf_prefix;
} ngx_live_script_full_name_code_t;


void ngx_live_script_flush_complex_value(ngx_live_variables_ctx_t *ctx,
    ngx_live_complex_value_t *val);
ngx_int_t ngx_live_complex_value(ngx_live_variables_ctx_t *ctx,
    ngx_live_complex_value_t *val, ngx_str_t *value);
size_t ngx_live_complex_value_size(ngx_live_variables_ctx_t *ctx,
    ngx_live_complex_value_t *val, size_t default_value);
ngx_int_t ngx_live_compile_complex_value(
    ngx_live_compile_complex_value_t *ccv);
char *ngx_live_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_live_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_uint_t ngx_live_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_live_script_compile(ngx_live_script_compile_t *sc);
u_char *ngx_live_script_run(ngx_live_variables_ctx_t *ctx, ngx_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void ngx_live_script_flush_no_cacheable_variables(
    ngx_live_variables_ctx_t *ctx, ngx_array_t *indices);

void *ngx_live_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_live_script_copy_len_code(ngx_live_script_engine_t *e);
void ngx_live_script_copy_code(ngx_live_script_engine_t *e);
size_t ngx_live_script_copy_var_len_code(ngx_live_script_engine_t *e);
void ngx_live_script_copy_var_code(ngx_live_script_engine_t *e);
size_t ngx_live_script_copy_capture_len_code(ngx_live_script_engine_t *e);
void ngx_live_script_copy_capture_code(ngx_live_script_engine_t *e);

#endif /* _NGX_LIVE_SCRIPT_H_INCLUDED_ */
