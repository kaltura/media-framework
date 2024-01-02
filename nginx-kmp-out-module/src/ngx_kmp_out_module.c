#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_kmp_out_track_internal.h"


static ngx_core_module_t  ngx_kmp_out_module_ctx = {
    ngx_string("kmp_out"),
    NULL,
    NULL
};


ngx_module_t  ngx_kmp_out_module = {
    NGX_MODULE_V1,
    &ngx_kmp_out_module_ctx,               /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_kmp_out_track_init_process,        /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
