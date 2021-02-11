#ifndef _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_
#define _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


enum {
    NGX_LIVE_PERSIST_FILE_SETUP,
    NGX_LIVE_PERSIST_FILE_INDEX,
    NGX_LIVE_PERSIST_FILE_DELTA,
    NGX_LIVE_PERSIST_FILE_MEDIA,

    NGX_LIVE_PERSIST_FILE_COUNT
};


typedef struct ngx_live_persist_main_conf_s  ngx_live_persist_main_conf_t;


typedef struct {
    ngx_live_complex_value_t      *path;
    size_t                         max_size;
} ngx_live_persist_file_conf_t;


typedef struct {
    ngx_live_store_t              *store;
    ngx_flag_t                     write;

    ngx_live_persist_file_conf_t   files[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_int_t                      comp_level;
} ngx_live_persist_preset_conf_t;


typedef struct {
    uint32_t                       started;
    uint32_t                       error;
    uint32_t                       success;
    uint64_t                       success_msec;
    uint64_t                       success_size;
} ngx_live_persist_file_stats_t;


typedef struct {
    ngx_pool_t                    *pool;
    ngx_live_channel_t            *channel;

    ngx_uint_t                     file;
    size_t                         size;
    ngx_msec_t                     start;
    u_char                         scope[1];    /* must be last */
} ngx_live_persist_write_file_ctx_t;


ngx_live_persist_write_file_ctx_t *ngx_live_persist_write_file(
    ngx_live_channel_t *channel, ngx_uint_t file, void *data, void *scope,
    size_t scope_size);

void ngx_live_persist_write_error(ngx_live_channel_t *channel,
    ngx_uint_t file);

void ngx_live_persist_write_file_destroy(
    ngx_live_persist_write_file_ctx_t *ctx);


ngx_int_t ngx_live_persist_write_blocks(ngx_live_channel_t *channel,
    ngx_live_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj);


ngx_int_t ngx_live_persist_read_blocks(ngx_live_persist_main_conf_t *pmcf,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj);

ngx_int_t ngx_live_persist_read_parse(ngx_live_channel_t *channel,
    ngx_str_t *buf, ngx_uint_t file, ngx_live_persist_index_scope_t *scope);


size_t ngx_live_persist_base_obj_json_get_size(
    ngx_live_persist_file_stats_t *obj);

u_char *ngx_live_persist_base_obj_json_write(u_char *p,
    ngx_live_persist_file_stats_t *obj);


extern ngx_module_t  ngx_live_persist_module;

#endif /* _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_ */
