#ifndef _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_
#define _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


typedef struct ngx_live_persist_main_conf_s  ngx_live_persist_main_conf_t;


typedef struct {
    ngx_live_complex_value_t      *path;
    size_t                         max_size;
} ngx_live_persist_file_conf_t;


typedef struct {
    uint32_t                       type;
    uint32_t                       ctx;
    ngx_flag_t                     compress;
} ngx_live_persist_file_type_t;


typedef struct {
    ngx_pool_t                    *pool;
    ngx_live_channel_t            *channel;

    size_t                         size;
    ngx_msec_t                     start;
    ngx_live_persist_scope_t       scope;
} ngx_live_persist_write_file_ctx_t;


typedef struct {
    ngx_live_channel_t            *channel;
    ngx_pool_t                    *pool;
    ngx_str_t                      path;
    ngx_pool_cleanup_t            *cln;
    void                          *data;
} ngx_live_persist_read_file_ctx_t;


typedef struct {
    ngx_live_store_t              *store;
    ngx_flag_t                     write;
    ngx_int_t                      comp_level;
    ngx_live_complex_value_t      *opaque;
} ngx_live_persist_preset_conf_t;


/* write */

ngx_int_t ngx_live_persist_write_channel_header(
    ngx_persist_write_ctx_t *write_ctx, ngx_live_channel_t *channel);

ngx_live_persist_write_file_ctx_t *ngx_live_persist_write_file(
    ngx_live_channel_t *channel, ngx_live_persist_file_conf_t *conf,
    ngx_live_persist_file_type_t *type,
    ngx_live_store_write_handler_pt handler, void *data,
    ngx_live_persist_scope_t *scope, size_t scope_size);

void ngx_live_persist_write_file_destroy(
    ngx_live_persist_write_file_ctx_t *ctx);


/* read */

ngx_int_t ngx_live_persist_read_channel_header(ngx_live_channel_t *channel,
    ngx_mem_rstream_t *rs);

ngx_int_t ngx_live_persist_read_blocks_internal(
    ngx_live_persist_main_conf_t *pmcf, ngx_uint_t ctx, ngx_mem_rstream_t *rs,
    void *obj);

ngx_int_t ngx_live_persist_read_parse(ngx_live_channel_t *channel,
    ngx_str_t *buf, ngx_live_persist_file_type_t *type, size_t max_size,
    void *scope);

ngx_live_persist_read_file_ctx_t *ngx_live_persist_read_file(
    ngx_live_channel_t *channel, ngx_pool_cleanup_t *cln,
    ngx_live_persist_file_conf_t *file, ngx_live_store_read_handler_pt handler,
    void *data, size_t data_size);


extern ngx_module_t  ngx_live_persist_module;

#endif /* _NGX_LIVE_PERSIST_INTERNAL_H_INCLUDED_ */
