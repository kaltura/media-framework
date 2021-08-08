#ifndef _NGX_LIVE_PERSIST_CORE_H_INCLUDED_
#define _NGX_LIVE_PERSIST_CORE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_internal.h"


/* file types */
#define NGX_LIVE_PERSIST_TYPE_SETUP              (0x70746573)    /* setp */

#define NGX_LIVE_PERSIST_TYPE_INDEX              (0x78696773)    /* sgix */

#define NGX_LIVE_PERSIST_TYPE_MEDIA              (0x73746773)    /* sgts */

#define NGX_LIVE_PERSIST_TYPE_SERVE              NGX_KSMP_PERSIST_TYPE


enum {
    NGX_LIVE_PERSIST_FILE_SETUP,
    NGX_LIVE_PERSIST_FILE_INDEX,
    NGX_LIVE_PERSIST_FILE_DELTA,
    NGX_LIVE_PERSIST_FILE_MEDIA,

    NGX_LIVE_PERSIST_FILE_COUNT
};


typedef struct {
    ngx_live_persist_file_conf_t   files[NGX_LIVE_PERSIST_FILE_COUNT];
    ngx_flag_t                     cancel_read_if_empty;
} ngx_live_persist_core_preset_conf_t;


typedef struct {
    uint32_t                       started;
    uint32_t                       error;
    uint32_t                       success;
    uint64_t                       success_msec;
    uint64_t                       success_size;
} ngx_live_persist_file_stats_t;


/*
 * NGX_OK - read at least one file successfully
 * NGX_DONE - didn't read any file (not found/old version)
 * NGX_BAD_DATA - one of files is corrupt
 * NGX_DECLINED - no segments after load, read should be cancelled
 */
typedef void (*ngx_live_persist_read_handler_pt)(void *arg, ngx_int_t rc);


/* write */

ngx_live_persist_write_file_ctx_t *ngx_live_persist_core_write_file(
    ngx_live_channel_t *channel, void *data,
    ngx_live_persist_scope_t *scope, size_t scope_size);

void ngx_live_persist_core_write_error(ngx_live_channel_t *channel,
    ngx_uint_t file);


/* read */

ngx_int_t ngx_live_persist_core_read_parse(ngx_live_channel_t *channel,
    ngx_str_t *buf, ngx_uint_t file, ngx_live_persist_index_scope_t *scope);

ngx_int_t ngx_live_persist_core_read(ngx_live_channel_t *channel,
    ngx_pool_t *handler_pool, ngx_live_persist_read_handler_pt handler,
    void *data);


/* json */

size_t ngx_live_persist_core_json_get_size(
    ngx_live_persist_file_stats_t *obj);

u_char *ngx_live_persist_core_json_write(u_char *p,
    ngx_live_persist_file_stats_t *obj);


extern ngx_module_t  ngx_live_persist_core_module;

#endif /* _NGX_LIVE_PERSIST_CORE_H_INCLUDED_ */
