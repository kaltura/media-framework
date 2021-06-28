#ifndef _NGX_LIVE_PERSIST_INDEX_H_INCLUDED_
#define _NGX_LIVE_PERSIST_INDEX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_internal.h"


ngx_live_persist_snap_t *ngx_live_persist_index_snap_create(
    ngx_live_channel_t *channel);


void ngx_live_persist_index_write_complete(
    ngx_live_persist_write_file_ctx_t *ctx, ngx_int_t rc);

ngx_int_t ngx_live_persist_index_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf);


size_t ngx_live_persist_index_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_persist_index_json_write(u_char *p,
    ngx_live_channel_t *channel);

size_t ngx_live_persist_delta_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_persist_delta_json_write(u_char *p,
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_INDEX_H_INCLUDED_ */
