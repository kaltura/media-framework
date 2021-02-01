#ifndef _NGX_LIVE_PERSIST_SETUP_H_INCLUDED_
#define _NGX_LIVE_PERSIST_SETUP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_internal.h"


void ngx_live_persist_setup_write_complete(
    ngx_live_persist_write_file_ctx_t *ctx, ngx_int_t rc);

ngx_int_t ngx_live_persist_setup_read_handler(ngx_live_channel_t *channel,
    ngx_uint_t file, ngx_str_t *buf, uint32_t *min_index);


size_t ngx_live_persist_setup_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_persist_setup_json_write(u_char *p,
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_SETUP_H_INCLUDED_ */
