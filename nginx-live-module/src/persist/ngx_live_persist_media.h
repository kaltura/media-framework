#ifndef _NGX_LIVE_PERSIST_MEDIA_H_INCLUDED_
#define _NGX_LIVE_PERSIST_MEDIA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_internal.h"


void ngx_live_persist_media_write_complete(
    ngx_live_persist_write_file_ctx_t *ctx, ngx_int_t rc);


size_t ngx_live_persist_media_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_persist_media_json_write(u_char *p,
    ngx_live_channel_t *channel);


size_t ngx_live_persist_media_read_json_get_size(ngx_live_channel_t *channel);

u_char *ngx_live_persist_media_read_json_write(u_char *p,
    ngx_live_channel_t *channel);

#endif /* _NGX_LIVE_PERSIST_MEDIA_H_INCLUDED_ */
