#ifndef _NGX_LIVE_DVR_H_INCLUDED_
#define _NGX_LIVE_DVR_H_INCLUDED_


#include "../ngx_live.h"


#ifndef NGX_HTTP_NOT_FOUND
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#endif


/* read + write */

typedef struct {
    uint32_t                   bucket_id;
    size_t                     size;
    ngx_msec_t                 start;
} ngx_live_dvr_save_request_t;


typedef ngx_int_t (*ngx_live_dvr_read_init_pt)(ngx_pool_t *pool,
    ngx_live_channel_t *channel, ngx_str_t *path, void *arg, ngx_str_t *name,
    void **result);

typedef ngx_int_t (*ngx_live_dvr_read_pt)(void *ctx, off_t offset, size_t size);

typedef ngx_int_t (*ngx_live_dvr_save_pt)(ngx_live_channel_t *channel,
    ngx_live_dvr_save_request_t *request);


typedef struct {
    ngx_live_dvr_read_init_pt  read_init;
    ngx_live_dvr_read_pt       read;
    ngx_live_dvr_save_pt       save;
} ngx_live_dvr_store_t;


typedef struct {
    ngx_live_dvr_store_t      *store;
    ngx_live_complex_value_t  *path;
    ngx_uint_t                 bucket_size;
    ngx_uint_t                 force_memory_segments;
    size_t                     initial_read_size;
} ngx_live_dvr_preset_conf_t;


ngx_int_t ngx_live_dvr_get_path(ngx_live_channel_t *channel, ngx_pool_t *pool,
    uint32_t bucket_id, ngx_str_t *path);


/* write */

void ngx_live_dvr_save_segment_created(ngx_live_channel_t *channel,
    uint32_t segment_index, ngx_flag_t exists);

ngx_chain_t *ngx_live_dvr_save_create_file(ngx_live_channel_t *channel,
    ngx_pool_t *pool, ngx_live_dvr_save_request_t *request);

void ngx_live_dvr_save_complete(ngx_live_channel_t *channel,
    ngx_live_dvr_save_request_t *request, ngx_int_t rc);


/* read */

void ngx_live_dvr_read_complete(void *arg, ngx_int_t rc, ngx_buf_t *response);


extern ngx_module_t  ngx_live_dvr_module;

#endif /* _NGX_LIVE_DVR_H_INCLUDED_ */
