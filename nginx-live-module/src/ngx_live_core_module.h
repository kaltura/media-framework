#ifndef _NGX_LIVE_CORE_MODULE_H_INCLUDED_
#define _NGX_LIVE_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_config.h"
#include "ngx_live_json_commands.h"


enum {
    NGX_LIVE_EVENT_CHANNEL_INIT,
    NGX_LIVE_EVENT_CHANNEL_FREE,
    NGX_LIVE_EVENT_CHANNEL_WATERMARK,
    NGX_LIVE_EVENT_CHANNEL_INACTIVE,

    NGX_LIVE_EVENT_TRACK_INIT,
    NGX_LIVE_EVENT_TRACK_FREE,
    NGX_LIVE_EVENT_TRACK_CHANNEL_FREE,
    NGX_LIVE_EVENT_TRACK_CONNECT,
    NGX_LIVE_EVENT_TRACK_INACTIVE,

    NGX_LIVE_EVENT_MAX
};


typedef size_t (*ngx_live_json_writer_get_size_pt)(void *obj);
typedef u_char *(*ngx_live_json_writer_write_pt)(u_char *p, void *obj);

typedef struct {
    ngx_live_json_writer_get_size_pt  get_size;
    ngx_live_json_writer_write_pt     write;
} ngx_live_json_writer_t;


typedef struct ngx_live_core_preset_conf_s {
    ngx_str_t                       name;
    ngx_live_conf_ctx_t            *ctx;

    size_t                          mem_limit;
    ngx_uint_t                      mem_high_watermark;
    ngx_uint_t                      mem_low_watermark;
    ngx_array_t                    *block_sizes;

    ngx_uint_t                      timescale;
} ngx_live_core_preset_conf_t;


typedef struct {
    ngx_array_t                     presets; /* ngx_live_core_preset_conf_t */

    ngx_hash_t                      presets_hash;

    ngx_uint_t                      preset_names_hash_max_size;
    ngx_uint_t                      preset_names_hash_bucket_size;

    ngx_hash_t                      variables_hash;

    ngx_array_t                     variables;        /* ngx_live_variable_t */
    ngx_array_t                     prefix_variables; /* ngx_live_variable_t */

    ngx_uint_t                      variables_hash_max_size;
    ngx_uint_t                      variables_hash_bucket_size;

    ngx_hash_keys_arrays_t         *variables_keys;

    ngx_array_t                     events[NGX_LIVE_EVENT_MAX];

    ngx_live_json_commands_conf_t   json_cmds[NGX_LIVE_JSON_CTX_MAX];
    ngx_array_t                     json_writers[NGX_LIVE_JSON_CTX_MAX];

} ngx_live_core_main_conf_t;


ngx_live_conf_ctx_t *ngx_live_core_get_preset_conf(ngx_cycle_t *cycle,
    ngx_str_t *preset_name);


ngx_int_t ngx_live_core_channel_init(ngx_live_channel_t *channel,
    size_t *track_ctx_size);

ngx_int_t ngx_live_core_channel_event(ngx_live_channel_t *channel,
    ngx_uint_t event);

ngx_int_t ngx_live_core_track_event(ngx_live_track_t *track, ngx_uint_t event);


size_t ngx_live_core_json_get_size(void *obj, ngx_live_channel_t *channel,
    ngx_uint_t ctx);

u_char * ngx_live_core_json_write(u_char *p, void *obj,
    ngx_live_channel_t *channel, ngx_uint_t ctx);


extern ngx_module_t  ngx_live_core_module;
extern ngx_uint_t    ngx_live_max_module;

#endif /* _NGX_LIVE_CORE_MODULE_H_INCLUDED_ */
