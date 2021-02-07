#ifndef _NGX_LIVE_CORE_MODULE_H_INCLUDED_
#define _NGX_LIVE_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_config.h"
#include "ngx_live_json_commands.h"


#define ngx_live_reserve_track_ctx_size(cf, module, size)                   \
    ngx_live_core_reserve_track_ctx_size(cf, module.ctx_index, size)


#define ngx_live_null_json_writer  { { NULL, NULL }, 0 }
#define ngx_live_null_event        { NULL, 0 }


enum {
    NGX_LIVE_EVENT_CHANNEL_INIT,
    NGX_LIVE_EVENT_CHANNEL_FREE,
    NGX_LIVE_EVENT_CHANNEL_WATERMARK,
    NGX_LIVE_EVENT_CHANNEL_INACTIVE,
    NGX_LIVE_EVENT_CHANNEL_SETUP_CHANGED,
    NGX_LIVE_EVENT_CHANNEL_INDEX_SNAP,
    NGX_LIVE_EVENT_CHANNEL_READ,

    NGX_LIVE_EVENT_CHANNEL_SEGMENT_CREATED,
    NGX_LIVE_EVENT_CHANNEL_SEGMENT_FREE,

    NGX_LIVE_EVENT_TRACK_INIT,
    NGX_LIVE_EVENT_TRACK_FREE,
    NGX_LIVE_EVENT_TRACK_CHANNEL_FREE,
    NGX_LIVE_EVENT_TRACK_CONNECT,
    NGX_LIVE_EVENT_TRACK_INACTIVE,
    NGX_LIVE_EVENT_TRACK_COPY,

    NGX_LIVE_EVENT_MAX
};


enum {
    NGX_LIVE_CORE_BP_TRACK,
    NGX_LIVE_CORE_BP_VARIANT,
    NGX_LIVE_CORE_BP_BUF_CHAIN,
    NGX_LIVE_CORE_BP_STR,

    NGX_LIVE_CORE_BP_COUNT
};


typedef size_t (*ngx_live_json_writer_get_size_pt)(void *obj);
typedef u_char *(*ngx_live_json_writer_write_pt)(u_char *p, void *obj);

typedef struct {
    ngx_live_json_writer_get_size_pt  get_size;
    ngx_live_json_writer_write_pt     write;
} ngx_live_json_writer_t;

typedef struct {
    ngx_live_json_writer_t          writer;
    ngx_uint_t                      ctx;
} ngx_live_json_writer_def_t;


typedef struct {
    ngx_uint_t                      index;
    size_t                          offset;
} ngx_live_core_ctx_offset_t;


typedef struct ngx_live_core_preset_conf_s {
    ngx_str_t                       name;
    ngx_live_conf_ctx_t            *ctx;

    size_t                          mem_limit;
    ngx_uint_t                      mem_high_watermark;
    ngx_uint_t                      mem_low_watermark;

    ngx_array_t                     mem_blocks;         /* size_t */
    ngx_array_t                    *mem_conf_blocks;    /* size_t */
    ngx_array_t                    *mem_temp_blocks;
                                             /* ngx_live_core_block_size_t */

    ngx_uint_t                      bp_idx[NGX_LIVE_CORE_BP_COUNT];

    ngx_array_t                     track_ctx_offset;
    size_t                          track_ctx_size;

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
    ngx_uint_t                      ncaptures;

    ngx_uint_t                      variables_hash_max_size;
    ngx_uint_t                      variables_hash_bucket_size;

    ngx_hash_keys_arrays_t         *variables_keys;

    ngx_array_t                     events[NGX_LIVE_EVENT_MAX];

    ngx_live_json_commands_conf_t   json_cmds[NGX_LIVE_JSON_CTX_MAX];
    ngx_array_t                     json_writers[NGX_LIVE_JSON_CTX_MAX];

    ngx_array_t                     lba_array;

} ngx_live_core_main_conf_t;


typedef ngx_int_t (*ngx_live_channel_handler_pt)(ngx_live_channel_t *channel,
    void *ctx);
typedef ngx_int_t (*ngx_live_track_handler_pt)(ngx_live_track_t *track,
    void *ctx);

typedef struct {
    ngx_live_channel_handler_pt     handler;
    ngx_uint_t                      event;
} ngx_live_channel_event_t;

typedef struct {
    ngx_live_track_handler_pt       handler;
    ngx_uint_t                      event;
} ngx_live_track_event_t;


ngx_live_conf_ctx_t *ngx_live_core_get_preset_conf(ngx_cycle_t *cycle,
    ngx_str_t *preset_name);


void ngx_live_core_channel_init(ngx_live_channel_t *channel);

ngx_int_t ngx_live_core_channel_event(ngx_live_channel_t *channel,
    ngx_uint_t event, void *ectx);

ngx_int_t ngx_live_core_track_event(ngx_live_track_t *track, ngx_uint_t event,
    void *ectx);


ngx_int_t ngx_live_core_reserve_track_ctx_size(ngx_conf_t *cf,
    ngx_uint_t index, size_t size);

ngx_int_t ngx_live_core_add_block_pool_index(ngx_conf_t *cf, ngx_uint_t *index,
    size_t size);

ngx_int_t ngx_live_core_prepare_preset(ngx_conf_t *cf,
    ngx_live_core_preset_conf_t *cpcf);


ngx_lba_t *ngx_live_core_get_lba(ngx_conf_t *cf, size_t buffer_size,
    ngx_uint_t bin_count);

ngx_int_t ngx_live_core_channel_events_add(ngx_conf_t *cf,
    ngx_live_channel_event_t *events);

ngx_int_t ngx_live_core_track_events_add(ngx_conf_t *cf,
    ngx_live_track_event_t *events);

ngx_int_t ngx_live_core_json_writers_add(ngx_conf_t *cf,
    ngx_live_json_writer_def_t *writers);


size_t ngx_live_core_json_get_size(void *obj, ngx_live_channel_t *channel,
    ngx_uint_t ctx);

u_char * ngx_live_core_json_write(u_char *p, void *obj,
    ngx_live_channel_t *channel, ngx_uint_t ctx);


extern ngx_module_t  ngx_live_core_module;
extern ngx_uint_t    ngx_live_max_module;

#endif /* _NGX_LIVE_CORE_MODULE_H_INCLUDED_ */
