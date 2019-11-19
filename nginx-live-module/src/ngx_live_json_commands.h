#ifndef _NGX_LIVE_JSON_COMMANDS_H_INCLUDED_
#define _NGX_LIVE_JSON_COMMANDS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_json_parser.h>


#define ngx_live_null_json_command { ngx_null_string, 0, 0, NULL }


enum {
    NGX_LIVE_JSON_CTX_GLOBAL,
    NGX_LIVE_JSON_CTX_CHANNEL,
    NGX_LIVE_JSON_CTX_TRACK,

    NGX_LIVE_JSON_CTX_MAX
};


typedef struct ngx_live_json_command_s  ngx_live_json_command_t;

struct ngx_live_json_command_s {
    ngx_str_t                name;
    ngx_int_t                type;
    ngx_int_t              (*set_handler)(void *ctx,
        ngx_live_json_command_t *cmd, ngx_json_value_t *value);
};


typedef struct {
    ngx_hash_keys_arrays_t  *keys;
    ngx_hash_t               hash;
} ngx_live_json_commands_conf_t;


ngx_int_t ngx_live_json_commands_prepare(ngx_conf_t *cf);

ngx_live_json_command_t *ngx_live_json_commands_add(ngx_conf_t *cf,
    ngx_str_t *name, ngx_uint_t context);

ngx_int_t ngx_live_json_commands_init(ngx_conf_t *cf);


ngx_int_t ngx_live_json_commands_exec(ngx_json_object_t *obj,
    ngx_hash_t *commands_hash, void *ctx, ngx_log_t *log);

#endif /* _NGX_LIVE_JSON_COMMANDS_H_INCLUDED_ */