#ifndef _NGX_LIVE_JSON_CMDS_H_INCLUDED_
#define _NGX_LIVE_JSON_CMDS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_json_parser.h>


#define ngx_live_null_json_cmd  { ngx_null_string, 0, NULL }


enum {
    NGX_LIVE_JSON_CTX_GLOBAL,
    NGX_LIVE_JSON_CTX_PRE_CHANNEL,      /* before read */
    NGX_LIVE_JSON_CTX_CHANNEL,
    NGX_LIVE_JSON_CTX_TRACK,
    NGX_LIVE_JSON_CTX_STORE,

    NGX_LIVE_JSON_CTX_MAX
};


typedef void (*ngx_live_json_cmds_handler_pt)(void *arg, ngx_int_t rc);

typedef struct {
    ngx_uint_t                      ctx;
    void                           *obj;
    ngx_pool_t                     *pool;
    ngx_live_json_cmds_handler_pt   handler;
    void                           *data;
} ngx_live_json_cmds_ctx_t;


typedef struct ngx_live_json_cmd_s  ngx_live_json_cmd_t;

struct ngx_live_json_cmd_s {
    ngx_str_t                       name;
    ngx_int_t                       type;
    ngx_int_t                     (*set_handler)(
        ngx_live_json_cmds_ctx_t *jctx, ngx_live_json_cmd_t *cmd,
        ngx_json_value_t *value);
};


typedef struct {
    ngx_hash_keys_arrays_t         *keys;
    ngx_hash_t                      hash;
    ngx_array_t                     post;   /* ngx_live_json_cmd_t */
} ngx_live_json_cmds_conf_t;


ngx_int_t ngx_live_json_cmds_prepare(ngx_conf_t *cf);

ngx_live_json_cmd_t *ngx_live_json_cmds_add(ngx_conf_t *cf,
    ngx_str_t *name, ngx_uint_t ctx);

ngx_int_t ngx_live_json_cmds_add_multi(ngx_conf_t *cf,
    ngx_live_json_cmd_t *cmds, ngx_uint_t ctx);

ngx_int_t ngx_live_json_cmds_init(ngx_conf_t *cf);


ngx_int_t ngx_live_json_cmds_exec(ngx_live_channel_t *channel,
    ngx_live_json_cmds_ctx_t *jctx, ngx_json_object_t *json);

#endif /* _NGX_LIVE_JSON_CMDS_H_INCLUDED_ */
