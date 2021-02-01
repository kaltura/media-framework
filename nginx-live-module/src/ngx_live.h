#ifndef _NGX_LIVE_H_INCLUDED_
#define _NGX_LIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_live_channel_s     ngx_live_channel_t;


#include "ngx_live_variables.h"
#include "ngx_live_config.h"
#include "ngx_live_channel.h"
#include "ngx_live_script.h"
#include "ngx_live_core_module.h"
#include "persist/ngx_live_persist.h"


#define NGX_LIVE_VALIDATIONS  NGX_DEBUG
#define NGX_LOG_DEBUG_LIVE    NGX_LOG_DEBUG_CORE


#define ngx_array_entries(x)                    (sizeof(x) / sizeof(x[0]))

#define ngx_round_to_multiple(num, mult)                                    \
    ((((num) + (mult) / 2) / (mult)) * (mult))

#define ngx_round_up_to_multiple(num, mult)                                 \
    ((((num) + (mult) - 1) / (mult)) * (mult))

#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)

#define ngx_abs_diff(val1, val2)                                            \
    ((val2) > (val1) ? (val2) - (val1) : (val1) - (val2))

#define ngx_rbtree_data(n, type, node)                                      \
    (type *) ((u_char *) n - offsetof(type, node))

#define ngx_queue_insert_before   ngx_queue_insert_tail


#define ngx_live_get_module_ctx(ch, module)     (ch)->ctx[module.ctx_index]
#define ngx_live_set_ctx(ch, c, module)         ch->ctx[module.ctx_index] = c;

#define ngx_live_rescale_time(time, cur_scale, new_scale)                   \
    ((((uint64_t) (time)) * (new_scale) + (cur_scale) / 2) / (cur_scale))


typedef struct {
    ngx_conf_t     *cf;
    ngx_command_t  *cmds;
} ngx_live_block_conf_ctx_t;


char *ngx_live_block_command_handler(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);


extern ngx_module_t  ngx_live_module;

#endif /* _NGX_LIVE_H_INCLUDED_ */
