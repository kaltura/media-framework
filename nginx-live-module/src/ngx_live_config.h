#ifndef _NGX_LIVE_CONFIG_H_INCLUDED_
#define _NGX_LIVE_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void        **main_conf;
    void        **preset_conf;
} ngx_live_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    void       *(*create_main_conf)(ngx_conf_t *cf);
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void       *(*create_preset_conf)(ngx_conf_t *cf);
    char       *(*merge_preset_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_live_module_t;


#define NGX_LIVE_MODULE           0x4556494c   /* "LIVE" */

#define NGX_LIVE_MAIN_CONF        0x02000000
#define NGX_LIVE_PRESET_CONF      0x08000000


#define NGX_LIVE_MAIN_CONF_OFFSET    offsetof(ngx_live_conf_ctx_t, main_conf)
#define NGX_LIVE_PRESET_CONF_OFFSET  offsetof(ngx_live_conf_ctx_t, preset_conf)


#define ngx_live_get_module_main_conf(channel, module)                        \
    (channel)->main_conf[module.ctx_index]
#define ngx_live_get_module_preset_conf(channel, module)                      \
    (channel)->preset_conf[module.ctx_index]


#define ngx_live_conf_get_module_main_conf(cf, module)                        \
    ((ngx_live_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_live_conf_get_module_preset_conf(cf, module)                      \
    ((ngx_live_conf_ctx_t *) cf->ctx)->preset_conf[module.ctx_index]

#define ngx_live_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_live_module.index] ?                                 \
        ((ngx_live_conf_ctx_t *) cycle->conf_ctx[ngx_live_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_LIVE_CONFIG_H_INCLUDED_ */
