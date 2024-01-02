#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"
#include "ngx_live_store.h"


static ngx_int_t ngx_live_store_postconfiguration(ngx_conf_t *cf);


static ngx_live_module_t  ngx_live_store_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_store_postconfiguration,         /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create preset configuration */
    NULL                                      /* merge preset configuration */
};


ngx_module_t  ngx_live_store_module = {
    NGX_MODULE_V1,
    &ngx_live_store_module_ctx,               /* module context */
    NULL,                                     /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


#include "ngx_live_store_json.h"


static ngx_live_json_writer_def_t  ngx_live_store_json_writers[] = {
    { { ngx_live_store_json_get_size,
        ngx_live_store_json_write },
      NGX_LIVE_JSON_CTX_GLOBAL },

      ngx_live_null_json_writer
};


static ngx_int_t
ngx_live_store_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_json_writers_add(cf,
        ngx_live_store_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
