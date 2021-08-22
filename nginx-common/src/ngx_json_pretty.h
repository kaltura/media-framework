#ifndef _NGX_JSON_PRETTY_H_INCLUDED_
#define _NGX_JSON_PRETTY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* Note: returns the last chain that was added */

ngx_chain_t *ngx_json_pretty(ngx_pool_t *pool, ngx_str_t *json,
    ngx_uint_t level, ngx_chain_t **last, size_t *size);

#endif /*_NGX_JSON_PRETTY_H_INCLUDED_ */
