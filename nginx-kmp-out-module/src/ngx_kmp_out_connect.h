#ifndef _NGX_KMP_OUT_CONNECT_H_INCLUDED_
#define _NGX_KMP_OUT_CONNECT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_DECLINED - response with code != "ok"
 * NGX_ERROR - error parsing the response
 */
ngx_int_t ngx_kmp_out_connect_parse(ngx_pool_t *pool, ngx_log_t *log,
    ngx_uint_t code, ngx_str_t *content_type, ngx_buf_t *body,
    ngx_str_t *desc);

#endif /* _NGX_KMP_OUT_CONNECT_H_INCLUDED_ */
