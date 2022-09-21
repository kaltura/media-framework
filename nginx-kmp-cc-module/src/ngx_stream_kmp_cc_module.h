#ifndef _NGX_STREAM_KMP_CC_MODULE_H_INCLUDED_
#define _NGX_STREAM_KMP_CC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_stream_kmp_cc_finalize_session(ngx_uint_t connection,
    ngx_log_t *log);


size_t ngx_stream_kmp_cc_stream_json_get_size(void *obj);

u_char *ngx_stream_kmp_cc_stream_json_write(u_char *p, void *obj);

#endif /* _NGX_STREAM_KMP_CC_MODULE_H_INCLUDED_ */
