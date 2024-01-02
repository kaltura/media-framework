#ifndef _NGX_RTMP_KMP_API_H_INCLUDED_
#define _NGX_RTMP_KMP_API_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_rtmp_kmp_api_finalize_session(ngx_uint_t connection,
    ngx_log_t *log);


size_t ngx_rtmp_kmp_api_servers_json_get_size(void *obj);

u_char *ngx_rtmp_kmp_api_servers_json_write(u_char *p, void *obj);

#endif /* _NGX_RTMP_KMP_API_H_INCLUDED_ */
