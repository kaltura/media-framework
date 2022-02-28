#ifndef _NGX_STREAM_TS_H_INCLUDED_
#define _NGX_STREAM_TS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_ts_stream.h"


ngx_int_t ngx_stream_ts_add_init_handler(ngx_conf_t *cf,
    ngx_ts_init_handler_pt handler, void *data);

#endif /* _NGX_STREAM_TS_H_INCLUDED_ */
