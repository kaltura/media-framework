#ifndef _NGX_TS_AC3_H_INCLUDED_
#define _NGX_TS_AC3_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_TS_AC3_MAX_EXTRA_DATA_LEN  (6)


typedef struct {
    uint32_t  bitrate;
    uint16_t  channels;
    uint16_t  bits_per_sample;
    uint32_t  sample_rate;
    uint64_t  channel_layout;
} ngx_ts_ac3_params_t;


ngx_int_t ngx_ts_ac3_ec3_parse(ngx_log_t *log, ngx_chain_t *cl,
    ngx_ts_ac3_params_t *params, ngx_str_t *extra_data);

#endif /* _NGX_TS_AC3_H_INCLUDED_ */
