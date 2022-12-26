#ifndef _NGX_TS_OPUS_H_INCLUDED_
#define _NGX_TS_OPUS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_chain_reader.h"


#define NGX_TS_OPUS_MAX_EXTRA_DATA_LEN  (11 + 2 + 8)


typedef struct {
    uint16_t  channels;
    uint32_t  sample_rate;
    uint64_t  channel_layout;
} ngx_ts_opus_params_t;


typedef struct {
    size_t    size;
    uint16_t  start_trim;
    uint32_t  duration;
} ngx_ts_opus_packet_header_t;


ngx_int_t ngx_ts_opus_get_channel_conf(ngx_log_t *log, ngx_str_t *es_info);

ngx_int_t ngx_ts_opus_parse(u_char channel_conf, uint16_t pre_skip,
    ngx_ts_opus_params_t *params, ngx_str_t *extra_data);

ngx_int_t ngx_ts_opus_read_control_header(ngx_log_t *log,
    ngx_ts_chain_reader_t *reader, ngx_ts_opus_packet_header_t *hdr);

#endif /* _NGX_TS_OPUS_H_INCLUDED_ */
