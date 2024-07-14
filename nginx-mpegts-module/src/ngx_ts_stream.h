
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#ifndef _NGX_TS_STREAM_H_INCLUDED_
#define _NGX_TS_STREAM_H_INCLUDED_


/*
 * ISO/IEC 13818-1 : 2000 (E)
 * Table 2-29 – Stream type assignments, p. 48
 *
 * ISO/IEC 13818-1:2007/Amd.3:2009 (E)
 * Table 2-34 – Stream type assignments, p. 6
 */

#define NGX_TS_VIDEO_MPEG1     0x01 /* ISO/IEC 11172-2, MPEG-1 Video */
#define NGX_TS_VIDEO_MPEG2     0x02 /* ISO/IEC 13818-2, MPEG-2 Video */
#define NGX_TS_VIDEO_MPEG4     0x10 /* ISO/IEC 14496-2, MPEG-4 Video */
#define NGX_TS_VIDEO_AVC       0x1b /* ISO/IEC 14496-10, AVC */
#define NGX_TS_VIDEO_HEVC      0x24


#define NGX_TS_AUDIO_MPEG1     0x03 /* ISO/IEC 11172-3, MPEG-1 Audio */
#define NGX_TS_AUDIO_MPEG2     0x04 /* ISO/IEC 13818-3, MPEG-2 Audio */
#define NGX_TS_AUDIO_AAC       0x0f /* ISO/IEC 13818-7, MPEG-2 AAC ADTS Audio */
#define NGX_TS_AUDIO_AC3       0x81
#define NGX_TS_AUDIO_EC3       0x87


#define NGX_TS_META_DATA       0x15 /* Packetized metadata */


typedef enum {
    NGX_TS_PAT = 0,
    NGX_TS_PMT,
    NGX_TS_PES
} ngx_ts_event_e;


typedef struct {
    ngx_chain_t                  *head;
    ngx_chain_t                 **tail;
} ngx_ts_bufs_t;


typedef struct {
    u_char                        type;
    u_char                        sid;
    u_char                        cont;
    uint16_t                      pid;
    uint64_t                      pts;
    uint64_t                      dts;
    ngx_str_t                     info;
    unsigned                      ptsf:1;
    unsigned                      rand:1;
    unsigned                      video:1;
    unsigned                      corrupt:1;
    ngx_ts_bufs_t                 bufs;  /* ES */
} ngx_ts_es_t;


typedef struct {
    uint16_t                      number;
    uint16_t                      pid;
    uint16_t                      pcr_pid;
    uint64_t                      pcr;
    ngx_uint_t                    video;  /* unisgned  video:1; */
    ngx_uint_t                    nes;
    ngx_ts_es_t                  *es;
    ngx_ts_bufs_t                 bufs;  /* PMT */
} ngx_ts_program_t;


typedef struct ngx_ts_handler_s  ngx_ts_handler_t;

typedef struct {
    ngx_connection_t             *connection;
    ngx_uint_t                    nprogs;
    ngx_ts_program_t             *progs;
    ngx_log_t                    *log;
    ngx_pool_t                   *pool;
    ngx_buf_t                    *buf;
    ngx_chain_t                  *free;
    ngx_ts_bufs_t                 bufs;  /* PAT */
    ngx_ts_handler_t             *handlers;
    void                         *data;
    ngx_str_t                     stream_id;
    size_t                        mem_left;

    ngx_str_t                     dump_folder;
    ngx_fd_t                      dump_fd;
    unsigned                      dump_input:1;
} ngx_ts_stream_t;


typedef struct {
    size_t                        mem_limit;
    ngx_str_t                     stream_id;
    ngx_str_t                     dump_folder;
} ngx_ts_stream_conf_t;


typedef struct {
    ngx_ts_event_e                event;
    ngx_ts_stream_t              *ts;
    ngx_ts_program_t             *prog;
    ngx_ts_es_t                  *es;
    ngx_chain_t                  *bufs;
    void                         *data;
} ngx_ts_handler_data_t;


typedef ngx_int_t (*ngx_ts_init_handler_pt)(ngx_ts_stream_t *ts, void *data);

typedef struct {
    ngx_ts_init_handler_pt        handler;
    void                         *data;
} ngx_ts_init_handler_t;


typedef ngx_int_t (*ngx_ts_handler_pt)(ngx_ts_handler_data_t *hd);

struct ngx_ts_handler_s {
    ngx_ts_handler_pt             handler;
    void                         *data;
    ngx_ts_handler_t             *next;
};


ngx_ts_stream_t *ngx_ts_stream_create(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_ts_stream_conf_t *conf);
ngx_int_t ngx_ts_add_handler(ngx_ts_stream_t *ts, ngx_ts_handler_pt handler,
    void *data);
ngx_int_t ngx_ts_read(ngx_ts_stream_t *ts, ngx_chain_t *in);
ngx_chain_t *ngx_ts_write_pat(ngx_ts_stream_t *ts, ngx_ts_program_t *prog);
ngx_chain_t *ngx_ts_write_pmt(ngx_ts_stream_t *ts, ngx_ts_program_t *prog);
ngx_chain_t *ngx_ts_write_pes(ngx_ts_stream_t *ts, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs);
ngx_uint_t ngx_ts_dash_get_oti(u_char type);

ngx_int_t ngx_ts_add_init_handler(ngx_conf_t *cf, ngx_array_t **a,
    ngx_ts_init_handler_pt handler, void *data);
ngx_int_t ngx_ts_init_handlers(ngx_array_t *handlers, ngx_ts_stream_t *ts);

#endif /* _NGX_TS_STREAM_H_INCLUDED_ */
