#ifndef _NGX_BUF_QUEUE_STREAM_H_INCLUDED_
#define _NGX_BUF_QUEUE_STREAM_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_queue.h"


#define ngx_buf_queue_stream_pos(s)  ((s)->pos)


typedef struct {
    ngx_buf_queue_t       *buf_queue;
    ngx_buf_queue_node_t  *node;
    u_char                *pos;
} ngx_buf_queue_stream_t;


/* Note: the init functions must not be called when empty */
void ngx_buf_queue_stream_init_head(ngx_buf_queue_stream_t *stream,
    ngx_buf_queue_t *buf_queue);

void ngx_buf_queue_stream_init_tail(ngx_buf_queue_stream_t *stream,
    ngx_buf_queue_t *buf_queue, u_char *pos);

ngx_int_t ngx_buf_queue_stream_md5(ngx_buf_queue_stream_t *stream,
    size_t size, u_char result[16]);

void *ngx_buf_queue_stream_read(ngx_buf_queue_stream_t *stream,
    void *buffer, size_t size);

void *ngx_buf_queue_stream_write(ngx_buf_queue_stream_t *stream,
    void *buffer, size_t size);

ngx_int_t ngx_buf_queue_stream_skip(ngx_buf_queue_stream_t *stream,
    size_t size);

#endif /* _NGX_BUF_QUEUE_STREAM_H_INCLUDED_ */
