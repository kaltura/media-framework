#ifndef _NGX_BUF_QUEUE_READER_H_INCLUDED_
#define _NGX_BUF_QUEUE_READER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_queue.h"


typedef struct {
    ngx_buf_queue_t       *buf_queue;
    ngx_buf_queue_node_t  *node;
    u_char                *start;
} ngx_buf_queue_reader_t;


void ngx_buf_queue_reader_init(ngx_buf_queue_reader_t *reader,
    ngx_buf_queue_t *buf_queue);

void *ngx_buf_queue_reader_copy(ngx_buf_queue_reader_t *reader,
    void *buffer, size_t size);

void *ngx_buf_queue_reader_read(ngx_buf_queue_reader_t *reader,
    void *buffer, size_t size);

ngx_int_t ngx_buf_queue_reader_skip(ngx_buf_queue_reader_t *reader,
    size_t size);

#endif /* _NGX_BUF_QUEUE_READER_H_INCLUDED_ */
