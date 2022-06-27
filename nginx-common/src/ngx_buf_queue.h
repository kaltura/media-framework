#ifndef _NGX_BUF_QUEUE_H_INCLUDED_
#define _NGX_BUF_QUEUE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_lba.h"


#define ngx_buf_queue_head(buf_queue) (buf_queue)->used_head

#define ngx_buf_queue_next(node) (node)->next

#define ngx_buf_queue_start(node)           \
    ((u_char *) (node) + sizeof(ngx_buf_queue_node_t))

#define ngx_buf_queue_end(buf_queue, node)  \
    ((u_char *) (node) + (buf_queue)->alloc_size)


typedef struct ngx_buf_queue_node_s  ngx_buf_queue_node_t;

struct ngx_buf_queue_node_s {
    ngx_buf_queue_node_t   *next;
};

typedef struct {
    ngx_lba_t              *lba;
    ngx_log_t              *log;
    size_t                  alloc_size;
    size_t                  used_size;
    size_t                 *mem_left;
    ngx_uint_t              nbuffers;
    ngx_buf_queue_node_t   *used_head;
    ngx_buf_queue_node_t  **used_tail;
    ngx_buf_queue_node_t   *free;
    ngx_uint_t              free_left;
} ngx_buf_queue_t;


ngx_int_t ngx_buf_queue_init(ngx_buf_queue_t *buf_queue, ngx_log_t *log,
    ngx_lba_t *lba, ngx_uint_t max_free_buffers, size_t *mem_left);

void ngx_buf_queue_delete(ngx_buf_queue_t *buf_queue);

void ngx_buf_queue_detach(ngx_buf_queue_t *buf_queue);

u_char *ngx_buf_queue_get(ngx_buf_queue_t *buf_queue);

void  ngx_buf_queue_free(ngx_buf_queue_t *buf_queue, u_char *limit);

#endif /* _NGX_BUF_QUEUE_H_INCLUDED_ */
