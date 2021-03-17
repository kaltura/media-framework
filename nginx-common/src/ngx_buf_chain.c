#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_buf_chain.h"


ngx_int_t
ngx_buf_chain_skip(ngx_buf_chain_t **head_ptr, size_t size)
{
    ngx_buf_chain_t  *head = *head_ptr;

    while (size > 0) {

        if (head == NULL) {
            return NGX_ERROR;
        }

        if (size < head->size) {
            head->data += size;
            head->size -= size;
            break;
        }

        size -= head->size;
        head = head->next;
        *head_ptr = head;
    }

    return NGX_OK;
}

void *
ngx_buf_chain_copy(ngx_buf_chain_t **head_ptr, void *buf, size_t size)
{
    u_char           *p;
    ngx_buf_chain_t  *head = *head_ptr;

    p = buf;
    while (size > 0) {

        if (head == NULL) {
            return NULL;
        }

        if (size < head->size) {
            ngx_memcpy(p, head->data, size);
            head->data += size;
            head->size -= size;
            break;
        }

        p = ngx_copy(p, head->data, head->size);
        size -= head->size;
        head = head->next;
        *head_ptr = head;
    }

    return buf;
}

void *
ngx_buf_chain_read(ngx_buf_chain_t **head_ptr, void *buf, size_t size)
{
    u_char           *p;
    ngx_buf_chain_t  *head = *head_ptr;

    if (head->size >= size) {
        /* data is contiguous, can avoid the memcpy */
        p = head->data;
        head->data = p + size;
        head->size -= size;
        if (head->size <= 0) {
            *head_ptr = head->next;
        }
        return p;
    }

    return ngx_buf_chain_copy(head_ptr, buf, size);
}

ngx_int_t
ngx_buf_chain_compare(ngx_buf_chain_t *head, void *buf, size_t size)
{
    u_char     *p;
    ngx_int_t   rc;

    if (size <= 0) {
        return 0;
    }

    p = buf;
    for (; head != NULL; head = head->next) {

        if (size <= head->size) {
            return ngx_memcmp(p, head->data, size);
        }

        rc = ngx_memcmp(p, head->data, head->size);
        if (rc != 0) {
            return rc;
        }

        p += head->size;
        size -= head->size;
    }

    return 1;
}
