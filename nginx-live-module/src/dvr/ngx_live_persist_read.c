#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_live_persist_read.h"


ngx_int_t
ngx_live_persist_read_file_header(ngx_str_t *buf, uint32_t type,
    ngx_log_t *log, ngx_mem_rstream_t *rs)
{
    uint32_t                         header_size;
    ngx_live_persist_file_header_t  *header;

    if (buf->len < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_read_file_header: buffer size %uz too small",
            buf->len);
        return NGX_BAD_DATA;
    }

    header = (void *) buf->data;

    if (header->magic != NGX_LIVE_PERSIST_FILE_MAGIC) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_read_file_header: invalid magic 0x%uxD",
            header->magic);
        return NGX_BAD_DATA;
    }

    header_size = header->header_size & NGX_LIVE_PERSIST_HEADER_SIZE_MASK;
    if (header_size < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_read_file_header: header size too small %uD",
            header_size);
        return NGX_BAD_DATA;
    }

    if (header_size > buf->len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_read_file_header: "
            "header size %uD larger than buffer %uz",
            header_size, buf->len);
        return NGX_BAD_DATA;
    }

    if (header->type != type) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_persist_read_file_header: "
            "invalid file type 0x%uxD, expected %*s",
            header->type, (size_t) sizeof(type), &type);
        return NGX_BAD_DATA;
    }

    ngx_mem_rstream_set(rs, buf->data + header_size, buf->data + buf->len,
        log);

    return NGX_OK;
}

ngx_live_persist_block_header_t *
ngx_live_persist_read_block(ngx_mem_rstream_t *rs, ngx_mem_rstream_t *block_rs)
{
    uint32_t                          size;
    ngx_live_persist_block_header_t  *header;

    header = ngx_mem_rstream_get_ptr(rs, sizeof(*header));
    if (header == NULL) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_block: read header failed");
        return NULL;
    }

    size = header->size;
    if (size < sizeof(*header)) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_block: "
            "header size %uD too small, id: 0x%uxD", size, header->id);
        return NULL;
    }

    size -= sizeof(*header);
    if (ngx_mem_rstream_get_stream(rs, size, block_rs) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_block: "
            "get stream failed, id: 0x%uxD", header->id);
        return NULL;
    }

    return header;
}

ngx_int_t
ngx_live_persist_read_skip_block_header(ngx_mem_rstream_t *rs,
    ngx_live_persist_block_header_t *header)
{
    uint32_t  size;
    uint32_t  read;

    read = ngx_mem_rstream_pos(rs) - (u_char *) header;
    size = header->header_size & NGX_LIVE_PERSIST_HEADER_SIZE_MASK;

    if (size < read) {
        ngx_log_error(NGX_LOG_ERR, rs->log, 0,
            "ngx_live_persist_read_skip_block_header: "
            "header size %uD smaller than read size %uD, id: %*s",
            size, read, (size_t) sizeof(header->id), &header->id);
        return NGX_BAD_DATA;

    } else if (size > read) {
        if (ngx_mem_rstream_get_ptr(rs, size - read) == NULL) {
            ngx_log_error(NGX_LOG_ERR, rs->log, 0,
                "ngx_live_persist_read_skip_block_header: "
                "skip failed, id: %*s",
                (size_t) sizeof(header->id), &header->id);
            return NGX_BAD_DATA;
        }
    }

    return NGX_OK;
}