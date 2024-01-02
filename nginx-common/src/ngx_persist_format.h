#ifndef _NGX_PERSIST_FORMAT_H_INCLUDED_
#define _NGX_PERSIST_FORMAT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PERSIST_FILE_MAGIC              (0x66706c6b)    /* klpf */


#define NGX_PERSIST_HEADER_SIZE_MASK        (0x0fffffff)

#define NGX_PERSIST_HEADER_FLAG_CONTAINER   (0x10000000)
#define NGX_PERSIST_HEADER_FLAG_INDEX       (0x20000000)
#define NGX_PERSIST_HEADER_FLAG_COMPRESSED  (0x40000000)


#define NGX_PERSIST_MAX_BLOCK_DEPTH         (5)


#define NGX_PERSIST_FILE_MIN_VERSION        (9)
#define NGX_PERSIST_FILE_MAX_VERSION        (10)
#define NGX_PERSIST_FILE_VERSION            NGX_PERSIST_FILE_MAX_VERSION


typedef struct {
    uint32_t        magic;
    uint32_t        size;
    uint32_t        header_size;
    uint32_t        uncomp_size;
    uint32_t        version;
    uint32_t        type;
    uint64_t        created;
} ngx_persist_file_header_t;


typedef struct {
    uint32_t        id;
    uint32_t        size;
    uint32_t        header_size;
} ngx_persist_block_header_t;


/* unaligned version */
typedef struct {
    u_char          id[4];
    u_char          size[4];
    u_char          header_size[4];
} ngx_persist_block_hdr_t;


#endif /* _NGX_PERSIST_FORMAT_H_INCLUDED_ */
