#ifndef _NGX_LIVE_PERSIST_FORMAT_H_INCLUDED_
#define _NGX_LIVE_PERSIST_FORMAT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_LIVE_PERSIST_FILE_MAGIC              (0x66706c6b)    /* klpf */


#define NGX_LIVE_PERSIST_HEADER_SIZE_MASK        (0x0fffffff)

#define NGX_LIVE_PERSIST_HEADER_FLAG_CONTAINER   (0x10000000)
#define NGX_LIVE_PERSIST_HEADER_FLAG_INDEX       (0x20000000)
#define NGX_LIVE_PERSIST_HEADER_FLAG_COMPRESSED  (0x40000000)


#define NGX_LIVE_PERSIST_MAX_BLOCK_DEPTH         (5)


#define NGX_LIVE_PERSIST_FILE_VERSION            (1)


/* file types */
#define NGX_LIVE_PERSIST_TYPE_SETUP              (0x70746573)    /* setp */

#define NGX_LIVE_PERSIST_TYPE_INDEX              (0x78696773)    /* sgix */

#define NGX_LIVE_PERSIST_TYPE_MEDIA              (0x73746773)    /* sgts */


/* block ids */
#define NGX_LIVE_PERSIST_BLOCK_CHANNEL           (0x6c6e6863)    /* chnl */

#define NGX_LIVE_PERSIST_BLOCK_VARIANT           (0x746e7276)    /* vrnt */

#define NGX_LIVE_PERSIST_BLOCK_TRACK             (0x6b617274)    /* trak */

#define NGX_LIVE_PERSIST_BLOCK_SEGMENT           (0x746d6773)    /* sgmt */
#define NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO        (0x666e696d)    /* minf */
#define NGX_LIVE_PERSIST_BLOCK_FRAME_LIST        (0x6e757274)    /* trun */
#define NGX_LIVE_PERSIST_BLOCK_FRAME_DATA        (0x7461646d)    /* mdat */


typedef struct {
    uint32_t        magic;
    uint32_t        size;
    uint32_t        header_size;
    uint32_t        uncomp_size;
    uint32_t        version;
    uint32_t        type;
    uint64_t        created;
} ngx_live_persist_file_header_t;

typedef struct {
    uint32_t        id;
    uint32_t        size;
    uint32_t        header_size;
} ngx_live_persist_block_header_t;

typedef struct {
    uint32_t        frame_count;
    uint32_t        reserved;
    int64_t         start_dts;
} ngx_live_persist_segment_header_t;

#endif /* _NGX_LIVE_PERSIST_FORMAT_H_INCLUDED_ */
