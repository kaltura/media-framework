#ifndef _NGX_LIVE_PERSIST_H_INCLUDED_
#define _NGX_LIVE_PERSIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_live_persist.h>
#include "ngx_live_store.h"


/* file types */
#define NGX_LIVE_PERSIST_TYPE_SETUP              (0x70746573)    /* setp */

#define NGX_LIVE_PERSIST_TYPE_INDEX              (0x78696773)    /* sgix */

#define NGX_LIVE_PERSIST_TYPE_MEDIA              (0x73746773)    /* sgts */

#define NGX_LIVE_PERSIST_TYPE_SERVE              (0x76726573)    /* serv */


/* block ids */
#define NGX_LIVE_PERSIST_BLOCK_CHANNEL           (0x6c6e6863)    /* chnl */

#define NGX_LIVE_PERSIST_BLOCK_VARIANT           (0x746e7276)    /* vrnt */

#define NGX_LIVE_PERSIST_BLOCK_TRACK             (0x6b617274)    /* trak */

#define NGX_LIVE_PERSIST_BLOCK_SEGMENT_INDEX     (0x78696773)    /* sgix */

#define NGX_LIVE_PERSIST_BLOCK_SEGMENT           (0x746d6773)    /* sgmt */
#define NGX_LIVE_PERSIST_BLOCK_MEDIA_INFO        (0x666e696d)    /* minf */
#define NGX_LIVE_PERSIST_BLOCK_FRAME_LIST        (0x6e757274)    /* trun */
#define NGX_LIVE_PERSIST_BLOCK_FRAME_DATA        (0x7461646d)    /* mdat */

#define NGX_LIVE_PERSIST_BLOCK_ERROR             (0x72727265)    /* errr */


#define NGX_LIVE_PERSIST_INVALID_SNAP  ((void *) -1)


#define NGX_LIVE_SERVE_MEDIA             (0x00000001)
#define NGX_LIVE_SERVE_TIMELINE          (0x00000002)
#define NGX_LIVE_SERVE_MEDIA_INFO        (0x00000004)
#define NGX_LIVE_SERVE_SEGMENT_INFO      (0x00000008)
#define NGX_LIVE_SERVE_DYNAMIC_VAR       (0x00000010)

#define NGX_LIVE_SERVE_ACTIVE_ONLY       (0x01000000)
#define NGX_LIVE_SERVE_CHECK_EXPIRY      (0x02000000)


/* ordered by desc prio */
enum {
    NGX_LIVE_SERVE_ERR_CHANNEL_NOT_FOUND = 10,
    NGX_LIVE_SERVE_ERR_CHANNEL_BLOCKED,

    NGX_LIVE_SERVE_ERR_TIMELINE_NOT_FOUND = 20,
    NGX_LIVE_SERVE_ERR_TIMELINE_EMPTY,
    NGX_LIVE_SERVE_ERR_TIMELINE_EMPTIED,
    NGX_LIVE_SERVE_ERR_TIMELINE_EXPIRED,

    NGX_LIVE_SERVE_ERR_SEGMENT_NOT_FOUND = 30,

    NGX_LIVE_SERVE_ERR_VARIANT_NOT_FOUND = 40,
    NGX_LIVE_SERVE_ERR_VARIANT_INACTIVE,
    NGX_LIVE_SERVE_ERR_VARIANT_NO_MATCH,

    NGX_LIVE_SERVE_ERR_MEDIA_INFO_NOT_FOUND = 50,

    NGX_LIVE_SERVE_ERR_TRACK_NOT_FOUND = 60,
};


enum {
    NGX_LIVE_PERSIST_CTX_SETUP_MAIN = 0,
    NGX_LIVE_PERSIST_CTX_SETUP_CHANNEL,
    NGX_LIVE_PERSIST_CTX_SETUP_TRACK,

    NGX_LIVE_PERSIST_CTX_INDEX_MAIN,
    NGX_LIVE_PERSIST_CTX_INDEX_CHANNEL,
    NGX_LIVE_PERSIST_CTX_INDEX_TRACK,
    NGX_LIVE_PERSIST_CTX_INDEX_TIMELINE,
    NGX_LIVE_PERSIST_CTX_INDEX_SEGMENT_LIST,
    NGX_LIVE_PERSIST_CTX_INDEX_MEDIA_INFO,

    NGX_LIVE_PERSIST_CTX_MEDIA_MAIN,
    NGX_LIVE_PERSIST_CTX_MEDIA_BUCKET,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_HEADER,
    NGX_LIVE_PERSIST_CTX_MEDIA_SEGMENT_DATA,

    NGX_LIVE_PERSIST_CTX_SERVE_MAIN,
    NGX_LIVE_PERSIST_CTX_SERVE_CHANNEL,
    NGX_LIVE_PERSIST_CTX_SERVE_TRACK,
    NGX_LIVE_PERSIST_CTX_SERVE_TIMELINE,
    NGX_LIVE_PERSIST_CTX_SERVE_MEDIA_INFO,
    NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_HEADER,
    NGX_LIVE_PERSIST_CTX_SERVE_SEGMENT_DATA,

    NGX_LIVE_PERSIST_CTX_COUNT
};


typedef enum {
    ngx_live_persist_snap_close_free,
    ngx_live_persist_snap_close_ack,
    ngx_live_persist_snap_close_write,
} ngx_live_persist_snap_close_action_e;


typedef struct {
    uint32_t     segment_index;
    uint32_t     reserved;
    int64_t      correction;
} ngx_live_persist_segment_index_t;


typedef struct {
    uint32_t     frame_count;
    uint32_t     reserved;
    int64_t      start_dts;
} ngx_live_persist_segment_header_t;


typedef struct {
    uint32_t     min_index;
    uint32_t     max_index;
} ngx_live_persist_index_scope_t;


typedef struct {
    ngx_live_channel_t               *channel;
    uint32_t                          max_track_id;
    ngx_live_persist_index_scope_t    scope;
    void                            (*close)(void *snap,
                                ngx_live_persist_snap_close_action_e action);
} ngx_live_persist_snap_t;


typedef struct {
    ngx_live_persist_snap_t           base;     /* must be first */
    ngx_pool_t                       *pool;
    void                            **ctx;
    ngx_live_persist_snap_t          *frames_snap;
} ngx_live_persist_snap_index_t;


typedef struct {
    ngx_live_channel_t               *channel;
    ngx_live_timeline_t              *timeline;
    ngx_live_variant_t              **variants;
    ngx_uint_t                        variant_count;
    ngx_array_t                      *track_refs;   /* ngx_live_track_ref_t */
    uint32_t                          segment_index;
    uint32_t                          flags;
    int64_t                           correction;
} ngx_live_persist_serve_scope_t;


typedef void (*ngx_live_persist_read_handler_pt)(void *arg, ngx_int_t rc);


char *ngx_live_persist_set_store(ngx_conf_t *cf, ngx_live_store_t *store);


ngx_int_t ngx_live_persist_add_blocks(ngx_conf_t *cf,
    ngx_live_persist_block_t *blocks);


ngx_int_t ngx_live_persist_read(ngx_live_channel_t *channel,
    ngx_pool_t *handler_pool, ngx_live_persist_read_handler_pt handler,
    void *data);


ngx_live_persist_snap_t *ngx_live_persist_snap_create(
    ngx_live_channel_t *channel);


ngx_int_t ngx_live_persist_read_blocks(ngx_live_channel_t *channel,
    ngx_uint_t ctx, ngx_mem_rstream_t *rs, void *obj);

ngx_int_t ngx_live_persist_write_blocks(ngx_live_channel_t *channel,
    ngx_live_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj);

#endif /* _NGX_LIVE_PERSIST_H_INCLUDED_ */
