#ifndef _NGX_LIVE_CHANNEL_H_INCLUDED_
#define _NGX_LIVE_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_live_kmp.h>
#include <ngx_buf_queue.h>
#include "media/media_format.h"
#include "ngx_live_config.h"
#include "ngx_block_pool.h"
#include "ngx_buf_chain.h"
#include "ngx_block_str.h"


#define NGX_LIVE_VARIANT_MAX_ID_LEN     (32)
#define NGX_LIVE_VARIANT_MAX_LABEL_LEN  (64)
#define NGX_LIVE_VARIANT_MAX_LANG_LEN   (6)

#define NGX_LIVE_TRACK_MAX_ID_LEN       (KMP_MAX_TRACK_ID_LEN)

#define NGX_LIVE_INVALID_SEGMENT_INDEX  (NGX_MAX_UINT32_VALUE)

#define NGX_LIVE_SEGMENT_NO_BITRATE     (1)

#define ngx_live_reserve_track_ctx_size(channel, module, size, total_size)  \
    channel->track_ctx_offset[module.ctx_index] = *total_size;              \
    *total_size += size;

#define ngx_live_channel_auto_free(channel, ptr)                            \
    ngx_block_pool_auto_free((channel)->block_pool, ptr)


typedef struct ngx_live_track_s  ngx_live_track_t;

typedef void (*live_track_ack_frames_pt)(ngx_live_track_t *track,
    ngx_uint_t count);

typedef void (*live_track_disconnect_pt)(ngx_live_track_t *track,
    ngx_uint_t rc);


typedef struct {
    ngx_rbtree_t                   rbtree;
    ngx_rbtree_node_t              sentinel;
    ngx_queue_t                    queue;
} ngx_live_channel_variants_t;

typedef struct {
    ngx_rbtree_t                   rbtree;        /* by string id */
    ngx_rbtree_node_t              sentinel;
    ngx_rbtree_t                   irbtree;       /* by int id */
    ngx_rbtree_node_t              isentinel;
    ngx_queue_t                    queue;
    uint32_t                       count;
    uint32_t                       next_id;
} ngx_live_channel_tracks_t;

struct ngx_live_channel_s {
    ngx_str_node_t                 sn;        /* must be first */
    ngx_queue_t                    queue;
    ngx_block_str_t                opaque;

    ngx_block_pool_t              *block_pool;
    ngx_pool_t                    *pool;
    ngx_log_t                      log;
    size_t                         mem_left;
    size_t                         mem_high_watermark;
    size_t                         mem_low_watermark;
    time_t                         last_modified;
    ngx_event_t                    close;
    ngx_msec_t                     start_msec;

    void                         **ctx;
    void                         **main_conf;
    void                         **preset_conf;

    ngx_live_channel_variants_t    variants;

    ngx_live_channel_tracks_t      tracks;
    uint32_t                       filler_media_types;

    size_t                        *track_ctx_offset;

    uint32_t                       next_segment_index;
    uint32_t                       last_segment_media_types;
    time_t                         last_segment_created;

    unsigned                       active:1;
};


typedef enum {
    ngx_live_track_type_regular,
    ngx_live_track_type_filler,
} ngx_live_track_type_e;

typedef struct {
    void                          *data;
    live_track_ack_frames_pt       ack_frames;
    live_track_disconnect_pt       disconnect;

    ngx_atomic_uint_t              connection;
    ngx_str_t                      remote_addr;
    ngx_msec_t                     start_msec;
    off_t                          received_bytes;
} ngx_live_track_input_t;

struct ngx_live_track_s {
    ngx_str_node_t                 sn;        /* must be first */
    ngx_rbtree_node_t              in;

    ngx_queue_t                    queue;
    ngx_live_channel_t            *channel;
    u_char                         id_buf[NGX_LIVE_TRACK_MAX_ID_LEN];
    ngx_block_str_t                opaque;

    uint32_t                       media_type;
    ngx_msec_t                     start_msec;
    ngx_live_track_type_e          type;

    void                         **ctx;
    ngx_log_t                      log;

    ngx_live_track_input_t         input;

    /* Note: when a track gets a segment from another track (gap filling),
        has_last_segment = 0 while last_segment_bitrate != 0 */
    uint32_t                       last_segment_bitrate;
    unsigned                       has_last_segment:1;
};


typedef enum {
    ngx_live_variant_role_main,
    ngx_live_variant_role_alternate,
} ngx_live_variant_role_e;

typedef struct {
    ngx_str_node_t                 sn;        /* must be first */
    ngx_queue_t                    queue;
    ngx_live_channel_t            *channel;
    u_char                         id_buf[NGX_LIVE_VARIANT_MAX_ID_LEN];
    ngx_block_str_t                opaque;

    ngx_live_track_t              *tracks[KMP_MEDIA_COUNT];
    uint32_t                       track_count;

    ngx_str_t                      label;
    u_char                         label_buf[NGX_LIVE_VARIANT_MAX_LABEL_LEN];

    ngx_str_t                      lang;
    u_char                         lang_buf[NGX_LIVE_VARIANT_MAX_LANG_LEN];

    ngx_live_variant_role_e        role;

    unsigned                       is_default:1;
} ngx_live_variant_t;


ngx_int_t ngx_live_channel_init_process(ngx_cycle_t *cycle);


/* channel */
ngx_int_t ngx_live_channel_create(ngx_str_t *channel_id,
    ngx_live_conf_ctx_t *conf_ctx, ngx_pool_t *temp_pool,
    ngx_live_channel_t **result);

void ngx_live_channel_free(ngx_live_channel_t *channel);

ngx_live_channel_t *ngx_live_channel_get(ngx_str_t *channel_id);

void ngx_live_channel_finalize(ngx_live_channel_t *channel);


ngx_block_pool_t *ngx_live_channel_create_block_pool(
    ngx_live_channel_t *channel, size_t *sizes, ngx_uint_t count);

ngx_buf_chain_t *ngx_live_channel_buf_chain_alloc(ngx_live_channel_t *channel);

void ngx_live_channel_buf_chain_free_list(ngx_live_channel_t *channel,
    ngx_buf_chain_t *head, ngx_buf_chain_t *tail);

void *ngx_live_channel_auto_alloc(ngx_live_channel_t *channel, size_t size);

ngx_int_t ngx_live_channel_block_str_set(ngx_live_channel_t *channel,
    ngx_block_str_t *dest, ngx_str_t *src);

void ngx_live_channel_block_str_free(ngx_live_channel_t *channel,
    ngx_block_str_t *str);


size_t ngx_live_channel_json_get_size(ngx_live_channel_t *obj);

u_char *ngx_live_channel_json_write(u_char *p, ngx_live_channel_t *obj);

size_t ngx_live_channels_json_get_size(void *obj);

u_char *ngx_live_channels_json_write(u_char *p, void *obj);


/* variant */
ngx_int_t ngx_live_variant_create(ngx_live_channel_t *channel,
    ngx_str_t *variant_id, ngx_log_t *log, ngx_live_variant_t **result);

void ngx_live_variant_free(ngx_live_variant_t *variant);

ngx_live_variant_t *ngx_live_variant_get(ngx_live_channel_t *channel,
    ngx_str_t *variant_id);

void ngx_live_variant_set_track(ngx_live_variant_t *variant,
    ngx_live_track_t *track);

ngx_flag_t ngx_live_variant_is_main_track_active(ngx_live_variant_t *variant,
    uint32_t media_type_mask);

size_t ngx_live_variants_json_get_size(ngx_live_channel_t *obj);

u_char *ngx_live_variants_json_write(u_char *p, ngx_live_channel_t *obj);


/* track */
ngx_int_t ngx_live_track_create(ngx_live_channel_t *channel,
    ngx_str_t *track_id, uint32_t media_type, ngx_log_t *log,
    ngx_live_track_t **result);

void ngx_live_track_free(ngx_live_track_t *track);

ngx_live_track_t *ngx_live_track_get(ngx_live_channel_t *channel,
    ngx_str_t *track_id);

ngx_live_track_t *ngx_live_track_get_by_int(ngx_live_channel_t *channel,
    uint32_t track_id);


size_t ngx_live_tracks_json_get_size(ngx_live_channel_t *obj);

u_char *ngx_live_tracks_json_write(u_char *p, ngx_live_channel_t *obj);


extern ngx_str_t  ngx_live_variant_role_names[];

extern ngx_str_t  ngx_live_track_media_type_names[];

#endif /* _NGX_LIVE_CHANNEL_H_INCLUDED_ */
