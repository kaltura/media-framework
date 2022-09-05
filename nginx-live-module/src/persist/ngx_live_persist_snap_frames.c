#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


typedef struct {
    uint32_t                               track_id;
    ngx_atomic_uint_t                      connection;
    uint64_t                               next_frame_id;
} ngx_live_persist_snap_frames_track_t;


typedef struct {
    ngx_live_persist_snap_t                base;
    ngx_live_persist_snap_frames_track_t  *tracks;
} ngx_live_persist_snap_frames_t;


static void
ngx_live_persist_snap_frames_free(ngx_live_persist_snap_t *snap)
{
    ngx_live_channel_t  *channel = snap->channel;

    if (channel->snapshots <= 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_persist_snap_frames_free: zero ref count");
        ngx_destroy_pool(snap->pool);
        return;
    }

    channel->snapshots--;

    ngx_destroy_pool(snap->pool);
}


static void
ngx_live_persist_snap_frames_close(void *data,
    ngx_live_persist_snap_close_action_e action)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_frames_t        *snap = data;
    ngx_live_persist_snap_frames_track_t  *tf;

    if (action == ngx_live_persist_snap_close_free) {
        goto done;
    }

    tf = snap->tracks;
    if (tf == NULL) {
        goto done;
    }

    channel = snap->base.channel;

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_snap_frames_close: "
        "sending acks, index: %uD", snap->base.scope.max_index);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->in.key > snap->base.max_track_id ||
            cur_track->input == NULL)
        {
            continue;
        }

        for (; tf->track_id != cur_track->in.key; tf++) {
            if (tf->track_id == NGX_LIVE_INVALID_TRACK_ID) {
                ngx_log_error(NGX_LOG_ALERT, &cur_track->log, 0,
                    "ngx_live_persist_snap_frames_close: "
                    "track %ui not found in snapshot", cur_track->in.key);
                goto done;
            }
        }

        if (tf->connection != cur_track->input->connection->number) {
            continue;
        }

        ngx_kmp_in_ack_frames(cur_track->input, tf->next_frame_id);
    }

done:

    ngx_live_persist_snap_frames_free(&snap->base);
}


static ngx_int_t
ngx_live_persist_snap_frames_update(void *data)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_frames_t        *snap;
    ngx_live_persist_snap_frames_track_t  *tf;

    snap = data;
    channel = snap->base.channel;

    tf = ngx_palloc(snap->base.pool,
        sizeof(*tf) * (channel->tracks.count + 1));
    if (tf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_snap_frames_update: alloc failed");
        return NGX_ERROR;
    }

    snap->tracks = tf;
    snap->base.max_track_id = channel->tracks.last_id;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        tf->track_id = cur_track->in.key;
        tf->connection = cur_track->input != NULL ?
            cur_track->input->connection->number : 0;
        tf->next_frame_id = cur_track->next_frame_id;
        tf++;
    }

    tf->track_id = NGX_LIVE_INVALID_TRACK_ID;

    return NGX_OK;
}


ngx_live_persist_snap_t *
ngx_live_persist_snap_frames_create(ngx_live_channel_t *channel,
    uint32_t segment_index)
{
    ngx_pool_t                      *pool;
    ngx_live_persist_snap_frames_t  *snap;

    pool = ngx_create_pool(1024, &channel->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_snap_frames_create: create pool failed");
        return NGX_LIVE_PERSIST_INVALID_SNAP;
    }

    snap = ngx_pcalloc(pool, sizeof(*snap));
    if (snap == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_snap_frames_create: alloc failed");
        ngx_destroy_pool(pool);
        return NGX_LIVE_PERSIST_INVALID_SNAP;
    }

    snap->base.channel = channel;
    snap->base.pool = pool;
    snap->base.scope.max_index = segment_index;

    snap->base.update = ngx_live_persist_snap_frames_update;
    snap->base.close = ngx_live_persist_snap_frames_close;

    channel->snapshots++;

    return &snap->base;
}
