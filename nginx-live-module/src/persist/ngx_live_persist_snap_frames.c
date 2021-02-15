#include <ngx_config.h>
#include <ngx_core.h>
#include "../ngx_live.h"


typedef struct {
    uint32_t           track_id;
    ngx_atomic_uint_t  connection;
    uint64_t           next_frame_id;
} ngx_live_persist_snap_frames_track_t;


static void
ngx_live_persist_snap_frames_free(ngx_live_persist_snap_t *snap)
{
    ngx_live_channel_t  *channel = snap->channel;

    if (channel->snapshots <= 0) {
        ngx_log_error(NGX_LOG_ALERT, &channel->log, 0,
            "ngx_live_persist_snap_frames_free: zero ref count");
        ngx_free(snap);
        return;
    }

    channel->snapshots--;
    if (channel->snapshots <= 0) {
        ngx_live_channel_ack_frames(channel);
    }

    ngx_free(snap);
}

static void
ngx_live_persist_snap_frames_close(void *data,
    ngx_live_persist_snap_close_action_e action)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_channel_t                    *channel;
    ngx_live_persist_snap_t               *snap = data;
    ngx_live_persist_snap_frames_track_t  *tf;

    if (action == ngx_live_persist_snap_close_free) {
        goto done;
    }

    channel = snap->channel;
    tf = (void *) (snap + 1);

    ngx_log_error(NGX_LOG_INFO, &channel->log, 0,
        "ngx_live_persist_snap_frames_close: "
        "sending acks, index: %uD", snap->scope.max_index);

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        if (cur_track->in.key > snap->max_track_id ||
            cur_track->input.ack_frames == NULL)
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

        if (tf->connection != cur_track->input.connection) {
            continue;
        }

        cur_track->input.ack_frames(cur_track, tf->next_frame_id);
    }

done:

    ngx_live_persist_snap_frames_free(snap);
}

ngx_live_persist_snap_t *
ngx_live_persist_snap_frames_create(ngx_live_channel_t *channel)
{
    ngx_queue_t                           *q;
    ngx_live_track_t                      *cur_track;
    ngx_live_persist_snap_t               *snap;
    ngx_live_persist_snap_frames_track_t  *tf;

    snap = ngx_alloc(sizeof(*snap) + sizeof(*tf) * (channel->tracks.count + 1),
        &channel->log);
    if (snap == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_persist_snap_frames_create: alloc failed");
        return NGX_LIVE_PERSIST_INVALID_SNAP;
    }

    tf = (void *) (snap + 1);

    snap->channel = channel;
    snap->max_track_id = channel->tracks.last_id;
    snap->scope.max_index = channel->next_segment_index;
    snap->close = ngx_live_persist_snap_frames_close;

    for (q = ngx_queue_head(&channel->tracks.queue);
        q != ngx_queue_sentinel(&channel->tracks.queue);
        q = ngx_queue_next(q))
    {
        cur_track = ngx_queue_data(q, ngx_live_track_t, queue);

        tf->track_id = cur_track->in.key;
        tf->connection = cur_track->input.connection;
        tf->next_frame_id = cur_track->next_frame_id;
        tf++;
    }

    tf->track_id = NGX_LIVE_INVALID_TRACK_ID;

    channel->snapshots++;

    return snap;
}
