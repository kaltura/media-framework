# Nginx Live Module

Partitions incoming media frames to aligned segments (stored in memory or in object storage), for delivery using HTTP-based streaming protocols (HLS / DASH).
Acts as the "database" of the Media-Framework suite - stores the compressed media, the list of segments, the media info etc.

Dependencies: [nginx-common](../nginx-common/), [nginx-kmp-in-module](../nginx-kmp-in-module/).


## Features

- Input
    - Protocol: *KMP*
    - Media types: video / audio / subtitle
    - Codec agnostic

- Output protocol: *KSMP*

- Persistence of media and configuration in object storage (S3 or compatible)

- Support for multiple timelines - each representing a subset of the publishing time of the channel

- Support for filling gaps in media tracks, either from other tracks of the same type, or from a pre-configured filler

- Management API


## Sample Configuration

```nginx
live {
    # persistence
    store_s3_block my_bucket {
        url http://my_live_bucket.s3.amazonaws.com:80;
        access_key AKIAIOSFODNN7EXAMPLE;
        secret_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY;
        service s3;
        region us-east-1;
    }

    store_s3 my_bucket;

    persist_opaque $hostname:$live_version;
    persist_setup_path /store/channel/$channel_id/setup;
    persist_index_path /store/channel/$channel_id/index;
    persist_delta_path /store/channel/$channel_id/delta;
    persist_media_path /store/channel/$channel_id/bucket/$persist_bucket_id;

    # live presets
    preset main {
    }

    preset ll {
        ll_segmenter;
    }
}

# kmp input
stream {
    server {
        listen 8003;

        live_kmp;
    }
}

http {
    server {
        listen 8001;

        # ksmp output
        location /ksmp/ {
            live_ksmp;
        }

        # api
        location /live_api/ {
            live_api write=on upsert=on;
        }
    }
}
```


## Architecture

### Segment List And Timelines

Every channel maintains a "segment list", containing the index and the duration of all active segments.
There is a single segment list per-channel - all tracks share the same segment indexes and durations.

The reasons for using a single segment list are:
- When the live window is large (consider several days, for example), keeping a separate segment list per track can increase memory usage significantly
- DASH manifests usually provide a single `SegmentTemplate` for all the `Representation`s of an `AdaptationSet`

In order to reduce the memory usage, the segment list uses run-length encoding -
every element in the segment list is a pair of integers - count and duration.
When the keyframe interval is constant, it is likely that many segments will have exactly the same duration,
and a single element in the array could represent many segments.

Every segment that is added to the channel, is added to the segment list.
Segments are removed from the segment list when they are no longer referenced by any timeline, as the live window advances.

Every channel can contain multiple timelines, each representing a subset of the segment list.
A timeline can contain multiple periods, each period is a continuous range of segments -
- Every segment in the period starts at the exact timestamp in which the previous segment ended
- Every segment in the period has an index that is the index of the previous segment plus 1

The duration of the segments is not saved on the period object, a period only holds a "pointer" to the segment list.
Therefore, a period is a very "light" object (only ~128 bytes), no matter how many segments it references.

Usually, media is streamed continuously, and therefore timeline objects do not contain many periods.
In these cases, a timeline object can also be considered "light", and many timelines can be created on a single channel,
for different uses. For example, when streaming a TV channel, it is possible to create a separate timeline for each TV show.

As the live window progresses, old segments are removed from the manifest.
Segments that are removed, must remain valid for a certain period of time after they are removed.
Otherwise, a player that is playing the stream in delay, at the furthest point from the live edge,
may get errors while trying to pull segments.

In order to address this requirement, each timeline is internally composed of two parts: main and manifest.
The main part contains all the segments that can requested, while the manifest part contains only the
subset that is returned in the manifest.
The manifest timeline is always a "suffix" of the main timeline - it contains the same segments as the main timeline,
except for a certain number of segments removed from the beginning.
The manifest timeline is, in fact, only a "pointer" to a segment contained in the main timeline.
When a timeline is created, it is possible to specify, for example, the maximum duration of the main part (`max_duration`) vs the duration of the manifest part (`manifest_max_duration`).

Whenever a segment is added to a timeline, the total duration and the number of segments are checked against the `max_duration` / `max_segments` settings in the timeline configuration.
If needed, segments are removed from the end of timeline, until the total duration and the number of segments drop below the configured limit.

When a timeline is inactive, the `max_duration` / `max_segments` limits are applied while taking into account the time of inactivity -
- `max_duration` - The time that passed since a segment was last added to the timeline is added to the total duration of the segments.
- `max_segments` - The time that passed since a segment was last added to the timeline divided by the average segment duration is added to the total number of segments.

### Timestamp Alignment

The syncer module in nginx-live-module aligns the timestamps of incoming KMP frames to the server time, using the KMP `created` value.
Since the timestamps of segments and periods are based on the frame timestamps, it is important to ensure that the timestamps of the frames are monotonically increasing.
Otherwise, there could be overlaps between periods / segments, and it won't be possible to uniquely map a timestamp to a segment.
In addition, MPEG-DASH streaming requires the use of absolute timestamps - DASH players use the HTTP `Date` header returned in server requests to synchronize.

This module works by applying a "correction" value to incoming timestamps.
The preference is to apply a single correction value across all the tracks in the channel, in order to avoid creating synchronization issues between video and audio.
However, there could be cases in which the incoming timestamps are already out-of-sync between the tracks, and multiple correction values will be required.

The syncer module maintains multiple correction values - per-channel and pre-track.
When calculating the correction value, each track prefers to use the channel-level correction value.
Only if the channel-level correction value doesn't bring the timestamp close enough to the `created` value, a new correction value is calculated, and saved on both the track and channel.

### Segmentation Logic

In the context of nginx-live-module, a segmenter is a module that receives KMP events, and generates aligned segments across all the tracks in the channel.
The events that are handled by a segmenter module are:
1. *Start stream* (a KMP `connect` packet was received)
2. *End stream* (a KMP `end-of-stream` packet was received)
3. *Media info*
4. *Frame*

Two distinct segmenter implementations are provided with nginx-live-module:
1. *Default*
2. *Low-Latency*

The default segmenter aims to maximize the stability of the stream, while the low-latency segmenter aims to reduce the playback latency, and is intended for use with LLHLS.
Since the default segmenter can wait longer before it outputs segments, it has more visibility on keyframe positions / media info changes etc.,
and can therefore generate perfectly aligned segments, in certain cases where the low-latency segmenter cannot.

For example, the low-latency segmenter may decide to slice a segment at a position in which one video track has a key frame, and other video tracks do not.
The impact of this may be significant deviation between the segment duration that is reported in the manifest, and the actual duration of the media.
With the default segmenter, this scenario is less likely, since the default segmenter checks the positions of the keyframes across all video tracks,
and tries to slice the segments in positions that will work well for all of them.

Additional scenarios that are supported only with the default segmenter -
1. Media info change while streaming - the low-latency segmenter may not generate a new period / discontinuity in this case (explained in more detail in [Low Latency Limitations](#low-latency-limitations))
2. Gap filling - for example, if the segmenter got frames on the 540p video track, but not on the 720p video track, it can duplicate the segment of the 540p track to the 720p track.
    The quality of the two tracks is not the same, of course, but this way there won't be any gaps in the output.
3. Filler content - for example, if audio frames stop arriving on a channel that has both video and audio, the default segmenter can use pre-ingested content to fill up the gap.

#### Default Segmenter

Every track in the channel holds a list of "pending" frames, each KMP frame that is received is added to the list.
Additionally, each video track maintains a list of key frames - when a KMP keyframe is received, some of its fields are added to this list.

The segmenter manages a "state" per-track, the following states are defined -
- `inactive` - no frame was received for a configured interval (`segmenter_inactive_timeout`), or an explicit end-of-stream packet was received
- `pending` - a frame was received recently, and the total duration of pending frames is less than the configured threshold
- `ready` - a frame was received recently, and the total duration of pending frames is greater than the configured threshold

The segmenter creates segments only when there are no tracks in `pending` state.

A segment is created in the following steps:
- Prepare -
    - Find the minimum frame pts and the media types of all the tracks that have pending frames
    - Dispose any frames with timestamps lower than the end pts of the previous segment.
        Performed only for tracks that did not participate in the previous segment or when starting a new period
        (when a track joins, it may have some frames whose pts is within the range of timestamps of a previous segment, these frames need to be disposed)
- Choose the start / end timestamps for the segment -
    - Collect "candidates" for the end pts of the segment from all tracks -
        - The pts of video keyframes
        - The start pts of tracks that were not part of the previous segment
        - The end pts of inactive tracks
        - The pts of frames that have the "split" flag enabled - the split flag is enabled on the first frame after a media info change, or following a jump in timestamp values
    - Each candidate is evaluated by calculating its "span" - the actual slice pts is calculated for all tracks, assuming the specific candidate is chosen for the end pts of the segment.
        The "span" is defined as the difference between the max slice pts and the min slice pts of the tracks.
    - The candidate that is closest to the target segment duration, and has a span that is close enough to the minimum span of all candidates is chosen
- Apply the input delay - if the difference between the server clock and the estimated KMP `created` value at the end of the segment, is lower than the configured `input_delay`,
    the creation of the segment is delayed.
- Calculate the copy / remove indexes for each track - the copy index is the number of frames that are copied to the newly created segment.
    The remove index is the number of frames that are removed from the pending frames list.
    In video / audio tracks, the copy index and the remove index always have the same value (aka "split index").
    In subtitle tracks, however, the remove index may be lower than the copy index, when a caption line spans across multiple segments.
    When the end pts of the segment is close to a timestamp where a track is being added / removed, or there is a split frame,
    the segment boundary is "snapped" to the timestamp of the track add / remove / split.
    This is done in order to avoid creating a very small segment with the residue (see the `segmenter_xxx_snap_range` directives).
- Dispose the segment if the split index of some video / audio track is zero.
    The frames of all other tracks, up to the remove index, are disposed in this case, in order to avoid gaps in the resulting segments.
- Create a segment object on all the participating tracks -
    - Pull the media info from the pending queue (explained in more detail in [Pending Queue](#pending-queue))
    - Copy the metadata of the frames
    - Remove the frames from the pending list
    - Publish the creation of the segment (releases blocking requests for the segment)
- Fill media gaps on tracks that did not participate, using filler content / other tracks (explained in more detail in [Gap Filling](#gap-filling))
- Add the segment to all active timelines
- Start saving the segment to storage, if persistence is enabled in the configuration

#### Low Latency Segmenter

The low-latency segmenter is intended for use with Low-Latency HLS protocol (LLHLS).

Every track in the channel holds a queue of "pending" frames, each KMP frame that is received is first added to the queue.
On each cycle, the LL segmenter chooses the track that has the lowest pts value, and processes a frame from the head of its queue.

All input frames are forced to wait a configured number of milliseconds in queue, before they are processed (`ll_segmenter_frame_process_delay`).
This delay is added in order to give all tracks a chance to receive a frame, before selecting which track to process.

Since the LL segmenter aims to align the segment boundaries with the video keyframes, video tracks are prioritized over audio tracks:
- When there are no pending video frames on the channel, the audio frames are forced to wait an extra amount of time (`ll_segmenter_wait_video_timeout`)
- When choosing which track to process by comparing the pts values, a fixed number is added to all audio pts values (`ll_segmenter_audio_process_delay`)

The LL segmenter creates partial segments (or in short "parts") so that media frames could be published before the full segment is ready.
Unlike regular segments, partial segments are not forced to start with a keyframe.

In the HLS specification, there are strict requirements on the duration of parts, that are enforced by Apple players
(e.g. parts must have a duration that is between 85% and 100% of the part target duration, other than a couple of exceptions).
To avoid potential problems related to the duration of parts, it was decided to use a consistent partitioning scheme across all the tracks in the channel.
The reported duration of all parts is always the configured part duration, except for parts that are last in their segment,
these have their duration set to the remainder: `segment_duration - part_duration x N`.
If no frames fall within the range of timestamps of a specific part, that part is reported as a gap (`GAP=YES`).

In order to keep the latency low, the LL segmenter allows different tracks to progress independently of each other.
This means that different tracks may be working on different segment indexes at the same time.
Therefore, a segment index has a "state" per-track, the following states are defined -
- `start` - the segment was created and currently accepting frames.
    When the first track starts handling a segment index, the index is added to all active timelines (even though the duration of the segment is undetermined at this point).
- `stop` - the segment got all its frames, and no additional frames will be accepted. A segment moves to this state when:
    - The track received a frame with a timestamp that calls for starting a new segment
    - The track was flushed, either because it explicitly received an *End Of Stream* KMP packet, or due to inactivity (=no frame was received for a configured timeout)
- `end` - the segment was stopped, and the duration of the segment was decided. When a segment reaches this state, the full segment can be published in the playlist.
    Note that a segment cannot be started before the previous segment has ended, because the playlist cannot publish a part of segment N, without publishing the full duration of segment N-1.

When getting a media playlist request on a track, it is possible that some of the segments in the timeline are pending on the requested track, or maybe even do not exist yet.
These segments are excluded from the timeline returned in the KSMP response.

In addition to the per-track state, a segment index can be in one of two states on the channel level:
- `pending` - tracks are allowed to start processing the segment index.
    The LL segmenter maintains an array of the pending segment indexes, the details that are saved for each pending segment include its
    start pts, end pts (tentative initially), and the time it was created.
- `closed` - the segment ended in all active tracks. Once a segment is closed, it cannot be started, on any track.
    If the frames of some track arrive late, it is possible that the track will "miss" the segment.
    In order to reduce the chances of missing a segment, the segmenter waits a configured number of milliseconds before closing a segment (measured from the time the segment index was initially created).
    Saving a segment index to storage, starts only when the segment index is closed.

##### Subtitle Tracks

The timestamps of parts / segments are determined only by video / audio tracks - subtitle tracks do not affect the timestamps of parts / segments.

When the first video / audio track starts handling a certain part, the part is started on all subtitle tracks.
The subtitle parts are stopped when the end timestamp of the part is determined, either when -
- the next part in the segment is started, or
- the end timestamp of the segment is set

When a subtitle part is stopped, all the subtitle cues that intersect with the time range of the part are added to the part.

Unlike video / audio parts, subtitle parts are started regardless of the incoming subtitle cues.
Therefore, it is possible that when a subtitle part is stopped, no cue intersects with the time range of the part.
In this case, an empty part is created.

For the same reason, it is also possible that an entire subtitle segment will not contain any cues.
The empty subtitle segment is kept in memory until the corresponding segment index is persisted / removed from all timelines.
Even though the empty segment contains no frames, it cannot be disposed, otherwise the empty parts it contains will disappear from the manifest.

The timestamps of a subtitle cue may span across multiple parts in a segment.
A cue is never added to a segment more than once, but in this case, a single cue is referenced by multiple parts (the different parts overlap with each other).

#### Low Latency Limitations

The low-latency segmenter has several limitations, when comparing it to the default segmenter:

1. Media info changes - when there is a change in the media info on some track (for example, video resolution change),
    the segmenter has to start a new period (rendered as `#EXT-X-DISCONTINUITY` in HLS).
    Starting a new period forces to player to reset the status of its decoder.
    A media info change within a period, can make some players stall / fail.
    Since the segment list and timelines are managed on the channel level (not per-track),
    it is not possible that one track will signal discontinuity while another track will not.
    When using the LL segmenter, the first track that starts handling a segment, decides whether the segment will force the creation of a new period,
    or it will reuse an existing period. If a media info change occurs on a track that is not the first to create a segment,
    it is possible that no discontinuity will be signaled for the media info change.

2. Gap filling - a special case of the first bullet, is the gap-filling feature, either from another track or from pre-made filler content.
    The gap-filling feature duplicates a segment from one track to some other track that is missing the segment.
    This process nearly always involves a change to the media info - since the filler content is unlikely to have a media info that is identical to the original track.
    The segmenter can't tell in advance that a certain track is going to have a gap - when the segmenter figures out that a gap is about to be created,
    some other track has surely started handling the segment already. As explained in the first bullet, at this point it's too late to force a new period.
    For this reason, the gap-filling feature is not supported when using the low-latency segmenter.

3. Aligned keyframes - both the default segmenter and the low-latency segmenter require keyframes that are aligned across the different video tracks,
    in order to generate aligned segments. If a video track has additional keyframes that do not exist in other tracks, the default segmenter will ignore them.
    The low-latency segmenter, however, may try to use such a keyframe as a segment boundary. This can result in gaps or significant differences between
    the segment duration that is reported in the manifest, and the actual duration of the media.

4. Muxed segments - in order to support muxed segments with low-latency, nginx-live-module would need to:
    - Report only the subset of parts that exist in both video and audio tracks
    - Complete blocking requests only when the requested part exists in both video and audio
    - Take both tracks into account when generating rendition reports

    In order to avoid these complexities and more, the low-latency features are supported only with unmuxed video / audio segments.
    The only LLHLS feature that is supported with muxed tracks is "Playlist Delta Updates".

### Media Info Queue

In order to support changes to the media info of a track (for example, a video track that changes the video resolution while streaming),
each track keeps a queue of media info objects.

#### Pending Queue

When a media info packet is received, a new media info node is allocated, and added to the "pending" queue of the track.
The pending queue holds media info objects of pending frames that were not assigned to a segment yet.
Each media info node in the pending queue holds a "delta" counter of the number of frames that were added, since the previous node was created.
When the pending queue is not empty, the counter of the first node is decremented whenever the segmenter removes frames from its pending queue.
Once the counter reaches zero, the pending media info node at the head of queue is put into effect.

#### Active Queue

In addition to the pending queue, each track has an "active" queue of media info nodes.
The active queue holds the media info nodes that are assigned to segments.
Since media info changes are fairly rare, the active queue maintains only changes to the media info.
Each node in the active queue holds the index of the first segment that uses the media info contained in the node.
The media info of the node applies to all segments starting from its segment index, and up to the segment index of the next node in the queue.

#### Gap Filling

If media frames stop arriving on some track, segments created after this point will not exist on the track.
In order to avoid media gaps, the module attempts to fill any missing segments by copying the segments of other tracks.

For every track that is missing in a segment, the module tries to assign a "source" track to copy from.
In order to reduce the number of media info changes, once a source track is selected, it will continue to be used to fill segment gaps, as long as -
- The source track has media, and -
- The original track does not

When selecting a source for a track, the module tries to find the best match, out of the existing tracks of the specific media type.
Each track is compared to the original track that requires filling, the selection of source uses the following priority order -
- If an existing track has a non-empty `group_id` value that matches the original track, it is selected
- Prefer tracks with matching codecs
- Video: prefer closer height values
- Audio: prefer a matching number of channels
- Audio: prefer a matching sampling rate
- Audio: prefer a matching sample size
- Prefer tracks with a bitrate that is lower than the original
- Prefer tracks with a bitrate that is closer to the original

When a segment gap is filled, the media frames are not copied, instead, a "link" is created from the missing track to the source track.
This link is represented by a node in the active media info queue.
Each media info node has a `track_id` field. Most of the time, the `track_id` holds the id of the track that contains the media info node in its queue.
However, when a gap is filled, a media info node is created in the queue of the missing track, with its `track_id` field pointing to the source track.

When a KSMP request for media is received, the module looks up the media info node that applies to the requested segment
(which is the media info node with the largest segment index, that is less than or equal to the requested segment index).
The `track_id` field of this media info node, determines from which track the media segment is served.

In addition to filling gaps in segments that are created, the module has support for "backfilling" segments when a track is added.
When a track is added after the channel contains media, the module tries to find a suitable source track for the track that is being added.
If a source track is found, its media info queue is copied to the new track.
A request for an old segment on the newly added track will be served from the source track.

### Segment Cache

The segment cache maintains a tree of segments per-track, each segment object in the cache has the following fields:
- Media info - points to a node in the media info active queue
- List of frames
- Start / end dts
- Media data - a chain of buffers, pointing to the input buffers
- Parts array - each part has the following fields:
    - Start dts
    - Frames list - points to the frames list of the segment
    - Media data - a chain of buffers, pointing to the input buffers

Newly created segments are always added to the segment cache.
A segment remains in the cache until either it is persisted, or until it is not referenced by any timeline.
Segments that are persisted, can be forced to remain in the cache for a certain period, in order to avoid the need to read them from storage, if a KSMP request for media arrives.

### Persistence

This module supports storing the compressed media segments and all channel metadata in object storage.

The data is stored in multiple [KLPF](../README.md#kaltura-live-persist-file-klpf) files -
- *Setup* (`setp`) - contains all the objects of a channel that can be set using the API - tracks, variants, timelines etc.
- *Segment index* (`sgix`) - an index of the segments of a channel, contains the duration of the segment, timeline association, bitrates etc.
- *Segment media* (`sgts`) - holds the media (compressed video / audio frames) of a set of segments.
- *Filler* (`fllr`) - stores media that is used to fill gaps in input tracks, for example, a slate video image, or silent audio frames.

When a channel is created, the files are read from storage in the following order -
1. The Setup file
2. The full index file
3. The delta index file (See [Delta index](#delta-index) below)
4. The filler file - only when the channel uses a filler, and the respective filler channel wasn't already loaded to memory

The create channel API request is completed only when the process of reading the files from storage finishes.
During this time, the channel is blocked for editing - no objects can be created / updated using the API, and no KMP connections are allowed to connect to the channel.

Note that media segment files are not read when a channel is loaded.
These files are read on-demand - only when getting a request for a segment that no longer exists in the memory segment cache.

#### Media Buckets

Media segments are saved in "buckets", each bucket contains one or more segment indexes.
In this context, a "bucket" is a container of several adjacent segment indexes, not to be confused with S3 buckets.
The number of segment indexes per-bucket is set in the configuration.

For example, when using the default bucket size of 2 segments - bucket 0 contains segment indexes 0 & 1, bucket 1 contains segment indexes 2 & 3 etc.
A bucket contains all the media of the respective segment indexes - across all the tracks in the channel.
If, under this configuration, a channel has a video track and an audio track, bucket 0 may contain 4 segments: video segment 0, video segment 1, audio segment 0, audio segment 1.

The reason for saving all the tracks together in a single file, is simply in order to reduce the number of objects that are created.
A channel can easily contain a double-digit number of tracks, so this reduces the number of objects significantly.
But when a client requests a media segment, only the media of one / two tracks is required - there's no need to read the whole file.

In order to have the ability to read only parts of a media file, all media files start with a "segment table", that acts as an index for the segments stored in the file.
Every entry in the segment table holds 4 values: the track id, the segment id, the full size of the segment and the size of the segment metadata (reserved for future use).
The offset of a segment in the file is not saved explicitly in the segment table, it is derived from the segment sizes -
the segments are stored in the file one after the other, in the same order they appear in the segment table.

#### Snapshots

Since reading / writing to object storage may be slow, all the read / write operations are performed asynchronously.
The write operation does not block the nginx process, and additional segments may be created while a write operation is pending.

This presents a challenge - when a segment is created, the module has to wait until the media of the segment is written,
before it can start writing an updated index file that references the segment.
Otherwise, if the module is restarted, and it restores its state from storage, the index file may contain references to media files that do not exist in storage.

Delaying the write of the index file, adds another complexity - new segments may have been created while the write of the index file was delayed.
These segments must not be included in the index file, since their media is still being written.
To solve this issue, whenever a segment is created, the module creates a "snapshot" object.
The snapshot keeps the minimum state that is required in order to generate an index file up to the specific segment index.

In addition to the data for writing the index file, snapshots also keep the KMP frame ids of the respective segments.
Only after both the media file and index file of the segment are written, the snapshot is "closed" and KMP `ack frames` packets are sent,
for all the tracks included in the snapshot.

#### Delta Index

The index files saved by this module may grow significantly over time, for example, consider a channel with a timeline that holds all the segments of the last 14 days.
In order to reduce the possible load of writing large index files, the index files are stored in two "flavors" - main and delta.
The main file includes all segments from the beginning up to a certain point in time, while the delta file continues from that point up to the live edge.

Once the index reaches a certain size, only the delta file gets updated on each segment that is created.
When the delta file reaches a certain number of segments, the main file is saved instead.
This way, most of the time, only a small and bounded number of segments is saved to the delta index file.

When a channel is read from storage, the module reads both the main file and the delta file, and merges them together.
The delta file may not match the main index file, for example, when the segmenter is restarted immediately after it performed a full index save.
In this case, the delta file is simply ignored.

#### Write Triggers

The triggers for writing the different files are -
- *Setup* - saved X seconds after a change to a channel object (timeline, variant etc.) is performed via API.
- *Segment media* - saved when the last segment in a media bucket is created, or the channel becomes inactive.
    When a media bucket is saved due to inactivity, the `next_segment_index` is bumped to the first index of the next bucket,
    so that future segments will not write to the same bucket.
- *Segment index* - saved when a media bucket is persisted successfully.
- *Filler* - saved only when getting an explicit channel update API request, with the `save` field set to `true`.

#### Multiple Files Consistency

Since the state of the module is partitioned across several different objects, it is possible, that the different objects will not be aligned with each other.

For example, consider a case where a channel is read from storage, and the read operation is canceled (see `persist_cancel_read_if_empty`).
The module then writes a new *Setup* file (overwriting the previous one), but gets restarted before it writes a new *Index* file.
If the module tries to read the channel from storage at this point, it will read a new *Setup* file, with an old *Index* file.
This mix of versions is likely to make the read operation fail, and consequently, fail the create channel API.

To protect from this scenario, a random 64-bit `uid` is generated whenever a channel is created.
This `uid` is stored in all persisted files.
When a channel is read from storage, the *Setup* file is read first, and it sets the `uid` of the channel.
As additional files are being read, the `uid` of the file is compared to the `uid` of the channel - if the uids do not match, the file is ignored.

#### Versioning

As new features are applied to this module, changes to the format of persisted files may be required.

Some changes can be implemented in a backward compatible manner, for example, when a new type of block is added,
it is ignored by existing parsers. Another example of a backward compatible change is adding a field at the end of a block header -
since the module uses the `header_size` field of the block to access the data of the block, the new field is ignored by existing parsers.

However, some changes are not backward compatible, in the sense that existing parsers will not be able to read files created after the code change.
The module uses the `version` field in the KLPF header in order to address this issue.
Every version of the code has a range of versions that can be read, as defined by the min / max version macros in [ngx_persist_format.h](../nginx-common/src/ngx_persist_format.h).
When reading a file, the module checks its version, and if the version is not within the range of supported versions, the file is ignored (the same behavior as when the file does not exist).

When a breaking change to the format is introduced, the max version is incremented, and new files are saved with the new version value.
The code is updated so that it can read both the new version, as well as the previous one, usually by adding explicit conditions on the version of the file being read.
In order to avoid accumulating extra code for supporting old versions, some time after a breaking change is introduced, the support for the older version is removed.
The extra code that was added to support reading the old versions is removed, and the min version value is updated accordingly.

#### Error Handling

Requests to write / read from object storage can fail.
The module supports retrying failed write / read requests a few times before failing, the number of retries is set in the configuration,

When a request to read a setup / index file fails (after exhausting the configured read attempts), the channel creation fails.
When a request to read a media file fails, an error is returned to the packager, and consequently, the client's request for the segment will fail.

When a request to write a segment fails, the module truncates all timelines up to the specific segment index, once the segment is evicted from the memory cache.
Truncating the timelines reduces the size of live "window" below the size that was configured, but it prevents the module from returning non-working segment URLs in manifest responses.
Assuming the segment cache is large enough to hold a few segments, a failure to save a segment to storage is not expected to cause any interruption to users who play the stream near the live edge.
In other words, even in case of a complete outage of the storage service, playback near the live edge is expected to work flawlessly.

Failures in saving setup / index files are ignored. Additional attempts to save the index file will be made, as more segments are being added to the channel.

### Active Policy

There are a few scenarios in which tracks may be added / removed while a channel is active, for example -
1. Multi audio - an audio track with a new language is added to an existing stream
2. A temporary issue in one of the tracks - the encoder didn't send any data, the transcoder is lagging etc.
    After the glitch is over, the track may resume.
3. Some encoders don't send any audio frames when the microphone is disconnected

If a variant becomes inactive, the goal is to move players to other variants that are still active.
Therefore, when a variant is inactive, it is removed from the master playlist, so that new players that join the stream will not use it.
In addition, requests for the media playlist of the variant return HTTP error 410 (gone), in order to force existing players to move to other variants.

The "main" track of the variant determines whether the variant is active or not -
- A variant that has a video track is active if the video track is active.
- A variant that has only an audio track is active if the audio track is active.

The module supports two "policies" for determining which tracks are active -
- `last` - a track is considered active if it participated in the last segment of the timeline.
    This option is recommended for playback, in order to move players to active variants.
- `any` - a track is considered active if it participated in any segment of the timeline.
    This option is recommended for recording, in order to be able to pull all the variants that have content on the recording timeline, even if they were not included in the last segment.

### Filler

The filler feature enables the use of pre-ingested video / audio content for filling gaps in incoming media.

#### Usage

Setup:

1. Create a channel and a timeline to hold the filler content, using the API
2. Publish some video / audio tracks to the filler channel - either using one of the ingest modules (nginx-rtmp-kmp-module / nginx-mpegts-kmp-module) or using KMP directly (can use the file-to-kmp utility in the test folder)
3. Optionally, save the filler to storage - by issuing a `PUT` request on the channel, with: `{"filler": {"save": "true", "timeline_id": "id"}}`

Enable:

- When creating a channel, add the `filler` property to the channel object.
    The `filler` must be an object containing the fields: `channel_id`, `preset`, `timeline_id`.
    A filler can also be added to an existing channel, using the channel update API.

Additional guidelines:

- The preset of the filler channel should not use any `persist_xxx_path` directives, other than `persist_filler_path`, so that the segments will not be removed from the memory cache.
- The content of the filler channel should never be changed - it is recommended to use a versioning scheme on the filler channel name, and move to a new version if needed.
    Replacing the video / audio content of the filler can cause playback interruptions in channels that use it.
- Removing / changing the filler association of a channel is not supported.
- It is recommended to use a small `segment_duration` on filler channels.
- When a filler is enabled, `filler` tracks are created on the target channel, with the same names as the tracks on the filler channel.
    Therefore, the names of the tracks on the filler channel, must not conflict with "regular" tracks used for streaming media.
    It is recommended to use a naming convention that will ensure no conflict will occur.
- It is recommended to use multiple renditions of video / audio in the filler channel, so that the filler could match the original media info of the track more closely.
    For example, providing the video filler content in the most commonly used resolutions, can avoid a resolution change when the filler is used.
- Avoid the use of B-frames in video filler content.
- The timeline on the filler channel must be continuous - it must contain a single period.

#### Implementation

Setting up a filler on a channel involves the following steps:
- If the filler channel does not exist, it is loaded from storage.
    The target channel subscribes for a ready event on the filler channel, the filler setup continues only when the filler channel is ready.
    The API request that was issued to enable the filler (channel create / update), is also blocked until the filler channel is ready.
- The cycle duration of the filler content is calculated, as well as the duration of the filler segments.
- Filler tracks are created on the target channel, with the same names as the original tracks on the filler channel.
    For each track -
    - The media info is copied
    - Media segments are created
    - A link to the original media buffers is created (the filler content is not duplicated, it exists only once in memory)

As part of the setup of the filler, all the tracks are forced to have a duration that is identical to the cycle duration,
some frames may be omitted / stretched, if needed.

When the default segmenter creates a segment, and no video tracks are active, the exact duration of the segment is set according to the duration of the filler segments.

The generation of media segments from filler content happens on-the-fly, only when the module gets a request for a segment that is missing.
This makes it possible to add the filler retroactively to segments that were previously created.
For example, a channel starts publishing video-only content, then, at some point, an audio track starts publishing.
The audio of the previously created segments can be served from the filler.

The filler content can be used to fill any duration that is needed, by looping the content in a "cycle".
Conceptually, the filler creates an infinite stream that cycles from pts zero, portions of this stream are used when serving filler segments.

### Segment Info

The segment info module stores the following details about segments, on a per-track basis:
1. Bitrate - the total size of the frames of the segment divided by the segment duration
2. Gap - a boolean indicating whether the specific segment index exists on the specific track.
    For example, a gap on an audio track may be created if no audio frames are received for some time, while video frames keep arriving.

This information can later be used to generate `#EXT-X-BITRATE` / `#EXT-X-GAP` tags in HLS media playlists.

In order to reduce the memory usage, the module stores the bitrate / gap value, only when it changes, similarly to run-length encoding.
Bitrate changes are stored only when the bitrate of a segment deviates from the last stored value by a configured percent (see the `segment_info_bitrate_xxx_bound` directives).

### Memory Management

#### Block Pool

nginx-live-module is a stateful module, and live channels can remain active for long periods of time.
In order to avoid memory fragmentation over time, all the allocations that are performed after a channel is fully initialized,
are done using fixed-size blocks allocation.

The block sizes that are used fall into two categories -
1. Static - these block sizes are implicitly added, according to the sizes of the different objects that are used in nginx-live-module.
    For example, one block size is set to the size of a timeline object, another for the size of a variant object etc.
2. Dynamic - additional block sizes that are set in the configuration. When allocating a buffer of a size that is not known in advance,
    the module goes over the existing block sizes, and uses the smallest block size that is large enough to satisfy the request.

Nearly all allocations are performed in sizes that are known in advance, and use the static block sizes.
Currently, the only exception is the allocation of the codec extra data. The allocation of the extra data will use either a static or a dynamic block,
depending on the size of the extra data, and the available block sizes.

Blocks that are allocated are freed only when the channel is deleted. When a block is no longer required, it is added to a list of free blocks.
Whenever there's a need to allocate a block, the free list is checked first. Additional memory is allocated only when the free list of the specific block size is empty.

For certain types of block sizes, it is possible to control the actual size that is allocated.
For example, some block sizes are used for the allocation of list parts (similarly to `ngx_list_t`),
and the number of elements in each part can be selected.
In these cases, an attempt was made to coalesce several different block types into one size.
Using fewer block sizes, improves the memory utilization, since a freed block from one type, can be reallocated by another type.

#### Media Buffers

Media buffers are allocated in fixed-size blocks (see `input_bufs_size`), which are allocated in large buffers (512KB).
The buffers are grouped in bins according to the number of used blocks they contain.

When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers,
and enable the allocator to free unused buffers.

In order to keep the CPU utilization of the module low, media buffers are not copied (zero-copy).
To avoid the need to copy, the module implements a locking mechanism on the input buffers.
Media is received from a KMP connection, directly to a media buffer.
When the media has to be served following a KSMP request, or needs to be saved to storage, a lock is created, to prevent the buffers from being freed.
The lock is removed when the serve / save request completes.

Each media buffer lock contains -
- Reference count - multiple read / write requests may lock the same segment
- A pointer to the data that is locked - on the queue of input buffers
- Segment index - used to compare different locks to each other when freeing buffers, in order to find the minimal locked position

#### Memory Limit

In order to protect the stability of the server, all the memory allocations that are performed after a channel completes its initialization, are bound to the channel memory limit.
The default memory limit of the channel is set in the configuration, but can be updated in runtime using the API.
If an allocation fails because the memory limit is hit, the channel is deleted.

In order to reduce the risk of hitting the memory limit, the module applies several strategies to free memory,
in case the memory usage exceeds a certain threshold (see `mem_high_watermark`) -
- Reduce the `input_delay` of the channel
- Cancel pending KSMP requests that lock media buffers
- Cancel pending requests to save media segments to storage
- Avoid starting new requests to save media segments to storage

This process stops when the memory usage drops below a configured threshold (`mem_low_watermark`)


## High Level Design

### Live Modules

nginx-live-module is internally composed of multiple nginx modules.

Like other types of nginx modules (http, stream etc.), the live nginx modules can -
- Register callbacks for different configuration phases
    - Pre-configuration / post-configuration
    - Create / initialize the main configuration
    - Create / merge the preset configuration
- Declare a set of configuration directives
- Save arbitrary context data on channel / track objects
- Define variables that can be evaluated in the context of a channel

In addition to the standard nginx interfaces, the live core modules provide the following -
- Block pool memory allocation - live modules register the block sizes they need during configuration phase, and can later use the returned indexes to perform allocations in runtime
- Events - live modules can publish / subscribe to events, that are sent in the context of a channel / track
- JSON read / write - live modules can extend the channel / track API objects.
    A module can read JSON properties by adding "JSON commands", similarly to configuration directives.
    A module can write JSON properties by adding a "JSON writer".
- Persistence - live modules can define additional blocks for persistence, each with its own read / writer handler functions.

### High Level Module Overview

- *ngx_live_module* / *ngx_live_core_module* -
    - Configuration context (the `live` / `preset` blocks)
    - Configuration variables
    - Memory management
    - Support for events (used for communication between modules)
    - Support for extending API JSON objects (read / write)
    - Core objects: channel / variant / track
- *ngx_live_map_module* - configuration variable mapping
- *ngx_live_notif_module* - publish / subscribe for channel ready event (used by the filler module)
- *ngx_live_notif_segment_module* - publish / subscribe for segment ready event (used for blocking requests in LLHLS)
- *ngx_live_segment_cache_module* - memory backed segment store, stores / serves segments and partial segments
- *ngx_live_segment_index_module* - manages the lifetime of segment indexes -
    - Create persistence snapshots
    - Remove persisted segment indexes from segment cache
    - Create / release locks for segment buffers
    - Cancel requests to save / serve segments, when memory usage is too high
- *ngx_live_store_http_module* - basic functions and configuration for working with an HTTP-based storage
- *ngx_live_store_s3_module* - functions for generating S3 `GET` / `PUT` requests, including the `Authorization` header
- *ngx_live_persist_module* - functions for reading / writing files and blocks
- *ngx_live_persist_core_module* - read / write the core files (setup / index / delta / media)
- *ngx_live_persist_setup_module* - read / write the setup file and its blocks
- *ngx_live_persist_index_module* - read / write the index file and its blocks
- *ngx_live_persist_media_module* - read / write media files
- *ngx_live_persist_serve_module* - write KSMP blocks of core objects
- *ngx_live_segmenter_module* - the default segmenter - creates segments from incoming KMP frames
- *ngx_live_lls_module* - low-latency segmenter
- *ngx_live_media_info_module* - maintains the pending / active media info queues, implements gap filling
- *ngx_live_timeline_module* - manages the segment list, timelines and periods
- *ngx_live_input_bufs_module* - media buffers allocation and locking
- *ngx_live_segment_info_module* - stores the bitrates of segments and media gaps
- *ngx_live_syncer_module* - align frame timestamps to server clock
- *ngx_live_filler_module* - fill media gaps using pre-ingested content
- *ngx_live_dynamic_var_module* - store arbitrary key / value pairs per channel
- *ngx_stream_live_kmp_module* - read frames and metadata from incoming KMP connections
- *ngx_http_live_api_module* - management API
- *ngx_http_live_ksmp_module* - serve KSMP requests


## Configuration Directives

### HTTP Directives

#### live_api
* **syntax**: `live_api [write=on|off] [upsert=on|off];`
* **default**: `none`
* **context**: `location`

Enables the API interface of this module in the surrounding location block. Access to this location should be limited.

The following optional parameters can be specified:
- `write` - determines whether the API is read-only or read-write. By default, the API is read-only.
- `upsert` - controls the behavior of the API when getting a request to create an object that already exists.
    By default, attempts to create an object that already exists return error 409.
    When set to `on`, the existing object is updated with the values sent in the API request.

#### live_ksmp
* **syntax**: `live_ksmp;`
* **default**: ``
* **context**: `location`

Enables the KSMP interface of this module in the surrounding location block.
The packager (*nginx-pckg-module*) can be configured to pull from this location, in order to serve HLS / DASH streams to the player.

#### live_ksmp_comp_level
* **syntax**: `live_ksmp_comp_level level;`
* **default**: `6`
* **context**: `http`, `server`, `location`

Sets a zlib compression level for the KSMP response buffer. Acceptable values are in the range from 1 to 9.

### Stream Directives

#### live_kmp
* **syntax**: `live_kmp;`
* **default**: ``
* **context**: `server`

Enables the KMP interface of this module in the surrounding server block.

#### live_kmp_read_timeout
* **syntax**: `live_kmp_read_timeout msec;`
* **default**: `20s`
* **context**: `stream`, `server`

Defines a timeout for reading from the client connection.
The timeout is set only between two successive read operations, not for the transmission of the whole stream.
If the client does not transmit anything within this time, the connection is closed.

#### live_kmp_send_timeout
* **syntax**: `live_kmp_send_timeout msec;`
* **default**: `10s`
* **context**: `stream`, `server`

Sets a timeout for sending acks back to the client.
The timeout is set only between two successive write operations.
If the client does not receive anything within this time, the connection is closed.

#### live_kmp_log_frames
* **syntax**: `live_kmp_log_frames all | key | off;`
* **default**: `off`
* **context**: `stream`, `server`

When enabled, the module logs the metadata of every frame that is received -
1. KMP frame header - created, dts, flags, pts delay
2. Data size and MD5 hash

The value `key` can be used to log only the metadata of video keyframes.

#### live_kmp_dump_folder
* **syntax**: `live_kmp_dump_folder path;`
* **default**: ``
* **context**: `stream`, `server`

When set to a non-empty string, the module saves all incoming KMP data to files under the specified folder.
The file names have the following structure: `ngx_live_kmp_dump_{date}_{pid}_{connection}.dat`.

### Core Directives

#### live
* **syntax**: `live { ... }`
* **default**: ``
* **context**: `main`

Provides the configuration file context in which the live `preset` directives are specified.

#### preset
* **syntax**: `preset name { ... }`
* **default**: ``
* **context**: `live`

Defines a live preset. A live preset is a collection of configuration parameters used by live channels.
When a channel is created via the API, the `preset` field must point to a `preset` blocked defined in the configuration.

#### variables_hash_max_size
* **syntax**: `variables_hash_max_size size;`
* **default**: `1024`
* **context**: `live`

Sets the maximum size of the variables hash table.

#### variables_hash_bucket_size
* **syntax**: `variables_hash_bucket_size size;`
* **default**: `64`
* **context**: `live`

Sets the bucket size for the variables hash table.

#### preset_names_hash_max_size
* **syntax**: `preset_names_hash_max_size size;`
* **default**: `512`
* **context**: `live`

Sets the maximum size of the presets hash table.

#### preset_names_hash_bucket_size
* **syntax**: `preset_names_hash_bucket_size size;`
* **default**: `32|64|128`
* **context**: `live`

Sets the bucket size for the presets hash table.
The default value depends on the processor’s cache line size.

#### mem_limit
* **syntax**: `mem_limit size;`
* **default**: `64m`
* **context**: `live`, `preset`

Sets the default maximum total size of memory used by a channel.
If the limit is hit, the channel is destroyed.

The default can be modified via API using the `mem_limit` field of the channel object.

Media buffers are the largest consumer of memory.
The memory limit should be set to a value high enough to keep several media segments, across all the tracks of the channel.

#### mem_high_watermark
* **syntax**: `mem_high_watermark percent;`
* **default**: `75`
* **context**: `live`, `preset`

A memory utilization threshold, expressed as a percent of the memory limit.

If the high watermark is reached, the module applies a few strategies in order to reduce memory usage (see [Memory Limit](#memory-limit) for more details).
This process stops when the memory usage drops below the low watermark threshold.

#### mem_low_watermark
* **syntax**: `mem_low_watermark percent;`
* **default**: `50`
* **context**: `live`, `preset`

See the description of `mem_high_watermark` above.

#### mem_block_sizes
* **syntax**: `mem_block_sizes size1 [size2 [ ... ] ];`
* **default**: `64 124 644 2240`
* **context**: `live`, `preset`

Sets the sizes of the memory blocks used for allocating dynamic buffers.
All the memory allocations that are performed after a channel is initialized are performed in fixed size blocks.
This is done in order to avoid memory fragmentation over time.
Nearly all allocations are performed in sizes that are known in advance, and are implicitly added to the memory manager.
Currently, the only exception is the allocation of the codec extra data - this is the only allocation affected by this setting.

#### timescale
* **syntax**: `timescale num;`
* **default**: `90000`
* **context**: `live`, `preset`

Sets the timescale of the channel (in Hz) used for: frame timestamp, segment duration, period start time etc.
All incoming KMP tracks must conform to the timescale of the channel - re-scaling is currently not supported.

#### segment_duration
* **syntax**: `segment_duration msec;`
* **default**: `6s`
* **context**: `live`, `preset`

Sets the default duration of media segments.
The default value set in the configuration can be overridden by setting the `segment_duration` field on the channel object.

The actual duration of the segments may be different than the configured value, depending on keyframe timestamps.
For example, if the segment duration is set to the default 6 sec, but some input video track has a GOP of 8 sec, the segments will have a duration of 8 sec.

#### part_duration
* **syntax**: `part_duration msec;`
* **default**: `1s`
* **context**: `live`, `preset`

Sets the duration of partial segments, applies only when using the low-latency segmenter.

#### input_delay
* **syntax**: `input_delay msec;`
* **default**: `0`
* **context**: `live`, `preset`

Delays the creation of segments by the configured time interval.
The delay can be useful in order to give captions that arrive late (e.g. consider a human captioning service) a chance to make it into the segment.

The default value set in the configuration can be overridden by setting the `input_delay` field on the channel object.

The `input_delay` is measured based on the KMP `created` timestamp of the frame.
This behavior was chosen instead of using the clock, so that in case of a reconnect,
frames that already waited long enough, will be processed immediately.

#### input_delay_margin
* **syntax**: `input_delay_margin msec;`
* **default**: `1s`
* **context**: `live`, `preset`

Sets a safety margin for the calculation of the `input_delay`, in order to prevent the module from waiting too long.
The module calculates the time to wait according to the `created` timestamp of the frame and the server clock.
Since the incoming KMP track may have been generated by another server, there may be clock differences that affect this calculation.
If the received `created` value seems older than actual, the module will apply a delay that is too low.
However, if the received `created` value is in the future, it's more problematic - the module may wait for a very long time.
In order to protect from this scenario, the module ignores `created` values that are "too" far in the future -
`created` values that are larger than `now + input_delay_margin` are considered invalid, and the respective frames are processed immediately.

### Map Directives

#### map
* **syntax**: `map string $variable { ... }`
* **default**: ``
* **context**: `live`

Creates a new variable whose value depends on values of one or more of the source variables specified in the first parameter.

See the documentation of the `map` directive of the nginx `stream` module for more details.

#### map_hash_max_size
* **syntax**: `map_hash_max_size size;`
* **default**: `2048`
* **context**: `live`

Sets the maximum size of the map variables hash table.

#### map_hash_bucket_size
* **syntax**: `map_hash_bucket_size size;`
* **default**: `32|64|128`
* **context**: `live`

Sets the bucket size for the map variables hash table.

### Input Buffers Directives

#### input_bufs_size
* **syntax**: `input_bufs_size size;`
* **default**: `10k`
* **context**: `live`, `preset`

Sets the size of the buffers used for reading from incoming KMP connections.
The buffers are released only when the respective frames / segments are persisted / discarded.

#### input_bufs_bin_count
* **syntax**: `input_bufs_bin_count num;`
* **default**: `8`
* **context**: `live`, `preset`

Sets the number of bins that are used to group the input buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### input_bufs_max_free
* **syntax**: `input_bufs_max_free num;`
* **default**: `4`
* **context**: `live`, `preset`

Sets the maximum number of input buffers that are kept after they are no longer required.
A large value may save some memory alloc / free operations, but can also increase memory usage.

### Syncer Directives

#### syncer
* **syntax**: `syncer on | off;`
* **default**: `on`
* **context**: `live`, `preset`

Enables / disables timestamp synchronization.

#### syncer_inter_jump_log_threshold
* **syntax**: `syncer_inter_jump_log_threshold sec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets a threshold for logging jumps in the timestamps of incoming inter-frames (=non keyframes).
Inter frame timestamps are expected to be close to the timestamp of the keyframe that preceded them.
If they are too far, it could be due to some corruption in the stream or wrap around.

#### syncer_inter_jump_threshold
* **syntax**: `syncer_inter_jump_threshold sec;`
* **default**: `100s`
* **context**: `live`, `preset`

Sets a threshold for applying synchronization on video inter-frames.
Normally, synchronization happens only on video keyframes and audio frames.
A very large timestamp jump on an inter-frame is most likely an indication of a wrap around, so it triggers immediate synchronization, without waiting for the next keyframe.

#### syncer_jump_sync_frames
* **syntax**: `syncer_jump_sync_frames num;`
* **default**: `10`
* **context**: `live`, `preset`

Sets the maximum number of frames that a track can process without performing synchronization, after some other track updated the channel correction value.
When a track changes the channel correction value, the preference is to move the other tracks to the new correction value.
However, assuming the channel correction change is due to a jump in timestamp values, it is possible that the other tracks in the channel didn't reach the jump yet.
This parameter gives the other tracks a "grace period" to perform synchronization - if they process `syncer_jump_sync_frames` frames without updating their correction value,
a synchronization is forced.

#### syncer_max_backward_drift
* **syntax**: `syncer_max_backward_drift sec;`
* **default**: `20s`
* **context**: `live`, `preset`

The maximum deviation a corrected timestamp value is allowed to be below the `created` value of the frame.
If the difference between the corrected timestamp and the `created` value exceeds the limit, a new correction value is set for the track.

#### syncer_max_forward_drift
* **syntax**: `syncer_max_forward_drift sec;`
* **default**: `20s`
* **context**: `live`, `preset`

The maximum deviation a corrected timestamp value is allowed to be above the `created` value of the frame.
If the difference between the corrected timestamp and the `created` value exceeds the limit, a new correction value is set for the track.

#### syncer_correction_reuse_threshold
* **syntax**: `syncer_correction_reuse_threshold sec;`
* **default**: `10s`
* **context**: `live`, `preset`

The maximum deviation that is accepted in order to reuse the channel correction value.
In other words, the channel correction is used only if adding it to the frame timestamp results in a value that is within `syncer_correction_reuse_threshold` from the `created` value of the frame.

### Segmenter Directives

#### segmenter_min_duration
* **syntax**: `segmenter_min_duration msec;`
* **default**: `100ms`
* **context**: `live`, `preset`

The minimum segment duration that is allowed.

#### segmenter_forward_skip_threshold
* **syntax**: `segmenter_forward_skip_threshold msec;`
* **default**: `1s`
* **context**: `live`, `preset`

Sets a threshold for creating a gap in segment timestamps.
By default, when a segment is created, its start pts is set to the end pts of the previous segment.
If the min pts of the pending frames is greater than the end pts of the previous segment by more than the configured threshold,
the start pts of the new segment is set according to the pts of the pending frames.

#### segmenter_forward_jump_threshold
* **syntax**: `segmenter_forward_jump_threshold msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets a threshold for enabling the "split" flag on video keyframes / audio frames.
The split flag is enabled on frames with a pts value that is larger than the pts of the previous frame, by more than the configured threshold.
Enabling the split flag forces the creation of a new period, when the frame is used in a segment.

#### segmenter_backward_jump_threshold
* **syntax**: `segmenter_backward_jump_threshold msec;`
* **default**: `0`
* **context**: `live`, `preset`

Sets a threshold for enabling the "split" flag on video keyframes / audio frames.
The split flag is enabled on frames with a pts value that is smaller than the pts of the previous frame, by more than the configured threshold.
Enabling the split flag forces the creation of a new period, when the frame is used in a segment.

#### segmenter_inactive_timeout
* **syntax**: `segmenter_inactive_timeout msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets the timeout after a frame is received, for considering the track as inactive.

#### segmenter_start_truncate_limit
* **syntax**: `segmenter_start_truncate_limit msec;`
* **default**: `5s`
* **context**: `live`, `preset`

When starting a new period, a track that starts after the start pts of the segment by more than start_truncate_limit is ignored,
and does not make the segment dispose the segments of the other tracks in the channel.

#### segmenter_track_add_snap_range
* **syntax**: `segmenter_track_add_snap_range msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

When calculating the split indexes, a track that did not participate in the previous segment,
and starts slightly before the segment end pts, is not included in the segment - it will be added only in the next segment.
This parameter sets the threshold for postponing the addition of the track -
if the start pts of the track is greater than target_pts - track_add_snap_range, the track is not included in the segment.

#### segmenter_track_remove_snap_range
* **syntax**: `segmenter_track_remove_snap_range msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

When calculating the split indexes, an inactive track whose end pts is slightly after the segment end pts,
will flush all its pending frames in the segment. This is done in order to avoid leaving a small remainder for the next segment.
This parameter sets the threshold for flushing all the pending frames of the track -
if the end pts of the track is less than target_pts + track_remove_snap_range, all the pending frames of the track are included in the segment.

#### segmenter_split_snap_range
* **syntax**: `segmenter_split_snap_range msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

When calculating the split indexes, if the segment end pts is close to a split frame,
all frames up to the split frame are included in the segment.
This parameter sets the threshold for flushing the frames up to the split frame -
if the split pts is less than target_pts + split_snap_range, all the pending frames before the split frame are included in the segment.

#### segmenter_candidate_margin
* **syntax**: `segmenter_candidate_margin msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

Sets the threshold for considering two candidates for segment end pts as identical.
When collecting the candidates for the end pts of a segment, a candidate whose distance from a previously added candidate is lower than the configured value,
tweaks the timestamp of the existing candidate instead of adding a new value to the candidate list.

#### segmenter_keyframe_alignment_margin
* **syntax**: `segmenter_keyframe_alignment_margin msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

Sets a margin around the minimum span for segment pts candidates.
When choosing the end pts for a segment, candidates whose span is greater than the minimum span by more than the configured margin are disqualified.

#### segmenter_max_span_average
* **syntax**: `segmenter_max_span_average msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

Sets a maximum value for averaging the min/max segment split pts values.
When choosing the end pts for a segment, if the difference between the min/max split pts of the different tracks is lower than this value, the average of the min/max is used.
Otherwise, the original candidate pts is used.

#### segmenter_ready_threshold
* **syntax**: `segmenter_ready_threshold percent;`
* **default**: `150`
* **context**: `live`, `preset`

Sets the minimum duration of pending frames that is required to move a track to the "ready" state, when the channel is active.
The threshold is expressed as a percent of the segment duration, that is configured on the channel.

#### segmenter_initial_ready_threshold
* **syntax**: `segmenter_initial_ready_threshold percent;`
* **default**: `200`
* **context**: `live`, `preset`

Sets the minimum duration of pending frames that is required to move a track to the "ready" state, when the channel is inactive.
The threshold is expressed as a percent of the segment duration, that is configured on the channel.

#### segmenter_max_skip_frames
* **syntax**: `segmenter_max_skip_frames num;`
* **default**: `2000`
* **context**: `live`, `preset`

Sets the maximum number of frames that may be skipped, after a KMP connection is re-established.
When a KMP connection is re-established, the segmenter may receive frames that it already processed.
For example, one possible cause is that the connection was dropped before an ack packet was received by the KMP publisher.
The number of frames to skip is set to the difference between the id of the last frame that was processed by the segmenter,
and the `initial_frame_id` sent in the KMP `connect` packet.
If the difference is too large, the `initial_frame_id` value is considered invalid, and the segmenter does not skip any frames.

### Low-latency Segmenter Directives

#### ll_segmenter
* **syntax**: `ll_segmenter;`
* **default**: ``
* **context**: `live`, `preset`

Enables the low-latency segmenter on the surrounding `preset`.

#### ll_segmenter_max_pending_segments
* **syntax**: `ll_segmenter_max_pending_segments num;`
* **default**: `5`
* **context**: `live`, `preset`

The maximum number of pending segment indexes.
If there is a need to start a segment index and there are no available slots, the oldest pending segment index is forcefully closed.

#### ll_segmenter_min_part_duration
* **syntax**: `ll_segmenter_min_part_duration msec;`
* **default**: `50ms`
* **context**: `live`, `preset`

The minimum duration of a part.
When a part is started, the segment duration is forced to be at least - part_duration * N + min_part_duration.

#### ll_segmenter_inactive_timeout
* **syntax**: `ll_segmenter_inactive_timeout msec;`
* **default**: `2s`
* **context**: `live`, `preset`

Sets the timeout after a frame is received, for considering the track as inactive, and flushing the current segment.

#### ll_segmenter_forward_jump_threshold
* **syntax**: `ll_segmenter_forward_jump_threshold msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets a threshold for enabling the "split" flag on video keyframes / audio frames.
The split flag is enabled on frames with a pts value that is larger than the pts of the previous frame, by more than the configured threshold.
Enabling the split flag can force the creation of a new period, when the frame is used in a segment.

#### ll_segmenter_backward_jump_threshold
* **syntax**: `ll_segmenter_backward_jump_threshold msec;`
* **default**: `0`
* **context**: `live`, `preset`

Sets a threshold for enabling the "split" flag on video keyframes / audio frames.
The split flag is enabled on frames with a pts value that is smaller than the pts of the previous frame, by more than the configured threshold.
Enabling the split flag can force the creation of a new period, when the frame is used in a segment.

#### ll_segmenter_dispose_threshold
* **syntax**: `ll_segmenter_dispose_threshold msec;`
* **default**: `250ms`
* **context**: `live`, `preset`

Sets a threshold for disposing frames that have a pts value that is smaller than the pts of the previous segment.
If the pts of the frame is smaller than the pts of the previous segmenter by more than the configured threshold, the frame is disposed.

#### ll_segmenter_start_period_threshold
* **syntax**: `ll_segmenter_start_period_threshold msec;`
* **default**: `500ms`
* **context**: `live`, `preset`

Sets the threshold for starting a new period due to a jump in pts value.
When starting a new pending segment, if the pts of the frame is larger than the pts of the last segment,
by at least the configured threshold, the new segment will start a new period.

#### ll_segmenter_frame_process_delay
* **syntax**: `ll_segmenter_frame_process_delay msec;`
* **default**: `100ms`
* **context**: `live`, `preset`

The minimum delay for processing an input frame.
A larger delay gives all tracks more time to receive their frames, so that the frame with minimum pts will indeed be processed first.
This reduces, for example, the probability of dropping frames when the different tracks do not start at the same timestamp.
The downside of a larger delay is, of course, higher latency.

#### ll_segmenter_audio_process_delay
* **syntax**: `ll_segmenter_audio_process_delay msec;`
* **default**: `100ms`
* **context**: `live`, `preset`

Sets the value that is added to the pts of audio frames when the segmenter chooses which frame to process.
The reason for this prioritization of video frames over audio frames, is that the segmenter tries to align the segments to the timestamps of the video keyframes.
A larger value gives the video tracks a more significant boost, but it also increases the latency of audio tracks.
Since the player tries to the play the video and audio in sync, a larger value increases the overall latency of the stream.

#### ll_segmenter_wait_video_timeout
* **syntax**: `ll_segmenter_wait_video_timeout msec;`
* **default**: `3s`
* **context**: `live`, `preset`

The minimum delay for processing audio frames when no pending video frames exist on the channel.
The segmenter prefers to wait for video frames, so that it can choose a segment duration that is aligned with the video keyframes.
A large value increases the latency of audio-only streams, if that is a concern, it may be best to use a separate `preset` for audio-only.

#### ll_segmenter_close_segment_delay
* **syntax**: `ll_segmenter_close_segment_delay msec;`
* **default**: `5s`
* **context**: `live`, `preset`

The minimum delay for closing a segment, measured from the time the pending segment was initially added.

#### ll_segmenter_segment_start_margin
* **syntax**: `ll_segmenter_segment_start_margin percent;`
* **default**: `15`
* **context**: `live`, `preset`

When the segmenter starts a segment on some track, it first tries to reuse some pending segment that already exists on the channel.
An existing pending segment is reused only when the pts of the frame is smaller than the end pts of the pending segment, including some margin.
The size of the margin is specified as a percent of the duration of the pending segment.

For example, with the default value of 15, if there is a pending segment index on the channel that spans from pts 10 to pts 16 sec,
a track may reuse the existing segment only if the pts of the frame is below `16 - (16 - 10) * 0.15 = 15.1 sec`.
If the frame has a pts value larger than 15.1, it will either use the next pending segment index (if already exists), or create a new one.

#### ll_segmenter_video_end_segment_margin
* **syntax**: `ll_segmenter_video_end_segment_margin percent;`
* **default**: `15`
* **context**: `live`, `preset`

Sets a threshold for starting a new segment, when getting a video key frame that is close to the configured segment duration.
This threshold is used only when the duration of the pending segment is not finalized.

For example, with the default value of 15, and the default segment duration of 6 sec, a video keyframe with a pts that is greater
than the start pts of the segment by at least `6 * 0.85 = 5.1` sec, will close the existing segment, and start a new one.

#### ll_segmenter_video_duration_margin
* **syntax**: `ll_segmenter_video_duration_margin percent;`
* **default**: `5`
* **context**: `live`, `preset`

Sets a threshold for starting a new segment, when getting a video key frame that is close to the configured segment duration.
This threshold is used only when the duration of the pending segment is already finalized.

#### ll_segmenter_max_skip_frames
* **syntax**: `ll_segmenter_max_skip_frames num;`
* **default**: `2000`
* **context**: `live`, `preset`

Sets the maximum number of frames that may be skipped, after a KMP connection is re-established.
When a KMP connection is re-established, the segmenter may receive frames that it already processed.
For example, one possible cause is that the connection was dropped before an ack packet was received by the KMP publisher.
The number of frames to skip is set to the difference between the id of the last frame that was processed by the segmenter,
and the `initial_frame_id` sent in the KMP `connect` packet.
If the difference is too large, the `initial_frame_id` value is considered invalid, and the segmenter does not skip any frames.

### Segment Info Directives

#### segment_info_gaps
* **syntax**: `segment_info_gaps on | off;`
* **default**: `on`
* **context**: `live`, `preset`

Enables / disables tracking of segment gaps.

#### segment_info_bitrate
* **syntax**: `segment_info_bitrate on | off;`
* **default**: `off`
* **context**: `live`, `preset`

Enables / disables tracking of segment bitrates.

#### segment_info_bitrate_lower_bound
* **syntax**: `segment_info_bitrate_lower_bound percent;`
* **default**: `90`
* **context**: `live`, `preset`

The bitrate of a segment is stored if it is below `segment_info_bitrate_lower_bound` percent of the last stored bitrate, for the specific track.

#### segment_info_bitrate_upper_bound
* **syntax**: `segment_info_bitrate_upper_bound percent;`
* **default**: `110`
* **context**: `live`, `preset`

The bitrate of a segment is stored if it is above `segment_info_bitrate_upper_bound` percent of the last stored bitrate, for the specific track.

### Persistence Directives

#### persist_write
* **syntax**: `persist_write on | off;`
* **default**: `on`
* **context**: `live`, `preset`

Enables / disables writing to the persistence files.
This setting can be used to load a channel in "read-only" mode, without the risk of losing data.

#### persist_comp_level
* **syntax**: `persist_comp_level level;`
* **default**: `6`
* **context**: `live`, `preset`

Sets a zlib compression level for the persisted index files. Acceptable values are in the range from 1 to 9.
Note that media files are never compressed using zlib.

#### persist_opaque
* **syntax**: `persist_opaque expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets a string that is written to the persisted files.
The module does not make any use of this string, other than logging it when a channel is read.
This setting can be used, for example, to save the name of the server which created the file, for investigation purposes.
The parameter value can contain variables.

#### persist_setup_path
* **syntax**: `persist_setup_path expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets the path of the setup file.
If the directive is not set, the module does not read / write the setup.

The parameter value can contain variables.
The `$channel_id` variable should be used in order to save different channels to different files.

#### persist_setup_max_size
* **syntax**: `persist_setup_max_size size;`
* **default**: `5m`
* **context**: `live`, `preset`

Sets the maximum uncompressed size of the setup file.
If the size of a setup file exceeds the limit, it will be rejected, and the channel creation will fail.

#### persist_index_path
* **syntax**: `persist_index_path expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets the path of the index file.
If the directive is not set, the module does not read / write the index.

The parameter value can contain variables.
The `$channel_id` variable should be used in order to save different channels to different files.

#### persist_delta_path
* **syntax**: `persist_delta_path expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets the path of the delta index file.
If the directive is not set, the module does not read / write the delta index.

The parameter value can contain variables.
The `$channel_id` variable should be used in order to save different channels to different files.

#### persist_media_path
* **syntax**: `persist_media_path expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets the path of the delta index file.
If the directive is not set, the module does not read / write media segments.

The parameter value can contain variables.
The `$channel_id` and `$persist_bucket_id` variables should be used in order to save different media buckets to different files.

#### persist_filler_path
* **syntax**: `persist_filler_path expr;`
* **default**: ``
* **context**: `live`, `preset`

Sets the path of the filler file.
If the directive is not set, the module does not read / write the filler.

The parameter value can contain variables.
The `$channel_id` variable should be used in order to save different channels to different files.

#### persist_cancel_read_if_empty
* **syntax**: `persist_cancel_read_if_empty on | off;`
* **default**: `on`
* **context**: `live`, `preset`

If the directive is set to `on` and the channel contains no segments after it is read, the read operation is canceled, and a new channel is created.
When there are no segments, previously created tracks / variants may be irrelevant, so it's safer to ignore them and start fresh.
One possible cause for a channel to lose all its segments after being read, is due to the `max_duration` / `max_segments` settings on the timeline.

#### persist_max_delta_segments
* **syntax**: `persist_max_delta_segments num;`
* **default**: `100`
* **context**: `live`, `preset`

The maximum number of segments in a delta index file.
If the number of segments created since the last index save exceeds `persist_max_delta_segments`, a full index save is performed.
For example, when using the default value of 100, a full index is saved only once every 100 segments.

#### persist_bucket_size
* **syntax**: `persist_bucket_size num;`
* **default**: `2`
* **context**: `live`, `preset`

Sets the number of segment indexes in each media bucket.

#### persist_media_initial_read_size
* **syntax**: `persist_media_initial_read_size size;`
* **default**: `4k`
* **context**: `live`, `preset`

Sets the size of the initial read request that is performed when reading a media segment file.
The configured size must be large enough to read the whole segment table.

The size of the file header together with the segment table header is at least 52 bytes,
and every entry in the segment table is 24 bytes.
Therefore, the default value of 4k, can handle files with at most `(4096 - 52) / 24 = 168` segments.
With the default bucket size of 2 segments, there can be at most `168 / 2 = 84` active tracks.

#### persist_bucket_time
* **syntax**: `persist_bucket_time $variable format [gmt|local];`
* **default**: ``
* **context**: `live`

Creates a new variable whose value depends on the timestamp of the media bucket being saved.
This directive can be used in order to arrange the media buckets in a folder structure according to their timestamp.
The format parameter specifies the time format using strptime syntax, for example, use `%Y/%m/%d` for `yyyy/mm/dd`.
The optional timezone parameter can be used to choose between `gmt` and `local`, the default is `local`.

#### persist_setup_timeout
* **syntax**: `persist_setup_timeout msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets the timeout for saving the setup file, following a change to the channel configuration.
Saving the setup file is delayed in order to reduce the number of times the file is saved during the initial setup, which often involves several frequent updates.

### HTTP Storage Directives

#### store_http_read_req_timeout
* **syntax**: `store_http_read_req_timeout msec;`
* **default**: `2s`
* **context**: `live`, `preset`

Sets the timeout for sending a request to read a file from storage.

#### store_http_read_resp_timeout
* **syntax**: `store_http_read_resp_timeout msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets the timeout for getting the response of a request to read a file from storage.

#### store_http_read_buffer_size
* **syntax**: `store_http_read_buffer_size size;`
* **default**: `4k`
* **context**: `live`, `preset`

Sets the size allocated for reading the headers of read requests.

#### store_http_read_retries
* **syntax**: `store_http_read_retries num;`
* **default**: `0`
* **context**: `live`, `preset`

Sets the number of retries on failed read requests.

#### store_http_read_retry_interval
* **syntax**: `store_http_read_retry_interval msec;`
* **default**: `1s`
* **context**: `live`, `preset`

Sets the interval for retrying a read request after a read request fails.

#### store_http_write_req_timeout
* **syntax**: `store_http_write_req_timeout msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets the timeout for sending a request to write a file to storage.

#### store_http_write_resp_timeout
* **syntax**: `store_http_write_resp_timeout msec;`
* **default**: `10s`
* **context**: `live`, `preset`

Sets the timeout for getting the response of a request to write a file to storage.

#### store_http_write_buffer_size
* **syntax**: `store_http_write_buffer_size size;`
* **default**: `4k`
* **context**: `live`, `preset`

Sets the size allocated for reading the response of write requests.

#### store_http_write_retries
* **syntax**: `store_http_write_retries num;`
* **default**: `5`
* **context**: `live`, `preset`

Sets the number of retries on failed write requests.

#### store_http_write_retry_interval
* **syntax**: `store_http_write_retry_interval msec;`
* **default**: `2s`
* **context**: `live`, `preset`

Sets the interval for retrying a write request after a write request fails.

### S3 Storage Directives

#### store_s3_block
* **syntax**: `store_s3_block name { ... }`
* **default**: ``
* **context**: `live`

Defines the parameters of an S3 bucket used for persistence.

#### store_s3
* **syntax**: `store_s3 name;`
* **default**: ``
* **context**: `live`, `preset`

Enables persistence using the specified S3 bucket.
The name parameter must match the name of a previously defined `store_s3_block` block.

#### store_s3_put_add_header
* **syntax**: `store_s3_put_add_header name value;`
* **default**: ``
* **context**: `live`, `preset`

Adds an HTTP header to PUT requests sent to S3.
The header value can contain variables.

#### url
* **syntax**: `url str;`
* **default**: ``
* **context**: `store_s3_block`

Sets the URL of the S3 bucket, usually in the format: `http://{bucket_name}.s3.amazonaws.com:80`.

#### host
* **syntax**: `host name;`
* **default**: ``
* **context**: `store_s3_block`

Sets the value of the Host header in S3 requests.
By default, if the `host` is not set explicitly, the host part of the `url` is used.

#### access_key
* **syntax**: `access_key key;`
* **default**: ``
* **context**: `store_s3_block`

Sets the AWS access key, e.g. `AKIAIOSFODNN7EXAMPLE`.

#### secret_key
* **syntax**: `secret_key key;`
* **default**: ``
* **context**: `store_s3_block`

Sets the AWS secret key, e.g. `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.

#### service
* **syntax**: `service name;`
* **default**: ``
* **context**: `store_s3_block`

The name of the AWS service, normally set to `s3`.

#### region
* **syntax**: `region name;`
* **default**: ``
* **context**: `store_s3_block`

Sets the AWS region, e.g. `us-east-1`.

### Misc Directives

#### force_memory_segments
* **syntax**: `force_memory_segments num;`
* **default**: `6`
* **context**: `live`, `preset`

The number of segments that are forced to remain in the memory cache, even after they are saved successfully to storage.
A higher number increases the probability of a hit on the segment cache, avoiding the need to read from storage, and improving response time.
However, the trade-off is that a higher number also increases the memory usage.

#### dynamic_var_max_size
* **syntax**: `dynamic_var_max_size size;`
* **default**: `920`
* **context**: `live`, `preset`

Sets the size allocated for each dynamic variable. The size includes both the key and the value.
Dynamic variables are set using the `vars` field on the channel object, and can be accessed using the `$var_{name}` variables.


## API Objects

The sections below list the possible fields in each type of API object.
The details provided for each field include -
- Name
- Type - string / integer / object ...
- Operations - C = Create, R = Read, U = update
- Description

### Global Scope

- `version` - string (R), nginx-live-module version
- `nginx_version` - string (R), nginx version
- `compiler` - string (R), the compiler used to build nginx-live-module
- `built` - string (R), the time nginx-live-module was built
- `pid` - integer (R), the nginx process id
- `time` - integer (R), the current unix timestamp
- `uptime` - integer (R), the time since the nginx worker was started, in seconds
- `channels` - object (R), the keys hold the channel id, while the values are [Channel Objects](#channel-object)
- `zombie_input_bufs` - object (R), contains statistics about "zombie" media buffers.
    Zombie buffers are created when the media buffers remain locked when a channel is freed.
    Normally, zombie buffers should not exist, since all save / serve requests that lock media buffers are canceled when the channel is freed.
    The object contains the following fields:
    - `size` - integer (R), the total size of memory occupied by zombie buffers
    - `count` - integer (R), the total number of zombie buffer queues
    - `lock_count` - integer (R), the total number of locks across all zombie buffers
- `store` - object (R), contains statistics about storage reads/writes, the object contains the following fields:
    - `s3` - object (R), contains statistics about s3 reads/writes.
        The keys are s3 block names, as defined using the `store_s3_block` directive.
        The values are objects, containing two fields - `read` / `write`.
        Each one of them is an object containing the following fields:
        - `started` - integer (R), the number of requests that were started
        - `error` - integer (R), the number of failed requests
        - `success` - integer (R), the number of successful requests
        - `success_msec` - integer (R), the total number of milliseconds consumed by successful requests
        - `success_size` - integer (R), the total number of bytes that were successfully written / read

### Channel Object

- `id` - string (C), the channel id. The maximum allowed length is 32 chars.
- `blocked` - boolean (R), returns `true` when the channel is being loaded from storage
- `uid` - hex string (R), a unique identifier generated when the channel was initially created
- `uptime` - integer (R), number of seconds since the channel was initially created
- `read` - boolean (C), when set to false, skip trying to load the channel from storage, always create a new channel (can be used in case there is corruption in the persisted files)
- `read_time` - integer (R), unix timestamp of the time the channel was read from storage, returns 0 if the channel was not read
- `preset` - string (CR), the name of the configuration `preset` block used by the channel
- `opaque` - string (CRU), can be used to store arbitrary data on the channel object
- `initial_segment_index` - integer (CR), the index of the first segment, default to 0
- `mem_left` - integer (R), number of memory bytes left out of the `mem_limit` quota
- `mem_limit` - integer (CRU), maximum number of memory bytes the channel is allowed to consume
- `mem_watermark_events` - integer (R), the number of times the channel reached the `mem_high_watermark` threshold
- `mem_blocks` - array of objects (R), returns statistics about memory blocks utilization, each object contains the following fields:
    - `block_size` - integer (R), the size of the block in bytes
    - `nalloc` - integer (R), the number of allocations that were done using this block size
    - `size` - integer (R), the total number of bytes allocated to blocks of this size
    - `auto_used` - integer (R), the total number of bytes requested by "auto" allocations that used this block size
    - `auto_nalloc` - integer (R), the number of "auto" allocations that used this block size
- `last_segment_created` - integer (R), unix timestamp of the last time a segment was created on the channel
- `last_accessed` - integer (R), unix timestamp of the last time a KSMP request for the channel was received
- `segment_duration` - integer (CRU), the target segment duration in milliseconds
- `input_delay` - integer (CRU), a configurable delay in milliseconds for the creation of segments
- `filler` - object (CR), contains the details of the filler content used by the channel, contains the following fields:
    - `channel_id` - string (CR), the id of the filler channel
    - `preset` - string (C), the configuration `preset` for the filler channel
    - `timeline_id` - string (CRU), the id of the timeline on the filler channel
    - `segments` - integer (R), the number of filler segments
    - `save` - boolean (U), when set to `true`, the channel is saved to a file that can later be loaded as filler.
        In this case, only the `timeline_id` field is required, the other fields are ignored.
- `snapshots` - integer (R), the number of active snapshots that exist for the channel
- `tracks` - object (R), the keys hold the track id, while the values are [Track Objects](#track-object)
- `variants` - object (R), the keys hold the variant id, while the values are [Variant Objects](#variant-object)
- `segment_cache` - object (R), returns statistics about the usage of the segment cache, contains the following fields:
    - `read_count` - integer (R), the number of KSMP media requests that were served from the segment cache
    - `read_size` - integer (R), the total number of bytes of media served from the segment cache
- `persist` - object (R), contains persistence statistics. The keys: `setup`, `index`, `delta`, `media` return statistics about write requests for each file type.
    The key `media_read` returns statistics about read requests for media. Each of the internal objects contain a subset of the following fields:
    - `pending` - integer (R), the number of requests that are currently in-progress
    - `error` - integer (R), the number of failed requests
    - `success` - integer (R), the number of successful requests
    - `success_msec` - integer (R), the total number of milliseconds consumed by successful requests
    - `success_size` - integer (R), the total number of bytes that were successfully written / read
    - `version` - integer (R), the current "setup" version of the channel
    - `success_version` - integer (R), the last "setup" version that was successfully written
    - `success_index` - integer (R), the last segment index successfully written
    - `cancel` - integer (R), the number of read requests that were canceled (in order to release buffer locks and free channel memory)
- `timelines` - object (R), the keys hold the timeline id, while the values are [Timeline Objects](#timeline-object)
- `segment_list` - object (R), returns statistics about the segment list, contains the following fields:
    - `node_count` - integer (R), the number of segment list nodes allocated in memory
    - `elt_count` - integer (R), the total number of segment list elements, each element represents a set of consecutive segments with identical duration
    - `segment_count` - integer (R), the total number of segments in the segment list
    - `min_index` - integer (R), the oldest segment that currently exists in the segment list
    - `min_index` - integer (R), the newest segment that currently exists in the segment list
- `truncate` - integer (R), the last segment index that could not be saved successfully, a caused truncation of the timelines. Returns zero if the timelines were never truncated.
- `syncer` - object (R), returns the statistics of the syncer module, contains the following fields:
    - `correction` - integer (R), the current channel-level correction value
    - `count` - integer (R), the number of times the channel correction value was updated
- `vars` - object (CRU), can be used to store arbitrary key / value pairs on the channel object (aka dynamic variables)

### Track Object

- `id` - string (C), the track id. The maximum allowed length is 32 chars.
- `media_type` - string (CR), the media type - video / audio / subtitle
- `type` - string (R), the type of the track, the following values are defined:
    - `default` - a regular track
    - `filler` - a local copy of a track from the filler channel
- `uptime` - integer (R), number of seconds since the track was initially created
- `opaque` - string (CRU), can be used to store arbitrary data on the track object
- `input` - object | null (R), returns statistics about the KMP input currently connected to the track.
    See [Input Object](../nginx-kmp-in-module/README.md#input-object) for more details.
    `null` is returned if no input connection is currently connected to the track.
- `last_segment_bitrate` - integer (R), the bitrate of the last segment in bits per second.
    The value is 0, if the last segment does not exist on the track.
    The value is 1, if the bitrate of the last segment was not calculated, for example, if the segment is shorter than the configured threshold.
- `segment_cache` - object (R), returns statistics about the segments stored in the cache, contains the following fields:
    - `count` - integer (R), the number of segments in the cache
    - `parts` - integer (R), the number of partial segments in the cache
    - `min_index` - integer (R), the oldest segment index stored in the cache
    - `max_index` - integer (R), the newest segment index stored in the cache
- `pending_segments` - integer (R), the number of pending segments on the track (only when using the low-latency segmenter)
- `pending_frames` - integer (R), the number of frames that are waiting to be added to a segment
- `last_created` - integer (R), the KMP `created` value of the last frame that was added to the segmenter
- `received_bytes` - integer (R), the total size of media frames received by the segmenter
- `received_frames` - integer (R), the total number of frames received by the segmenter
- `received_key_frames` - integer (R), the total number of keyframes received by the segmenter
- `dropped_frames` - integer (R), the total number of frames that were dropped by the segmenter. For example, frames may be dropped, if there are overlaps in the timestamps of incoming frames
- `latency` - object (R), the best-case output latency.
    The latency values are updated whenever a partial segment is created, the latency is defined as the difference between the KMP `created` value of the first frame of the part and the server clock.
    When running in multi-server environments, the measurement may be inaccurate due to clock differences.
    The object contains the following fields:
    - `min` - integer (R), the minimum latency, in timescale units
    - `max` - integer (R), the maximum latency, in timescale units
    - `avg` - integer (R), the average latency, in timescale units
- `group_id` - string (CRU), can be used to group tracks that contain the same media parameters (width, height etc.).
    When filling a gap in some track, the preference is to use a track with a matching group id.
    This can be used, for example, to pair the primary and backup versions of the same rendition.
    The maximum allowed length is 32 chars.
- `gap_fill_dest` - integer (R), the number of segments that were copied to this track in order to fill media gaps, since the channel was created on the server (not persisted)
- `gap_fill_source` - integer (R), the number of segments that were copied from this track in order to fill media gaps, since the channel was created on the server (not persisted)
- `media_info` - object (R), returns statistics about the media info queue of the track, contains the following fields:
    - `added` - integer (R), the total number of media info nodes that were created
    - `removed` - integer (R), the total number of media info nodes that were removed, due to the sliding of the live window
    - `source` - string (R), returns the source track id. This field is returned only when the track was not included in the last segment, and the gap was filled from another track
    - `last` - object (R), the last media info node that was added, see [Media Info Node](#media-info-node)
- `input_bufs` - object (R), returns statistics about the use of media buffers, contains the following fields:
    - `size` - integer (R), the total size used by the media buffers of the track
    - `min_used_index` - integer (R), the oldest segment index whose buffers exist in the queue
    - `lock_count` - integer (R), the number of active buffer locks. A buffer lock is created when a KSMP request for media is served from cache, and when a segment is saved to storage
    - `min_lock_index` - integer (R), the oldest segment index that is currently being locked
- `syncer` - object (R), returns the statistics of the syncer module, contains the following fields:
    - `correction` - integer (R), the current track-level correction value
    - `count` - integer (R), the number of times the track correction value was updated

### Media Info Node Object

#### Common Fields

- `segment_index` - integer (R), the first segment index that used this media info node
- `codec_id` - integer (R), the KMP codec identifier, see the KMP_CODEC_XXX constants in [ngx_live_kmp.h](../nginx-common/src/ngx_live_kmp.h)
- `bitrate` - integer (R), the bitrate in bits per second, as reported in the KMP *Media info* packet
- `extra_data` - hex string (R), the private / extra data of the codec
- `bitrate_max` - integer (R), the maximum bitrate in bits per second of segments that use this media info node
- `bitrate_avg` - integer (R), the average bitrate in bits per second of segments that use this media info node
- `frame_rate_min` - float (R), the minimum frame rate of segments that use this media info node
- `frame_rate_max` - float (R), the maximum frame rate of segments that use this media info node
- `frame_rate_avg` - float (R), the average frame rate of segments that use this media info node

#### Video Fields

- `width` - integer (R), the video width in pixels
- `height` - integer (R), the video height in pixels
- `frame_rate` - float (R), the video frame rate in frames per second
- `cea_captions` - boolean (R), returns `true` when EIA-608 / CTA-708 captions were detected in the video stream

#### Audio Fields

- `channels` - integer (R), the number of audio channels
- `channel_layout` - hex string (R), a bit mask of the audio channels, see the KMP_CH_XXX constants in [ngx_live_kmp.h](../nginx-common/src/ngx_live_kmp.h)
- `bits_per_sample` - integer (R), the number of bits in each audio sample
- `sample_rate` - integer (R), the sampling rate of the audio in Hz

### Variant Object

- `id` - string (C), the variant id. The maximum allowed length is 32 chars.
- `track_ids` - object (CRU), the keys are media types (video / audio / subtitle), the values are track ids
- `opaque` - string (CRU), can be used to store arbitrary data on the variant object
- `label` - string (CRU), a "friendly" name for the variant, sent to the player in HLS / DASH manifests. The maximum allowed length is 64 chars.
- `lang` - string (CRU), an RFC5646 language code (e.g. `en`)
- `role` - string (CRU), the role of the media contained in the variant, the following values are defined:
    - `main` - the main content of the stream
    - `alternate` - used to provide an alternative audio track, usually for supporting multiple languages
- `is_default` - boolean (CRU), can be used to mark the default variant of the specific type.
    This field controls the `AUTOSELECT` / `DEFAULT` attributes of `EXT-X-MEDIA`, when streaming HLS
- `active` - boolean (R), returns `true` when the tracks of the variant were included in the last segment that was created

### Timeline Object

- `id` - string (C), the timeline id. The maximum allowed length is 32 chars.
- `conf` - object (CRU), the configuration of the timeline, contains the following fields:
    - `active` - boolean (CRU), when set to `true`, new segments that are being created will be added to this timeline
    - `no_truncate` - boolean (CRU), when set to `true`, the timeline is not truncated in case of an error saving a segment to storage.
        An implication of this is that the timeline may reference segments that are inaccessible
    - `end_list` - string (CRU), controls the signaling of `#EXT-X-ENDLIST` in media playlists, the following values are defined:
        `off` - no `#EXT-X-ENDLIST` is returned
        `on` - return `#EXT-X-ENDLIST`, unless the timeline contains a pending segment, or some segments were removed from the timeline since they are pending on the track (low-latency mode only)
        `forced` - always return `#EXT-X-ENDLIST`, unless the `max_segment_index` KSMP parameter was used, and removed some segments from the response
    - `period_gap` - integer (CRU), when set to a value other than -1, sets a fixed gap in the timestamps between periods, in timescale units.
        This field can be used to "swallow" the gaps between periods, to create a stream with continuous timestamps (used in the recording / live-to-vod flow)
    - `max_segments` - integer (CRU), sets the maximum number of segments in the timeline
    - `max_duration` - integer (CRU), sets the maximum duration of the segments in the timeline, in timescale units
    - `start` - integer (CRU), sets the start timestamp of the timeline, in timescale units.
        New segments that are being created are added to the timeline only if their timestamp is greater than `start`.
        If the timeline is created from another timeline (using the `source` field), only segments with timestamp greater than `start` are copied
    - `end` - integer (CRU), sets the end timestamp of the timeline, in timescale units.
        New segments that are being created are added to the timeline only if their timestamp is less than `end`.
        If the timeline is created from another timeline (using the `source` field), only segments with timestamp less than `end` are copied.
        A zero value for `end` is implicitly translated to max int
    - `manifest_max_segments` - integer (CRU), sets the maximum number of segments in the manifest timeline
    - `manifest_max_duration` - integer (CRU), sets the maximum duration of the segments in the manifest timeline, in timescale units
    - `manifest_expiry_threshold` - integer (CRU), when set to a positive number, defines a timeout after the last segment is created for considering the timeline as expired.
        When the timeline is expired, requests for manifests return HTTP error 410 (gone)
        The value is set as a percentage of the segment duration. For example, if the value is set to `300`, the timeline is expired after a timeout of 3 segment durations.
    - `manifest_target_duration_segments` - integer (CRU), sets the number of segments that are probed to set the value of `#EXT-X-TARGETDURATION`.
        The HLS spec has two conflicting requirements about the value of the target duration:
        1. The rounded duration of all segments must not exceed the target duration
        2. The target duration must not change

        The problem is when the duration of a segment exceeds the previously published value for target duration (for example, due to a large interval between two successive keyframes).
        If the previously published target duration value is kept, the first requirement will be violated, if the value is updated, the second requirement is validated.
        With the default value of 0, the target duration is allowed to change any time, in order to make sure the duration of all segments is below the target duration.
        If the parameter is set to 3, for example, the target duration is updated only when adding the first 3 segments to the timeline.
    - `source` - object (C), can be used to create a timeline by copying a portion of another timeline, contains the following fields:
        - `id` - string (C), the id of the source timeline
        - `start_offset` - integer (C), an offset from the start of the source timeline to start copying from.
            If supplied, the offset is translated to an absolute time, and set as the `start` value of the resulting timeline
        - `end_offset` - integer (C), an offset from the start of the source timeline to stop copying from.
            If supplied, the offset is translated to an absolute time, and set as the `end` value of the resulting timeline

- `period_count` - integer (R), the number of periods in the timeline
- `segment_count` - integer (R), the total number of segments in the timeline
- `duration` - integer (R), the sum of the duration of all the periods in the timeline, in timescale units
- `removed_duration` - integer (R), the total duration of all the segments that were removed from the timeline since its creation, in timescale units
- `first_segment_index` - integer (R), the index of the oldest segment that exists in the timeline
- `last_segment_created` - integer (R), a unix timestamp of the last time a segment was added to the timeline
- `last_accessed` - integer (R), unix timestamp of the last time a KSMP request for the timeline was received
- `last_periods` - array of objects (R), returns statistics about the last 5 periods in the timeline. Each object contains the following fields:
    - `time` - integer (R), the start time of the period, in timescale units
    - `duration` - integer (R), the duration of the period, in timescale units
    - `segment_index` - integer (R), the index of the first segment in the period
    - `segment_count` - integer (R), the number of segments in the period


## API Endpoints

### GET /

Get the full status JSON.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /channels

Get the status of all active channels.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /channels?list=1

Get the ids of all active channels.

Possible status codes:
- 200 - Success, returns a JSON array of strings

### POST /channels

Create a new channel object, the request body must be a channel object.

Possible status codes:
- 201 - The channel was created successfully
- 204 - Either the channel already exists, and was updated successfully (only when the `upsert` setting is enabled on the API),
    or the channel was successfully read from storage.
- 400 - The specified `preset` does not exist, the provided `id` string is too long etc.
- 403 - A channel with the specified `id` exists and is currently blocked (a channel is blocked while its state is being read from storage)
- 409 - A channel with the specified `id` already exists (only when the `upsert` setting it not enabled on the API)
- 415 - Request body is not a valid JSON object, required fields are missing (`id` / `preset`), invalid `segment_duration` value etc.
- 502 - A request to read one of the channel files failed with an unexpected error, for example, invalid status code
- 503 - A file that was read from storage contained invalid data
- 504 - Timeout while reading a file from storage

### GET /channels/{channel_id}

Get the status of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No channel matching the provided id was found

### PUT /channels/{channel_id}

Update the specified channel, the request body must be a channel object.

Possible status codes:
- 204 - The channel was updated successfully
- 400 - Invalid `mem_limit` value, invalid `filler` params etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel matching the provided id was found
- 415 - Request body is not a valid JSON object, invalid `segment_duration` value etc.

### DELETE /channels/{channel_id}

Delete the specified channel.

Possible status codes:
- 204 - The channel was deleted successfully
- 404 - No channel matching the provided id was found

### GET /channels/{channel_id}/variants

Get the variants of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No channel matching the provided id was found

### GET /channels/{channel_id}/variants?list=1

Get the ids of the variants of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON array of strings
- 404 - No channel matching the provided id was found

### POST /channels/{channel_id}/variants

Create a new variant object, the request body must be a variant object.

Possible status codes:
- 201 - The variant was created successfully
- 204 - The variant already exists, and was updated successfully (only when the `upsert` setting is enabled on the API)
- 400 - The provided `id` contains invalid chars, the provided `id` / `label` / `lang` fields are too long, etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel matching the provided id was found, a track listed in the `track_ids` field was not found
- 409 - A variant with the specified `id` already exists (only when the `upsert` setting it not enabled on the API)
- 415 - Request body is not a valid JSON object, required fields are missing (`id`), invalid key in the `track_ids` field etc.

### PUT /channels/{channel_id}/variants/{variant_id}

Update the specified variant, the request body must be a variant object.

Possible status codes:
- 204 - The variant was updated successfully
- 400 - The provided `label` / `lang` fields are too long, etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel/variant matching the provided ids were found, a track listed in the `track_ids` field was not found
- 415 - Request body is not a valid JSON object, invalid key in the `track_ids` field etc.

### DELETE /channels/{channel_id}/variants/{variant_id}

Delete the specified variant.

Possible status codes:
- 204 - The variant was deleted successfully
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel/variant matching the provided ids were found

### GET /channels/{channel_id}/tracks

Get the tracks of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No channel matching the provided id was found

### GET /channels/{channel_id}/tracks?list=1

Get the ids of the tracks of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON array of strings
- 404 - No channel matching the provided id was found

### POST /channels/{channel_id}/tracks

Create a new track object, the request body must be a track object.

Possible status codes:
- 201 - The track was created successfully
- 204 - The track already exists, and was updated successfully (only when the `upsert` setting is enabled on the API)
- 400 - The provided `id` is too long, attempt to change the `media_type` of an existing track etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel matching the provided id was found
- 409 - A track with the specified `id` already exists (only when the `upsert` setting it not enabled on the API)
- 415 - Request body is not a valid JSON object, required fields are missing (`id` / `media_type`)

### PUT /channels/{channel_id}/tracks/{track_id}

Update the specified track, the request body must be a track object.

Possible status codes:
- 204 - The track was updated successfully
- 400 - The provided `group_id` field is too long
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / track matching the provided ids were found
- 415 - Request body is not a valid JSON object

### DELETE /channels/{channel_id}/tracks/{track_id}

Delete the specified track.

Possible status codes:
- 204 - The track was deleted successfully
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / track matching the provided ids were found

### DELETE /channels/{channel_id}/tracks/{track_id}/input

Drop the incoming KMP connection that is associated with the specified track.

Possible status codes:
- 204 - The connection was dropped successfully
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / track matching the provided ids were found
- 409 - No KMP connection is associated with the specified track

### POST /channels/{channel_id}/variants/{variant_id}/tracks

Add a track to the specified variant, the request body must be a track object (only the `id` field is used).

Possible status codes:
- 201 - The track was successfully added to the variant
- 204 - The specified track was already associated to the variant
- 400 - The specified track is a filler track
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / variant / track matching the provided ids were found
- 409 - The variant already has a track matching the `media_type` of the provided track (only when the `upsert` setting it not enabled on the API)
- 415 - Request body is not a valid JSON object, required fields are missing (`id`)

### GET /channels/{channel_id}/timelines

Get the timelines of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No channel matching the provided id was found

### GET /channels/{channel_id}/timelines?list=1

Get the ids of the timelines of the specified channel.

Possible status codes:
- 200 - Success, returns a JSON array of strings
- 404 - No channel matching the provided id was found

### POST /channels/{channel_id}/timelines

Create a new timeline object, the request body must be a timeline object.

Possible status codes:
- 201 - The timeline was created successfully
- 204 - The timeline already exists, and was updated successfully (only when the `upsert` setting is enabled on the API)
- 400 - Invalid `start` / `end` values, invalid `start_offset` / `end_offset` source values etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel matching the provided id was found, no timeline matching the provided `source` id was found
- 409 - A timeline with the specified `id` already exists (only when the `upsert` setting it not enabled on the API)
- 415 - Request body is not a valid JSON object, required fields are missing (`id`), invalid `source` object etc.

### GET /channels/{channel_id}/timelines/{timeline_id}

Get the specified timeline.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No channel / timeline matching the provided ids were found

### PUT /channels/{channel_id}/timelines/{timeline_id}

Update the specified timeline, the request body must be a timeline object.

Possible status codes:
- 204 - The timeline was updated successfully
- 400 - Invalid `start` / `end` values, invalid `end_list` value etc.
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / timeline matching the provided ids were found, a track listed in the `track_ids` field was not found
- 415 - Request body is not a valid JSON object

### DELETE /channels/{channel_id}/timelines/{timeline_id}

Delete the specified timeline.

Possible status codes:
- 204 - The timeline was deleted successfully
- 403 - The requested channel is currently blocked (a channel is blocked while its state is being read from storage)
- 404 - No channel / timeline matching the provided ids were found


## Embedded Variables

This module supports the following embedded variables in `http` context:
- `$live_ksmp_err_code` - the KSMP error code, the possible values are defined in [ngx_ksmp_errs_x.h](../nginx-common/src/ngx_ksmp_errs_x.h).
- `$live_ksmp_err_msg` - the KSMP error message
- `$live_ksmp_block_duration` - the number of seconds a blocking request (e.g. a request with the `_HLS_msn` query parameter) waited, in milliseconds resolution
- `$live_ksmp_source` - in successful KSMP media requests, contains the source of the media frames -
    - `cache` - the media segment was served from the in-memory cache
    - `filler` - the filler content was used to service the request
    - `{store_name}` - the name of the s3 configuration what was used, as specified in the `store_s3_block` directive

This module supports the following embedded variables in `live` context:
- `$nginx_version` - the version of nginx
- `$live_version` - the version of nginx-live-module
- `$hostname` - the host name of the server
- `$pid` - PID of the worker process
- `$msec` - current time in seconds with milliseconds resolution
- `$channel_id` - the id of the live channel
- `$next_segment_index` - the zero-based index that will be used for the next created segment
- `$persist_bucket_id` - the id of the media persistence bucket, intended for use in `persist_media_path`
- `$var_{name}` - returns the value of the dynamic live channel variable `{name}`, see the `vars` property of the channel object
