# Nginx KMP Input Module

A utility module for parsing incoming KMP tracks.

Used by: *nginx-live-module*, *nginx-kmp-cc-module*, *nginx-kmp-rtmp-module*.

Dependencies: *nginx-common*.


## Features

- Invoke callbacks on connection events (connect / disconnect)

- Invoke callbacks on KMP packets (media info / frame / end-of-stream)

- Interface for sending back acks

- Debugging features - log frame metadata / dump input to file

- Generation of status JSON with statistics about the input connection


## Input object

- `connection` - integer, the nginx connection identifier, unique per nginx worker process
- `remote_addr` - string, the ip + port of the remote peer
- `channel_id` - string, the channel id
- `track_id` - string, the track id
- `uptime` - integer, the time that passed since the connection was established, in seconds
- `received_bytes` - integer, the total number of bytes received from the remote peer
- `received_data_bytes` - integer, the sum of the data size of all the received frames
- `received_frames` - integer, the total number of frames that were received
- `received_key_frames` - integer, the total number of keyframes that were received
- `last_created` - integer, the KMP `created` value of the last frame that was received
- `skipped_frames` - object, contains the statistics about frames that were received and discarded, contains the following fields:
    - `duplicate` - integer, frames that were already received before the connection dropped and was re-established
    - `empty` - integer, frames with zero data size
    - `no_media_info` - integer, frames received before any media info packet
    - `no_key` - integer, video frames received before the first keyframe
- `latency` - object, the latency of the incoming frames.
    The latency is defined as the difference between the KMP `created` value of the frame and the server clock.
    When running in multi-server environments, the measurement may be inaccurate due to clock differences.
    The object contains the following fields:
    - `min` - integer, the minimum latency, in timescale units
    - `max` - integer, the maximum latency, in timescale units
    - `avg` - integer, the average latency, in timescale units
