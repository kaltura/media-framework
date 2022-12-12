# Nginx KMP -> RTMP Module

Publishes incoming KMP tracks to an upstream server using the RTMP protocol.

Dependencies: [nginx-common](../nginx-common/), [nginx-kmp-in-module](../nginx-kmp-in-module/).


## Features

- Input
    - Protocol: *KMP*
    - Codecs:
        - Video: *h264 / AVC*
        - Audio: *AAC*, *MP3*

- Output protocol: *RTMP*

- Dynamic configuration - passed in the data of the KMP `connect` packet - see [Connect Data JSON](#connect-data-json) for more details

- Support for publishing multiple tracks and multiple streams on a single RTMP connection -
    incoming KMP tracks are grouped according the `upstream_id` that is set in the KMP connect data.

- Support for sending RTMP `onFI` messages (containing absolute timestamps)

- Support for HTTP notifications (sent on RTMP connection close)

- Management API


## Glossary

- *track* - a single rendition of video/audio.

- *stream* - an RTMP message stream, created using the RTMP `createStream` command, published using the RTMP `publish` command, etc.
    An RTMP stream can contain at most one video track and one audio track.
    An RTMP stream is automatically created when the first track is connected to the stream, and automatically destroyed when the last track disconnects.

- *upstream* - an RTMP connection to an upstream server. Multiple streams/tracks can be sent on a single upstream connection.
    An RTMP upstream object is created automatically when the first track is connected to it, and destroyed when the last track disconnects.

**Important:** this module assumes that the upstream RTMP server allocates stream ids in incremental numbers starting from 1.
To put it differently, this module does not parse the response of the `createStream` command (or anything else returned from the upstream, following the RTMP handshake).
If this assumption does not hold for the specific upstream server to which the stream is published, the stream is likely to be rejected.


## Configuration

### Sample Configuration

```nginx
stream {
    server {
        listen 8005;
        resolver 8.8.8.8;

        kmp_rtmp;
    }
}

http {
    server {
        listen 8001;

        location /kmp_rtmp_api/ {
            kmp_rtmp_api write=on;
        }
    }
}
```


### Configuration Directives

#### kmp_rtmp_api
* **syntax**: `kmp_rtmp_api [write=on|off];`
* **default**: `none`
* **context**: `location`

Enables the API interface of this module in the surrounding location block. Access to this location should be limited.

The optional `write` parameter determines whether the API is read-only or read-write. By default, the API is read-only.

#### kmp_rtmp
* **syntax**: `kmp_rtmp;`
* **default**: ``
* **context**: `server`

Enables the media interface of this module in the surrounding server block.

#### kmp_rtmp_in_read_timeout
* **syntax**: `kmp_rtmp_in_read_timeout msec;`
* **default**: `20s`
* **context**: `stream`, `server`

Defines a timeout for reading from the client connection.
The timeout is set only between two successive read operations, not for the transmission of the whole stream.
If the client does not transmit anything within this time, the connection is closed.

#### kmp_rtmp_in_send_timeout
* **syntax**: `kmp_rtmp_in_send_timeout msec;`
* **default**: `10s`
* **context**: `stream`, `server`

Sets a timeout for sending acks back to the client.
The timeout is set only between two successive write operations.
If the client does not receive anything within this time, the connection is closed.

#### kmp_rtmp_in_mem_limit
* **syntax**: `kmp_rtmp_in_mem_limit size;`
* **default**: `256k`
* **context**: `stream`, `server`

Sets the maximum total size of the buffers used to receive from the client.
If the limit is hit, the module drops the KMP connection.
This memory limit applies until the KMP `connect` data is read from the client,
at this point, the KMP connection is linked to an upstream object,
and the memory usage tracking moves to the upstream level (`kmp_rtmp_out_mem_limit`)

#### kmp_rtmp_in_buffer_size
* **syntax**: `kmp_rtmp_in_buffer_size size;`
* **default**: `64k`
* **context**: `stream`, `server`

Sets the size of the buffers used to read video / audio data from the client connection.

#### kmp_rtmp_in_buffer_bin_count
* **syntax**: `kmp_rtmp_in_buffer_bin_count num;`
* **default**: `8`
* **context**: `stream`, `server`

Sets the number of bins that are used to group the input video / audio buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### kmp_rtmp_in_max_free_buffers
* **syntax**: `kmp_rtmp_in_max_free_buffers num;`
* **default**: `4`
* **context**: `stream`, `server`

Sets the maximum number of free input buffers that are kept after they are copied.
A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_rtmp_in_log_frames
* **syntax**: `kmp_rtmp_in_log_frames on | off;`
* **default**: `off`
* **context**: `stream`, `server`

When enabled, the module logs the metadata of every video / audio frame that is received -
1. KMP frame header - created, dts, flags, pts delay
2. Data size and MD5 hash

#### kmp_rtmp_in_dump_folder
* **syntax**: `kmp_rtmp_in_dump_folder path;`
* **default**: ``
* **context**: `stream`, `server`

When set to a non-empty string, the module saves all incoming KMP data to files under the specified folder.
The file names have the following structure: `ngx_live_kmp_dump_{date}_{pid}_{connection}.dat`.

#### kmp_rtmp_out_notif_url
* **syntax**: `kmp_rtmp_out_notif_url url;`
* **default**: ``
* **context**: `stream`, `server`

Sets an HTTP notification callback.
The callback is invoked when the RTMP upstream is destroyed.

Sample request body:
```json
{
    "event_type": "rtmp_close",
    "reason": "done",
    "upstream_id": "id1",
    "url": "rtmp://127.0.0.1:1935/app/stream",
    "header": "",
    "opaque": ""
}
```

The field `event_type` always has the string value `rtmp_close`.
The fields `upstream_id`, `url`, `header`, `opaque` have the values specified in the connect data JSON.

The `reason` field in the request can have the following values -
- `done` - the upstream no longer contains any active streams, and all pending data was sent
- `api_delete` - the upstream was deleted via the management API
- `start_resolve_failed` - a hostname was used in the url, and no resolver was configured / error allocating resolver context
- `resolve_failed` - failed to resolve the hostname of the upstream URL
- `handshake_failed` - RTMP handshake error, can be due to TCP connect error / receive error / receive timeout / invalid response received from upstream
- `send_failed` - error sending to the RTMP upstream
- `recv_failed` - error receiving from the RTMP upstream
- `get_buf_failed` - error allocating an input buffer / input memory limit reached
- `alloc_chain_failed` - error allocating a chain for for holding an input buffer
- `add_media_info_failed` - error allocating the extra data of the codec
- `start_connect_failed` - error creating / setting up a socket or nginx connection
- `alloc_failed` - error copying connect data fields (`url`, `header` etc.) to the upstream object
- `flush_failed` - error allocating / sending buffer
- `create_stream_failed` - error allocating stream object / buffers for stream publish commands
- `unpublish_stream_failed` - error allocating buffers for stream unpublish commands
- `write_connect_failed` - error allocating buffers for RTMP connect message
- `write_meta_failed` - error allocating buffers for RTMP stream metadata (media info)
- `create_track_failed` - error allocating track object / initial frame list part
- `mem_limit_exceeded` - track could not be added to the upstream, as the memory used by its input buffers exceeds the available quota on the upstream
- `push_frame_failed` - error pushing a frame to the pending queue of the track
- `process_frame_failed` - error allocating output buffer / chain, possibly due to upstream memory limit

#### kmp_rtmp_out_notif_add_header
* **syntax**: `kmp_rtmp_out_notif_add_header name value;`
* **default**: ``
* **context**: `stream`, `server`

Adds a request header to notification requests.
There could be several `kmp_rtmp_out_notif_add_header` directives.
These directives are inherited from the previous level if and only if there are no `kmp_rtmp_out_notif_add_header` directives defined on the current level.

#### kmp_rtmp_out_notif_timeout
* **syntax**: `kmp_rtmp_out_notif_timeout msec;`
* **default**: `2s`
* **context**: `stream`, `server`

Sets a timeout for sending notification requests.
The timeout includes both the connection establishment as well as the sending of the request.

#### kmp_rtmp_out_notif_read_timeout
* **syntax**: `kmp_rtmp_out_notif_read_timeout msec;`
* **default**: `20s`
* **context**: `stream`, `server`

Sets a timeout for reading the response of notification requests.

#### kmp_rtmp_out_notif_buffer_size
* **syntax**: `kmp_rtmp_out_notif_buffer_size size;`
* **default**: `4k`
* **context**: `stream`, `server`

Sets the size of the buffer that holds the response of the notification requests.

#### kmp_rtmp_out_mem_limit
* **syntax**: `kmp_rtmp_out_mem_limit size;`
* **default**: `16m`
* **context**: `stream`, `server`

Sets the maximum size of memory used by each upstream.
The value should be large enough to hold the pending input frames until they are processed (see `min_process_delay`),
as well as the RTMP output buffers until they are sent.
If the limit is hit, the module drops the upstream RTMP connection and all its input KMP connections.

#### kmp_rtmp_out_max_free_buffers
* **syntax**: `kmp_rtmp_out_max_free_buffers num;`
* **default**: `4`
* **context**: `stream`, `server`

Sets the maximum number of free output buffers that are kept after being sent to the upstream server.
A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_rtmp_out_timeout
* **syntax**: `kmp_rtmp_out_timeout msec;`
* **default**: `10s`
* **context**: `stream`, `server`

Sets the timeout for sending data to the upstream RTMP server.
The timeout is set only between two successive write operations.

#### kmp_rtmp_out_flush_timeout
* **syntax**: `kmp_rtmp_out_flush_timeout msec;`
* **default**: `500ms`
* **context**: `stream`, `server`

Sets the timeout for flushing buffered data to the upstream RTMP server.
RTMP output data is kept in buffers of size `kmp_rtmp_out_buffer_size`, a buffer is sent when it becomes full, or when the flush timeout expires.

#### kmp_rtmp_out_buffer_size
* **syntax**: `kmp_rtmp_out_buffer_size size;`
* **default**: ``
* **context**: `stream`, `server`

Sets the size of the buffers used to send data to the upstream server.
A large value can be more efficient, but increases the latency (a buffer is sent either when it's full or the flush timeout expires).

#### kmp_rtmp_out_buffer_bin_count
* **syntax**: `kmp_rtmp_out_buffer_bin_count num;`
* **default**: ``
* **context**: `stream`, `server`

Sets the number of bins that are used to group the output buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### kmp_rtmp_out_flash_ver
* **syntax**: `kmp_rtmp_out_flash_ver str;`
* **default**: `FMLE/3.0 (compatible; KalturaLive/{version})`
* **context**: `stream`, `server`

Sets the default `flashVer` value that is sent in the RTMP connect command.
This default can be overridden per-upstream by supplying the `flash_ver` field in the connect data JSON.

#### kmp_rtmp_out_chunk_size
* **syntax**: `kmp_rtmp_out_chunk_size size;`
* **default**: `64k`
* **context**: `stream`, `server`

Sets the size of the RTMP chunks sent to the upstream server.
The value must be in the range 128 .. 16777215.

#### kmp_rtmp_out_write_meta_timeout
* **syntax**: `kmp_rtmp_out_write_meta_timeout msec;`
* **default**: `3s`
* **context**: `stream`, `server`

Sets the timeout for sending the RTMP `@onMetaData` packet for an RTMP stream.
The metadata of the stream includes both video and audio parameters.
When a stream has both video and audio data, the metadata is sent immediately.
However, if a stream gets only video data, for example, the module will wait, in order to give the audio a chance to arrive.
If the audio arrives after the metadata was already sent, the module will reject the incoming KMP connection.

#### kmp_rtmp_out_min_process_delay
* **syntax**: `kmp_rtmp_out_min_process_delay msec;`
* **default**: `500ms`
* **context**: `stream`, `server`

Sets the minimum amount of time an incoming frame waits in queue before being processed.
When a stream has both video and audio tracks, the respective RTMP packets are multiplexed according to their timestamps,
each packet reports the delta from the previous video / audio packet.
Delaying the processing of input frames enables the module to sort the frames according to their timestamps.
To put it differently - the fact that video frame X has a timestamp lower than audio frame Y,
doesn't necessarily mean that frame X will be read by this module before frame Y.

#### kmp_rtmp_out_max_process_delay
* **syntax**: `kmp_rtmp_out_max_process_delay msec;`
* **default**: `1s`
* **context**: `stream`, `server`

Sets the maximum amount of time an incoming frame waits in queue before being processed.
Normally, the module processes the frame that has the lowest timestamp out of the frames pending in the queue.
This behavior creates a risk of starvation - if the timestamps (both audio and video) jump backwards,
one of the tracks will get to the timestamp jump first. From that point on, that track will always be chosen,
since its top frame has a lower timestamp.
Capping the processing delay prevents this starvation - at some point the track that did not reach the jump
will exceed the max processing delay, and will be chosen. This enables the track to reach the jump,
and once that happens, processing will continue normally.

#### kmp_rtmp_out_onfi_period
* **syntax**: `kmp_rtmp_out_onfi_period msec;`
* **default**: `5s`
* **context**: `stream`, `server`

Sets the period for sending RTMP `onFI` messages, containing the absolute KMP `created` timestamp.
This can be useful since RTMP timestamps wrap around every ~49 days.
If the period is set to zero, no `onFI` messages are sent.

#### kmp_rtmp_out_dump_folder
* **syntax**: `kmp_rtmp_out_dump_folder path;`
* **default**: ``
* **context**: `stream`, `server`

When set to a non-empty string, the module saves the raw data received from the RTMP upstream to a file under the specified folder.
The file names have the following structure: `ngx_kmp_rtmp_dump_{date}_{upstream_id}_{connection}.dat`.
This can be used in order to inspect error messages returned from the upstream.


## Connect Data JSON

### Sample JSON

```json
{
    "upstream_id": "ch1-twitch",
    "url": "rtmp://live.twitch.tv:1935/app/live_123456789_abcdefABCDEF12345",
    "opaque": "{\"remote_id\":\"123456789\"}"
}
```

### Structure

The KMP connect data of incoming connections must be a JSON object containing the following fields:
- `upstream_id` - string, required, identifies the RTMP upstream. All incoming KMP tracks that have the same `upstream_id` share a single RTMP connection.
- `url` - string, required, the upstream RTMP URL. The URL has the format: `rtmp://{host}:{port}/{app}/{stream}`, the `rtmp://` prefix is optional.
- `header` - string, optional, sent on the upstream TCP connection upon establishment.
    Can be used to send additional parameters when the RTMP connection goes through a proxy.
    One sample use case, is pushing to a local nginx stream proxy, in order to publish using `RTMPS`.
- `opaque` - string, optional, can be used to store arbitrary data on the upstream object.
- `app` - string, optional, the RTMP application name.
    By default, the application name is extracted from the `url`.
- `name` - string, optional, the RTMP stream name.
    By default, the stream name is extracted from the `url`.
- `flash_ver` - string, optional, sets the the value of the `flashVer` field of the RTMP `connect` message.
    By default, the module uses the value set using the `kmp_rtmp_out_flash_ver` directive.
- `swf_url` - string, optional, sets the the value of the `swfUrl` field of the RTMP `connect` message.
    By default, an empty string is sent.
- `tc_url` - string, optional, sets the the value of the `tcUrl` field of the RTMP `connect` message.
    By default, the module uses the value of `url`, excluding the stream name part (=up to the application name).
- `page_url` - string, optional, sets the the value of the `pageUrl` field of the RTMP `connect` message.
    By default, an empty string is sent.

If an upstream with the id `upstream_id` exists when the track is added, most of the fields listed above are ignored.
The only fields that are used in this case (other than `upstream_id`) are:
- `name` - if specified, or -
- `url` - if `name` is not specified (note that only the `{stream}` part of the `url` is used)


## API Objects

The sections below list the possible fields in each type of API object.

### Global Scope

- `version` - string, nginx-kmp-rtmp-module version
- `nginx_version` - string, nginx version
- `compiler` - string, the compiler used to build nginx-kmp-rtmp-module
- `built` - string, the time nginx-kmp-rtmp-module was built
- `pid` - integer, the nginx process id
- `uptime` - integer, the time since the nginx worker was started, in seconds
- `upstreams` - object, the keys are upstream ids, the values are [Upstream Objects](#upstream-object)

### Upstream Object

- `url` - string, the url of the upstream RTMP connection
- `header` - string, the `header` value that was set on the connect data JSON
- `opaque` - string, the `opaque` value that was set on the connect data JSON
- `remote_addr` - string, the ip + port of the remote peer
- `local_addr` - string, the local ip + port of the connection
- `connection` - integer, the nginx connection identifier, unique per nginx worker process
- `mem_limit` - integer, maximum number of memory bytes the upstream object is allowed to consume
- `mem_left` - integer, number of memory bytes left out of the `mem_limit` quota
- `written_bytes` - integer, the total number of bytes written to the output queue of the upstream
- `sent_bytes` - integer, the total number of bytes that were sent to the RTMP upstream
- `received_bytes` - integer, the total number of bytes that were received from the RTMP upstream
- `streams` - object, the keys are RTMP stream names, the values are [Stream Objects](#stream-object)

### Stream Object

- `id` - integer, the RTMP message stream id (msid) of the stream
- `uptime` - integer, the time that passed since the stream was created, in seconds
- `tracks` - object, the keys hold the media type (`video` / `audio`), the values are [Track Objects](#track-object)

### Track Object

- `pending_frames` - integer, the number of frames in the pending queue of the track
- `mem_used` - integer, the number of used bytes in the input buffer queue of the track
- `input` - object | null, returns statistics about the KMP input currently connected to the track.
    See [Input Object](../nginx-kmp-in-module/README.md#input-object) for more details.
    `null` is returned if no input connection is currently connected to the track.


## API Endpoints

### GET /

Get the full status JSON.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /upstreams

Get the status of all active upstreams.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /upstreams?list=1

Get the ids of all active upstreams.

Possible status codes:
- 200 - Success, returns a JSON array of strings

### GET /upstreams/{upstream_id}

Get the status of the specified upstream.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No upstream matching the provided id was found

### DELETE /upstreams/{upstream_id}

Drop an upstream by id, including all the associated KMP input connections.

Possible status codes:
- 204 - Success, connection was dropped
- 404 - No upstream matching the provided id was found

### GET /upstreams/{upstream_id}/streams

Get the status of the RTMP streams of the specified upstream.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - No upstream matching the provided id was found

### GET /upstreams/{upstream_id}/streams?list=1

Get the ids of the RTMP streams of the specified upstream.

Possible status codes:
- 200 - Success, returns a JSON array of strings
- 404 - No upstream matching the provided id was found

### DELETE /upstreams/{upstream_id}/tracks/{connection}

Drop an incoming KMP connection by id.

Possible status codes:
- 204 - Success, connection was dropped
- 400 - The provided connection id is not a number
- 404 - No upstream / connection matching the provided ids were found
