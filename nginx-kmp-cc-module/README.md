# Nginx KMP CC-Decoder Module

Decodes *EIA-608* / *CTA-708* closed captions embedded in video tracks.

Dependencies: *nginx-common*, *nginx-kmp-in-module*, *nginx-kmp-out-module*

## Features

- Input
    - Protocol: *KMP*
    - Codecs: *h264 / AVC*, *h265 / HEVC*

- Output
    - Protocol: *KMP*
    - Codecs: *WebVTT*

- Supported styles
    - 608 - italics/underline, positioning, colors
    - 708 - italics/underline

- Operation modes
    - Pre-configured - the data of the KMP `connect` packet contains a JSON specifying which CC channels to extract and where to publish them to.
        See [Connect Data JSON](#connect-data-json) for more details on the JSON structure.
    - On-demand - in this mode, the module sends a `publish` request for each CC channel that is received, in order to find where to publish it to.

- Management API

## Configuration

### Sample Configuration

```
stream {
    server {
        listen 8004;

        kmp_cc;
        kmp_cc_out_ctrl_publish_url http://127.0.0.1:8001/control/;
    }
}

http {
    server {
        listen 8001;

        location /api/kmp_cc/ {
            kmp_cc_api write=on;
        }
    }
}
```

### Configuration Directives

#### kmp_cc_api
* **syntax**: `kmp_cc_api [write=on|off]`
* **default**: `none`
* **context**: `location`

Enables the API interface of this module in the surrounding location block. Access to this location should be limited.

The write parameter determines whether the API is read-only or read-write. By default, the API is read-only.

#### kmp_cc
* **syntax**: `kmp_cc`
* **default**: ``
* **context**: `server`

Enables the media interface of this module in the surrounding server block.

#### kmp_cc_dump_folder
* **syntax**: `kmp_cc_dump_folder path`
* **default**: ``
* **context**: `stream`, `server`

When set to a non-empty string, the module saves the raw data received on each CC channel to a file under the specified folder.
The file names have the following structure: `ngx_live_cc_dump_{date}_{channel}_{track}_{cc-channel}.dat`.

#### kmp_cc_max_pending_packets
* **syntax**: `kmp_cc_max_pending_packets num`
* **default**: `128`
* **context**: `stream`, `server`

Sets the maximum number of pending CC packets.
The packets are kept in a queue until either an I-frame or a P-frame arrives (CC data must be decoded according to the presentation-order of the video frames)

#### kmp_cc_in_read_timeout
* **syntax**: `kmp_cc_in_read_timeout msec`
* **default**: `20s`
* **context**: `stream`, `server`

Defines a timeout for reading from the client connection.
The timeout is set only between two successive read operations, not for the transmission of the whole stream.
If the client does not transmit anything within this time, the connection is closed.

#### kmp_cc_in_send_timeout
* **syntax**: `kmp_cc_in_send_timeout msec`
* **default**: `10s`
* **context**: `stream`, `server`

Sets a timeout for sending acks back to the client.
The timeout is set only between two successive write operations.
If the client does not receive anything within this time, the connection is closed.

#### kmp_cc_in_dump_folder
* **syntax**: `kmp_cc_in_dump_folder path`
* **default**: ``
* **context**: `stream`, `server`

When set to a non-empty string, the module saves all incoming KMP data to files under the specified folder.
The file names have the following structure: `ngx_live_kmp_dump_{date}_{pid}_{connection}.dat`.

#### kmp_cc_in_log_frames
* **syntax**: `kmp_cc_in_log_frames on | off`
* **default**: `off`
* **context**: `stream`, `server`

When enabled, the module logs the metadata of every video frame that is received -
1. KMP frame header - created, dts, flags, pts delay
2. Data size and MD5 hash

#### kmp_cc_in_mem_limit
* **syntax**: `kmp_cc_in_mem_limit size`
* **default**: `16m`
* **context**: `stream`, `server`

Sets the maximum total size of the buffers used to receive video data from the client.
If the limit is hit, the module drops the KMP connection.

#### kmp_cc_in_buffer_size
* **syntax**: `kmp_cc_in_buffer_size size`
* **default**: `64k`
* **context**: `stream`, `server`

Sets the size of the buffers used to read video data from the client connection.

#### kmp_cc_in_buffer_bin_count
* **syntax**: `kmp_cc_in_buffer_bin_count num`
* **default**: `8`
* **context**: `stream`, `server`

Sets the number of bins that are used to group the input video buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### kmp_cc_in_max_free_buffers
* **syntax**: `kmp_cc_in_max_free_buffers num`
* **default**: `4`
* **context**: `stream`, `server`

Sets the maximum number of free input buffers that are kept after they are parsed.
A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_cc_out_ctrl_publish_url
* **syntax**: `kmp_cc_out_ctrl_publish_url`
* **default**: ``
* **context**: `stream`, `server`

Sets the HTTP `publish` callback, called for CC channels that are published, and do not have a pre-configured destination in the connect data JSON.

Sample request body:
```
{
    "event_type": "publish",
    "input_id": "kmp-cc://ch1/trk1/cc1",
    "input_type": "cc",
    "cc": {
        "channel_id": "ch1",
        "track_id": "trk1",
        "service_id": "cc1"
    },
    "media_info": {
        "media_type": "subtitle",
        "bitrate": 0,
        "codec_id": 2001,
        "extra_data": "574542565454"
    }
}
```

See [Publish](../nginx-kmp-out-module/README.md#publish) for more details on the `publish` request.

#### kmp_cc_out_ctrl_unpublish_url
* **syntax**: `kmp_cc_out_ctrl_unpublish_url`
* **default**: ``
* **context**: `stream`, `server`

Sets the HTTP `unpublish` callback, called whenever a CC channel stops being published, or some unrecoverable error occurs when sending to upstream.
The response of this notification is ignored, and no retries are performed in case of error.

See [Unpublish](../nginx-kmp-out-module/README.md#unpublish) for more details on the `unpublish` request.

In addition to the `reason` values listed in nginx-kmp-out-module, this module adds the following values:
* `write_failed` - error writing KMP packet to output track, either due to allocation error or hitting the output mem limit
* `packet_limit_reached` - the number of pending packets reached the limit (`kmp_cc_max_pending_packets`)
* `bad_media_info` - invalid media type / codec / extra data received on the incoming KMP connection
* `bad_publish_json` - error parsing the connect data JSON
* `disconnected` - client KMP connection dropped
* `create_failed` - unknown error while initializing the CC channel parsers
* `internal_error` - unexpected error

#### kmp_cc_out_ctrl_republish_url
* **syntax**: `kmp_cc_out_ctrl_republish_url url`
* **default**: `none`
* **context**: `stream`, `server`

Sets the HTTP `republish` callback, called in case of an error/disconnect on some upstream KMP connection.
The upstream server can use this event to provide the module with a new KMP endpoint to publish to.

See [Republish](../nginx-kmp-out-module/README.md#republish) for more details on the `republish` request.

#### kmp_cc_out_ctrl_add_header
* **syntax**: `kmp_cc_out_ctrl_add_header name value`
* **default**: `none`
* **context**: `stream`, `server`

Adds a request header to all control requests (`publish`, `unpublish` etc.).
There could be several `kmp_cc_out_ctrl_add_header` directives.
These directives are inherited from the previous level if and only if there are no `kmp_cc_out_ctrl_add_header` directives defined on the current level.

#### kmp_cc_out_ctrl_timeout
* **syntax**: `kmp_cc_out_ctrl_timeout msec`
* **default**: `2s`
* **context**: `stream`, `server`

Sets a timeout for sending HTTP requests to the upstream server.
The timeout includes both the connection establishment as well as the sending of the request.

#### kmp_cc_out_ctrl_read_timeout
* **syntax**: `kmp_cc_out_ctrl_read_timeout msec`
* **default**: `20s`
* **context**: `stream`, `server`

Sets a timeout for reading the response of HTTP requests sent to the upstream server.

#### kmp_cc_out_ctrl_buffer_size
* **syntax**: `kmp_cc_out_ctrl_buffer_size size`
* **default**: `4k`
* **context**: `stream`, `server`

Sets the size of the buffer that holds the response of the HTTP requests.
The buffer size should be large enough to hold the largest expected response.

#### kmp_cc_out_ctrl_retries
* **syntax**: `kmp_cc_out_ctrl_retries count`
* **default**: `5`
* **context**: `stream`, `server`

Sets the number of retries for issuing HTTP requests. A request is considered as failed if -
- The request could not be sent (e.g. connect error)
- The response could not be parsed as JSON (bad http status, non-json content type, invalid JSON)

#### kmp_cc_out_ctrl_retry_interval
* **syntax**: `kmp_cc_out_ctrl_retry_interval msec`
* **default**: `2s`
* **context**: `stream`, `server`

Sets the time to wait before performing each retry attempt for HTTP requests.

#### kmp_cc_out_timescale
* **syntax**: `kmp_cc_out_timescale num`
* **default**: `90000`
* **context**: `stream`, `server`

Sets the timescale of the KMP output tracks.

#### kmp_cc_out_timeout
* **syntax**: `kmp_cc_out_timeout msec`
* **default**: `10s`
* **context**: `stream`, `server`

Sets the timeout for sending data to the upstream KMP server.

#### kmp_cc_out_max_free_buffers
* **syntax**: `kmp_cc_out_max_free_buffers num`
* **default**: `4`
* **context**: `stream`, `server`

Sets the maximum number of free output buffers that are kept after receiving acks from the upstream server.
A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_cc_out_buffer_bin_count
* **syntax**: `kmp_cc_out_buffer_bin_count num`
* **default**: `8`
* **context**: `stream`, `server`

Sets the number of bins that are used to group the output subtitle buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### kmp_cc_out_mem_high_watermark
* **syntax**: `kmp_cc_out_mem_high_watermark percent`
* **default**: `75`
* **context**: `stream`, `server`

A memory utilization threshold, expressed as a percent of the memory limit.
If the high watermark is reached, the module starts releasing subtitle buffers
of frames that were not acknowledged. The process stops when the memory usage
drops below the low watermark threshold.

#### kmp_cc_out_mem_low_watermark
* **syntax**: `kmp_cc_out_mem_low_watermark percent`
* **default**: `50`
* **context**: `stream`, `server`

See the description of `kmp_cc_out_mem_high_watermark` above.

#### kmp_cc_out_subtitle_buffer_size
* **syntax**: `kmp_cc_out_subtitle_buffer_size size`
* **default**: `1k`
* **context**: `stream`, `server`

Sets the size of the buffers used to send subtitle data to the upstream server.
A large value can be more efficient, but increases the latency (a buffer is sent either when it's full or the flush timeout expires).

#### kmp_cc_out_subtitle_mem_limit
* **syntax**: `kmp_cc_out_subtitle_mem_limit size`
* **default**: `128k`
* **context**: `stream`, `server`

Sets the maximum total size of the buffers used to send subtitle data to the upstream server.
If the limit is hit, the module drops the KMP connection.

#### kmp_cc_out_flush_timeout
* **syntax**: `kmp_cc_out_flush_timeout msec`
* **default**: `1s`
* **context**: `stream`, `server`

Sets the timeout for flushing buffered data to the upstream KMP server.
KMP output data is kept in buffers of size `kmp_cc_out_subtitle_buffer_size`, a buffer is sent when it becomes full, or when the flush timeout expires.

#### kmp_cc_out_keepalive_interval
* **syntax**: `kmp_cc_out_keepalive_interval msec`
* **default**: `10s`
* **context**: `stream`, `server`

Sets the period for sending `null` KMP packets to upstream servers.
The `null` packets are sent in order to signal "liveness" to the upstream.
They prevent it from closing the connection due to inactivity, during long periods of time without captions.

#### kmp_cc_out_log_frames
* **syntax**: `kmp_cc_out_log_frames on | off`
* **default**: `off`
* **context**: `stream`, `server`

When enabled, the module logs the metadata of every subtitle frame that is sent -
1. KMP frame header - created, dts, flags, pts delay
2. Data size and MD5 hash

#### kmp_cc_out_republish_interval
* **syntax**: `kmp_cc_out_republish_interval sec`
* **default**: `1`
* **context**: `stream`, `server`

The minimum time that should pass between `republish` requests, in seconds.

#### kmp_cc_out_max_republishes
* **syntax**: `kmp_cc_out_max_republishes num`
* **default**: `10`
* **context**: `stream`, `server`

The maximum number of consecutive `republish` requests that can be sent before giving up.
If more than `kmp_republish_interval` seconds passed since the last `republish`, the counter is reset.


## Connect Data JSON

### Sample JSON

```
{
    "cc1": {
        "channel_id": "ch1",
        "track_id": "cc1",
        "upstreams": [
            {
                "id": "cc-sub",
                "url": "kmp://127.0.0.1:8003"
            }
        ]
    },
    "service2": {
        "channel_id": "ch1",
        "track_id": "service2",
        "upstreams": [
            {
                "id": "cc-sub",
                "url": "kmp://127.0.0.1:8003"
            }
        ]
    }
}
```

### Structure

The KMP `connect` data, must be either a JSON object or `null` / `` (empty string).

If the `connect` data is `null` / ``, a `publish` request is sent for each CC channel that is encountered, to the endpoint specified using the `kmp_cc_out_ctrl_publish_url` directive.

If the `connect` data is an object -
- The keys must be closed caption channel ids:
    - `cc1` .. `cc4` for 608 captions
    - `service1` .. `service63` for 708 captions.

- The values must be either -
    - `null` - a `publish` request will be issued for the specific CC channel, or
    - A `publish` response object - as documented in [Response fields](../nginx-kmp-out-module/README.md#response-fields)

- If the `connect` data object contains the special key `*` with a `null` value, all CC channels that are not included in the JSON, will issue a `publish` request
    (by default, CC channels that are not listed are ignored)


## API Endpoints

### GET /

Get the full status JSON.

Possible status codes:
- 200 - Success, returns a JSON object

### DELETE /sessions/{connection}

Drop a KMP session by connection id.

Possible status codes:
- 204 - Success, connection was dropped
- 400 - The provided connection id is not a number
- 404 - No session matching the provided connection id was found
