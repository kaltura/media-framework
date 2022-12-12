# Nginx RTMP -> KMP Module

Publishes incoming RTMP streams to one or more destinations using the KMP (Kaltura Media Protocol) protocol.

Dependencies: *nginx-common*, *nginx-kmp-out-module*


## Configuration

### Sample Configuration

```nginx
rtmp {
    server {
        listen 1935;

        application live {
            live on;
            sandbox on;
            deny play all;

            kmp_ctrl_connect_url http://controller/connect;
            kmp_ctrl_publish_url http://controller/publish;
            kmp_ctrl_unpublish_url http://controller/unpublish;
            kmp_ctrl_republish_url http://controller/republish;
        }
    }
}

http {
    server {
        listen 8001;

        location /rtmp_kmp_api/ {
            rtmp_kmp_api write=on;
        }
    }
}
```

### Configuration Directives

#### kmp_ctrl_connect_url
* **syntax**: `kmp_ctrl_connect_url url;`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the URL of the HTTP `connect` callback. When clients issue an RTMP connect command, an HTTP request is issued asynchronously and command processing is suspended until it returns.
If the response includes a `code` field with a value of `ok`, command processing is resumed.
If the response does not include a `code` field or its value is not `ok`, the RTMP connection is dropped.
In this case, the string in the `message` field is returned as the error description to the client.

Sample request body:
```json
{
    "event_type": "connect",
    "input_type": "rtmp",
    "rtmp": {
        "app": "live",
        "flashver": "FMLE/3.0 (compatible; FMSc/1.0)",
        "swf_url": "",
        "tc_url": "rtmp://testserver:1935/live?arg=value",
        "page_url": "",
        "addr": "127.0.0.1",
        "connection": 57
    }
}
```

Sample response:
```json
{
    "code": "ok",
    "message": "Success"
}
```

#### kmp_ctrl_publish_url
* **syntax**: `kmp_ctrl_publish_url url;`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the URL of the HTTP `publish` callback, called for each track (audio/video) that is published to the server.

See [Publish](../nginx-kmp-out-module/README.md#publish) for more details on the `publish` request.

#### kmp_ctrl_unpublish_url
* **syntax**: `kmp_ctrl_unpublish_url url;`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the URL of the HTTP `unpublish` callback, called whenever a track (audio/video) stops being published to the server, or some unrecoverable error occurs when sending to upstream.
The response of this notification is ignored, and no retries are performed in case of error.

See [Unpublish](../nginx-kmp-out-module/README.md#unpublish) for more details on the `unpublish` request.

In addition to the `reason` values listed in nginx-kmp-out-module, this module adds the following values:
* `create_track_failed` - failed to create track object (out of memory)
* `rtmp_bad_data` - invalid audio/video data received on rtmp
* `rtmp_close` - graceful rtmp unpublish
* `rtmp_disconnect` - HTTP/TCP connection dropped
* `rtmp_kmp_error` - generic module error, usually appears when some other track on the same RTMP connection initiated the disconnect

#### kmp_ctrl_republish_url
* **syntax**: `kmp_ctrl_republish_url url;`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the URL of the HTTP `republish` callback, called in case of an error/disconnect on some upstream KMP connection.
The upstream server can use this event to provide the module with a new KMP endpoint to publish to.

See [Republish](../nginx-kmp-out-module/README.md#republish) for more details on the `republish` request.

#### kmp_ctrl_add_header
* **syntax**: `kmp_ctrl_add_header name value;`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Adds a request header to all control requests (`publish`, `unpublish` etc.).
There could be several `kmp_ctrl_add_header` directives.
These directives are inherited from the previous level if and only if there are no `kmp_ctrl_add_header` directives defined on the current level.

#### kmp_ctrl_timeout
* **syntax**: `kmp_ctrl_timeout msec;`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for sending HTTP requests to the upstream server.
The timeout includes both the connection establishment as well as the sending of the request.

#### kmp_ctrl_read_timeout
* **syntax**: `kmp_ctrl_read_timeout msec;`
* **default**: `20s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for reading the response of HTTP requests sent to the upstream server.

#### kmp_ctrl_buffer_size
* **syntax**: `kmp_ctrl_buffer_size size;`
* **default**: `4k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffer that holds the response of the HTTP requests.
The buffer size should be large enough to hold the largest expected response.

#### kmp_ctrl_retries
* **syntax**: `kmp_ctrl_retries num;`
* **default**: `5`
* **context**: `rtmp`, `server`, `application`

Sets the number of retries for issuing HTTP requests. A request is considered as failed if -
- The request could not be sent (e.g. connect error)
- The response could not be parsed as JSON (bad http status, non-json content type, invalid JSON)
- The `code` field is missing/has a value other than `ok`

#### kmp_ctrl_retry_interval
* **syntax**: `kmp_ctrl_retry_interval msec;`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets the time to wait before performing each retry attempt for HTTP requests.

#### kmp_timescale
* **syntax**: `kmp_timescale num;`
* **default**: `90000`
* **context**: `rtmp`, `server`, `application`

Sets the timescale used for frame timestamps in the KMP protocol. This value has to be a multiple of the RTMP timescale (1000), otherwise sync issues will occur.

#### kmp_timeout
* **syntax**: `kmp_timeout msec;`
* **default**: `10s`
* **context**: `rtmp`, `server`, `application`

Sets the timeout for sending data to the upstream KMP server.

#### kmp_max_free_buffers
* **syntax**: `kmp_max_free_buffers num;`
* **default**: `4`
* **context**: `rtmp`, `server`, `application`

Sets the maximum number of free buffers that are kept after receiving acks from the upstream server.
A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_buffer_bin_count
* **syntax**: `kmp_buffer_bin_count num;`
* **default**: `8`
* **context**: `rtmp`, `server`, `application`

Sets the number of bins that are used to group the video/audio buffers.
The buffers are grouped in bins according to the number of allocated blocks they contain.
When allocating a block, the allocator prefers to use buffers that are more utilized.
This is done in order to concentrate the allocated blocks in fewer buffers, and enable
the allocator to free unused buffers.

#### kmp_mem_high_watermark
* **syntax**: `kmp_mem_high_watermark percent;`
* **default**: `75`
* **context**: `rtmp`, `server`, `application`

A memory utilization threshold, expressed as a percent of the memory limit.
If the high watermark is reached, the module starts releasing video/audio buffers
of frames that were not acknowledged. The process stops when the memory usage
drops below the low watermark threshold.

#### kmp_mem_low_watermark
* **syntax**: `kmp_mem_low_watermark percent;`
* **default**: `50`
* **context**: `rtmp`, `server`, `application`

See the description of `kmp_mem_high_watermark` above.

#### kmp_video_buffer_size
* **syntax**: `kmp_video_buffer_size size;`
* **default**: `64k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send video data to the upstream server.
A large value can be more efficient, but increases the latency (a buffer is sent either when it's full or the flush timeout expires).

#### kmp_video_mem_limit
* **syntax**: `kmp_video_mem_limit size;`
* **default**: `32m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send video data to the upstream server.
If the limit is hit, the module drops the RTMP connection.

#### kmp_audio_buffer_size
* **syntax**: `kmp_audio_buffer_size size;`
* **default**: `4k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send audio data to the upstream server.
A large value can be more efficient, but increases the latency (a buffer is sent either when it's full or the flush timeout expires).

#### kmp_audio_mem_limit
* **syntax**: `kmp_audio_mem_limit size;`
* **default**: `1m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send audio data to the upstream server.
If the limit is hit, the module drops the RTMP connection.

#### kmp_flush_timeout
* **syntax**: `kmp_flush_timeout msec;`
* **default**: `1s`
* **context**: `rtmp`, `server`, `application`

Sets the timeout for flushing buffered data to the upstream KMP server.
KMP data is kept in buffers of size kmp_xxx_buffer_size, a buffer is sent when it becomes full, or when the flush timeout expires.

#### kmp_log_frames
* **syntax**: `kmp_log_frames on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

When enabled, the module logs the metadata of every frame that is sent -
1. KMP frame header - created, dts, flags, pts delay
2. Data size and MD5 hash

#### kmp_republish_interval
* **syntax**: `kmp_republish_interval sec;`
* **default**: `1`
* **context**: `rtmp`, `server`, `application`

The minimum time that should pass between `republish` requests, in seconds.

#### kmp_max_republishes
* **syntax**: `kmp_max_republishes num;`
* **default**: `10`
* **context**: `rtmp`, `server`, `application`

The maximum number of consecutive `republish` requests that can be sent before giving up.
If more than `kmp_republish_interval` seconds passed since the last `republish`, the counter is reset.

#### kmp_idle_timeout
* **syntax**: `kmp_idle_timeout msec;`
* **default**: `30s`
* **context**: `rtmp`, `server`

Sets the idle time for the RTMP connection.
The idle timer starts when the RTMP socket is connected, and gets reset on every incoming video/audio frame.
If the idle timer expires, the RTMP connection is dropped.

#### rtmp_kmp_api
* **syntax**: `rtmp_kmp_api [write=on|off];`
* **default**: `none`
* **context**: `location`

Enables the API interface of this module in the surrounding location block. Access to this location should be limited.

The optional `write` parameter determines whether the API is read-only or read-write. By default, the API is read-only.


## API Objects

The sections below list the possible fields in each type of API object.

### Global Scope

- `version` - string, nginx-rtmp-kmp-module version
- `nginx_version` - string, nginx version
- `rtmp_version` - string, nginx-rtmp-module version
- `compiler` - string, the compiler used to build nginx-rtmp-kmp-module
- `built` - string, the time nginx-rtmp-kmp-module was built
- `pid` - integer, the nginx process id
- `uptime` - integer, the time since the nginx worker was started, in seconds
- `naccepted` - integer, the total number of RTMP connections that were accepted since the nginx worker started
- `bw_in` - integer, the incoming bandwidth of RTMP connections (measured in 10 sec intervals), in bits per second
- `bytes_in` - integer, the total number of bytes received in RTMP connections
- `bw_out` - integer, the outgoing bandwidth of RTMP connections (measured in 10 sec intervals), in bits per second
- `bytes_out` - integer, the total number of bytes sent in RTMP connections
- `servers` - array of objects, each object is a [Server Object](#server-object)

### Server Object

- `applications` - array of objects, each object is an [Application Object](#application-object)

### Application Object

- `name` - string, the name of the application, as specified in the `application` block in nginx configuration
- `sessions` - array of objects, each object is a [Session Object](#session-object), representing an incoming RTMP connection

### Session Object

- `flashver` - string, the `flashVer` value that was received in the RTMP `connect` command
- `swf_url` - string, the `swfUrl` value that was received in the RTMP `connect` command
- `tc_url` - string, the `tcUrl` value that was received in the RTMP `connect` command
- `page_url` - string, the `pageUrl` value that was received in the RTMP `connect` command
- `type3_ext_ts` - string, the detection status of the extended timestamp field in type 3 RTMP packets. The following values are defined:
    - `off` - extended timestamps are not sent in type 3 packets
    - `on` - extended timestamps are sent in type 3 packets
    - `unknown` - no type 3 packet on a message containing an extended timestamp was received yet
- `remote_addr` - string, the ip + port of the remote peer
- `uptime` - integer, the time that passed since the connection was accepted, in seconds
- `connection` - integer, the nginx connection identifier, unique per nginx worker process
- `streams` - array of objects, each object is a [Stream Object](#stream-object)

### Stream Object

- `name` - string, the name of the stream, as received in the RTMP `publish` command
- `args` - string, the args of the stream, as received in the RTMP `publish` command. The args are extracted by splitting the incoming stream name with a `?` delimiter.
- `type` - string, the type of the stream, as received in the RTMP `publish` command, usually `live`
- `bw_in` - integer, the incoming bandwidth on the stream (measured in 10 sec intervals), in bits per second
- `bytes_in` - integer, the total number of bytes received on the stream
- `bw_in_audio` - integer, the incoming bandwidth of audio packets on the stream (measured in 10 sec intervals), in bits per second
- `bytes_in_audio` - integer, the total number of bytes of audio packets received on the stream
- `bw_in_video` - integer, the incoming bandwidth of video packets on the stream (measured in 10 sec intervals), in bits per second
- `bytes_in_video` - integer, the total number of bytes of video packets received on the stream
- `bw_out` - integer, the outgoing bandwidth on the stream (measured in 10 sec intervals), in bits per second
- `bytes_out` - integer, the total number of bytes sent on the stream
- `uptime` - integer, the time that passed since the stream was published, in seconds
- `tracks` - object, the keys hold the media type (`video` / `audio`), the values are [Track Objects](../nginx-kmp-out-module/README.md#track-object)


## API Endpoints

### GET /

Get the full status JSON.

Possible status codes:
- 200 - Success, returns a JSON object

### DELETE /sessions/{connection}

Drop an RTMP session by connection id.

Possible status codes:
- 204 - Success, connection was dropped
- 400 - The provided connection id is not a number
- 404 - No session matching the provided connection id was found
