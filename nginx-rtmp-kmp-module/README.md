# Nginx based RTMP -> KMP connector

Publishes incoming RTMP streams to one or more destinations using the KMP (Kaltura Media Protocol) protocol.
The module sends notifications in JSON format using HTTP POST to some configured server.
The upstream server is expected to return JSON objects, that contain the destinations to which the KMP stream should be published.

## Configuration

### Sample configuration

```
rtmp {

    log_format rtmp_format '$remote_addr [$time_local] $command "$app" "$name" "$args" - '
        '$bytes_received $bytes_sent "$pageurl" "$flashver" ($session_time) *$connection';

    access_log /var/log/nginx/rtmp_access_log rtmp_format;

    server {

        listen 1935;

        application live{
            live on;
            deny play all;

            kmp_ctrl_connect_url http://controller/connect;
            kmp_ctrl_publish_url http://controller/publish;
            kmp_ctrl_unpublish_url http://controller/unpublish;
            kmp_ctrl_republish_url http://controller/republish;
        }
    }
}

http {

    location /rtmp_kmp_api/ {
        rtmp_kmp_api write=on;
    }
}
```

### Configuration directives

#### kmp_ctrl_connect_url
* **syntax**: `kmp_ctrl_connect_url url`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets HTTP connection callback. When clients issue an RTMP connect command, an HTTP request is issued asynchronously and command processing is suspended until it returns.

Sample request:
```
{
    "event_type": "connect",
    "app": "live",
    "flashver": "FMLE/3.0 (compatible; FMSc/1.0)",
    "swf_url": "rtmp://testserver:1935/live?arg=value",
    "tc_url": "rtmp://testserver:1935/live?arg=value",
    "page_url": "",
    "addr": "1.2.3.4",
    "connection": 983
}
```

Sample response:
```
{
    "code": "ok",
    "message": "Success"
}
```

If the code field is not `ok`, the RTMP connection is dropped. In this case, the string in the `message` field is returned as the error description to the client.

#### kmp_ctrl_publish_url
* **syntax**: `kmp_ctrl_publish_url url`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the HTTP publish callback, called for each track (audio/video) that is published to the server.

Sample request:
```
{
    "event_type": "publish",
    "input_id": "rtmp://testserver:1935/live?arg=value/streamname_1/video",
    "input_type": "rtmp",
    "rtmp": {
        "app": "live",
        "flashver": "FMLE/3.0 (compatible; FMSc/1.0)",
        "swf_url": "rtmp://testserver:1935/live?arg=value",
        "tc_url": "rtmp://testserver:1935/live?arg=value",
        "page_url": "",
        "addr": "5.6.7.8",
        "connection": 983,
        "name": "streamname_1",
        "type": "live",
        "args": "videoKeyframeFrequency=5&totalDatarate=200",
    },
    "media_info": {
        "media_type": "video",
        "bitrate": 82000,
        "codec_id": 7,
        "extra_data": "0164000bffe100196764000bacd942847e5c0440000003004000000783c50a658001000468efbcb0",
        "width": 160,
        "height": 120,
        "frame_rate": 15.00
    }
}
```

Sample response:
```
{
    "channel_id": "somechannel",
    "track_id": "sometrack",
    "upstreams": [{
        "url": "kmp://127.0.0.1:6543"
    }]
}
```

#### kmp_ctrl_unpublish_url
* **syntax**: `kmp_ctrl_unpublish_url url`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets the HTTP unpublish callback, called whenever a track (audio/video) stops being published to the server, or some unrecoverable error occurs when sending to upstream.
The response of this notification is ignored, and no retries are performed in case of error.

Sample request:
```
{
    "event_type": "unpublish",
    "input_id": "rtmp://testserver:1935/live?arg=value/streamname_1/video"
    "reason": "rtmp_close"
}
```

#### kmp_ctrl_republish_url
* **syntax**: `kmp_ctrl_republish_url url`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets an HTTP callback that is called in case of an error/disconnect on some upstream KMP connection.
The upstream server can use this notification to provide the module with a new KMP endpoint to publish to.

Sample request:
```
{
    "event_type": "republish",
    "id": "upstream_id",
    "input_id": "rtmp://testserver:1935/live?arg=value/streamname_1/video"
    "channel_id": "somechannel",
    "track_id": "sometrack"
    "input_type": "rtmp",
    "rtmp": {
        "app": "live",
        "flashver": "FMLE/3.0 (compatible; FMSc/1.0)",
        "swf_url": "rtmp://testserver:1935/live?arg=value",
        "tc_url": "rtmp://testserver:1935/live?arg=value",
        "page_url": "",
        "addr": "5.6.7.8",
        "connection": 983,
        "name": "streamname_1",
        "type": "live",
        "args": "videoKeyframeFrequency=5&totalDatarate=200",
    },
    "media_info": {
        "media_type": "video",
        "bitrate": 82000,
        "codec_id": 7,
        "extra_data": "0164000bffe100196764000bacd942847e5c0440000003004000000783c50a658001000468efbcb0",
        "width": 160,
        "height": 120,
        "frame_rate": 15.00
    }
}
```

Sample response:
```
{
    "url": "kmp://127.0.0.1:6543"
}
```

#### kmp_ctrl_add_header
* **syntax**: `kmp_ctrl_add_header name value`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Adds a request header to all control requests (publish, unpublish etc.).
There could be several kmp_ctrl_add_header directives. These directives are inherited from the previous level if and only if there are no kmp_ctrl_add_header directives defined on the current level.

#### kmp_ctrl_timeout
* **syntax**: `kmp_ctrl_timeout time`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for sending HTTP requests to the upstream server. The timeout includes both the connection establishment as well as the sending of the request.

#### kmp_ctrl_read_timeout
* **syntax**: `kmp_ctrl_read_timeout time`
* **default**: `20s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for reading the response of HTTP requests sent to the upstream server.

#### kmp_ctrl_buffer_size
* **syntax**: `kmp_ctrl_buffer_size size`
* **default**: `4k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffer that holds the response of the notifications. The buffer size should be large enough to hold the largest expected response.

#### kmp_ctrl_retries
* **syntax**: `kmp_ctrl_retries count`
* **default**: `5`
* **context**: `rtmp`, `server`, `application`

Sets the number of retries for issuing notification requests. A request is considered as failed if -
- The request could not be sent (e.g. connect error)
- The response could not be parsed as JSON (bad http status, non-json content type, invalid JSON)
- The `code` field is missing/has a value other than `ok`

#### kmp_ctrl_retry_interval
* **syntax**: `kmp_ctrl_retry_interval time`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets the time to wait before performing each retry attempt for notification requests.

#### kmp_timescale
* **syntax**: `kmp_timescale number`
* **default**: `90000`
* **context**: `rtmp`, `server`, `application`

Sets the timescale used for frame timestamps in the KMP protocol. This value has to be a multiple of the RTMP timescale (1000), otherwise sync issues will occur.

#### kmp_timeout
* **syntax**: `kmp_timeout time`
* **default**: `10s`
* **context**: `rtmp`, `server`, `application`

Sets the timeout for sending data to the upstream KMP server.

#### kmp_max_free_buffers
* **syntax**: `kmp_max_free_buffers num`
* **default**: `4`
* **context**: `rtmp`, `server`, `application`

Sets the number of buffers that are retained after received acks from the upstream server. A large value may save some memory alloc/free operations, but can also increase memory usage.

#### kmp_video_buffer_size
* **syntax**: `kmp_video_buffer_size size`
* **default**: `64k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send video data to the upstream server. A large value can be more efficient, but increases the latency (a buffer is sent only when full).

#### kmp_video_mem_limit
* **syntax**: `kmp_video_mem_limit size`
* **default**: `32m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send video data to the upstream server. If the limit is hit, the module drops the RTMP connection.

#### kmp_audio_buffer_size
* **syntax**: `kmp_audio_buffer_size size`
* **default**: `4k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send audio data to the upstream server. A large value can be more efficient, but increases the latency (a buffer is sent only when full).

#### kmp_audio_mem_limit
* **syntax**: `kmp_audio_mem_limit size`
* **default**: `1m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send audio data to the upstream server. If the limit is hit, the module drops the RTMP connection.

#### kmp_flush_timeout
* **syntax**: `kmp_flush_timeout time`
* **default**: `1s`
* **context**: `rtmp`, `server`, `application`

Sets the timeout for flushing buffered data to the upstream KMP server.
KMP data is kept in buffers of size kmp_xxx_buffer_size, a buffer is sent when it becomes full, or when the flush timeout expires.

#### kmp_idle_timeout
* **syntax**: `kmp_idle_timeout time`
* **default**: `30s`
* **context**: `rtmp`, `server`

Sets the idle time for the RTMP connection.
The idle timer starts when the RTMP socket is connected, and gets reset on every incoming video/audio frame.
If the idle timer expires, the RTMP connection is dropped.

#### rtmp_kmp_api
* **syntax**: `rtmp_kmp_api [write=on|off]`
* **default**: `none`
* **context**: `location`

Turns on the module API interface in the surrounding location. Access to this location should be limited.

The write parameter determines whether the API is read-only or read-write. By default, the API is read-only.


## API endpoints

- /

    Supported methods:

    * GET - Returns detailed information about all connected sessions and upstreams.

        Possible responses:

        200 - Success, returns an object

- /sessions/{connection}

    Supported methods:

    * DELETE - Drops an RTMP session by connection id.

        Possible responses:

        204 - Success, connection was dropped

        400 - Provided connection id is not a number

        404 - No session matching the provided connection id was found


## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path.

Copyright © Kaltura Inc. All rights reserved.

