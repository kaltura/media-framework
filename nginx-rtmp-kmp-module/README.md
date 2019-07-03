# Nginx based RTMP -> KMP connector

Publishes incoming RTMP streams to one or more destinations using the KMP (Kaltura Media Protocol) protocol.
The module sends notifications in JSON format using HTTP POST to some configured server.
The upstream server is expected to return JSON objects, that contain the destinations to which the KMP stream should be published.

## Configuration

### kmp_ctrl_connect_url
* **syntax**: `kmp_ctrl_connect_url url`
* **default**: `none`
* **context**: `rtmp`, `server`

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

### kmp_ctrl_connect_timeout
* **syntax**: `kmp_ctrl_connect_timeout time`
* **default**: `2s`
* **context**: `rtmp`, `server`

Sets a timeout for sending the connect HTTP request to the upstream server. The timeout includes both the connection establishment as well as the sending of the request.

### kmp_ctrl_connect_read_timeout
* **syntax**: `kmp_ctrl_connect_read_timeout time`
* **default**: `10s`
* **context**: `rtmp`, `server`

Sets a timeout for reading the response of the connect HTTP request from the upstream server. 

### kmp_ctrl_connect_buffer_size
* **syntax**: `kmp_ctrl_connect_buffer_size size`
* **default**: `4k`
* **context**: `rtmp`, `server`

Sets the size of the buffer that holds the response of the connect notification. The buffer size should be large enough to hold the largest expected response.

### kmp_ctrl_connect_retries
* **syntax**: `kmp_ctrl_connect_retries count`
* **default**: `5`
* **context**: `rtmp`, `server`

Sets the number of retries for issuing the connect notification request. A request is considered as failed if -
- The request could not be sent (e.g. connect error)
- The response could not be parsed as JSON (bad http status, non-json content type, invalid JSON)
- The `code` field is missing/has a value other than `ok`

### kmp_ctrl_connect_retry_interval
* **syntax**: `kmp_ctrl_connect_retry_interval time`
* **default**: `2s`
* **context**: `rtmp`, `server`

Sets the time to wait before performing each retry attempt for the connect request.

### kmp_ctrl_publish_url
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
	"media_type": "video",
	"width": 320,
	"height": 240,
	...
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

### kmp_ctrl_unpublish_url
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
}
```

### kmp_ctrl_republish_url
* **syntax**: `kmp_ctrl_republish_url url`
* **default**: `none`
* **context**: `rtmp`, `server`, `application`

Sets an HTTP callback that is called in case of an error/disconnect on some upstream KMP connection.
The upstream server can use this notification to provide the module with a new KMP endpoint to publish to.

Sample request:
```
{
	"event_type": "republish",
	"input_id": "rtmp://testserver:1935/live?arg=value/streamname_1/video"
	"channel_id": "somechannel",
	"track_id": "sometrack",
}
```

Sample response:
```
{
	"url": "kmp://127.0.0.1:6543"
}
```

### kmp_ctrl_timeout
* **syntax**: `kmp_ctrl_timeout time`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for sending HTTP requests to the upstream server. The timeout includes both the connection establishment as well as the sending of the request.

### kmp_ctrl_read_timeout
* **syntax**: `kmp_ctrl_read_timeout time`
* **default**: `20s`
* **context**: `rtmp`, `server`, `application`

Sets a timeout for reading the response of HTTP requests sent to the upstream server. 

### kmp_ctrl_buffer_size
* **syntax**: `kmp_ctrl_buffer_size size`
* **default**: `4k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffer that holds the response of the notifications. The buffer size should be large enough to hold the largest expected response.

### kmp_ctrl_retries
* **syntax**: `kmp_ctrl_retries count`
* **default**: `5`
* **context**: `rtmp`, `server`, `application`

Sets the number of retries for issuing notification requests. A request is considered as failed if -
- The request could not be sent (e.g. connect error)
- The response could not be parsed as JSON (bad http status, non-json content type, invalid JSON)
- The `code` field is missing/has a value other than `ok`

### kmp_ctrl_retry_interval
* **syntax**: `kmp_ctrl_retry_interval time`
* **default**: `2s`
* **context**: `rtmp`, `server`, `application`

Sets the time to wait before performing each retry attempt for notification requests.

### kmp_timescale
* **syntax**: `kmp_timescale number`
* **default**: `90000`
* **context**: `rtmp`, `server`, `application`

Sets the timescale used for frame timestamps in the KMP protocol. This value has to be a multiple of the RTMP timescale (1000), otherwise sync issues will occur.

### kmp_timeout
* **syntax**: `kmp_timeout time`
* **default**: `10s`
* **context**: `rtmp`, `server`, `application`

Sets the timeout for sending data to the upstream KMP server.

### kmp_max_free_buffers
* **syntax**: `kmp_max_free_buffers num`
* **default**: `4`
* **context**: `rtmp`, `server`, `application`

Sets the number of buffers that are retained after received acks from the upstream server. A large value may save some memory alloc/free operations, but can also increase memory usage.

### kmp_video_buffer_size
* **syntax**: `kmp_video_buffer_size size`
* **default**: `64k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send video data to the upstream server. A large value can be more efficient, but increases the latency (a buffer is sent only when full).

### kmp_video_memory_limit
* **syntax**: `kmp_video_memory_limit size`
* **default**: `16m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send video data to the upstream server. If the limit is hit, the module drops the RTMP connection.

### kmp_audio_buffer_size
* **syntax**: `kmp_audio_buffer_size size`
* **default**: `64k`
* **context**: `rtmp`, `server`, `application`

Sets the size of the buffers used to send audio data to the upstream server. A large value can be more efficient, but increases the latency (a buffer is sent only when full).

### kmp_audio_memory_limit
* **syntax**: `kmp_audio_memory_limit size`
* **default**: `16m`
* **context**: `rtmp`, `server`, `application`

Sets the maximum total size of the buffers used to send audio data to the upstream server. If the limit is hit, the module drops the RTMP connection.

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path. 

Copyright © Kaltura Inc. All rights reserved.

