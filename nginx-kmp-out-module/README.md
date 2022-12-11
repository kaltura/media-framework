# Nginx KMP Output Module

A utility module for outputting KMP tracks.

Used by: *nginx-rtmp-kmp-module*, *nginx-mpegts-kmp-module*, *nginx-kmp-cc-module*.

Dependencies: *nginx-common*.

## Features

- Support for dynamic destinations, via the `publish` HTTP request
- Notification on input end / upstream error (`unpublish` HTTP request)
- Support for publishing a single track to multiple upstreams (replication)
- Reconnect on upstream error, via the `republish` HTTP request
- Configurable resume offset - in case of `republish`, can start sending frames from one of the following offsets -
    - The frame after the last frame that was explicitly acked
    - The frame after the last frame was sent successfully (can be used with upstreams that do not support sending KMP acks)
- Memory usage enforcement
- Protection against upstreams that do not return acks in a timely manner - free buffers when the memory usage percent exceeds a configured value
- Management API

## Control messages

### Publish

#### Sample request (RTMP publishing)

```json
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

**Note:** the exact structure may change depending on which module uses nginx-kmp-out-module.
For example, when used with nginx-mpegts-kmp-module, the `rtmp` block is replaced with an `mpegts` block, and contains different fields.

#### Sample response

```json
{
    "channel_id": "somechannel",
    "track_id": "sometrack",
    "upstreams": [{
        "url": "kmp://127.0.0.1:6543"
    }]
}
```

#### Response fields

- `channel_id` - required, string, the channel id sent on the KMP connect packet
- `track_id` - required, string, the track id sent on the KMP connect packet
- `upstreams` - required, array of objects, each object can contain the following fields:
    - `url` - required, string, must include ip address and port (hostname is not supported), can optionally be prefixed with `kmp://`
    - `id` - optional, string, used for identifying the upstream in `republish` requests and in the management API
    - `resume_from` - optional, string, sets the offset from which the module starts sending frames, if the upstream connection is re-established.
        The following values are defined:
        - `last_acked` - the frame after the last frame that was explicitly acked (this is the default)
        - `last_sent` - the frame after the last frame that was successfully sent
    - `connect_data` - optional, string, base64 encoded, sent as the data of the KMP connect packet

### Unpublish

#### Sample request (RTMP publishing)

```json
{
    "event_type": "unpublish",
    "input_id": "rtmp://testserver:1935/live?arg=value/streamname_1/video"
    "reason": "rtmp_close"
}
```

The `reason` field in the request can have the following values:
* `alloc_failed` - memory limit reached / out of memory
* `append_failed` - failed to append data to an upstream (out of memory)
* `create_publish_failed` - failed to create publish request (out of memory)
* `create_upstream_failed` - failed to create upstream object (invalid url or out of memory)
* `parse_publish_failed` - got invalid response to 'publish' event (error http status, unknown content type etc.)
* `upstream_error` - error on a KMP upstream connection

### Republish

#### Sample request (RTMP publishing)

```json
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
        "swf_url": "",
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

#### Sample response

```json
{
    "url": "kmp://127.0.0.1:6543"
}
```

#### Response fields

- `url` - required, string, must include ip address and port (hostname is not supported), can optionally be prefixed with `kmp://`
- `connect_data` - optional, string, base64 encoded, sent as the data of the KMP connect packet

## Configuration Directives

### kmp_out_api
* **syntax**: `kmp_out_api [write=on]`
* **default**: `none`
* **context**: `location`

Enables the API interface of this module in the surrounding location block. Access to this location should be limited.

The optional `write` parameter determines whether the API is read-only or read-write. By default, the API is read-only.

## API Endpoints

### GET /

Get the full status JSON.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /tracks

Get the status of the active output tracks.

Possible status codes:
- 200 - Success, returns a JSON object

### GET /tracks?list=1

Get the ids of the active output tracks.

Possible status codes:
- 200 - Success, returns a JSON array of strings

### GET /tracks/{track_id}

Get the status of the specified output track.

Possible status codes:
- 200 - Success, returns a JSON object
- 404 - Track not found

### GET /tracks/{track_id}/upstreams

Get the status of the upstreams of the specified output track.

Possible status codes:
- 200 - Success, returns a JSON array of objects
- 404 - Track not found

### GET /tracks/{track_id}/upstreams?list=1

Get the ids of the upstreams of the specified output track.

Possible status codes:
- 200 - Success, returns a JSON array of strings
- 404 - Track not found

### POST /tracks/{track_id}/upstreams

Add an upstream to the specified output track.

The request body must be a JSON object, with the following fields:
- `url` - required, string, must include ip address and port (hostname is not supported), can optionally be prefixed with `kmp://`
- `id` - optional, string, used for identifying the upstream in `republish` requests and in the API
- `src_id` - optional, string, if supplied, must contain the id of an existing upstream on the track to copy from
- `resume_from` - optional, string, sets the offset from which the module starts sending frames, if the upstream connection is re-established.
    The following values are defined:
    - `last_acked` - the frame after the last frame that was explicitly acked (this is the default)
    - `last_sent` - the frame after the last frame that was successfully sent
- `connect_data` - optional, string, base64 encoded, sent as the data of the KMP connect packet

Possible status codes:
- 201 - Success, upstream was created
- 404 - Track not found / track has no upstreams / source upstream not found
- 415 - Request body is not a valid JSON object / missing `url` property / invalid `url`

### DELETE /tracks/{track_id}/upstreams/{upstream_id}

Remove the specified upstream from the specified track.

Possible status codes:
- 204 - Success, upstream was removed
- 404 - Track not found / upstream not found
