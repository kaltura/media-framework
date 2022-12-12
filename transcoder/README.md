# Transcoder

FFmpeg-based KMP video/audio transcoder.

## Build

```sh
docker build -t kaltura/transcoder-dev -f Dockerfile.build ./
docker build -t kaltura/transcoder-dev -f Dockerfile ./
```

## Run

```sh
docker run -p 16543:16543 -p 18001:18001 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it -v `pwd`/config.json:/data/config.json kaltura/transcoder-dev:latest /build/transcoder -f /data/config.json
```

## Usage

`transcoder [-c CONF_JSON] [-f CONF_FILE]`

### Options

#### -c CONF_JSON
Sets the configuration JSON.

#### -f CONF_FILE
Loads the configuration JSON from the provided file name.

## Configuration

The transcoder configuration is provided as a JSON object, each one of the sections below describes a key that can be set under the top level object.

### kmp object

#### kmp.listenPort
* **type**: `int`
* **default**: `9000`

The TCP port number to listen on for incoming KMP connections.

#### kmp.listenAddress
* **type**: `string`
* **default**: `127.0.0.1`

The interface to listen on for incoming KMP connections.

#### kmp.acceptTimeout
* **type**: `int`
* **default**: `10`

Sets the timeout in seconds for accepting a KMP connection.

#### kmp.sndRcvTimeout
* **type**: `int`
* **default**: `180`

Sets the send/receive timeout in seconds for incoming KMP connections (the SO_RCVTIMEO / SO_SNDTIMEO socket options).

#### kmp.userTimeoutMs
* **type**: `int`
* **default**: `2000`

Sets the value of the TCP_USER_TIMEOUT setting for outgoing KMP connections.
When the value is greater than 0, it specifies the maximum amount of time in milliseconds
that transmitted data may remain unacknowledged, or bufferred data may remain
untransmitted before the connection is dropped.

#### kmp.fd
* **type**: `int`
* **default**: `-1`

When greater than zero, sets the file descriptor of the incoming KMP connection.
When the value is negative, the transcoder accepts a connection, using the provided address/port.

### output object

#### output.streamingUrl
* **type**: `string`
* **default**: ``

Sets the destination host/port of outgoing KMP connections, must be in the format `kmp://host:port`.

#### output.saveFile
* **type**: `boolean`
* **default**: `false`

When set to `true` the transcoder saves each output track in a file.

#### output.outputFileNamePattern
* **type**: `string`
* **default**: `output_%s.mp4`

Sets the pattern of output file names, the string `%s` is replaced with the id of the output track.

### control object

#### control.listenPort
* **type**: `int`
* **default**: `12345`

The TCP port number to listen on for incoming HTTP connections.

#### control.listenAddress
* **type**: `string`
* **default**: `0.0.0.0`

The interface to listen on for incoming HTTP connections.

### engine object

#### engine.encoders
* **type**: `object`
* **default**: ``

Each key defines a codec name, that can be referenced by the `codec` value under an output track (see below).
The values are arrays of strings, that contain ffmpeg encoder names (e.g. `libx264`) ordered by priority.

#### engine.presets
* **type**: `object`
* **default**: ``

An object that defines presets for the different video codecs.
Each key defines a preset name, that can be referenced by the `preset` value under `videoParams` (see below).
The values are objects that map an ffmpeg encoder name (e.g. `libx264`) to a preset (e.g. `faster`).

#### engine.nvidiaAccelerated
* **type**: `boolean`
* **default**: `true`

When enabled, the transcoder will attempt to use an hardware accelerated video decoder.

### outputTracks array

An array of objects, each representing an output track.

#### outputTracks[n].trackId
* **type**: `string`
* **default**: ``

Sets the id of the track, sent in the KMP `connect` packet.

#### outputTracks[n].enabled
* **type**: `boolean`
* **default**: `true`

When set to `false`, the output track is ignored.

#### outputTracks[n].passthrough
* **type**: `boolean`
* **default**: `true`

When set to `true`, the incoming media frames will be sent to the output track as-is.
When set to `false`, the incoming media frames will be transcoded to generate the output.

#### outputTracks[n].bitrate
* **type**: `int`
* **default**: `-1`

Sets the bitrate of the output track.

#### outputTracks[n].codec
* **type**: `string`
* **default**: ``

Sets the encoder, the value must match one of the keys of the `encoders` object under `engine`.

#### outputTracks[n].videoParams object

##### outputTracks[n].videoParams.width
* **type**: `int`
* **default**: `-2`

The width of the output video in pixels.

##### outputTracks[n].videoParams.height
* **type**: `int`
* **default**: `-2`

The height of the output video in pixels.

##### outputTracks[n].videoParams.profile
* **type**: `string`
* **default**: ``

Sets the name of the profile (e.g. `high`) that should be used.

##### outputTracks[n].videoParams.preset
* **type**: `string`
* **default**: ``

Sets the preset, the value must match one of the keys of the `presets` object under `engine`.

##### outputTracks[n].videoParams.skipFrame
* **type**: `int`
* **default**: `1`

The transcoder selects one frame every N-th frame, when the value is 1, no frame will be skipped.
When the value is 2, for example, half of the frames will be skipped.

#### outputTracks[n].audioParams object

##### outputTracks[n].audioParams.channels
* **type**: `int`
* **default**: `2`

Sets the number of audio channels.

##### outputTracks[n].audioParams.samplingRate
* **type**: `int`
* **default**: `48000`

Sets the audio sampling rate.

### input object

#### input.file
* **type**: `string`
* **default**: ``

Enables streaming of the supplied file to the transcoder's KMP server.
When the file name ends with `.kmp`, it is assumed to be in KMP format, and streamed as-is.
Otherwise, it is parsed as a media file using libavformat.

#### input.channelId
* **type**: `string`
* **default**: `1_abcdefgh`

Sets the KMP channel id that is sent when streaming from a media file.

#### input.duration
* **type**: `int`
* **default**: `-1`

Sets the maximum duration to stream when streaming from a media file, using 90kHz timescale.
When set to -1, the entire file is streamed.

#### input.realTime
* **type**: `boolean`
* **default**: `false`

When enabled, the frames are sent at a rate matching their timestamp differences.
When disabled, the frames are sent as fast as possible.

#### input.activeStream
* **type**: `int`
* **default**: `0`

Sets the index of the track that should be streamed.
For example, when streaming a video/audio mp4 file, activeStream 0 will stream the video track, while activeStream 1 will stream the audio track.

#### input.randomDataPercentage
* **type**: `int`
* **default**: `0`

When set to a value greater than zero, sets the percent of frames that will be replaced with random data, instead of the real codec sample.
Used for testing resilience to bad input.

### debug object

#### debug.diagnosticsIntervalInSeconds
* **type**: `int`
* **default**: `60`

Sets the interval in seconds for updating the diagnostics data.

### frameDropper object

#### frameDropper.enabled
* **type**: `boolean`
* **default**: `false`

When set to `true`, the transcoder will drop frames, if it accumulates a lag from real time (due to CPU/GPU reaching 100%).

#### frameDropper.queueSize
* **type**: `int`
* **default**: `2000`

Sets the maximum size of the frame dropper queue, in frames.

#### frameDropper.nonKeyFrameDropperThreshold
* **type**: `int`
* **default**: `10`

Sets the threshold for dropping a packet before it's decoded, in seconds.
Before sending a packet to the decoder, if the delta between its timestamp and the latest timestamp is greater than the threshold, the packet is dropped (as well as all other packets until the next keyframe).
Keyframes are never dropped.

#### frameDropper.decodedFrameDropperThreshold
* **type**: `int`
* **default**: `10`

Sets the threshold for dropping a frame before it's encoded, in seconds.
Before sending a frame to the encoder, if the delta between its timestamp and the latest timestamp is greater than the threshold, the frame is dropped.
Keyframes are never dropped.

### logger object

#### logger.logLevel
* **type**: `string`
* **default**: `verbose`

Sets the logging level, the following values are supported -
- `quiet`
- `panic`
- `fatal`
- `error`
- `warning`
- `info`
- `verbose`
- `debug`
- `trace`

#### logger.id
* **type**: `string`
* **default**: ``

Sets the logger id, the logger id is printed on all log messages.

### errorPolicy object

#### errorPolicy.exitOnError
* **type**: `boolean`
* **default**: `false`

When set to `true`, the transcoder exits on any error.
When set to `false`, the transcoder exits only on fatal errors.

### autoAckModeEnabled
* **type**: `boolean`
* **default**: `false`

When set to `true`, no acks will be sent on the incoming KMP connection.

## Control Endpoints

### GET /control/status

Returns a fixed response:
```json
{
    "uri": "/control/status",
    "result": {
        "state": "ready"
    }
}
```
Can be used as a readiness probe.

### GET /control/diagnostics

Returns a JSON object with the latest diagnostics data that was collected.

Sample response:
```json
{
    "uri": "/control/diagnostics",
    "result": {
        "transcoder": {
            "processed": {
                "totalSamples": 1906,
                "totalErrors": 0,
                "bitrate": 434517,
                "fps": 24.27,
                "rate": 0.97,
                "drift": -42,
                "firstTimeStamp": "2022-11-20T07:41:14.98Z",
                "lastTimeStamp": "2022-11-20T07:42:31.14Z",
                "lastDts": 6860070
            },
            "outputs": [{
                "track_id": "vsrc",
                "totalFrames": 1906,
                "currentFrameRate": 24.27,
                "codecData": "480x256",
                "lastAck": 150203706746277,
                "lastDts": 6860070,
                "bitrate": -1,
                "currentBitrate": 434517
            },
            ...
            ],
            "lastIncomingDts": 0,
            "lastProcessedDts": 6860070,
            "minDts": 6813270,
            "processTime": 520,
            "latency": 1549,
            "currentIncomingQueueLength": 0
        },
        "receiver": {
            "totalSamples": 1906,
            "totalErrors": 0,
            "bitrate": 434517,
            "fps": 24.27,
            "rate": 0.97,
            "drift": -42,
            "firstTimeStamp": "2022-11-20T07:41:14.98Z",
            "lastTimeStamp": "2022-11-20T07:42:31.14Z",
            "lastDts": 6860070
        },
        "time": 1668930152
    }
}
```

## Valgrind

In order to find leaks with valgrind:
1. Make sure you use the dev image, or alternatively, attach to a running container and run `apt-get install valgrind`.
2. Modify command line to `valgrind --leak-check=<full|summary> <original command line>`. For example, `docker run -ti dev-transcoder:latest valgrind --leak-check=full /build/transcoder -f jsonfile`
3. Run the container, the more time the better.
4. Observe the logs, once program exits valgrind will report any leaks if finds including call stack.
