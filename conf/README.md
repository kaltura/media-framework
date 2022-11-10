# Media-Framework Sample

This folder contains a sample configuration and controller implementation.
This sample assumes all the media-framework components are deployed on a single server.

## Dependencies

- nginx source code - version 1.9.0 or newer
- PHP-FPM - used by the sample controller implementation
- openssl - required for media encryption (e.g. HLS AES-128)
- libsrt (https://github.com/Haivision/srt) - required for SRT input

## Build

Compile nginx with the following options:
```
--with-stream
--with-threads
--with-http_dav_module
--add-module=/path/to/nginx-srt-module
--add-module=/path/to/media-framework/nginx-common
--add-module=/path/to/media-framework/nginx-kmp-in-module
--add-module=/path/to/media-framework/nginx-kmp-out-module
--add-module=/path/to/media-framework/nginx-rtmp-module
--add-module=/path/to/media-framework/nginx-rtmp-kmp-module
--add-module=/path/to/media-framework/nginx-mpegts-module
--add-module=/path/to/media-framework/nginx-mpegts-kmp-module
--add-module=/path/to/media-framework/nginx-kmp-cc-module
--add-module=/path/to/media-framework/nginx-kmp-rtmp-module
--add-module=/path/to/media-framework/nginx-live-module
--add-module=/path/to/media-framework/nginx-pckg-module
```

## Publish

### Params

The sample commands below use the following parameters:
- `{channel}` - a string (up to 32 chars) that identifies the video being published, for example, `all_hands_22`. To use the low-latency segmenter, prefix the channel name with `ll_`, for example, `ll_sports`.
- `{stream}` - a string (up to 32 chars) that identifies the quality being published, for example, `hd` / `sd`.

### RTMP

Sample ffmpeg command:
`ffmpeg -re -i test.mp4 -c copy -f flv "rtmp://localhost:1935/live/{channel}_{stream}"`

Supported codecs:
- Video: h264
- Audio: aac, mp3

### SRT

Sample ffmpeg command:
`ffmpeg -re -i test.mp4 -c copy -f mpegts "srt://localhost:7045?streamid={channel}_{stream}"`

Supported codecs:
- Video: h264, h265
- Audio: aac, mp3, ac3, e-ac3

## Play

### HLS

- Clear: `http://localhost/clear/ch/{channel}/master.m3u8`
- AES-128: `http://localhost/aes128/ch/{channel}/master.m3u8`
- SAMPLE-AES: `http://localhost/cbcs/ch/{channel}/master.m3u8`

### DASH

- Clear: `http://localhost/clear/ch/{channel}/manifest.mpd`
