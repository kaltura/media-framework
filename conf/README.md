# Media-Framework Sample

This folder contains a sample configuration and controller implementation.
This sample assumes all the media-framework components are deployed on a single server.

## Dependencies

- nginx source code - version 1.17.0 or newer
- PHP-FPM - used by the sample controller implementation
- openssl - required for media encryption (e.g. HLS AES-128)

The following dependencies are required for SRT input:
- nginx-stream-preread-str-module source code - https://github.com/kaltura/nginx-stream-preread-str-module
- nginx-srt-module source code - https://github.com/kaltura/nginx-srt-module
- libsrt - build & install (https://github.com/Haivision/srt)

## Build

1. Use [build.sh](build.sh) to configure nginx - from the nginx source root, execute -

    `/path/to/media-framework/conf/build.sh /path/to/nginx-srt-module /path/to/nginx-stream-preread-str-module`

2. Run: `make`

## Step-by-step commands for Ubuntu 20

```
# install dependencies
sudo apt update
sudo apt-get install build-essential libpcre3-dev zlib1g-dev
sudo apt-get install tclsh cmake libssl-dev
sudo apt-get install php-fpm php-curl

# clone repos
cd /opt
git clone https://github.com/nginx/nginx/
git clone https://github.com/kaltura/media-framework/
git clone https://github.com/Haivision/srt
git clone https://github.com/kaltura/nginx-srt-module
git clone https://github.com/kaltura/nginx-stream-preread-str-module

# build libsrt
cd /opt/srt
./configure
make
sudo make install

# build nginx
cd /opt/nginx
/opt/media-framework/conf/build.sh /opt/nginx-srt-module /opt/nginx-stream-preread-str-module
make
sudo make install

# setup nginx
mv /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.conf.orig
ln -s /opt/media-framework/conf/nginx.conf /usr/local/nginx/conf/nginx.conf
mkdir /var/log/nginx

# start nginx
sudo /usr/local/nginx/sbin/nginx

# publish a test stream
sudo apt-get install ffmpeg
wget http://cdnapi.kaltura.com/p/2035982/playManifest/entryId/0_w4l3m87h/flavorId/0_vsu1xutk/format/download/a.mp4
ffmpeg -re -i a.mp4 -c copy -f flv "rtmp://localhost:1935/live/ch1_s1"

# play
# HLS - localhost/clear/ch/ch1/master.m3u8
# DASH - localhost/clear/ch/ch1/manifest.mpd
```

## Publish

### Params

The sample commands below use the following parameters:
- `{channel}` - a string (up to 32 chars) that identifies the video being published, for example, `all_hands_22`. To use the low-latency segmenter, prefix the channel name with `ll_`, for example, `ll_sports`.
- `{stream}` - a string (up to 32 chars) that identifies the quality being published, for example, `hd` / `sd`.

### RTMP/TCP

Sample ffmpeg command:
`ffmpeg -re -i test.mp4 -c copy -f flv "rtmp://localhost:1935/live/{channel}_{stream}"`

Supported codecs:
- Video: h264
- Audio: aac, mp3

### MPEGTS/SRT

Sample ffmpeg command:
`ffmpeg -re -i test.mp4 -c copy -f mpegts "srt://localhost:7045?streamid={channel}_{stream}"`

Supported codecs:
- Video: h264, h265
- Audio: aac, mp3, ac3, e-ac3

### MPEGTS/HTTP

Sample ffmpeg command:
`ffmpeg -re -i test.mp4 -c copy -f mpegts "http://127.0.0.1:80/publish/?streamid={channel}_{stream}"`

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
