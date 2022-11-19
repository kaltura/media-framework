# Media-Framework Sample

This folder contains a sample configuration and controller implementation.
This sample assumes all the media-framework components are deployed on a single server -
1. A single nginx server runs all nginx-based components - ingest modules (rtmp/srt), segmenter, packager etc.
2. The transcoder runs in docker containers - the controller spawns a transcoder container on-demand, for each input video/audio track that uses transcoding

This sample is provided mainly for test/evaluation purposes, and can be used as a reference for implementing your own controller.
However, for production use, it is highly recommended to implement your own controller, so that you can:
1. Deploy the components in a distributed manner (on multiple servers/containers)
2. Authenticate incoming streams
3. Set up the desired topology for each incoming stream, for example, should the stream:
    1. Use transcoding for video/audio? If so, which renditions should be generated?
    2. Push to an external service?
    3. Decode closed-captions?
4. Choose a configuration for each stream, for example:
    1. Should the media be persisted?
    2. Use the low-latency segmenter or the default?
    3. What should be the size of the sliding window (DVR)?
    4. Map the incoming audio/subtitle track to languages

## Contents

- *controller.php* - sample controller implementation
- *build.sh* - shell script for configuring nginx with all the required modules
- *nginx.conf* - sample nginx configuration with all the nginx-based media-framework modules
- *transcoder.json* - sample transcoder configuration - contains the parameters of the renditions that should be generated

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

### Passthrough streaming

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
sudo mkdir /var/log/nginx

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

### Transcode Streaming

```
# install docker engine (https://docs.docker.com/engine/install/ubuntu/)
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

# build transcoder image
cd /opt/media-framework/transcoder
docker build -t kaltura/transcoder-dev -f Dockerfile.build ./
docker build -t kaltura/transcoder-dev -f Dockerfile ./

# allow www-data user (php-fpm) to run docker
sudo usermod -aG docker www-data
service php7.4-fpm restart

# create transcoder log folder
sudo mkdir /var/log/transcoder
sudo chown www-data:www-data /var/log/transcoder

# enable transcoding in controller
sed -i 's#//\$transConfFile = #$transConfFile = #g' /opt/media-framework/conf/controller.php

# publish & play - same as passthrough
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
