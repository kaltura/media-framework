# Kaltura Media Framework

A distributed framework for live video streaming. The system is composed of multiple components, each one responsible for a specific function.
The components can be deployed on a single server for small scale deployments/testing, but it is recommended to deploy them separately
for a more optimal resource utilization. For example, the transcoder can utilize the GPU, so it would be more cost efficient to deploy the
transcoders on GPU-enabled servers, while the other components would run on servers without GPU.

Media is transmitted between the different components internally using custom protocols -
1. *Kaltura Media Protocol* (KMP) - a TCP-based protocol for delivering streaming media, conceptually, similar to a single track of fMP4/MPEG-TS
2. *Kaltura Segmented Media Protocol* (KSMP) - an HTTP-based protocol for delivering media in segments, conceptually, a super-set of LLHLS/DASH

The orchestration of the different media components is performed by a "controller". The main responsibility of the controller is building
the topology of the media pipeline, and updating it in case of failures. The controller gets JSON events from the media components sent
as HTTP-POSTs. In addition, all the media processing components expose a JSON-based REST API, that is used by the controller to get
the latest status and take actions. A sample controller implementation for an all-in-one server is provided under the `conf` folder.

## Main Features

- Publishing protocols: RTMP, MPEGTS (over SRT/HTTP/TCP)
- Playback protocols: HLS/LLHLS, DASH
- Live push/relay protocols: RTMP
- Video/audio transcoding - including GPU support, based on ffmpeg API
- Persistence - in S3 (or compatible) object storage
- Adaptive bitrate delivery
- Subtitle support - including conversion of 608/708 to WebVTT
- Alternative audio
- Media encryption and DRM
- Video frame capture

## Getting Started

The [conf](conf/README.md) folder contains sample code and configuration for running an all-in-one server.

## Glossary

- *Channel* - a container that represents a live stream, may contain tracks, variants, timelines etc.
- *Track* - a single rendition of video/audio/subtitle. For example, a channel may have 3 video tracks: 1080p, 720p, 540p.
- *Variant* - a grouping of tracks used for packaging. Variants determine which audio track will be paired to each video track, when muxed segments are used.
    A variant can point to multiple tracks, but no more than one track per media type.
    Tracks must be associated to variants in order to be delivered via HLS/DASH.
- *Segment* - a group of frames of a specific track. Segments are always independent - video segments will always start with a key/IDR frame.
- *Segment index* - a number that identifies the segments of the different tracks that are associated with a specific time interval.
- *Period* - a set of segment indexes that can be played continuously.
- *Timeline* - a set of periods. Multiple timelines can be created, each with its own set of periods.
    Timelines can be used, for example, in order to implement "preview mode" - the publisher consumes one timeline, while the viewers consume another.
    The timeline of the publisher is always `active`, while the timeline of the viewers is activated upon the publisher's discretion.

## Components Overview

### Media components

- **nginx-rtmp-kmp-module** - live media ingestion, input: *RTMP*, output: *KMP x N*

- **nginx-mpegts-kmp-module** - live media ingestion, input: *MPEG-TS over TCP/HTTP*, output: *KMP x N*

- **transcoder** - video/audio transcoding, input: *KMP*, output: *KMP x N*

- **nginx-live-module** - live media segmenter, input: *KMP x N*, output: *KSMP*

    *Additional features*: persistence, filler, timeline support.

- **nginx-pckg-module** - live media packager (stateless), input: *KSMP*, output: *HLS/LLHLS, DASH*

    *Additional features*: adaptive bitrate, subtitles, alternative audio, media encryption / DRM, video frame capture

- **nginx-kmp-cc-module** - closed-captions decoder, input: *KMP video (h264/5)*, output: *KMP subtitle (WebVTT) x N*

- **nginx-kmp-rtmp-module** - live media relay, input: *KMP x N*, output: *RTMP*

**Important**: All stateful nginx-based components (=all except nginx-pckg-module), must be deployed on a single process nginx server (`worker_processes 1;`).
    The module state is kept per process, and when multiple processes are used, it is not possible to control which process will get the request.
    For example, the request to create a channel on the segmenter may arrive to worker 1, while the KMP connection with the actual media, will hit worker 2.
    In deployments that use containers, this shouldn't be a problem - multiple containers can be deployed on a single server, instead of using multiple nginx processes.
    Another possibility is to use a patch like arut's [per-worker listener](https://github.com/arut/nginx-patches/blob/master/per-worker-listener),
    but it will probably need to be updated to apply to `stream` connections as well.

### Dependencies

The following modules are dependencies for building the media components listed above.
When compiling nginx, the dependencies must be added (`--add-module`) before any module that requires them.

- **nginx-common** - shared code for: exposing an HTTP API, sending HTTP events, parsing JSON, KMP/KSMP definitions, etc.,
    used by: most nginx modules.

- **nginx-kmp-in-module** - a utility module for receiving KMP input, used by: nginx-live-module, nginx-kmp-cc-module, nginx-kmp-rtmp-module.

- **nginx-kmp-out-module** - a utility module for sending KMP output, used by nginx-rtmp-kmp-module, nginx-mpegts-kmp-module, nginx-kmp-cc-module.

- **nginx-rtmp-module** - a modified version of [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module), used by: nginx-rtmp-kmp-module.
    - Support for multiple RTMP streams on a single connection
    - Support for additional encoders (automatic detection of ext-timestamp in type-3 packets, generation of onFCPublish messages)
    - Detection of embedded captions
    - Removed features: hls/dash output, notifications, relay, auto push, rtmp playback etc.

- **nginx-mpegts-module** - a modified version of [nginx-ts-module](https://github.com/arut/nginx-ts-module), used by: nginx-mpegts-kmp-module.
    - Support for additional codecs: h265, AC-3, E-AC-3
    - Removed features: hls/dash output

## Kaltura Media Protocol (KMP)

Kaltura Media Protocol is a simple packet-based protocol for streaming media over TCP.
A KMP connection can deliver the media of a single video/audio/subtitle track - when multiple tracks are needed, multiple TCP connections are established.

Each packet starts with a header that contains the following fields (32 bits each) -
- *Type* - the type of the packet. The packet types are four-character codes, see below the list of currently defined types.
- *Header size* - the size of the packet header, must be between sizeof(kmp_packet_header_t) and 64KB.
    Parsers must use the header size in order to access the data of the packet, this enables the addition of new fields to packet headers without breaking existing parsers.
- *Data size* - the size of the packet data, must be between 0 and 16MB.
- *Reserved* - reserved for future use, must be set to 0.

The following packet types can be sent by a KMP producer:
- *Connect* (`cnct`) - sent upon the establishment of the TCP connection, identifies the track that is being sent.
- *Media info* (`minf`) - contains the parameters of the media - media type (video/audio/subtitle), codec id, bitrate etc.
    The data of the packet is the codec private/extra data, for example, for h264 video, it contains the data of the avcC MP4 box.
    Parsers should handle media info changes, for example, a change to the video resolution.
    However, the type of the media sent in a KMP connection (video/audio/subtitle), must not change.
- *Frame* (`fram`) - a single video frame/audio frame/subtitle cue. Each frame has an implicit frame id that is used for acks -
    the initial frame id is sent in the *Connect* packet, and it is incremented by one on each *Frame* packet.
- *Null* (`null`) - sent in order to signal "liveness", and prevent idle timers from expiring. Parsers must ignore null packets.
- *End of stream* (`eost`) - a graceful termination of the publishing session.

The following packet types can be sent by a KMP receiver:
- *Ack frames* (`ackf`) - acknowledge the receipt of frames. It is up to receiver to decide when to send the ack, for example,
    when persistence is enabled, the segmenter sends an ack only after the frame is saved to storage.
    Some receivers do not send acks at all, in this case the KMP producer must be configured to discard the frames right after they are sent (=auto ack)

For additional details on the internal structure of each packet, refer to [ngx_live_kmp.h](nginx-common/src/ngx_live_kmp.h)

## Kaltura Segmented Media Protocol (KSMP)

Kaltura Segmented Media Protocol is an HTTP-based protocol for delivering media in segments, similarly to HLS/DASH.

A KSMP request is an HTTP GET request, the following query parameters are defined -
- `channel_id` - required string, the id of the channel
- `timeline_id` - required string, the id of the timeline
- `flags` - required hex integer, the flags:
    - Select the subset of data that is required (like the column list in an SQL SELECT statement)
    - Control various behaviors when servicing the request.
        For example, the 'closest key' flag, returns only the key frame that is closest to the request timestamp, instead of returning the whole segment.
- `variant_ids` - optional string, selects a subset of the variants that should be returned, by default, all variants are returned.
    If multiple variants are specified, they should be delimited with an hyphen (-).
- `media_type_mask` - optional hex integer, sets the media types that should be returned, by default, all media types are returned.
- `time` - optional integer, the requested timestamp. The timestamp is used, for example, in order to capture a video frame at a specific time.
- `segment_index` - optional integer, the index of the segment
- `max_segment_index` - optional integer, used to limit the scope of segments returned in the response. This parameter can be used to replay a persisted stream for debugging.
- `part_index` - optional integer, the zero based index of the partial segment within the segment. A request that uses `part_index` must send also `segment_index`.
- `skip_boundary_percent` - optional integer, sets the *skip boundary* value as a percent of the *target duration*
    (see the definition of the `CAN-SKIP-UNTIL` attribute in the HLS specification for more details)
- `padding` - optional integer, adds additional zero bytes at the end of the response. Used to comply with ffmpeg's padding requirements without incurring additional copy operations.

A KSMP response uses KLPF format (see below), with type *Serve* (`serv`).
The KSMP-specific definitions can be found in [ngx_ksmp.h](nginx-common/src/ngx_ksmp.h)

## Kaltura Live Persist File (KLPF)

Kaltura Live Persist File is a serialization scheme that is used in KSMP responses and in the S3 objects created by nginx-live-module.
A KLPF is composed of blocks, similar to MP4 atoms/boxes. Each block has the following header -
- `id` - a four-character code identifying the block
- `size` - uint32, the full size of the block (header & data)
- `flags` - 4 bits, the following flags are defined:
   - *container* (0x1) - the block contains other blocks
   - *index* (0x2) - the block is an index to another block, header size should not be used
   - *compressed* (0x4) - the data of the block is zlib-compressed
- `header_size` - 28 bits, the size of the block header. Parsers must use the header size in order to access the data of the block,
    so that fields could be added to the header without breaking compatibility

A KLPF file is a block whose id is set to `klpf`.
Following the generic block header fields (listed above), a KLPF file has the following fields in its header -
- `uncomp_size` - uint32, holds the uncompressed size of the data, when the KLPF data is compressed
- `version` - uint32, the version of the file format. The version used for new files is updated on every breaking change to the format, the code will be updated to either
   - support reading both the new format and the old format, or
   - ignore files that use the old format
- `type` - a four-character code that identifies the type of data stored in the KLPF.
- `created` - uint64, the unix timestamp when the KLPF was created

The following types of KLPF are currently defined -
- *Serve* (`serv`) - a KSMP response, used in the communication between the packager and the segmenter.
- *Setup* (`setp`) - contains all the objects of a channel that can be set using the segmenter API - tracks, variants, timelines etc. Used in segmenter persistence
- *Segment index* (`sgix`) - an index of the segments of a channel, contains the duration of the segment, timeline association, bitrates etc. Used in segmenter persistence
- *Segment media* (`sgts`) - holds the media (compressed video/audio frames) of a set of segments. Used in segmenter persistence

For more details on the internal structure of KLPF blocks, see [KLFP-SPEC.md](nginx-common/KLFP-SPEC.md).

To inspect the contents of KLPF objects/KSMP responses, use [klpf_parse.py](nginx-common/scripts/klpf_parse.py).
The script can show the block structure without any additional info, however, in order to parse the fields inside the blocks:
- run [generate_persist_spec.py](nginx-live-module/scripts/generate_persist_spec.py), and save the output to a file
- provide the file name as an additional argument to klpf_parse.py

### Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path.

Copyright © Kaltura Inc. All rights reserved.
