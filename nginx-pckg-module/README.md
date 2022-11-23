# Nginx Packager module

Stateless live media packager.

Required dependencies: *nginx-common*

Optional dependencies:
- *openssl* - required for media encryption / DRM
- *libavcodec* - required for video frame capture
- *libswscale* - required for scaling captured video frames

## Features

- Input protocol: *KSMP*

- Output
    - protocols: *HLS / LLHLS*, *DASH*
    - containers: *MPEG-TS*, *fMP4*, *WebVTT*

- Codecs
    - Video: *h264 / AVC*, *h265 / HEVC*
    - Audio: *AAC*, *MP3*, *AC3*, *E-AC3*
    - Subtitle: *WebVTT*, *TTML*

- Adaptive bitrate
- Alternative audio
- Media encryption / DRM
- Video frame capture

## Sample Configuration

```
http {

    # Capture channel / timeline ids from URI
    map $uri $channel_id {
        ~/ch/(?P<result>[^/]+) $result;
        default '';
    }

    map $uri $timeline_id {
        ~/tl/(?P<result>[^/]+) $result;
        default 'main';
    }

    server {
        listen       80;
        server_name  _;

        # CORS headers
        add_header Access-Control-Allow-Headers 'Origin,Range,Accept-Encoding,Referer,Cache-Control';
        add_header Access-Control-Expose-Headers 'Server,Content-Length,Content-Range,Date,Age';
        add_header Access-Control-Allow-Methods 'GET,HEAD,OPTIONS';
        add_header Access-Control-Allow-Origin '*';

        # Compress manifests
        gzip on;
        gzip_types application/vnd.apple.mpegurl video/f4m application/dash+xml text/xml text/vtt;
        gzip_proxied any;

        # Shared packager directives
        pckg_uri /ksmp_proxy/;
        pckg_channel_id $channel_id;
        pckg_timeline_id $timeline_id;
        pckg_m3u8_low_latency on;

        # Clear HLS/DASH
        location /clear/ {
            pckg;
        }

        # Clear key HLS AES-128
        location /aes128/ {
            pckg;

            pckg_enc_scheme aes-128;
            pckg_enc_key_seed 'Secret123$channel_id';
        }

        # Clear key HLS SAMPLE-AES
        location /cbcs/ {
            pckg;

            pckg_enc_scheme cbcs;
            pckg_enc_key_seed 'Secret123$channel_id';
        }

        # DRM HLS/DASH cenc scheme
        location /drm-cenc/ {
            pckg;

            pckg_enc_scheme cenc;
            pckg_enc_json $pckg_var_drm_cenc_json;

            pckg_m3u8_container fmp4;
            pckg_m3u8_mux_segments off;
            pckg_m3u8_enc_output_iv off;
            pckg_m3u8_enc_key_format 'urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed';
            pckg_m3u8_enc_key_format_versions '1';
        }

        # DRM FairPlay HLS
        location /drm-fps/ {
            pckg;

            pckg_enc_scheme cbcs;
            pckg_enc_json $pckg_var_drm_cbcs_json;

            pckg_m3u8_enc_output_iv off;
            pckg_m3u8_enc_key_uri 'skd://channel-$channel_id';
            pckg_m3u8_enc_key_format 'com.apple.streamingkeydelivery';
            pckg_m3u8_enc_key_format_versions 1;
        }

        # internal proxy to live segmenter (nginx-live-module)
        location /ksmp_proxy/ {
            internal;
            proxy_pass http://127.0.0.1:8001/ksmp/;
            subrequest_output_buffer_size 20m;
        }
    }
}
```

## URL structure

The module parses the file name part of the URL (anything after the last `/`) in order to service the request.
The file name has the following structure -
`<prefix>[-<seg_index>[-<part_index>]][-<option1>[-<option2>...]].<extension>`

The `prefix` part must have one of the following values -
- `manifest` - a DASH manifest, must use `mpd` extension
- `master` - an HLS master playlist, must use `m3u8` extension
- `index` - an HLS media playlist, must use `m3u8` extension
- `init` - an initialization segment, used with fMP4 container, must use `mp4` extension
- `seg` - a media segment, the extension must be one of:
    - `ts` - when using MPEG-TS container (video/audio)
    - `m4s` - when using fMP4 container (video/audio/subtitle)
    - `vtt` - when using WebVTT container (subtitle)
- `part` - a partial media segment (LLHLS), supports the same extensions listed above for media segments
- `frame` - a single video frame, used when capturing frames, the extension must be `jpg`
- `enc` - an encryption key, must use `key` extension

The `<seg_index>` parameter is required for media / initialization segment requests. The `<seg_index>` and `<part_index>` parameters are required for partial media segment requests.
These parameters are not allowed in other types of requests.

The following options are supported -
- `s<variant_id>` - choose a subset of the available variants. For example, `master-s720p-s480p.m3u8` returns only the variants with ids `720p` / `480p`.
    Certain types of requests (e.g. `manifest.mpd` / `master.m3u8`) support getting multiple variant options, while other requests (e.g. `index.m3u8` / `seg.ts`) require a single variant option.
- `v` / `a` / `t` - choose a subset of the available media types. For example, `master-a.m3u8` returns an audio-only stream.

Capture requests use a slightly different format:
`frame-<timestamp>-s<variant_id>[-w<width>][-h<height>].jpg`

By default, the `timestamp` parameter is an absolute timestamp.
If the `timestamp` is prefixed with `-`, it is interpreted as an offset relative to the end of the timeline.
If the `timestamp` is prefixed with `+`, it is interpreted as an offset relative to the start of the timeline.

The `width` / `height` parameters can be used to scale the returned image.
When these parameters are not supplied, no scaling will be performed - the returned image will use the original video dimensions.
When only one of the parameters is specified, the other dimension is set to a value that retains the aspect ratio of the captured video frame.

## Configuration Directives

### Core Directives

#### pckg
* **syntax**: `pckg`
* **default**: ``
* **context**: `location`

Enables the media packager in the surrounding location.
Requests to this location will be parsed according the format explained in [URL structure](#url-structure).

#### pckg_uri
* **syntax**: `pckg_uri expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the internal uri that should be used to query the segmenter.
On every HLS/DASH request that the packager receives, it evaluates the provided expression, and creates an nginx subrequest with the value as its uri.
The location referenced by the `pckg_uri` directive, should use the `proxy_pass` directive to relay the request to nginx-live-module.
The parameter value can contain variables.

#### pckg_format
* **syntax**: `pckg_format format`
* **default**: `ksmp`
* **context**: `http`, `server`, `location`

Sets the format of the responses to the packager requests, the following values are supported -
- `ksmp` - Kaltura Segmented Media Protocol, this is the format returned by nginx-live-module
- `sgts` - the format nginx-live-module uses for persisting media. This format can be used for recovery purposes,
    in order to convert persisted files directly to HLS/DASH, without the need to set up a channel using nginx-live-module APIs.

#### pckg_channel_id
* **syntax**: `pckg_channel_id expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the live channel id.
The channel id is usually captured from the request uri using a regex location or map (as in the [Sample Configuration](#sample-configuration)).
The parameter value can contain variables.

#### pckg_timeline_id
* **syntax**: `pckg_timeline_id expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the live timeline id.
The timeline id is usually captured from the request uri using a regex location or map (as in the [Sample Configuration](#sample-configuration)).
The parameter value can contain variables.

#### pckg_max_segment_index
* **syntax**: `pckg_max_segment_index expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Limits the segment indexes returned in manifest requests to the specified value.
This parameter can be used to create a live replay of persisted streams - the limit can be raised every few sec, thereby exposing additional segments to the player.
The parameter value can contain variables.

#### pckg_ksmp_max_uncomp_size
* **syntax**: `pckg_ksmp_max_uncomp_size size`
* **default**: `5m`
* **context**: `http`, `server`, `location`

Sets the maximum uncompressed size that is allowed when parsing compressed KLPF responses.

#### pckg_expires_static
* **syntax**: `pckg_expires_static secs`
* **default**: `100d`
* **context**: `http`, `server`, `location`

Sets the value of the `Expires` and `Cache-Control` response headers for successful requests in which the response is static (e.g. media segments and initialization segments).

#### pckg_expires_index
* **syntax**: `pckg_expires_index secs`
* **default**: `3s`
* **context**: `http`, `server`, `location`

Sets the value of the `Expires` and `Cache-Control` response headers for successful requests in which the response contains a list of segments, specifically: HLS index playlists and DASH manifests.

#### pckg_expires_index_gone
* **syntax**: `pckg_expires_index_gone secs`
* **default**: `5s`
* **context**: `http`, `server`, `location`

Sets the value of the `Expires` and `Cache-Control` response headers for requests that return HTTP status 410 (Gone).

#### pckg_expires_index_blocking
* **syntax**: `pckg_expires_index_blocking secs`
* **default**: `30`
* **context**: `http`, `server`, `location`

Sets the value of the `Expires` and `Cache-Control` response headers for successful index playlist requests that use the `_HLS_msn` query parameter.

#### pckg_expires_master
* **syntax**: `pckg_expires_master secs`
* **default**: `30`
* **context**: `http`, `server`, `location`

Sets the value of the `Expires` and `Cache-Control` response headers for successful master playlist requests.

#### pckg_last_modified_static
* **syntax**: `pckg_last_modified_static http_time`
* **default**: `Fri, 01 Jan 2010 00:00:00 GMT`
* **context**: `http`, `server`, `location`

Sets the value of the `Last-Modified` response header for successful requests in which the response is static (e.g. media segments and initialization segments).

#### pckg_pass_codes
* **syntax**: `pckg_pass_codes off | any | code...`
* **default**: `off`
* **context**: `http`, `server`, `location`

Controls the status code that is returned when the HTTP request to nginx-live-module fails.
When the value is `off`, any error status code returned from nginx-live-module will fail the packager request with 502.
When the value is `any`, any error status code returned from nginx-live-module will propagate to the packager request.
Alternatively, a list of specific status codes can be specified, the supported status codes are: 400, 404, 410.

#### pckg_active_policy
* **syntax**: `pckg_active_policy last | any`
* **default**: `last`
* **context**: `http`, `server`, `location`

Controls which variants are considered active, and returned in manifest requests.
When the value is `last`, only variants which contain the last segment in the timeline are considered active.
When the value is `any`, variants which contain any segment in the timeline are considered active.

#### pckg_media_type_selector
* **syntax**: `pckg_media_type_selector request | actual`
* **default**: `request`
* **context**: `http`, `server`, `location`

Controls how media type selectors (v/a/t) should be determined for URLs that are returned in manifests.
When the value is `request`, the returned selectors will match the selectors of the request.
For example, URLs in the response of `master.m3u8` will not contain a selector, while URLs in the response of `master-v.m3u8` will contain a video selector (`v`).
When the value is `actual`, the returned selectors will match the media types that exist in the returned variants.
For example, a request for `index.m3u8` may return a video selector (`v`) when the variant is video-only,
and it may return an audio selector (`a`) when the variant is audio-only.

#### pckg_back_fill
* **syntax**: `pckg_back_fill on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enables or disables back-filling.
Consider a channel with two variants, each with its own video track and audio track - `v1`/`a1`, `v2`/`a2`.
In the first few segments, no media is received for `a2`, so the segments do not contain this track.
Then, at some point, `a2` starts publishing. When `pckg_back_fill` is enabled, requests for segments that did not contain
media for `a2`, will fill the gap by copying the respective media from `a1`. When `pckg_back_fill` is disabled,
requests for segments that did not contain media for `a2`, will return only the video track - `v2`.
An implication of back-filling is that responses for segment requests may change over time.

#### pckg_empty_segments
* **syntax**: `pckg_empty_segments on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

When enabled, requests for segments that do not exist on the specific variant/media type will return an empty segment.
For example, when the container is MPEG-TS, the response will contain only a PAT and a PMT.
When disabled, requests for segments that do not exist on the specific variant/media type will return a 404 error.

#### pckg_output_buffer_pool
* **syntax**: `pckg_output_buffer_pool size count`
* **default**: ``
* **context**: `http`, `server`, `location`

Pre-allocates a set of buffers with the specified count and size for storing output media.
The buffer pool can provide a slight performance optimization by avoiding the need to allocate/free the media buffers for every request.

#### pckg_segment_metadata
* **syntax**: `pckg_segment_metadata expr`
* **default**: ``
* **context**: `http`, `server`, `location`

When the provided expression is evaluated to a non-empty string, it is returned as metadata on segment requests.
The metadata is encapsulated as an ID3 TEXT frame.
When using fMP4 container, the ID3 frame is sent inside an `emsg` box with the scheme `https://developer.apple.com/streaming/emsg-id3`.
When using MPEG-TS container, the ID3 frame is sent in a private stream (SID 0xbd).
The parameter value can contain variables.

### M3u8 Directives (HLS)

#### pckg_m3u8_low_latency
* **syntax**: `pckg_m3u8_low_latency on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enables or disables low-latency HLS features on the surrounding location.
When set to `on`, this directive is an alias to the following:
```
pckg_m3u8_mux_segments off;
pckg_m3u8_parts on;
pckg_m3u8_rendition_reports on;

pckg_m3u8_ctl_block_reload on;
pckg_m3u8_ctl_part_hold_back_percent 300;
pckg_m3u8_ctl_skip_boundary_percent 600;
```

When set to `off`, this directive is an alias to the following:
```
pckg_m3u8_mux_segments on;
pckg_m3u8_parts off;
pckg_m3u8_rendition_reports off;

pckg_m3u8_ctl_block_reload off;
pckg_m3u8_ctl_part_hold_back_percent 0;
pckg_m3u8_ctl_skip_boundary_percent 0;
```

#### pckg_m3u8_container
* **syntax**: `pckg_m3u8_container auto | mpegts | fmp4`
* **default**: `auto`
* **context**: `http`, `server`, `location`

Sets the container used for media segments.
When set to `auto`, MPEG-TS container is used by default, however, if any of the following conditions applies, fMP4 container is used instead -
- The channel uses the low latency segmenter - in LLHLS, media is delivered in small parts, using MPEG-TS in this case, can result in a significant overhead in bandwidth.
- Encryption using the `cenc` scheme is enabled - MPEG-TS does not support this scheme.
- The variant contains an h265/HEVC video track - according to the HLS authoring specification, the container format for HEVC video must be fMP4.

#### pckg_m3u8_subtitle_format
* **syntax**: `pckg_m3u8_subtitle_format webvtt | imsc`
* **default**: `webvtt`
* **context**: `http`, `server`, `location`

Sets the container used for delivering subtitles -
- `webvtt` - the segments are WebVTT file sections.
- `imsc` - the segments are TTML sections, encapsulated in an fMP4 container.

#### pckg_m3u8_mux_segments
* **syntax**: `pckg_m3u8_mux_segments on | off | expr`
* **default**: `on`
* **context**: `http`, `server`, `location`

When the provided expression evaluates to `on`, video and audio tracks are muxed together in the same segments.
When the provided expression evaluates to `off`, video and audio tracks are delivered in separate segments.
The master playlist uses `#EXT-X-MEDIA` to connect the video stream and the audio stream.
The parameter value can contain variables.

#### pckg_m3u8_parts
* **syntax**: `pckg_m3u8_parts on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

When enabled, the module will output parts in returned index playlists (using `#EXT-X-PART` / `#EXT-X-PRELOAD-HINT` tags).

#### pckg_m3u8_rendition_reports
* **syntax**: `pckg_m3u8_rendition_reports on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

When enabled, the module will output rendition reports in returned index playlists (using `#EXT-X-RENDITION-REPORT` tags).

#### pckg_m3u8_program_date_time
* **syntax**: `pckg_m3u8_program_date_time on | off | expr`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled, the module output an `#EXT-X-PROGRAM-DATE-TIME` tag for each period, containing its absolute timestamp.
The parameter value can contain variables.

#### pckg_m3u8_ctl_block_reload
* **syntax**: `pckg_m3u8_ctl_block_reload on | off | expr`
* **default**: ``
* **context**: `http`, `server`, `location`

When enabled, the module will include the `CAN-BLOCK-RELOAD=YES` attribute in the returned `#EXT-X-SERVER-CONTROL` tag.
The parameter value can contain variables.

#### pckg_m3u8_ctl_part_hold_back_percent
* **syntax**: `pckg_m3u8_ctl_part_hold_back_percent num | expr`
* **default**: `300`
* **context**: `http`, `server`, `location`

Sets the value of the `PART-HOLD-BACK` attribute in the returned `#EXT-X-SERVER-CONTROL` tag.
The value is expressed as a percent of the part duration defined in the segmenter.
The parameter value can contain variables.

#### pckg_m3u8_ctl_skip_boundary_percent
* **syntax**: `pckg_m3u8_ctl_skip_boundary_percent num | expr`
* **default**: `0`
* **context**: `http`, `server`, `location`

Sets the value of the `CAN-SKIP-UNTIL` attribute in the returned `#EXT-X-SERVER-CONTROL` tag.
The value is expressed as a percent of the target duration of the timeline.
The parameter value can contain variables.

#### pckg_m3u8_enc_output_iv
* **syntax**: `pckg_m3u8_enc_output_iv on | off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled, the module outputs the `IV` attribute in returned `#EXT-X-KEY` / `#EXT-X-SESSION-KEY` tags.

#### pckg_m3u8_enc_key_uri
* **syntax**: `pckg_m3u8_enc_key_uri expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the value of the `URI` attribute of the `#EXT-X-KEY` tag.
The parameter value can contain variables.
The provided expression may be evaluated multiple times, depending on the value of `pckg_enc_scope`.
The variables `pckg_variant_id` / `pckg_media_type` can be used in the expression to produce different URLs, when the encryption scope is not `channel`.
When encryption is enabled, and this directive is not used, a URI is generated automatically:
- If `pckg_enc_scheme` is set to `cenc`, the URI will contain the PSSH boxes provided in `pckg_enc_json`, base64 encoded.
- Otherwise, URI will return an `enc.key` URL, according to the the configured `pckg_enc_scope`.

#### pckg_m3u8_enc_key_format
* **syntax**: `pckg_m3u8_enc_key_format str`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the value of the `KEYFORMAT` attribute of the `#EXT-X-KEY` tag.

#### pckg_m3u8_enc_key_format_versions
* **syntax**: `pckg_m3u8_enc_key_format_versions`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the value of the `KEYFORMATVERSIONS` attribute of the `#EXT-X-KEY` tag.

### MPD Directives (DASH)

#### pckg_mpd_profiles
* **syntax**: `pckg_mpd_profiles expr`
* **default**: `urn:mpeg:dash:profile:isoff-live:2011`
* **context**: `http`, `server`, `location`

Sets the value of the `profiles` attribute of the `MPD` element.
The parameter value can contain variables.

#### pckg_mpd_subtitle_format
* **syntax**: `pckg_mpd_subtitle_format wvtt | stpp`
* **default**: `wvtt`
* **context**: `http`, `server`, `location`

Sets the container used for delivering subtitles -
- `wvtt` - the segments are WebVTT sections, encapsulated in an fMP4 container.
- `stpp` - the segments are TTML sections, encapsulated in an fMP4 container.

#### pckg_mpd_pres_delay_segments
* **syntax**: `pckg_mpd_pres_delay_segments num`
* **default**: `3`
* **context**: `http`, `server`, `location`

Sets the segment according to which the `suggestedPresentationDelay` attribute of the `MPD` element is set.
The value is expressed as a number of segments, starting from the end of the timeline.
For example, if the segments of the timeline are numbered as 1 .. N, when using the default value of 3,
the suggested presentation delay will be: `now - segment_start_time[N - 2]`.

### MPEG-TS Directives

#### pckg_mpegts_interleave_frames
* **syntax**: `pckg_mpegts_interleave_frames on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

When enabled, the MPEG-TS muxer interleaves frames of different streams (video / audio).
When disabled, on every switch between audio / video the muxer flushes the MPEG TS packet.
Enabling this setting can reduce the muxing overhead of the MPEG-TS packaging.

#### pckg_mpegts_align_frames
* **syntax**: `pckg_mpegts_align_frames on | off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled, every video / audio frame is aligned to MPEG-TS packet boundary, padding is added as needed.
Disabling this setting can reduce the muxing overhead of the MPEG-TS packaging.

### Encryption Directives

#### pckg_enc_scheme
* **syntax**: `pckg_enc_scheme none | aes-128 | cbcs | cenc`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the encryption scheme that is used to encrypt media segments.
When using the MPEG-TS container:
- the `cbcs` scheme follows the [HLS Sample Encryption](https://developer.apple.com/library/ios/documentation/AudioVideo/Conceptual/HLS_Sample_Encryption/) specification.
- the `cenc` scheme is not supported.

#### pckg_enc_scope
* **syntax**: `pckg_enc_scope channel | media_type | variant | track`
* **default**: `channel`
* **context**: `http`, `server`, `location`

Sets the scope of the encryption keys, the following values are supported:
- `channel` - a single encryption key is used to encrypt all the tracks in the channel.
- `media_type` - at most 2 encryption keys are used - one for video, one audio.
- `variant` - an encryption key is assigned for each variant.
- `track` - an encryption key is assigned for each track.

#### pckg_enc_key_seed
* **syntax**: `pckg_enc_key_seed expr`
* **default**: `$pckg_channel_id`
* **context**: `http`, `server`, `location`

Sets a seed that is used to generate encryption keys.
The parameter value can contain variables.
The provided expression may be evaluated multiple times, depending on the value of `pckg_enc_scope`.
The variables `pckg_variant_id` / `pckg_media_type` can be used in the expression to produce multiple seeds, when the encryption scope is not `channel`.

#### pckg_enc_iv_seed
* **syntax**: `pckg_enc_iv_seed expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets a seed that is used to generate encryption initialization vectors (IVs).
The parameter value can contain variables.
The provided expression may be evaluated multiple times, depending on the value of `pckg_enc_scope`.
The variables `pckg_variant_id` / `pckg_media_type` can be used in the expression to produce multiple seeds, when the encryption scope is not `channel`.
If this directive is not set, the expression provided in `pckg_enc_key_seed` is used by default.


#### pckg_enc_serve_key
* **syntax**: `pckg_enc_serve_key on | off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled, the module serves the encryption keys in the clear, when getting `enc.key` requests.

#### pckg_enc_json
* **syntax**: `pckg_enc_json expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the parameters used for encryption.
The parameter value can contain variables.
The provided expression may be evaluated multiple times, depending on the value of `pckg_enc_scope`.
The variables `pckg_variant_id` / `pckg_media_type` can be used in the expression to map to the different JSONs, when the encryption scope is not `channel`.
This directive is used mostly for enabling DRM, therefore, by default, it disables `pckg_enc_serve_key`
(this behavior can be overridden by explicitly setting `pckg_enc_serve_key on;` before `pckg_enc_json` in the same configuration block)

The provided expression must evaluate to a JSON object, containing the following fields:
`key` - string, required, the encryption key (128 bit) in base64 encoding
`key_id` - string, optional, the encryption key identifier (128 bit) in base64 encoding
`iv` - string, optional, the encryption initialization vector (128 bit) in base64 encoding
`systems` - object, optional, the keys are DRM system IDs (GUIDs), the values are strings containing base64 encoded PSSH (Protection System Specific Header).

### Capture Directives

#### pckg_capture
* **syntax**: `pckg_capture on | off`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enables / disables the capture functionality on the surrounding location.
Capture requests are more CPU-intensive than requests for serving media, therefore, they are disabled by default.

#### pckg_capture_redirect
* **syntax**: `pckg_capture_redirect on | off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled, capture requests that use relative timestamps, will redirect to a URL that uses the corresponding absolute timestamp.
Requests that use timestamps relative to the end of the live stream can return different images when the stream is live,
while requests that use absolute timestamps return a static image. The use of redirect on relative requests enables the caching
of the response (by a CDN / proxy).

#### pckg_capture_granularity
* **syntax**: `pckg_capture_granularity frame | key`
* **default**: `frame`
* **context**: `http`, `server`, `location`

When set to `frame`, capture requests will use the frame that is closest to the requested timestamp.
When set to `key`, capture requests will use the keyframe that is closest to the requested timestamp.
This directive provides a trade-off between resource usage and capture accuracy -
setting the value to `key` reduces CPU usage (only one frame is decoded) and internal bandwidth (nginx-live-module returns a single frame).

### Closed Captions Directives

#### pckg_captions_json
* **syntax**: `pckg_captions_json expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the parameters of the closed captions embedded in the video tracks of the channel.
The parameter value can contain variables.
The provided expression must evaluate to a JSON object.
The keys must be closed caption channel ids - `cc1` .. `cc4` for 608 captions, `service1` .. `service63` for 708 captions.
The values must be objects containing the following fields:
- `label` - string, required, a "friendly" name for the closed captions channel (e.g. `English`).
- `lang` - string, optional, an RFC5646 language code (e.g. `en`).
- `is_default` - boolean, optional, sets the values of the `AUTOSELECT` / `DEFAULT` attributes of the `#EXT-X-MEDIA` tag in HLS.

### Session Data Directives

#### pckg_session_data_json
* **syntax**: `pckg_session_data_json expr`
* **default**: ``
* **context**: `http`, `server`, `location`

Sets the "session data" of the channel, returned as `#EXT-X-SESSION-DATA` tags in master playlist responses.
The parameter value can contain variables.
The provided expression must evaluate to a JSON array containing objects.
Each object in the array, is rendered as an `#EXT-X-SESSION-DATA` tag, and contains the following fields:
- `id` - string, required, sets the DATA-ID attribute.
- `value` - string, optional, sets the VALUE attribute.
- `uri` - string, optional, sets the URI attribute.
- `lang` - string, optional, sets the LANGUAGE attribute.

The object must contain either `value` or `uri`, but not both.

## Embedded Variables

The nginx-pckg-module supports the following embedded variables:
- `$pckg_channel_id` - the channel id, as provided to the `pckg_channel_id` directive.
- `$pckg_timeline_id` - the timeline id, as provided to the `pckg_timeline_id` directive.
- `$pckg_variant_ids` - the variant ids supplied on the request URL, if multiple values are provided, they are delimited with an hyphen (`-`).
- `$pckg_variant_id` - the id of the variant currently being initialized, intended for use in `pckg_m3u8_enc_key_uri`, `pckg_enc_key_seed`, `pckg_enc_iv_seed`, `pckg_enc_json`.
- `$pckg_media_type` - the media type currently being initialized (`video` / `audio`), intended for use in `pckg_m3u8_enc_key_uri`, `pckg_enc_key_seed`, `pckg_enc_iv_seed`, `pckg_enc_json`.
- `$pckg_err_code` - evaluates to the KSMP error code returned from nginx-live-module, the possible values are defined in [ngx_ksmp_errs_x.h](../nginx-common/src/ngx_ksmp_errs_x.h).
- `$pckg_err_msg` - evaluates to the KSMP error message returned from nginx-live-module.
- `$pckg_part_duration` - when the channel uses the low latency segmenter, evaluates to the part duration in milliseconds. Evaluates to zero if the channel uses the default segmenter.
- `$pckg_last_part` - the index of the last part returned in an index playlist request, uses the format `<segment_index>:<part_index>`.
- `$pckg_segment_dts` - the initial timestamp (dts) of the segment in milliseconds. When the segment contains multiple tracks, returns the dts of the first track that contains frames.
- `$pckg_var_{name}` - returns the value of the live channel variable `{name}`, as returned from nginx-live-module.
- `$pckg_upstream_{name}` - returns the value of the `$upstream_{name}` variable, when evaluated on the KSMP subrequest.
    For example:
    - `$pckg_upstream_status` returns the status code of the HTTP request that was sent to nginx-live-module.
    - `$pckg_upstream_http_block_duration` returns the value of the `Block-Duration` header returned from nginx-live-module.

    See the documentation of the nginx upstream module for the list of `upstream_` variables that can be used.
