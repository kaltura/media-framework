# Nginx RTMP Module

A modified version of [nginx-rtmp-module](https://github.com/arut/nginx-rtmp-module).

Several features were added on top of the original nginx-rtmp-module implementation:
- Support for publishing multiple RTMP streams on a single connection
- Support for additional encoders (automatic detection of ext-timestamp in type-3 packets, generation of onFCPublish messages)
- Detection of embedded captions

In the context of Media-Framework, this module is used only for receiving RTMP input.
Therefore, several features that exist in the original nginx-rtmp-module were removed, including:
- HLS/DASH output
- Notifications
- Relay
- Auto push
- RTMP playback
- Recording

Used by: *nginx-rtmp-kmp-module*.


## Configuration

### Sample Configuration

See the sample provided in [nginx-rtmp-kmp-module](../nginx-rtmp-kmp-module/README.md#sample-configuration)

### Core Directives

#### rtmp
* **syntax**: `rtmp { ... }`
* **default**: ``
* **context**: `main`

Provides the configuration file context in which the RTMP server directives are specified.

#### server
* **syntax**: `server { ... }`
* **default**: ``
* **context**: `rtmp`

Sets the configuration for a server.

#### listen
* **syntax**: `listen (addr[:port]|port|unix:path) [bind] [ipv6only=on|off] [so_keepalive=on|off|keepidle:keepintvl:keepcnt|proxy_protocol];`
* **default**: ``
* **context**: `server`

Sets the address and port for the socket on which the server will accept connections.
See the documentation of the listen directive of the Nginx `stream` module for more details on the optional parameters supported by this directive.

#### application
* **syntax**: `application name { ... }`
* **default**: ``
* **context**: `server`

Creates an RTMP application. Unlike the `location` directive in `http`, application names cannot use patterns.

#### timeout
* **syntax**: `timeout msec;`
* **default**: `1m`
* **context**: `rtmp`, `server`

Socket timeout, this value is primarily used for writing. Most of the time, the RTMP module does not expect any activity on active connections, except for publishers.
If you want broken socket to get quickly disconnected use active tools like keepalive or RTMP ping.

#### ping
* **syntax**: `ping msec;`
* **default**: `1m`
* **context**: `rtmp`, `server`

RTMP ping interval, zero disables pings. RTMP ping is a protocol feature for active connection check.
A special packet is sent to the remote peer, and a reply is expected within the timeout specified using the `ping_timeout` directive.
If a ping reply is not received within this time, the connection is closed.

#### ping_timeout
* **syntax**: `ping_timeout msec;`
* **default**: `30s`
* **context**: `rtmp`, `server`

See the description of `ping` above.

#### max_streams
* **syntax**: `max_streams num;`
* **default**: `32`
* **context**: `rtmp`, `server`

Sets the maximum number of RTMP streams.

#### ack_window
* **syntax**: `ack_window num;`
* **default**: `5000000`
* **context**: `rtmp`, `server`

Sets the RTMP acknowledge window size - the number of received bytes after which the peer should send an acknowledge packet.

#### chunk_size
* **syntax**: `chunk_size num;`
* **default**: `4096`
* **context**: `rtmp`, `server`

Maximum chunk size for stream multiplexing. The bigger this value the lower CPU overhead. This value cannot be less than 128.

#### max_message
* **syntax**: `max_message size;`
* **default**: `1m`
* **context**: `rtmp`, `server`

Maximum size for input data messages. All input data is split into messages (and further in chunks).
A partial message is kept in memory while waiting for it to complete. Therefore, large messages can compromise server stability.

#### out_queue
* **syntax**: `out_queue size;`
* **default**: `256`
* **context**: `rtmp`, `server`

Sets the number of slots in the output queue. If the output queue becomes full, lower priority messages are dropped.

#### out_cork
* **syntax**: `out_cork size;`
* **default**: `out_queue / 8`
* **context**: `rtmp`, `server`

Sets the number of pending slots in the output queue that are required in order to start sending data, when a send is not already active.

#### busy
* **syntax**: `busy on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`

When enabled, connections that have no send/recv activity between pings, are terminated.

#### play_time_fix
* **syntax**: `play_time_fix on | off;`
* **default**: `on`
* **context**: `rtmp`, `server`, `application`

When enabled, extended timestamps are sent on outgoing type 3 RTMP chunks.

#### type3_ext_ts
* **syntax**: `type3_ext_ts on | off | auto;`
* **default**: `auto`
* **context**: `rtmp`, `server`, `application`

When set to `auto`, the module automatically detects whether the remote peer is sending extended timestamps on type 3 chunks.
When set to `on`, extended timestamps are expected on incoming type 3 chunks.

#### buflen
* **syntax**: `buflen msec;`
* **default**: `1s`
* **context**: `rtmp`, `server`

Used by MP4/FLV modules.
This parameter is not relevant in the context of Media-Framework.

#### dump_folder
* **syntax**: `dump_folder path;`
* **default**: ``
* **context**: `rtmp`, `server`

When set to a non-empty string, the module saves all incoming RTMP data to files under the specified folder.
The file names have the following structure: `ngx_rtmp_dump_{date}_{pid}_{connection}.dat`.

### Live Directives

#### live
* **syntax**: `live on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

Enables/disables live mode, i.e. one-to-many broadcasting.

#### sandbox
* **syntax**: `sandbox on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

When enabled, incoming publish/play streams are allocated a unique name.
Enabling this setting, making it possible to have multiple publish requests with the same stream name.

#### stream_buckets
* **syntax**: `stream_buckets num;`
* **default**: `1024`
* **context**: `rtmp`, `server`, `application`

Sets the number of buckets used for grouping streams by name.
A higher number increases memory usage, but enables faster lookup of stream by name.

#### buffer
* **syntax**: `buffer msec;`
* **default**: `0`
* **context**: `rtmp`, `server`, `application`

When set to non-zero, output messages are buffered in queue, until the number of buffers reaches the value set in `out_cork`.

#### sync
* **syntax**: `sync msec;`
* **default**: `300ms`
* **context**: `rtmp`, `server`, `application`

When set to a non-zero value, if the duration of dropped packets exceeds the configured value, the stream is resynched.
This parameter is not relevant in the context of Media-Framework.

#### interleave
* **syntax**: `interleave on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

When enabled, audio and video data is transmitted on the same RTMP chunk stream.
This parameter is not relevant in the context of Media-Framework.

#### wait_key
* **syntax**: `wait_key on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

Makes video streams start with a key frame.
This parameter is not relevant in the context of Media-Framework.

#### wait_video
* **syntax**: `wait_video on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

Disable audio until first video frame is sent. Can be combined with wait_key to make client receive video key frame with all other data following it.
This parameter is not relevant in the context of Media-Framework.

#### publish_notify
* **syntax**: `publish_notify on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

Send `NetStream.Play.PublishNotify` and `NetStream.Play.UnpublishNotify` to subscribers.
This parameter is not relevant in the context of Media-Framework.

#### play_restart
* **syntax**: `play_restart on | off;`
* **default**: `off`
* **context**: `rtmp`, `server`, `application`

If enabled, nginx-rtmp sends `NetStream.Play.Start` and `NetStream.Play.Stop` to each subscriber every time publisher starts or stops publishing.
If disabled, each subscriber receives those notifications only at the start and end of playback.
This parameter is not relevant in the context of Media-Framework.

#### idle_streams
* **syntax**: `idle_streams on | off;`
* **default**: `on`
* **context**: `rtmp`, `server`, `application`

If disabled nginx-rtmp prevents subscribers from connecting to idle/nonexistent live streams and disconnects all subscribers when stream publisher disconnects.

#### drop_idle_publisher
* **syntax**: `drop_idle_publisher msec;`
* **default**: `0`
* **context**: `rtmp`, `server`, `application`

Drop publisher connection which has been idle (no audio/video data) within the specified time.
Note this only works when connection is in publish mode (after sending publish command).

### Access Control Directives

#### allow
* **syntax**: `allow [play|publish] address | subnet | all;`
* **default**: ``
* **context**: `rtmp`, `server`, `application`

Allow publish/play from the specified addresses.
The `allow` / `deny` directives are checked in order of appearance.

#### deny
* **syntax**: `deny [play|publish] address | subnet | all;`
* **default**: ``
* **context**: `rtmp`, `server`, `application`

Deny publish/play from the specified addresses.
The `allow` / `deny` directives are checked in order of appearance.

### Codec Directives

#### meta
* **syntax**: `meta on | copy | off;`
* **default**: `on`
* **context**: `rtmp`, `server`, `application`

Sets the metadata sending mode. When set to `on`, subscribers receive reconstructed metadata packets containing predefined fields such as: width, height etc.
When set to `copy`, clients receive an exact copy of the publisher metadata block, including both standard and specific fields.
When set to `off`, no metadata is sent to subscribers.
This parameter is not relevant in the context of Media-Framework.

### Access Log Directives

#### access_log
* **syntax**: `access_log off | path [format_name];`
* **default**: ``
* **context**: `rtmp`, `server`, `application`

Sets access log parameters. Logging is turned on by default. To turn disable logging, use `access_log off`.
By default, access logging is done to the same file as HTTP access logger (logs/access.log).

The second argument can be used to specify the logging format by name.
See the `log_format` directive for more details about formats.

#### log_format
* **syntax**: `log_format name format;`
* **default**: `combined ...`
* **context**: `rtmp`, `server`, `application`

Creates a named log format. Log formats look similarly to nginx's HTTP log formats.
Several variables are supported in the log format:

- `connection` - connection number
- `remote_addr` - client address
- `app` - application name
- `name` - last stream name
- `args` - last stream play/publish arguments
- `flashver` - client flashVer
- `swfurl` - client swfUrl
- `tcurl` - client tcUrl
- `pageurl` - client pageUrl
- `command` - play/publish commands sent by client: `NONE`, `PLAY`, `PUBLISH`, `PLAY+PUBLISH`
- `bytes_sent` - number of bytes sent to client
- `bytes_received` - number of bytes received from client
- `time_local` - local time at the end of client connection
- `session_time` - connection duration in seconds
- `session_readable_time` - connection duration in human-readable format
- `msec` - current unix timestamp in `SEC.MSEC` format

The default log format has the name `combined`, and uses the following structure:

`$remote_addr [$time_local] $command "$app" "$name" "$args" - $bytes_received $bytes_sent "$pageurl" "$flashver" ($session_readable_time)`
