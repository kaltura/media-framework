# Nginx MPEG-TS module

A modified version of [nginx-ts-module](https://github.com/arut/nginx-ts-module).

Support for additional codecs was added, on top of the original nginx-ts-module implementation.

In the context of Media-Framework, this module is used only for receiving MPEG-TS input.
Therefore, the support for HLS/DASH output, that exists in the original nginx-ts-module, was removed.

Input protocols:
- MPEG-TS over HTTP
- MPEG-TS over TCP

Input codecs:
- video: *h264 / AVC*, *h265 / HEVC*
- audio: *AAC*, *MP3*, *AC3*, *E-AC3*

Used by: [nginx-mpegts-kmp-module](../nginx-mpegts-kmp-module/).


## Configuration

### Sample Configuration

See the sample provided in [nginx-mpegts-kmp-module](../nginx-mpegts-kmp-module/README.md#sample-configuration)

### Configuration Directives

#### ts
* **syntax**: `ts;`
* **default**: `none`
* **context**: `stream/server`, `location`

Enables MPEG-TS input in the surrounding stream-server/location block.
By default, HTTP request body size is limited in nginx. To enable live streaming without size limitation, use the directive `client_max_body_size 0`.

#### ts_stream_id
* **syntax**: `ts_stream_id expr;`
* **default**: ``
* **context**: `http`, `server`, `location`, `stream`, `server`

Sets the id of the incoming stream. The id is stored on the mpeg-ts session, and is available for use by other modules.
The parameter value can contain variables.

#### ts_timeout
* **syntax**: `ts_timeout msec;`
* **default**: `5s`
* **context**: `stream`, `server`

Defines a timeout for reading data from the client connection.
The timeout is set only between two successive read operations, not for the transmission of the whole response.
If the client does not transmit anything within this time, the connection is closed.

#### ts_buffer_size
* **syntax**: `ts_buffer_size size;`
* **default**: `64k`
* **context**: `stream`, `server`

Sets the size of the buffer used for reading data from the client connection.

#### ts_mem_limit
* **syntax**: `ts_mem_limit size;`
* **default**: `5m`
* **context**: `http`, `server`, `location`, `stream`, `server`

Sets the maximum total size of the buffers used for assembling MPEG-TS packets.
If the limit is hit, the module drops the HTTP/TCP connection.

#### ts_dump_folder
* **syntax**: `ts_dump_folder path;`
* **default**: ``
* **context**: `http`, `server`, `location`, `stream`, `server`

When set to a non-empty string, the module saves all incoming MPEG-TS data to files under the specified folder.
The file names have the following structure: `ngx_ts_dump_{date}_{pid}_{connection}.dat`.
