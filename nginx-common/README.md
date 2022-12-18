# Nginx Common

Shared code used by the different nginx modules in the media-framework.


## Src

- *ngx_buf_chain* - a lightweight chain of buffers (similar to ngx_chain_t + ngx_buf_t)
- *ngx_buf_queue* - a queue of fixed-size buffers, used for buffering KMP input/output
- *ngx_buf_queue_stream* - a read/write stream implementation over an ngx_buf_queue_t
- *ngx_http_api* - HTTP API dispatcher -
    - parse incoming requests
    - route the request to the configured handler
    - handle `multi` requests
    - parse query args

    See [API Overview](../README.md#api-overview) for more details
- *ngx_http_call* - HTTP client implementation over nginx connection (can be used by non-HTTP nginx modules)
- *ngx_json_parser* - JSON parser
- *ngx_json_pretty* - re-format JSONs in a "pretty" / indented format
- *ngx_ksmp* - Kaltura Segmented Media Protocol definitions
- *ngx_lba* - Large Buffer Allocator, allocate media buffers in large chunks using `mmap`
- *ngx_live_kmp* - Kaltura Media Protocol definitions
- *ngx_mem_rstream* - a read stream over a continuous memory buffer
- *ngx_persist* - functions for managing KLPF block definitions
- *ngx_persist_read* - functions for reading KLPFs
- *ngx_persist_write* - functions for writing KLPFs
- *ngx_wstream* - an abstract write stream definition


## Scripts

- *generate_json_header* - generate code for reading/writing JSON objects
- *generate_kmp_spec.py* - generate a specification JSON of the KMP format, for parsing with klpf_parse
- *generate_routes_header* - generate code for routing HTTP requests
- *klpf_generate_doc* - generate markdown documentation from a KLPF specification file
- *klpf_parse* - parse a KLPF object
