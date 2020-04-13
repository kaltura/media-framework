#ifndef _NGX_LIVE_DVR_FORMAT_H_INCLUDED_
#define _NGX_LIVE_DVR_FORMAT_H_INCLUDED_


#include <ngx_live_kmp.h>


#define NGX_LIVE_DVR_FILE_MAGIC                                             \
    (0x66706c6b)    /* 'klpf' - kaltura live persistent file */

#define NGX_LIVE_DVR_SEGMENT_MAGIC                                          \
    (0x6765736d)    /* 'mseg' - media segment */

#define NGX_LIVE_DVR_TYPE_SEGMENT_LIST                                      \
    (0x6c67736d)    /* 'msgl' - media segment list */

#define NGX_LIVE_DVR_FILE_VERSION   (1)


typedef struct {
    uint32_t          magic;
    uint32_t          flags;
    uint32_t          version;
    uint32_t          type;
    uint32_t          header_size;
    uint32_t          data_size;
    uint32_t          segment_count;
} ngx_live_dvr_file_header_t;

typedef struct {
    uint32_t          segment_id;
    uint32_t          track_id;
    uint32_t          header_size;
    uint32_t          data_size;
} ngx_live_dvr_segment_entry_t;

typedef struct {
    uint32_t          magic;
    uint32_t          flags;
    uint32_t          header_size;
    uint32_t          frames_start;
    uint32_t          frame_count;
    uint32_t          reserved;
    int64_t           start_dts;
    uint32_t          extra_data_len;
    kmp_media_info_t  media_info;
} ngx_live_dvr_segment_header_t;

#endif /* _NGX_LIVE_DVR_FORMAT_H_INCLUDED_ */
