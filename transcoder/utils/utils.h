//
//  utils.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef utils_h
#define utils_h

#include "../core.h"
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <libavcodec/avcodec.h>

size_t load_file_to_memory(const char *filename, char **result);

uint64_t getClock90Khz();
uint64_t getClock64();
uint64_t getTime64();
int kbhit(void);

#define K_TS_MAX_STRING_SIZE 100

char *av_ts_make_time_stringEx(char *buf, int64_t ts,bool shortFormat);
char *av_pts_to_string(char *buf, int64_t pts);

const char* pict_type_to_string(int pt);

char *av_get_frame_desc(char *buf,int len, const AVFrame * frame);
char *av_get_packet_desc(char *buf,int len, const AVPacket * packet);
char* av_socket_info(char* buf,int len,const struct sockaddr_in* sa);
void log_frame_side_data(const char* category,const AVFrame *pFrame);
typedef int64_t pts_t;
int add_packet_frame_id_and_pts(AVPacket *packet,int64_t frame_id,pts_t pts);
int add_packet_frame_metadata(AVPacket *packet,int64_t frame_id,pts_t pts,int64_t created);
int add_packet_timing_context(AVPacket *packet,int64_t frame_id,pts_t pts,int64_t input_created,int64_t input_dts);
int get_frame_id(const AVFrame *frame,uint64_t *frame_id_ptr);
int get_packet_frame_id(const AVPacket *packet,int64_t *frame_id_ptr);
int get_packet_original_pts(const AVPacket *packet,pts_t *pts_ptr);
int get_packet_created_timestamp(const AVPacket *packet,int64_t *created_ptr);
int get_packet_input_timing_context(const AVPacket *packet,int64_t *input_created_ptr,int64_t *input_dts_ptr);
int get_frame_original_pts(const AVFrame *frame,pts_t *pts_ptr);
/**
 * Convenience macro, the return value should be used only directly in
 * function arguments but never stand-alone.
 */
#define getPacketDesc(packet) av_get_packet_desc((char[200]){0},200,packet)
#define getFrameDesc(frame) av_get_frame_desc((char[200]){0},200,frame)
#define socketAddress(sa) av_socket_info((char[200]){0},200,sa)

#define ts2str(ts,short) av_ts_make_time_stringEx((char[K_TS_MAX_STRING_SIZE]){0}, ts,short)
#define pts2str(pts) av_pts_to_string((char[K_TS_MAX_STRING_SIZE]){0}, pts)


extern const AVRational standard_timebase,clockScale;

#define __MAX(x, y) (((x) > (y)) ? (x) : (y))
#define __MIN(x, y) (((x) < (y)) ? (x) : (y))

av_always_inline int64_t ff_samples_from_time_base(const AVCodecContext *avctx,
                                                        int64_t pts)
{
    if(pts == AV_NOPTS_VALUE)
      return AV_NOPTS_VALUE;
     return av_rescale_q(pts, avctx->time_base,(AVRational){ 1, avctx->sample_rate });
}

av_always_inline int64_t ff_samples_to_time_base(AVCodecContext *avctx,
                                                        int64_t samples)
{
    if(samples == AV_NOPTS_VALUE)
       return AV_NOPTS_VALUE;
    return av_rescale_q(samples, (AVRational){ 1, avctx->sample_rate },
                        avctx->time_base);
}

#endif /* utils_h */
