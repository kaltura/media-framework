//
//  utils.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "utils.h"
#include <stdio.h>
#include <termios.h>
#include <time.h>
#include <sys/ioctl.h> // For FIONREAD
#include <libavutil/pixdesc.h>
#include <arpa/inet.h>

int load_file_to_memory(const char *filename, char **result)
{
    int size = 0;
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        *result = NULL;
        return -1; // -1 means file opening fail
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (char *)malloc(size+1);
    if (size != fread(*result, sizeof(char), size, f))
    {
        //free(*result);
        return -2; // -2 means file reading fail
    }
    fclose(f);
    (*result)[size] = 0;
    return size;
}


int kbhit(void)
{
    static bool initflag = false;
    static const int STDIN = 0;
    
    if (!initflag) {
        // Use termios to turn off line buffering
        struct termios term;
        tcgetattr(STDIN, &term);
        term.c_lflag &= ~ICANON;
        tcsetattr(STDIN, TCSANOW, &term);
        setbuf(stdin, NULL);
        initflag = true;
    }
    
    int nbbytes;
    ioctl(STDIN, FIONREAD, &nbbytes);  // 0 is STDIN
    return nbbytes;
}


uint64_t getTime64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    
    uint64_t usecondsSinceEpoch =
    (uint64_t)(ts.tv_sec) * 1000000 +
    (uint64_t)(ts.tv_nsec) / 1000;
    
    return usecondsSinceEpoch;
}

uint64_t getClock64()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    
    uint64_t usecondsSinceEpoch =
    (uint64_t)(ts.tv_sec) * 1000000 +
    (uint64_t)(ts.tv_nsec) / 1000;
    
    return usecondsSinceEpoch;
}

char *av_ts_make_time_stringEx(char *buf, int64_t ts,bool shortFormat)
{
    
    if (ts == AV_NOPTS_VALUE) {
        snprintf(buf, K_TS_MAX_STRING_SIZE, "NOPTS");
        return buf;
    }
    
    time_t epoch=ts/standard_timebase.den;
    
    struct tm *gm = localtime(&epoch);
    
    
    size_t written = (size_t)strftime(buf, K_TS_MAX_STRING_SIZE, shortFormat ? "%H:%M:%S" : "%Y-%m-%dT%H:%M:%S", gm);
    if ((written > 0) && ((size_t)written < K_TS_MAX_STRING_SIZE))
    {
        snprintf(buf+written, K_TS_MAX_STRING_SIZE-(size_t)written, ".%03lld", ((1000*ts) / standard_timebase.den) % 1000);
        
    }
    return buf;
}

const char* pict_type_to_string(int pt) {
    
    const char *pict_type;
    switch (pt)
    {
        case AV_PICTURE_TYPE_I: pict_type="I"; break;     ///< Intra
        case AV_PICTURE_TYPE_P: pict_type="P"; break;      ///< Predicted
        case AV_PICTURE_TYPE_B: pict_type="B"; break;      ///< Bi-dir predicted
        case AV_PICTURE_TYPE_S: pict_type="S"; break;      ///< S(GMC)-VOP MPEG-4
        case AV_PICTURE_TYPE_SI: pict_type="SI"; break;     ///< Switching Intra
        case AV_PICTURE_TYPE_SP: pict_type="SP"; break;     ///< Switching Predicted
        case AV_PICTURE_TYPE_BI: pict_type="BI"; break;     ///< BI type
        default: pict_type="";
    }
    return pict_type;
}

char *av_get_frame_desc(char* buf, int size,const AVFrame * pFrame)
{
    if (pFrame==NULL) {
        return "<NULL>";
    }
    if (pFrame->width>0) {
        snprintf(buf,size,"pts=%s;key=%s;data=%p;hwctx=%p;format=%s;pictype=%s;width=%d;height=%d",
             ts2str(pFrame->pts,true),
             pFrame->key_frame==1 ? "True" : "False",
             &pFrame->data[0],
             pFrame->hw_frames_ctx,
             av_get_pix_fmt_name(pFrame->format),
             pict_type_to_string(pFrame->pict_type),
             pFrame->width,
             pFrame->height);
    } else {
        snprintf(buf,size,"pts=%s;channels=%d;sampleRate=%d;format=%d;size=%d;channel_layout=%lld",
                 ts2str(pFrame->pts,true),
                 pFrame->channels,pFrame->sample_rate,pFrame->format,pFrame->nb_samples,pFrame->channel_layout);
    }
    return buf;
}

char *av_get_packet_desc(char *buf,int len,const  AVPacket * packet)
{
    if (packet==NULL) {
        return "<NULL>";
    }
    snprintf(buf,len,"mem=%p;data=%p;pts=%s;dts=%s;key=%s;size=%d;flags=%d",
             packet,
             packet->data,
             ts2str(packet->pts,true),
             ts2str(packet->dts,true),
             (packet->flags & AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY ? "Yes" : "No",
             packet->size,
             packet->flags);
    return buf;
}

char* av_socket_info(char* buf,int len,const struct sockaddr_in* sa)
{
    char buffer[100];

    inet_ntop(AF_INET, &(sa->sin_addr), buffer, len);
    int port = 0;
    if (sa->sin_family == AF_INET) {
        port=((struct sockaddr_in*)sa)->sin_port;
    } else {
        port=((struct sockaddr_in6*)sa)->sin6_port;
    }
    snprintf(buf,len,"%s:%d",buffer,ntohs(port));
    return buf;
}
