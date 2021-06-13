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
#include <arpa/inet.h>

size_t load_file_to_memory(const char *filename, char **result)
{
    size_t size = 0;
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


uint64_t getClock90Khz()
{
    return av_rescale_q( getClock64(), clockScale, standard_timebase);
}

char *av_ts_make_time_stringEx(char *buf, int64_t ts,bool shortFormat)
{
    
    if (ts == AV_NOPTS_VALUE) {
        snprintf(buf, K_TS_MAX_STRING_SIZE, "NOPTS");
        return buf;
    }
    
    time_t epoch=ts/standard_timebase.den;
    
    struct tm *gm = gmtime(&epoch);
    
    
    size_t written = (size_t)strftime(buf, K_TS_MAX_STRING_SIZE, shortFormat ? "%H:%M:%S" : "%Y-%m-%dT%H:%M:%S", gm);
    if ((written > 0) && ((size_t)written < K_TS_MAX_STRING_SIZE))
    {
        written+=snprintf(buf+written, K_TS_MAX_STRING_SIZE-(size_t)written, ".%03lld", ((1000*ts) / standard_timebase.den) % 1000);
    }
    if (!shortFormat){
        buf[written-1]='Z';
        buf[written]=0;
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
    int64_t frame_id;
    if (pFrame==NULL) {
        return "<NULL>";
    }
    get_frame_id(pFrame,&frame_id);
    if (pFrame->width>0) {
        snprintf(buf,size,"pts=%s;clock=%s;key=%s;data=%p;hwctx=%p;format=%s;pictype=%s;width=%d;height=%d;has_53cc=%d;frame_id=%lld",
             pts2str(pFrame->pts),
             pFrame->pkt_pos != 0 ? ts2str(pFrame->pkt_pos,false) :  "N/A",
             pFrame->key_frame==1 ? "True" : "False",
             &pFrame->data[0],
             pFrame->hw_frames_ctx,
             av_get_pix_fmt_name(pFrame->format),
             pict_type_to_string(pFrame->pict_type),
             pFrame->width,
             pFrame->height,
             av_frame_get_side_data(pFrame,AV_FRAME_DATA_A53_CC) != NULL,
             frame_id);
    } else {
        snprintf(buf,size,"pts=%s;channels=%d;sampleRate=%d;format=%d;size=%d;channel_layout=%lld;frame_id=%lld",
                 pts2str(pFrame->pts),
                 pFrame->channels,pFrame->sample_rate,pFrame->format,pFrame->nb_samples,pFrame->channel_layout,frame_id);
    }
    return buf;
}

char *av_get_packet_desc(char *buf,int len,const  AVPacket * packet)
{
    int64_t frame_id;
    if (packet==NULL) {
        return "<NULL>";
    }
    get_packet_frame_id(packet,&frame_id);
    snprintf(buf,len,"mem=%p;data=%p;pts=%s;dts=%s;clock=%s;key=%s;size=%d;flags=%d;frame_id=%lld",
             packet,
             packet->data,
             pts2str(packet->pts),
             pts2str(packet->dts),
             packet->pos != 0 ? ts2str(packet->pos,false) :  "N/A",
             (packet->flags & AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY ? "Yes" : "No",
             packet->size,
             packet->flags,
             frame_id);
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


char *av_pts_to_string(char *buf, int64_t pts)
{
    int64_t totalSeconds=llabs(pts/90000);
    int milliseconds=abs((int)(pts % 90000)/90);
    int seconds = (totalSeconds % 60);
    int minutes = (totalSeconds % 3600) / 60;
    int hours = (totalSeconds % 86400) / 3600;
    int days = (int)(totalSeconds / 86400);
    
    if (days==0) {
        sprintf(buf,"%s%.2d:%.2d:%.2d.%.3d",pts>=0 ? "" : "-",hours,minutes,seconds,milliseconds);
    } else {
        sprintf(buf,"%s%d %.2d:%.2d:%.2d.%.3d",pts>=0 ? "" : "-",days,hours,minutes,seconds,milliseconds);
    }
    return buf;
}

void log_frame_side_data(const char* category,const AVFrame *pFrame)
{

    if (get_log_level(category)<AV_LOG_DEBUG)
        return;

    if (pFrame->nb_side_data==0)
        return;
    
    for (int i = 0; i < pFrame->nb_side_data; i++) {
        const AVFrameSideData *sd = pFrame->side_data[i];
        switch(sd->type)
        {
            case AV_FRAME_DATA_A53_CC:
                LOGGER(category,AV_LOG_DEBUG, "A/53 closed captions (%d bytes) %s", sd->size,sd->data);
                break;
            case AV_FRAME_DATA_S12M_TIMECODE: {
                uint32_t *tc = (uint32_t*)sd->data;
                for (int j = 1; j <= tc[0]; j++) {
                    char tcbuf[100];
                    av_timecode_make_smpte_tc_string(tcbuf, tc[j], 0);
                    LOGGER(category,AV_LOG_DEBUG, "timecode - %s%s", tcbuf, j != tc[0] ? ", " : "");
                }
                break;
            }
            default: {
                const char *name = av_frame_side_data_name(sd->type);
                LOGGER(category,AV_LOG_DEBUG, "%s (%d bytes)", name,sd->size);
            }
        }
    }
}

int add_packet_frame_id(AVPacket *packet,int64_t frame_id) {
     AVDictionary * frameDict = NULL;
     int frameDictSize = 0;
     char buf[sizeof("9223372036854775807")];
     uint8_t *frameDictData = NULL;
     sprintf(buf,"%lld",frame_id);
     _S(av_dict_set(&frameDict, "frame_id", buf, 0));
     // Pack dictionary to be able to use it as a side data in AVPacket
     frameDictData = av_packet_pack_dictionary(frameDict, &frameDictSize);
     if(!frameDictData)
      return AVERROR(ENOMEM);
     // Free dictionary not used any more
     av_dict_free(&frameDict);
     // Add side_data to AVPacket which will be decoded
     return av_packet_add_side_data(packet, AV_PKT_DATA_STRINGS_METADATA, frameDictData, frameDictSize);
}

int get_packet_frame_id(const AVPacket *packet,int64_t *frame_id_ptr)
{
    const char *frame_str;
     AVDictionary * frameDict = NULL;
     int frameDictSize = 0;
     uint8_t *frameDictData = av_packet_get_side_data(packet, AV_PKT_DATA_STRINGS_METADATA, &frameDictSize);
     *frame_id_ptr = AV_NOPTS_VALUE;
     if (!frameDictData)
        return AVERROR(EINVAL);
    _S(av_packet_unpack_dictionary(frameDictData,frameDictSize,&frameDict));
    frame_str = av_dict_get(frameDict, "frame_id", NULL, 0)->value;
    if(!frame_str)
       return AVERROR(EINVAL);
    *frame_id_ptr = strtoull(frame_str,NULL,10);
    av_dict_free(&frameDict);
    return 0;
}

int get_frame_id(AVFrame *frame,int64_t *frame_id_ptr)
{
    *frame_id_ptr = AV_NOPTS_VALUE;
    if(frame->metadata) {
        const char *frame_str = av_dict_get(frame->metadata, "frame_id", NULL, 0)->value;
         if(!frame_str)
            return AVERROR(EINVAL);
        *frame_id_ptr = strtoull(frame_str,NULL,10);
    }
    return AVERROR(EINVAL);
}