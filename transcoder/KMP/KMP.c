//
//  sender.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 21/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "core.h"
#include "utils.h"
#include "logger.h"

#include "kalturaMediaProtocol.h"
#include "KMP.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>
#include <unistd.h> // close function
#include "libavutil/intreadwrite.h"

int KMP_connect( KMP_session_t *context,char* url)
{
    
    context->socket=0;
    int ret=0;
    struct sockaddr_in serv_addr;
    if ((ret = socket(AF_INET, SOCK_STREAM, 0)) <= 0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket creation error %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    context->socket=ret;
    
    
    char host[256];
    int port=0;
    
    int n=sscanf(url,"kmp://%255[^:]:%d",host,&port);// this line isnt working properly
    if (n!=2) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Cannot parse url '%s'",url);
        return 0;
    }

    struct hostent        *he;
    if ( (he = gethostbyname(host) ) == NULL ) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Cannot resolve %s",host);
        return -1;
    }
    
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    if ( (ret=connect(context->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Connection Failed (%s) %d (%s)",url,ret,av_err2str(ret));
        return ret;
    }
    return 1;
}

int KMP_send_header( KMP_session_t *context,AVCodecParameters *codecpar,AVRational frame_rate)
{
    if (context->socket==0)
    {
        LOGGER0(CATEGORY_KMP,AV_LOG_FATAL,"Invalid socket");
        return -1;
    }
    packet_header_t header;
    live_media_info_t media_info;
    header.packet_type=PACKET_TYPE_MEDIA_INFO;
    header.header_size=sizeof(packet_header_t);
    header.data_size=codecpar->extradata_size;
    media_info.bitrate=(uint32_t)codecpar->bit_rate;
    media_info.codec_id=codecpar->codec_id;
    media_info.timescale=90000;
    if (codecpar->codec_type==AVMEDIA_TYPE_VIDEO)
    {
        media_info.media_type=LIVE_MEDIA_TYPE_VIDEO;
        media_info.u.video.width=codecpar->width;
        media_info.u.video.height=codecpar->height;
        media_info.u.video.frame_rate.den=frame_rate.den;
        media_info.u.video.frame_rate.num=frame_rate.num;
    }
    if (codecpar->codec_type==AVMEDIA_TYPE_AUDIO)
    {
        media_info.media_type=LIVE_MEDIA_TYPE_AUDIO;
        media_info.u.audio.bits_per_sample=codecpar->bits_per_raw_sample;
        media_info.u.audio.sample_rate=codecpar->sample_rate;
        media_info.u.audio.channels=codecpar->channels;
    }
    
    send(context->socket , &header , sizeof(header) , 0 );
    send(context->socket , &media_info , sizeof(media_info) , 0 );
    if (codecpar->extradata_size>0) {
        send(context->socket , codecpar->extradata , codecpar->extradata_size , 0 );
    }
    
    return 0;
}



static const uint8_t *kk_avc_find_startcode_internal(const uint8_t *p, const uint8_t *end)
{
    const uint8_t *a = p + 4 - ((intptr_t)p & 3);
    
    for (end -= 3; p < a && p < end; p++) {
        if (p[0] == 0 && p[1] == 0 && p[2] == 1)
            return p;
    }
    
    for (end -= 3; p < end; p += 4) {
        uint32_t x = *(const uint32_t*)p;
        //      if ((x - 0x01000100) & (~x) & 0x80008000) // little endian
        //      if ((x - 0x00010001) & (~x) & 0x00800080) // big endian
        if ((x - 0x01010101) & (~x) & 0x80808080) { // generic
            if (p[1] == 0) {
                if (p[0] == 0 && p[2] == 1)
                    return p;
                if (p[2] == 0 && p[3] == 1)
                    return p+1;
            }
            if (p[3] == 0) {
                if (p[2] == 0 && p[4] == 1)
                    return p+2;
                if (p[4] == 0 && p[5] == 1)
                    return p+3;
            }
        }
    }
    
    for (end += 3; p < end; p++) {
        if (p[0] == 0 && p[1] == 0 && p[2] == 1)
            return p;
    }
    
    return end + 3;
}

const uint8_t *kk_avc_find_startcode(const uint8_t *p, const uint8_t *end){
    const uint8_t *out= kk_avc_find_startcode_internal(p, end);
    if(p<out && out<end && !out[-1]) out--;
    return out;
}


uint32_t kk_avc_parse_nal_units( const uint8_t *buf_in, int size,int socket)
{
    
    const uint8_t *p = buf_in;
    const uint8_t *end = p + size;
    const uint8_t *nal_start=NULL, *nal_end=NULL;
    uint32_t nNalSize;
    uint32_t written = 0;
    nal_start = kk_avc_find_startcode(p, end);
    for (;;) {
        while (nal_start < end && !*(nal_start++));
        if (nal_start == end)
            break;
        
        nal_end = kk_avc_find_startcode(nal_start, end);
        nNalSize = (uint32_t)(nal_end - nal_start);
        
        if (socket!=0) {
            send(socket, &nNalSize, sizeof(uint32_t), 0);
            send(socket, nal_start, nNalSize, 0);
        }
        written += sizeof(uint32_t) + nNalSize;
        nal_start = nal_end;
    }
    return written;
}




int KMP_send_packet( KMP_session_t *context,AVPacket* packet)
{
    bool annex_b=
        AV_RB32(packet->data) == 0x00000001 ||
        AV_RB24(packet->data) == 0x000001;
    
    packet_header_t packetHeader;
    frame_info_t sample;
    
    packetHeader.packet_type=PACKET_TYPE_FRAME;
    packetHeader.header_size=sizeof(sample);
    packetHeader.data_size = annex_b ? kk_avc_parse_nal_units(packet->data,packet->size,0) : packet->size;
    if (AV_NOPTS_VALUE!=packet->pts) {
        sample.pts_delay=(uint32_t)(packet->pts - packet->dts);
    } else {
        sample.pts_delay=-999999;
    }
    sample.dts=packet->dts;
    sample.flags=0;
    
    send(context->socket, &packetHeader, sizeof(packetHeader), 0);
    send(context->socket, &sample, sizeof(sample), 0);
    if (annex_b) {
        kk_avc_parse_nal_units(packet->data, packet->size,context->socket);
    } else {
        send(context->socket, packet->data, packet->size, 0);
    }
    return 0;
}


int KMP_send_eof( KMP_session_t *context)
{
    packet_header_t packetHeader;
    packetHeader.packet_type=PACKET_TYPE_EOS;
    packetHeader.header_size=0;
    packetHeader.data_size=0;
    send(context->socket, &packetHeader, sizeof(packetHeader), 0);
    
    return 0;
}

int KMP_send_handshake( KMP_session_t *context,const char* set_id,const char* track_id)
{
    connect_header_t connect;
    connect.header.packet_type=PACKET_TYPE_CONNECT;
    connect.header.header_size=sizeof(packet_header_t);
    connect.header.data_size=sizeof(connect_header_t)-sizeof(packet_header_t);
    strcpy((char*)connect.set_id,set_id);
    strcpy((char*)connect.track_id,track_id);
    send(context->socket, &connect, sizeof(connect), 0);

    return 0;
}

int KMP_close( KMP_session_t *context)
{
    close(context->socket);
    context->socket=0;
    return 0;
}

int KMP_listen( KMP_session_t *context,int port)
{
    int ret=0;
    // Creating socket file descriptor
    if ((ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket creation error %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    
    context->socket =ret;
    
    /*
     if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
     &opt, sizeof(opt)))
     {
     perror("setsockopt");
     exit(EXIT_FAILURE);
     }*/
    context->address.sin_family = AF_INET;
    context->address.sin_addr.s_addr = INADDR_ANY;
    context->address.sin_port = htons( port );
    
    // Forcefully attaching socket to the port
    if ( (ret=bind(context->socket, (struct sockaddr *)&context->address,sizeof(context->address)))<0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"bind error %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    if ( (ret=listen(context->socket, 10)) < 0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"listen failed %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    return 0;
}

int KMP_accept( KMP_session_t *context, KMP_session_t *client)
{
    int addrlen = sizeof(context->address);
    int clientSocket=accept(context->socket, (struct sockaddr *)&context->address,
                            (socklen_t*)&addrlen);
    
    if (clientSocket<=0) {
        return clientSocket;
    }
    client->socket =clientSocket;
    return 1;
}


int recvEx(int socket,char* buffer,int bytesToRead) {
    
    if (bytesToRead==0) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"!!!!recvEx invalid bytesToRead=  %d",bytesToRead);

    }
    int bytesRead=0;
    while (bytesToRead>0) {
        
        
        int valread = (int)recv(socket,buffer+bytesRead, bytesToRead, 0);
        if (valread<=0){
            LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"incomplete recv, returned %d",valread);
            return valread;
        }
        bytesRead+=valread;
        bytesToRead-=valread;
    }
    return bytesRead;
}


int KMP_read_header( KMP_session_t *context,packet_header_t *header)
{
    int valread =recvEx(context->socket,(char*)header,sizeof(packet_header_t));
    return valread;
}
int KMP_read_handshake( KMP_session_t *context,packet_header_t *header,char* set_id,char* track_id)
{
    connect_header_t connect;
    if (header->packet_type!=PACKET_TYPE_CONNECT) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"invalid packet, expceted PACKET_TYPE_HANDSHAKE received packet_type=%d",header->packet_type);
        return -1;
    }
    int valread =recvEx(context->socket,((char*)&connect)+sizeof(packet_header_t),sizeof(connect_header_t)-sizeof(packet_header_t));
    if (valread<=0) {
        return valread;
    }
    
    strcpy(set_id,(char*)connect.set_id);
    strcpy(track_id,(char*)connect.track_id);
    return 0;
}

int KMP_read_mediaInfo( KMP_session_t *context,packet_header_t *header,AVCodecParameters* params,AVRational *frameRate)
{
    live_media_info_t mediaInfo;
    if (header->packet_type!=PACKET_TYPE_MEDIA_INFO) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"invalid packet, expceted PACKET_TYPE_HEADER received packet_type=%d",header->packet_type);
        return -1;
    }
    int valread =recvEx(context->socket,(char*)&mediaInfo,sizeof(mediaInfo));
    if (valread<=0) {
        return valread;
    }
    if (mediaInfo.media_type==LIVE_MEDIA_TYPE_AUDIO) {
        params->codec_type=AVMEDIA_TYPE_AUDIO;
        params->sample_rate=mediaInfo.u.audio.sample_rate;
        params->bits_per_raw_sample=mediaInfo.u.audio.bits_per_sample;
        params->channels=mediaInfo.u.audio.channels;
        params->channel_layout=3;
    }
    if (mediaInfo.media_type==LIVE_MEDIA_TYPE_VIDEO) {
        params->codec_type=AVMEDIA_TYPE_VIDEO;
        params->format=AV_PIX_FMT_YUV420P;
        params->width=mediaInfo.u.video.width;
        params->height=mediaInfo.u.video.height;
        frameRate->den=mediaInfo.u.video.frame_rate.den;
        frameRate->num=mediaInfo.u.video.frame_rate.num;
        
    }
    params->bit_rate=mediaInfo.bitrate;
    params->codec_id=mediaInfo.codec_id;
    params->extradata_size=header->data_size;
    params->extradata=NULL;
    if (params->extradata_size>0) {
        params->extradata=av_mallocz(params->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
        valread =recvEx(context->socket,(char*)params->extradata,header->data_size);
        if (valread<=0) {
            return valread;
        }
    }
    
    return 1;
    
}

int KMP_readPacket( KMP_session_t *context,packet_header_t *header,AVPacket *packet)
{
    frame_info_t sample;
    
    int valread =recvEx(context->socket,(char*)&sample,header->header_size);
    if (valread<=0){
        return valread;
    }
    
    av_new_packet(packet,(int)header->data_size);
    packet->dts=sample.dts;
    if (sample.pts_delay!=-999999) {
        packet->pts=sample.dts+sample.pts_delay;
    } else {
        packet->pts=AV_NOPTS_VALUE;
    }
    packet->duration=0;
    
    valread =recvEx(context->socket,(char*)packet->data,(int)header->data_size);
    return valread;
}
