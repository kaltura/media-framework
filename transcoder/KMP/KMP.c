//
//  sender.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 21/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "core.h"

#include "kalturaMediaProtocol.h"
#include "KMP.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>
#include <unistd.h> // close function
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/tcp.h>

inline __attribute__((always_inline)) int checkReturn(int retval)
{
    if(retval == 0)
        retval = errno ? AVERROR(errno) : -1;
    return retval;
}

static ssize_t KMP_send( KMP_session_t *context,const void *buf, size_t len)
{
    if(context->socket <= 0) {
       LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket invalid error as %d",context->socket);
       return AVERROR(EBADFD);
    }
    int bytesRead=0;
    while (len>0) {
        int valread = (int)send(context->socket ,buf+bytesRead , len , 0 );
        if (valread<=0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK) {
                if(context->non_blocking) {
                    struct timespec tv;
                    tv.tv_sec=0;
                    tv.tv_nsec=250*1000000;//wait 250ms
                    nanosleep(&tv,NULL);
                    continue;
                }
            }
            LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"incomplete send, returned %d errno=%d",valread,errno);
            return AVERROR(errno);
        }
        bytesRead+=valread;
        len-=valread;
    }
    return 0;
}
int KMP_init( KMP_session_t *context)
{
    context->socket=0;
    context->bindAddress[0]=0;
    context->listenPort=0;
    context->non_blocking=true;
    memset(&context->address,0,sizeof(context->address));
    context->sessionName[0]=0;
    context->input_is_annex_b=false;
    return 0;
}

int KMP_connect( KMP_session_t *context,char* url)
{

    int fd=0,ret=0;

    char host[256];
    char port[6];

    int user_timeout_ms;  // user timeout in milliseconds
    json_get_int(GetConfig(),"kmp.userTimeoutMs",2 * 1000,&user_timeout_ms);


    int n=sscanf(url,"kmp://%255[^:]:%5s",host,port);// this line isnt working properly
    if (n!=2) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Cannot parse url '%s'",url);
        return 0;
    }

    struct addrinfo hints, *servinfo;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; //ipv4!
    hints.ai_socktype = SOCK_STREAM; //tcp
    hints.ai_flags = AI_CANONNAME;

    if ((ret = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Cannot resolve %s - error %d (%s)",url,errno,strerror(errno));
        return -1;
    }
    struct addrinfo *p=servinfo; //take first match

    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) <= 0)
    {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket creation for %s - error %d (%s)",url,errno,strerror(errno));
        return -1;
    }
    context->socket=fd;

    setsockopt(context->socket, SOL_TCP, TCP_USER_TIMEOUT, (char*) &user_timeout_ms, sizeof (user_timeout_ms));

    if ( connect(context->socket,p->ai_addr, p->ai_addrlen) < 0)
    {
        context->socket=-1;
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Connection Failed for %s - error %d (%s)",url,errno,strerror(errno));
        return -1;
    }

    if (context->non_blocking) {
        int flags=0;
        if (-1 == (flags = fcntl(context->socket, F_GETFL, 0)))
            flags = 0;
        fcntl(context->socket, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in address;
    socklen_t addrLen = sizeof(address);
    if (getsockname(context->socket, (struct sockaddr *)&address, &addrLen) == -1) {
        LOGGER0(CATEGORY_KMP,AV_LOG_FATAL,"getsockname() failed");
        return -1;
    }

    sprintf(context->sessionName,"localhost:%d => %s:%s",htons(address.sin_port),host,port);

    LOGGER(CATEGORY_KMP,AV_LOG_INFO,"[%s] connected",context->sessionName);
    return 1;
}


static kmp_codec_id get_audio_codec(AVCodecParameters *apar)
{
    switch (apar->codec_id) {
        case AV_CODEC_ID_AAC:
            return KMP_CODEC_AUDIO_AAC;
        case AV_CODEC_ID_MP3:
            return KMP_CODEC_AUDIO_MP3;
        default:
            return (kmp_codec_id)apar->codec_id;
    }
}

static kmp_codec_id get_video_codec(AVCodecParameters *apar)
{
    switch (apar->codec_id) {
        case AV_CODEC_ID_FLV1:
            return KMP_CODEC_VIDEO_SORENSON_H263;
        case AV_CODEC_ID_FLASHSV:
            return KMP_CODEC_VIDEO_SCREEN;
        case AV_CODEC_ID_FLASHSV2:
            return KMP_CODEC_VIDEO_SCREEN2;
        case AV_CODEC_ID_VP6F:
            return KMP_CODEC_VIDEO_ON2_VP6;
        case AV_CODEC_ID_VP6A:
            return KMP_CODEC_VIDEO_ON2_VP6_ALPHA;
        case AV_CODEC_ID_H264:
            return KMP_CODEC_VIDEO_H264;
        case AV_CODEC_ID_HEVC:
            return KMP_CODEC_VIDEO_HEVC;
        default:
            return (kmp_codec_id)apar->codec_id;
    }
}

int KMP_send_mediainfo( KMP_session_t *context,transcode_mediaInfo_t* mediaInfo )
{
    if (context->socket <= 0)
    {
        LOGGER0(CATEGORY_KMP,AV_LOG_FATAL,"Invalid socket (KMP_send_mediainfo)");
        return -1;
    }
    LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] send kmp_media_info",context->sessionName);
    uint8_t *actualExtraData = NULL;
    AVCodecParameters *codecpar=mediaInfo->codecParams;
    kmp_packet_header_t header;
    kmp_media_info_t media_info;
    header.packet_type=KMP_PACKET_MEDIA_INFO;
    header.header_size=sizeof(kmp_packet_header_t)+sizeof(media_info);
    header.data_size=codecpar->extradata_size;
    header.reserved=0;
    media_info.bitrate=(uint32_t)codecpar->bit_rate;
    media_info.timescale=mediaInfo->timeScale.den;
    if (codecpar->codec_type==AVMEDIA_TYPE_VIDEO)
    {
        media_info.media_type=KMP_MEDIA_VIDEO;
        media_info.codec_id=get_video_codec(codecpar);
        media_info.u.video.width=codecpar->width;
        media_info.u.video.height=codecpar->height;
        media_info.u.video.frame_rate.denom=mediaInfo->frameRate.den;
        media_info.u.video.frame_rate.num=mediaInfo->frameRate.num;
        media_info.u.video.cea_captions=mediaInfo->closed_captions;
    }
    if (codecpar->codec_type==AVMEDIA_TYPE_AUDIO)
    {
        media_info.media_type=KMP_MEDIA_AUDIO;
        media_info.codec_id=get_audio_codec(codecpar);
        media_info.u.audio.bits_per_sample=codecpar->bits_per_coded_sample;
        media_info.u.audio.sample_rate=codecpar->sample_rate;
        media_info.u.audio.channels=codecpar->channels;
        media_info.u.audio.channel_layout=codecpar->channel_layout;

        LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] audio kmp_media_info, codec id %d samplerate %d bps %d channels %d channel layout %d",
            context->sessionName,
            media_info.codec_id,
            media_info.u.audio.sample_rate,
            media_info.u.audio.bits_per_sample,
            media_info.u.audio.channels,
            media_info.u.audio.channel_layout);
    }

    if (codecpar->codec_type==AVMEDIA_TYPE_VIDEO && codecpar->extradata_size>0 && codecpar->extradata[0] != 1) { //convert to mp4 header
        AVIOContext *extra = NULL;
        avio_open_dyn_buf(&extra);

        switch(codecpar->codec_id) {
        case AV_CODEC_ID_H264:
            ff_isom_write_avcc(extra,codecpar->extradata , codecpar->extradata_size);
            break;
        case AV_CODEC_ID_H265:
            ff_isom_write_hvcc(extra,codecpar->extradata , codecpar->extradata_size, 0);
            break;
        };
        //override data_size with mp4 format
        header.data_size = avio_close_dyn_buf(extra, &actualExtraData);

        LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] video kmp_media_info, codec id %d extradata_size %d bytes converted(mp4) %d bytes",
                context->sessionName,
                media_info.codec_id,
                codecpar->extradata_size,
                header.data_size);

    }


    _S(KMP_send(context , &header , sizeof(header) ));
    _S(KMP_send(context , &media_info , sizeof(media_info) ));
    if (header.data_size>0) {
        _S(KMP_send(context , actualExtraData!=NULL  ?  actualExtraData : codecpar->extradata, header.data_size ));
        av_free(actualExtraData);
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


uint32_t kk_avc_parse_nal_units(KMP_session_t *context, const uint8_t *buf_in, int size)
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

        if (context!=NULL) {
            uint32_t size=htonl(nNalSize);
            _S(KMP_send(context, &size, sizeof(uint32_t)));
            _S(KMP_send(context, nal_start, nNalSize));
        }
        written += sizeof(uint32_t) + nNalSize;
        nal_start = nal_end;
    }
    return written;
}


void print_mp4_units(char* data,uint size) {
    int pos=0;
    bool annex_b=   AV_RB32(data) == 0x00000001 ||  AV_RB24(data) == 0x000001;

    printf ("packet (%d): ",annex_b);

    while(pos<size) {
        uint32_t chunkSize=AV_RB32(data+pos);
        printf("%d,",chunkSize);
        pos+=chunkSize;
        if (pos>size) {
            printf("problem!!");
            exit(-1);
        }
        pos+=4;
    }
    printf("\n");
}


int KMP_send_packet( KMP_session_t *context,AVPacket* packet)
{
    if (context->socket<=0) {
        LOGGER0(CATEGORY_KMP,AV_LOG_FATAL,"Invalid socket (KMP_send_packet)");
        return -1;
    }
    //LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] send KMP_send_packet",context->sessionName);

    kmp_packet_header_t packetHeader;
    kmp_frame_t sample;

    packetHeader.packet_type=KMP_PACKET_FRAME;
    packetHeader.header_size=sizeof(sample)+sizeof(packetHeader);
    packetHeader.reserved=0;
    packetHeader.data_size = context->input_is_annex_b ? kk_avc_parse_nal_units(NULL,packet->data,packet->size) : packet->size;
    sample.pts_delay=packet->pts - packet->dts;
    sample.dts=packet->dts;
    sample.created=packet->pos;
    sample.flags=((packet->flags& AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY)? KMP_FRAME_FLAG_KEY : 0;

    _S(KMP_send(context, &packetHeader, sizeof(packetHeader)));
    _S(KMP_send(context, &sample, sizeof(sample)));
    if (context->input_is_annex_b) {
        _S(kk_avc_parse_nal_units(context,packet->data, packet->size));
    } else {
        //print_mp4_units(packet->data,packet->size);
        _S(KMP_send(context, packet->data, packet->size));
    }
    return 0;
}

int KMP_send_eof( KMP_session_t *context)
{
    LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] send KMP_send_eof",context->sessionName);
    kmp_packet_header_t packetHeader;
    packetHeader.packet_type=KMP_PACKET_EOS;
    packetHeader.header_size=sizeof(packetHeader);
    packetHeader.data_size=0;
    packetHeader.reserved=0;
    _S(KMP_send(context, &packetHeader, sizeof(packetHeader)));
    return 0;
}

int KMP_send_ack( KMP_session_t *context,kmp_frame_position_t *cur_pos)
{
    LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] send KMP_send_ack %lld offset %ld",context->sessionName,cur_pos->frame_id,cur_pos->offset);
    kmp_ack_frames_packet_t pkt;
    pkt.header.packet_type=KMP_PACKET_ACK_FRAMES;
    pkt.header.data_size=0;
    pkt.header.reserved=0;
    pkt.header.header_size=sizeof(kmp_ack_frames_packet_t);
    pkt.frame_id=cur_pos->frame_id;
    pkt.transcoded_frame_id = cur_pos->transcoded_frame_id;
    pkt.offset = cur_pos->offset;
    pkt.padding=0;
    _S(KMP_send(context, &pkt, sizeof(pkt)));
    return 0;
}

int KMP_send_handshake( KMP_session_t *context,const char* channel_id,const char* track_id,uint64_t initial_frame_id)
{
    LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] send KMP_send_handshake %s,%s",context->sessionName,channel_id,track_id);
    kmp_connect_packet_t connect = {0};
    connect.header.packet_type=KMP_PACKET_CONNECT;
    connect.header.header_size=sizeof(connect);
    connect.initial_frame_id=initial_frame_id;
    connect.offset = 0;
    strcpy((char*)connect.channel_id,channel_id);
    strcpy((char*)connect.track_id,track_id);
    _S(KMP_send(context, &connect, sizeof(connect)));
    return 0;
}

int KMP_close( KMP_session_t *context)
{
    LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] KMP_close",context->sessionName);
    close(context->socket);
    context->socket=0;
    return 0;
}

int KMP_listen( KMP_session_t *context)
{
    int ret= 0;

     // Creating socket file descriptor
     if ((ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) <= 0)
     {
         LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket creation error %d (%s)",ret,av_err2str(ret));
          return checkReturn(ret);
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
     context->address.sin_port = htons( context->listenPort );

        // Forcefully attaching socket to the port
     if ( (ret=bind(context->socket, (struct sockaddr *)&context->address,sizeof(context->address)))<0)
     {
         LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"bind to port %d failed  error:%d (%s)",context->listenPort,errno,av_err2str(errno));
         return ret;
     }

     if ( (ret=listen(context->socket, 10)) < 0)
     {
         LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"listen failed %d (%s)",errno,av_err2str(errno));
         return ret;
    }

    socklen_t addrLen = sizeof(context->address);
    if (getsockname(context->socket, (struct sockaddr *)&context->address, &addrLen) < 0) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"getsockname() failed %d (%s)",errno,av_err2str(errno));
        return -1;
    }

    context->listenPort=htons( context->address.sin_port );


    sprintf(context->sessionName,"Listen %s",socketAddress(&context->address));
    return 0;
}

int KMP_accept( KMP_session_t *context, KMP_session_t *client)
{
    int clientSocket;
    int addrlen = sizeof(context->address);
    struct timeval tv;
    int flags=0;
    int tv_sec;

    json_get_int(GetConfig(),"kmp.fd",-1,&clientSocket);
    if(clientSocket < 0){
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(context->socket, &rfds);


        json_get_int(GetConfig(),"kmp.acceptTimeout",10,&tv_sec);

        tv.tv_sec = tv_sec;
        tv.tv_usec = 0;

        int nfd = select(context->socket+1, &rfds, &rfds, NULL, &tv);

        if (nfd<0)
        {
            LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"accept failure errno=%d",errno);
            return -1;
        }
        if (nfd==0) {
            LOGGER0(CATEGORY_KMP,AV_LOG_FATAL,"timeout waiting for accept");
            return -1;
        }
        clientSocket=accept(context->socket, (struct sockaddr *)&client->address,
                                (socklen_t*)&addrlen);

    }
    if (clientSocket<=0) {
        return clientSocket;
    }
    client->socket =clientSocket;
    client->listenPort=0;
    if (-1 == (flags = fcntl(client->socket, F_GETFL, 0)))
        flags = 0;
    fcntl(client->socket, F_SETFL, flags & (~O_NONBLOCK));
    client->non_blocking = false;
    json_get_int(GetConfig(),"kmp.sndRcvTimeout",60*3,&tv_sec);
    tv.tv_sec = tv_sec;
    tv.tv_usec = 0;
    _S(setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv));
    _S(setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv));

    sprintf(client->sessionName,"%s => %s | snd.rcv.tout %d",socketAddress(&client->address),
        socketAddress(&context->address),
      tv_sec);

    return 1;
}

static
int recvExact(KMP_session_t *context,char* buffer,int bytesToRead) {

    if(context->socket <= 0) {
       LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"Socket invalid error as %d",context->socket);
       return AVERROR(EBADFD);
    }
    if (bytesToRead==0) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"recvExact invalid bytesToRead=  %d",bytesToRead);
    }

    int bytesRead=0;
    while (bytesToRead>0) {
        int valread = (int)recv(context->socket,buffer+bytesRead, bytesToRead, 0);
        if (valread<=0){
            if(valread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) && context->non_blocking) {
                LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"in recvExact, inside recv error -> sleeping, errno = %d", errno);
                struct timespec tv;
                tv.tv_sec=0;
                tv.tv_nsec=250*1000000; // 250 ms
                nanosleep(&tv,NULL);
                continue;
            }
            LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"incomplete recv when reading offset %d-%d, returned %d (errno=%d)",bytesRead,bytesRead+bytesToRead,valread,errno);
            return checkReturn(valread);
        }
        bytesRead+=valread;
        bytesToRead-=valread;
    }
    return bytesRead;
}


int KMP_read_header( KMP_session_t *context,kmp_packet_header_t *header)
{
    int valread =recvExact(context,(char*)header,sizeof(kmp_packet_header_t));
    return checkReturn(valread);
}
int KMP_read_handshake( KMP_session_t *context,kmp_packet_header_t *header,char* channel_id,char* track_id,kmp_frame_position_t *start_pos)
{
    kmp_connect_packet_t connect;
    if (header->packet_type!=KMP_PACKET_CONNECT) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"KMP_read_handshake. invalid packet, expected PACKET_TYPE_HANDSHAKE received packet_type=%d",header->packet_type);
        return -1;
    }
    int bytesToRead = sizeof(kmp_connect_packet_t)-sizeof(kmp_packet_header_t);
    int valread =recvExact(context,((char*)&connect)+sizeof(kmp_packet_header_t),bytesToRead);
    if (valread < bytesToRead) {
         LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"KMP_read_handshake, expected %d bytes, read %d",bytesToRead,valread);
         return -1;
    }
    strcpy(channel_id,(char*)connect.channel_id);
    strcpy(track_id,(char*)connect.track_id);
    start_pos->frame_id = connect.initial_frame_id;
    start_pos->transcoded_frame_id = connect.initial_transcoded_frame_id;
    start_pos->offset   = connect.offset;
    return 0;
}


static void set_audio_codec(int codecid,AVCodecParameters *apar)
{
    switch (codecid) {
            // no distinction between S16 and S8 PCM codec flags
        case KMP_CODEC_AUDIO_UNCOMPRESSED:
            apar->codec_id = apar->bits_per_coded_sample == 8 ? AV_CODEC_ID_PCM_U8
#if HAVE_BIGENDIAN
            : AV_CODEC_ID_PCM_S16BE;
#else
            : AV_CODEC_ID_PCM_S16LE;
#endif
            break;
        case KMP_CODEC_AUDIO_LINEAR_LE:
            apar->codec_id = apar->bits_per_coded_sample == 8
            ? AV_CODEC_ID_PCM_U8
            : AV_CODEC_ID_PCM_S16LE;
            break;
        case KMP_CODEC_AUDIO_AAC:
            apar->codec_id = AV_CODEC_ID_AAC;
            break;
        case KMP_CODEC_AUDIO_ADPCM:
            apar->codec_id = AV_CODEC_ID_ADPCM_SWF;
            break;
        case KMP_CODEC_AUDIO_SPEEX:
            apar->codec_id    = AV_CODEC_ID_SPEEX;
            apar->sample_rate = 16000;
            break;
        case KMP_CODEC_AUDIO_MP3:
            apar->codec_id      = AV_CODEC_ID_MP3;
            break;
        case KMP_CODEC_AUDIO_NELLY8:
            // in case metadata does not otherwise declare samplerate
            apar->sample_rate = 8000;
            apar->codec_id    = AV_CODEC_ID_NELLYMOSER;
            break;
        case KMP_CODEC_AUDIO_NELLY16:
            apar->sample_rate = 16000;
            apar->codec_id    = AV_CODEC_ID_NELLYMOSER;
            break;
        case KMP_CODEC_AUDIO_NELLY:
            apar->codec_id = AV_CODEC_ID_NELLYMOSER;
            break;
        case KMP_CODEC_AUDIO_G711U:
            apar->sample_rate = 8000;
            apar->codec_id    = AV_CODEC_ID_PCM_MULAW;
            break;
        case KMP_CODEC_AUDIO_G711A:
            apar->sample_rate = 8000;
            apar->codec_id    = AV_CODEC_ID_PCM_ALAW;
            break;
        default:
            apar->codec_tag = codecid;
            break;
    }
}

static void set_video_codec(int codecid,AVCodecParameters *apar)
{

    switch (codecid) {
        case KMP_CODEC_VIDEO_SORENSON_H263:
            apar->codec_id = AV_CODEC_ID_FLV1;
            break;
        case KMP_CODEC_VIDEO_SCREEN:
            apar->codec_id = AV_CODEC_ID_FLASHSV;
            break;
        case KMP_CODEC_VIDEO_SCREEN2:
            apar->codec_id = AV_CODEC_ID_FLASHSV2;
            break;
        case KMP_CODEC_VIDEO_ON2_VP6:
            apar->codec_id = AV_CODEC_ID_VP6F;
            break;
        case KMP_CODEC_VIDEO_ON2_VP6_ALPHA:
            apar->codec_id = AV_CODEC_ID_VP6A;
            break;
        case KMP_CODEC_VIDEO_H264:
            apar->codec_id = AV_CODEC_ID_H264;
            break;
         case KMP_CODEC_VIDEO_HEVC:
             apar->codec_id = AV_CODEC_ID_HEVC;
             break;
        default:
            apar->codec_tag = codecid;
            break;
    }
}

int KMP_read_mediaInfo( KMP_session_t *context,kmp_packet_header_t *header,transcode_mediaInfo_t *transcodeMediaInfo)
{
    kmp_media_info_t mediaInfo;
    if (header->packet_type!=KMP_PACKET_MEDIA_INFO) {
        LOGGER(CATEGORY_KMP,AV_LOG_FATAL,"invalid packet, expceted PACKET_TYPE_HEADER received packet_type=%d",header->packet_type);
        return -1;
    }
    int valread =recvExact(context,(char*)&mediaInfo,sizeof(kmp_media_info_t));
    if (valread<=0) {
        return checkReturn(valread);
    }
    AVCodecParameters* params=transcodeMediaInfo->codecParams;
    if (mediaInfo.media_type==KMP_MEDIA_AUDIO) {
        params->codec_type=AVMEDIA_TYPE_AUDIO;
        params->sample_rate=mediaInfo.u.audio.sample_rate;
        params->bits_per_coded_sample=mediaInfo.u.audio.bits_per_sample;
        params->channels=mediaInfo.u.audio.channels;
        params->channel_layout=mediaInfo.u.audio.channel_layout;
        set_audio_codec(mediaInfo.codec_id,params);


        LOGGER(CATEGORY_KMP,AV_LOG_DEBUG,"[%s] KMP_read_mediaInfo audio kmp_media_info, codec id %d samplerate %d bps %d channels %d channel layout %d",
            context->sessionName,
            mediaInfo.codec_id,
            mediaInfo.u.audio.sample_rate,
            mediaInfo.u.audio.bits_per_sample,
            mediaInfo.u.audio.channels,
            mediaInfo.u.audio.channel_layout);
    }
    if (mediaInfo.media_type==KMP_MEDIA_VIDEO) {
        params->codec_type=AVMEDIA_TYPE_VIDEO;
        params->format=AV_PIX_FMT_YUV420P;
        params->width=mediaInfo.u.video.width;
        params->height=mediaInfo.u.video.height;
        transcodeMediaInfo->frameRate.den=mediaInfo.u.video.frame_rate.denom;
        transcodeMediaInfo->frameRate.num=mediaInfo.u.video.frame_rate.num;
        transcodeMediaInfo->closed_captions = mediaInfo.u.video.cea_captions;
        set_video_codec(mediaInfo.codec_id,params);
    }
    transcodeMediaInfo->timeScale.den=mediaInfo.timescale;
    transcodeMediaInfo->timeScale.num=1;
    params->bit_rate=mediaInfo.bitrate;
    //params->codec_id=mediaInfo.codec_id;
    params->extradata_size=header->data_size;
    params->extradata=NULL;
    if (params->extradata_size>0) {
        params->extradata=av_mallocz(params->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
        valread =recvExact(context,(char*)params->extradata,header->data_size);
        return checkReturn(valread);
    }

    return 0;

}

int KMP_read_packet( KMP_session_t *context,kmp_packet_header_t *header,AVPacket *packet)
{
    kmp_frame_t sample;

    int valread =recvExact(context,(char*)&sample,sizeof(kmp_frame_t));
    if (valread<=0){
        return checkReturn(valread);
    }

    av_new_packet(packet,(int)header->data_size);
    packet->dts=sample.dts;
    packet->pts=sample.dts+sample.pts_delay;
    packet->duration=0;
    packet->pos=sample.created;
    packet->flags=((sample.flags& KMP_FRAME_FLAG_KEY )==KMP_FRAME_FLAG_KEY)? AV_PKT_FLAG_KEY : 0;

    valread =recvExact(context,(char*)packet->data,(int)header->data_size);

    return checkReturn(valread);
}

bool KMP_read_ack(KMP_session_t *context,uint64_t* frame_id)
{
    *frame_id=0;
    while(true) {
        int bytesAv=0;
        if ( ioctl (context->socket,FIONREAD,&bytesAv) <0  || bytesAv<sizeof(kmp_ack_frames_packet_t)) {
            break;
        }
        kmp_ack_frames_packet_t pkt;
        recvExact(context,(char*)&pkt,(int)sizeof(kmp_ack_frames_packet_t));
        //validate ack packet;
        if(pkt.header.header_size != sizeof(pkt)){
             LOGGER(CATEGORY_KMP,AV_LOG_ERROR,"[%s] KMP_read_ack header_size %d != %d",
                    context->sessionName,pkt.header.header_size,sizeof(pkt));
             break;
        }
        if(pkt.header.data_size != 0){
           LOGGER(CATEGORY_KMP,AV_LOG_ERROR,"[%s] KMP_read_ack data_size %d != 0",
                    context->sessionName,pkt.header.data_size);
            break;
        }
        *frame_id=pkt.frame_id;
        return true;
    }
    return false;
}

static const char *hex = "0123456789ABCDEF";

int KMP_log_mediainfo(KMP_session_t *context,
    const char *category, int level,
    transcode_mediaInfo_t* transcodeMediaInfo) {

    AVCodecParameters* params = transcodeMediaInfo->codecParams;

    if(!params){
        return -1;
    }

    char *ex = NULL;
    if(params->extradata_size > 0 ){
        ex = av_malloc(2 * params->extradata_size + 1);
        char *walk = ex;
        for(int i = 0; i < params->extradata_size; i++) {
           *walk++ = hex[params->extradata[i] >> 4];
           *walk++ = hex[params->extradata[i] & 0x0f];
        }
        *walk = '\0';
    }

    if (params->codec_type == AVMEDIA_TYPE_AUDIO) {

        LOGGER(category,level,"[%s] KMP_PACKET_MEDIA_INFO type=audio"
            " codec_id=%s (0x%x) samplerate=%d bps=%d channels=%d channel_layout=%d"
            " bitrate=%.3f kbps timescale=%d:%d"
            " extra_data=%s",
            context->sessionName,
            avcodec_get_name(params->codec_id),
            params->codec_tag,
            params->sample_rate,
            params->bits_per_coded_sample,
            params->channels,
            params->channel_layout,
            params->bit_rate / 1000.0, transcodeMediaInfo->timeScale.num, transcodeMediaInfo->timeScale.den,
            ex);
    }
    else if (params->codec_type == AVMEDIA_TYPE_VIDEO) {

        LOGGER(category,level,"[%s] KMP_PACKET_MEDIA_INFO type=video"
            " codec_id=%s (0x%x) width=%d height=%d frame_rate=%d:%d"
            " bitrate=%.3f kbps timescale=%d:%d"
            " cc=%s extra_data=%s",
            context->sessionName,
            avcodec_get_name(params->codec_id),
            params->codec_tag,
            params->width,
            params->height,
            transcodeMediaInfo->frameRate.num, transcodeMediaInfo->frameRate.den,
            params->bit_rate / 1000.0, transcodeMediaInfo->timeScale.num, transcodeMediaInfo->timeScale.den,
            transcodeMediaInfo->closed_captions ? "yes" : "no",
            ex);
    }

    if(ex) {
        av_free(ex);
    }

    return 0;
}

