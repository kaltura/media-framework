//
//  sender.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 21/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef sender_h
#define sender_h

#include <stdio.h>
#include "kalturaMediaProtocol.h"
#include <netinet/in.h>
//KMP
typedef struct
{
    int socket;
    char bindAddress[MAX_URL_LENGTH];
    uint16_t listenPort;
    struct sockaddr_in address;
    char sessionName[MAX_URL_LENGTH];
} KMP_session_t;


typedef struct
{
    AVCodecParameters* codecParams;
    AVRational timeScale;
    AVRational frameRate;
} transcode_mediaInfo_t;

int KMP_init( KMP_session_t *context);

int KMP_connect( KMP_session_t *context,char* url);
int KMP_send_header( KMP_session_t *context,transcode_mediaInfo_t* mediaInfo);
int KMP_send_handshake( KMP_session_t *context,const char* channel_id,const char* track_id);
int KMP_send_packet( KMP_session_t *context,AVPacket*);
int KMP_send_eof( KMP_session_t *context);

int KMP_close( KMP_session_t *context);


int KMP_listen( KMP_session_t *context);
int KMP_accept( KMP_session_t *context, KMP_session_t *client);
int KMP_read_handshake( KMP_session_t *context,kmp_packet_header_t *header,char* channel_id,char* track_id);
int KMP_read_header( KMP_session_t *context,kmp_packet_header_t *header);
int KMP_read_mediaInfo( KMP_session_t *context,kmp_packet_header_t *header,transcode_mediaInfo_t *mediaInfo);
int KMP_readPacket( KMP_session_t *context,kmp_packet_header_t *header,AVPacket *packet);

#endif /* sender_h */
