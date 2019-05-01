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
    struct sockaddr_in address;
} KMP_session_t;

int KMP_connect( KMP_session_t *context,char* url);
int KMP_send_header( KMP_session_t *context,AVCodecParameters *codecpar,AVRational frame_rate);
int KMP_send_handshake( KMP_session_t *context,const char* set_id,const char* track_id);
int KMP_send_packet( KMP_session_t *context,AVPacket*);
int KMP_send_eof( KMP_session_t *context);

int KMP_close( KMP_session_t *context);


int KMP_listen( KMP_session_t *context,int port);
int KMP_accept( KMP_session_t *context, KMP_session_t *client);
int KMP_read_handshake( KMP_session_t *context,packet_header_t *header,char* set_id,char* track_id);
int KMP_read_header( KMP_session_t *context,packet_header_t *header);
int KMP_read_mediaInfo( KMP_session_t *context,packet_header_t *header,AVCodecParameters* params,AVRational *frameRate);
int KMP_readPacket( KMP_session_t *context,packet_header_t *header,AVPacket *packet);

#endif /* sender_h */
