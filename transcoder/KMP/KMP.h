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
    bool_t non_blocking;
    bool_t input_is_annex_b;
} KMP_session_t;


typedef struct
{
    AVCodecParameters* codecParams;
    AVRational timeScale;
    AVRational frameRate;
    bool_t closed_captions;
} transcode_mediaInfo_t;

int KMP_init( KMP_session_t *context);

int KMP_connect( KMP_session_t *context,char* url);
int KMP_send_mediainfo( KMP_session_t *context,transcode_mediaInfo_t* mediaInfo);
int KMP_send_handshake( KMP_session_t *context,const char* channel_id,const char* track_id,uint64_t initial_frame_id);
int KMP_send_packet( KMP_session_t *context,AVPacket*);
int KMP_send_eof( KMP_session_t *context);
int KMP_send_ack( KMP_session_t *context,kmp_session_position_t *cur_pos);

int KMP_close( KMP_session_t *context);


int KMP_listen( KMP_session_t *context);
int KMP_accept( KMP_session_t *context, KMP_session_t *client);
int KMP_read_handshake( KMP_session_t *context,kmp_packet_header_t *header,char* channel_id,char* track_id,kmp_session_position_t *start_pos);
int KMP_read_header( KMP_session_t *context,kmp_packet_header_t *header);
int KMP_read_mediaInfo( KMP_session_t *context,kmp_packet_header_t *header,transcode_mediaInfo_t *mediaInfo);
int KMP_read_packet( KMP_session_t *context,kmp_packet_header_t *header,AVPacket *packet);
bool KMP_read_ack(KMP_session_t *context,uint64_t* frame_id);

#endif /* sender_h */
