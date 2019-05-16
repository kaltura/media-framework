//
//  packetQueue.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 13/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef packetQueue_h
#define packetQueue_h

#include <stdio.h>
#include "../core.h"

#include "libavutil/threadmessage.h"
#include "../KMP/KMP.h"

typedef int packet_queue_packetCB(void* cbContext,AVPacket* packet);
typedef int packet_queue_mediaInfoCB(void* cbContext,transcode_mediaInfo_t* mediaInfo);

typedef struct  {
    pthread_t thread;
    int totalPackets;
    AVThreadMessageQueue *queue;
    void* callbackContext;
    packet_queue_packetCB*  onPacket;
    packet_queue_mediaInfoCB*  onMediaInfo;
} PacketQueueContext_t;


typedef enum FifoMessageType {
    FIFO_WRITE_NOPS,
    FIFO_WRITE_CODEC_PARAMS,
    FIFO_WRITE_PACKET,
    FIFO_WRITE_STOP
} FifoMessageType;


typedef struct FifoMessage {
    FifoMessageType type;
    AVPacket* pkt;
    transcode_mediaInfo_t* mediaInfo;
} FifoMessage;

#define CATEGORY_PACKET_QUEUE "CATEGORY_PACKET_QUEUE"

int packet_queue_write_packet(PacketQueueContext_t *ctx, AVPacket *pkt);
int packet_queue_write_mediaInfo(PacketQueueContext_t *ctx, transcode_mediaInfo_t *mediaInfo);

void* fifo_consumer_thread(void* params);
int packet_queue_init(PacketQueueContext_t *ctx);
void packet_queue_destroy(PacketQueueContext_t *ctx);

#endif /* packetQueue_h */
