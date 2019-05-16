//
//  packetQueue.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 13/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "packetQueue.h"
#include <pthread.h>
#include "logger.h"


#define CATEGORY_PACKET_QUEUE "CATEGORY_PACKET_QUEUE"

int packet_queue_write_packet(PacketQueueContext_t *ctx, AVPacket *pkt)
{
    FifoMessage msg = {.type =  FIFO_WRITE_PACKET, .pkt=pkt};
    return av_thread_message_queue_send(ctx->queue, &msg, 0);
}

int packet_queue_write_mediaInfo(PacketQueueContext_t *ctx, transcode_mediaInfo_t *mediaInfo)
{
    FifoMessage msg = {.type = FIFO_WRITE_CODEC_PARAMS, .mediaInfo=mediaInfo};
    return av_thread_message_queue_send(ctx->queue, &msg, 0);
}

int packet_queue_write_stop(PacketQueueContext_t *ctx)
{
    FifoMessage msg = {.type = FIFO_WRITE_STOP, .mediaInfo=NULL, .pkt=NULL};
    return av_thread_message_queue_send(ctx->queue, &msg, 0);
}

void* fifo_consumer_thread(void* params) {
    PacketQueueContext_t *ctx=(PacketQueueContext_t *)params;
    FifoMessage msg = {FIFO_WRITE_NOPS, NULL,NULL};
    int ret=0;
    while(1) {
        
        ret = av_thread_message_queue_recv(ctx->queue, &msg, 0);
        if (ret < 0) {
            av_thread_message_queue_set_err_send(ctx->queue, ret);
            break;
        }
        if (msg.type==FIFO_WRITE_CODEC_PARAMS) {
            ctx->onMediaInfo(ctx->callbackContext,msg.mediaInfo);
        }
        if (msg.type==FIFO_WRITE_PACKET) {
            ctx->onPacket(ctx->callbackContext,msg.pkt);
            av_packet_free(&msg.pkt);
        }
        if (msg.type==FIFO_WRITE_STOP) {
            break;
        }
    }
    LOGGER0(CATEGORY_PACKET_QUEUE, AV_LOG_INFO, "Stopped packet queue thread");
    return NULL;
}

int packet_queue_init(PacketQueueContext_t *ctx)
{
     int ret;
     av_thread_message_queue_alloc(&ctx->queue,ctx->totalPackets,sizeof(FifoMessage));
    
     ret = pthread_create(&ctx->thread, NULL, fifo_consumer_thread, ctx);
     if (ret) {
          LOGGER(CATEGORY_PACKET_QUEUE, AV_LOG_ERROR, "Failed to start thread: %s", av_err2str(AVERROR(ret)));
          return AVERROR(ret);
      }

     return ret;
}

void packet_queue_destroy(PacketQueueContext_t *ctx)
{
    LOGGER0(CATEGORY_PACKET_QUEUE, AV_LOG_INFO, "Destroying packet queue");
    packet_queue_write_stop(ctx);
    
    pthread_join(ctx->thread,NULL);
    av_thread_message_queue_free(&ctx->queue);
}


