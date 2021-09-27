#pragma once

#include "../ackHandler/ackHandler.h"

av_always_inline
int frame_desc_from_avframe(enum AVMediaType codec_type,
    const AVFrame *pFrame,
    frame_desc_t *ret) {
    switch (codec_type){
        case AVMEDIA_TYPE_AUDIO:
           ret->samples = pFrame->nb_samples;
           break;
        case AVMEDIA_TYPE_VIDEO:
           ret->pts = pFrame->pts;
           break;
        default:
           return AVERROR_INVALIDDATA;
    };
    ret->key = pFrame->key_frame;
    ret->id = INVALID_FRAME_ID;
    get_frame_id(pFrame,&ret->id);
    return 0;
}

av_always_inline
int frame_desc_from_avpacket(const AVCodecContext *ctx,
                            const AVPacket *packet,
                           frame_desc_t *ret) {
     _S(get_packet_frame_id(packet,&ret->id));
     switch (ctx->codec_type){
       case AVMEDIA_TYPE_AUDIO:
         ret->samples = ff_samples_from_time_base(ctx,packet->duration);
         break;
       case AVMEDIA_TYPE_VIDEO:
         ret->pts = packet->pts;
         break;
       default:
         return -1;
     };
     ret->key = (packet->flags & AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY ? 1 : 0;
     return 0;
}


av_always_inline
void handleAckFrame(AVFrame *pFrame,ack_handler_t *acker,frame_ack_handler method) {
   frame_desc_t desc;
   if(!frame_desc_from_avframe(acker->codec_type,pFrame,&desc)) {
         method(acker,&desc);
   } else {
       LOGGER(LoggingCategory,AV_LOG_ERROR,"handleAckFrame(%p) . failed to extract frame id from frame",
              acker->ctx);
   }
}

av_always_inline
void ackDecode(ack_handler_t *acker,AVFrame *pFrame) {
    handleAckFrame(pFrame,acker,acker->decoded);
}

av_always_inline
void ackFilter(ack_handler_t *acker,AVFrame *pFrame) {
    handleAckFrame(pFrame,acker,acker->filtered);
}

av_always_inline
int ackEncode(AVCodecContext *ctx,ack_handler_t *acker,AVPacket *packet) {
   frame_desc_t desc;
   _S(frame_desc_from_avpacket(ctx,packet,&desc));
   acker->encoded(acker,&desc);
   return 0;
}

