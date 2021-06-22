#pragma once

#include "../ackHandler/ackHandler.h"

av_always_inline
void handleAckFrame(AVFrame *pFrame,ack_handler_t *acker,frame_ack_handler method) {
     uint64_t frameId;
     if(!get_frame_id(pFrame,&frameId)){
          frame_desc_t desc = {frameId,pFrame->nb_samples};
          method(acker,&desc);
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