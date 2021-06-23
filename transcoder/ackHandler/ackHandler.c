#include "../utils/logger.h"
#include "ackHandlerInternal.h"
#include "./audioAckMap.h"

void empty_handler(struct ack_handler_s *m,frame_desc_t *fr){}
void empty_destroy(void *p){}
void default_map_ack_handler(struct ack_handler_s *m,uint64_t ack,frame_desc_t *ao){
    ao->id = ack;
    ao->offset = 0;
}

void ack_hanler_init(ack_handler_t *h) {
     memset(h,0,sizeof(*h));
     h->decoded = h->filtered = h->encoded = &empty_handler;
     h->map = &default_map_ack_handler;
}

int ack_hanler_create(uint64_t initialFrameId,const char *name,int media_type,ack_handler_t *h) {
    ack_handler_ctx_t *ahctx = h->ctx = malloc(sizeof(ack_handler_ctx_t));
    if(!ahctx)
         return AVERROR(ENOMEM);
    ahctx->ctx = NULL;
    ahctx->destroy = empty_destroy;
   switch(media_type) {
    case AVMEDIA_TYPE_AUDIO:
      _S(audio_ack_map_create(initialFrameId,name,h));
      break;
    default:
        return AVERROR(EINVAL);
    };
    return 0;
}

void ack_hanler_destroy(ack_handler_t *h) {
    if(h->ctx){
        ack_handler_ctx_t *ahctx = h->ctx;
        ahctx->destroy(ahctx->ctx);
        free(ahctx);
        memset(h,0,sizeof(*h));
    }
}