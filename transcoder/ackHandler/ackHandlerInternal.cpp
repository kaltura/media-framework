#include "ackHandlerInternal.h"

   void BaseAckMap::ack_map_add_input(ack_handler_t *h,ack_desc_t *desc) {
       if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
            try {
               am.addIn(*desc);
             } catch(const std::exception &e) {
                   LOGGER(LoggingCategory,AV_LOG_ERROR," %s audio map. ack_map_add_input %d %lld failed due to %s",
                        am.m_name.c_str(),desc->id, desc->pts,e.what());
             }
       }
    }

     void BaseAckMap::ack_map_add_filtered(ack_handler_t *h,ack_desc_t *desc) {
           if(h){
                ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
                auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
                try {
                   am.addFiltered(*desc);
                 } catch(const std::exception &e) {
                       LOGGER(LoggingCategory,AV_LOG_ERROR," %s audio map. ack_map_add_filtered %d %lld failed due to %s",
                            am.m_name.c_str(),desc->id, desc->pts,e.what());
                 }
           }
        }

    void BaseAckMap::ack_map_add_output(ack_handler_t *h,ack_desc_t *desc) {
        if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
             try {
                am.addOut(*desc);
            } catch(const std::exception &e) {
                  LOGGER(LoggingCategory,AV_LOG_ERROR," %s audio map. ack_map_add_output %d %lld failed due to %s",
                    am.m_name.c_str(),desc->id, desc->pts,e.what());
            }
        }
    }

    void  BaseAckMap::ack_map_ack(ack_handler_t *h,uint64_t ack,ack_desc_t *ao) {
        if(!ao)   return;
        if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
            try {
              am.map(ack,*ao);
              return;
            } catch(const std::exception &e) {
                 LOGGER(LoggingCategory,AV_LOG_ERROR," %s audio map. ack_map_ack %lld failed due to %s",
                        am.m_name.c_str(),ack, e.what());
            }
        }
        ao->id = ack;
        ao->offset = 0;
    }

    void BaseAckMap::ack_map_destroy(void *m) {
        if(m){
            delete reinterpret_cast<BaseAckMap*>(m);
        }
    }