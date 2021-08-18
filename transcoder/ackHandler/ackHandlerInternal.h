#pragma once

#ifdef __cplusplus

#include <deque>
#include <string>
#include <cassert>
#include <limits>
#include <stdexcept>
typedef uint64_t frameId_t;

extern "C" {
#endif

#include "./ackHandler.h"
#include "../utils/logger.h"

typedef void (*destroy_handler)(void *m);


typedef struct ack_handler_ctx_s {
    void *ctx;
    destroy_handler destroy;
} ack_handler_ctx_t;

#define LoggingCategory CATEGORY_OUTPUT

#ifdef __cplusplus
}

class BaseAckMap
{
  void operator=(const BaseAckMap&) = delete;
  BaseAckMap(const BaseAckMap&) = delete;
protected:
    const std::string m_name;
public:
    BaseAckMap(const std::string &name) :m_name(name){}
    virtual ~BaseAckMap(){}
    virtual void addIn(const ack_desc_t &desc) throw() = 0;
    virtual void addOut(const ack_desc_t &desc) throw() = 0;
    virtual void map(const uint64_t &id,ack_desc_t &ret) throw() = 0;

    // helpers
    static void ack_map_add_input(ack_handler_t *h,ack_desc_t *desc) {
       if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
            try {
               am.addIn(*desc);
             } catch(const std::exception &e) {
                   LOGGER(LoggingCategory,AV_LOG_ERROR," %s map. ack_map_add_input %d %lld failed due to %s",
                        am.m_name.c_str(),desc->id, desc->pts,e.what());
             }
       }
    }
    static void ack_map_add_output(ack_handler_t *h,ack_desc_t *desc) {
        if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
             try {
                am.addOut(*desc);
            } catch(const std::exception &e) {
                  LOGGER(LoggingCategory,AV_LOG_ERROR," %s map. ack_map_add_output %d %lld failed due to %s",
                    am.m_name.c_str(),desc->id, desc->pts,e.what());
            }
        }
    }
    static void  ack_map_ack(ack_handler_t *h,uint64_t ack,ack_desc_t *ao) {
        if(!ao)   return;
        if(h){
            ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
            auto &am = *reinterpret_cast<BaseAckMap*>(ahc->ctx);
            try {
              am.map(ack,*ao);
              return;
            } catch(const std::exception &e) {
                 LOGGER(LoggingCategory,AV_LOG_ERROR," %s map. ack_map_ack %lld failed due to %s",
                        am.m_name.c_str(),ack, e.what());
            }
        }
        ao->id = ack;
        ao->offset = 0;
    }
    static void ack_map_destroy(void *m) {
        if(m){
            delete reinterpret_cast<BaseAckMap*>(m);
        }
    }
};

#endif
