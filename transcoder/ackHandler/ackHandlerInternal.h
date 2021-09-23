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
    virtual void addIn(const ack_desc_t &desc) = 0;
    virtual void addOut(const ack_desc_t &desc) = 0;
    virtual void map(const uint64_t &id,ack_desc_t &ret) = 0;

    // helpers
    static void ack_map_add_input(ack_handler_t *h,ack_desc_t *desc);
    static void ack_map_add_output(ack_handler_t *h,ack_desc_t *desc);
    static void  ack_map_ack(ack_handler_t *h,uint64_t ack,ack_desc_t *ao);
    static void ack_map_destroy(void *m);
};

#endif
