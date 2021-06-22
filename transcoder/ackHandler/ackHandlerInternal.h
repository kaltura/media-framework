#pragma once

#include "./ackHandler.h"

typedef void (*destroy_handler)(void *m);


typedef struct ack_handler_ctx_s {
    void *ctx;
    destroy_handler destroy;
} ack_handler_ctx_t;

typedef int (*creator_handler)(uint64_t initialFrameId,const char *name,ack_handler_t *m);
