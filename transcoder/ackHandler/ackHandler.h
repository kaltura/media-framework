#pragma once

typedef struct {
    uint64_t id;
    uint32_t offset;
} frame_desc_t;

typedef frame_desc_t ack_desc_t;

typedef void * ack_handle_t;

struct ack_handler_s;

typedef void (*frame_ack_handler)(struct ack_handler_s *m,frame_desc_t *fr);
typedef void (*map_ack_handler)(struct ack_handler_s *m,uint64_t ack,frame_desc_t *ao);

typedef struct ack_handler_s {
    frame_ack_handler  decoded,
                       filtered,
                       encoded;
    map_ack_handler    map;
    ack_handle_t       ctx;
} ack_handler_t;

//factory
void ack_hanler_init(ack_handler_t *h);
int ack_hanler_create(uint64_t initialFrameIdInput,uint64_t initialFrameIdOutput,const char *name,int media_type,ack_handler_t *h);
void ack_hanler_destroy(ack_handler_t *h);