#pragma once

typedef void * atsc_a53_handler_t;

int atsc_a53_handler_create(enum AVCodecID codecId,atsc_a53_handler_t *h);

void atsc_a53_handler_free(atsc_a53_handler_t *h);

int atsc_a53_add_stream(atsc_a53_handler_t h,int id);

int atsc_a53_decoded(atsc_a53_handler_t h,AVFrame *f);

int atsc_a53_filtered(atsc_a53_handler_t h,int id,AVFrame *f);

int atsc_a53_encoded(atsc_a53_handler_t h,int id,AVPacket **f);
