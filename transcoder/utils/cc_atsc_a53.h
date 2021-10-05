#pragma once

typedef void * atsc_a53_handler_t;
typedef int stream_id_t;

int atsc_a53_handler_create(atsc_a53_handler_t *h);

void atsc_a53_handler_free(atsc_a53_handler_t *h);

int atsc_a53_add_stream(atsc_a53_handler_t h,AVCodecContext *codec,stream_id_t id);

int atsc_a53_decoded(atsc_a53_handler_t h,AVFrame *f);

int atsc_a53_filtered(atsc_a53_handler_t h,stream_id_t id,AVFrame *f);

int atsc_a53_encoded(atsc_a53_handler_t h,stream_id_t id,AVPacket **f);
