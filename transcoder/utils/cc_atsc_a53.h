#pragma once

typedef void * atsc_a53_handler_t;

int atsc_a53_handler_create(atsc_a53_handler_t *h);

void atsc_a53_handler_free(atsc_a53_handler_t *h);

int atsc_a53_input_frame(atsc_a53_handler_t h,AVFrame *f);

int atsc_a53_add_stream(atsc_a53_handler_t h,int id);

int atsc_a53_output_frame(atsc_a53_handler_t h,int id,AVFrame *f);
