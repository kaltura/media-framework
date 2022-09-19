#ifndef WEBVTT_H_
#define WEBVTT_H_


#include "decoder.h"


#define WEBVTT_TAG_STACK_SIZE  3


typedef struct {
    cc_str_t             open;
    cc_str_t             close;
} webvtt_tag_t;

typedef struct {
    subtitle_handler_t   handler;
    void                *data;
    cc_str_t             tags[WEBVTT_TAG_STACK_SIZE];
    int                  tags_pos;
} webvtt_writer_t;


void webvtt_writer_init(webvtt_writer_t *writer, subtitle_handler_t *handler,
    void *data);

/* Note: the value is supplied in percent * 100 in order to allow fractions */
void webvtt_writer_add_percent_setting(webvtt_writer_t *writer,
    cc_str_t *setting, uint32_t value);

void webvtt_writer_char(webvtt_writer_t *writer, u_char *ch, size_t len);

void webvtt_writer_push_tag(webvtt_writer_t *writer, webvtt_tag_t *tag);

void webvtt_writer_pop_tags(webvtt_writer_t *writer);


extern webvtt_tag_t  webvtt_tag_italics;
extern webvtt_tag_t  webvtt_tag_underline;

extern webvtt_tag_t  webvtt_tag_color_lime;
extern webvtt_tag_t  webvtt_tag_color_blue;
extern webvtt_tag_t  webvtt_tag_color_cyan;
extern webvtt_tag_t  webvtt_tag_color_red;
extern webvtt_tag_t  webvtt_tag_color_yellow;
extern webvtt_tag_t  webvtt_tag_color_magenta;

extern cc_str_t  webvtt_setting_align_left;
extern cc_str_t  webvtt_setting_line;
extern cc_str_t  webvtt_setting_position;

#endif
