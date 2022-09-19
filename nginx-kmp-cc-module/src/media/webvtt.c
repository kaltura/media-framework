#include "webvtt.h"


webvtt_tag_t  webvtt_tag_italics =
    { cc_string("<i>"),         cc_string("</i>") };

webvtt_tag_t  webvtt_tag_underline =
    { cc_string("<u>"),         cc_string("</u>") };


webvtt_tag_t  webvtt_tag_color_lime =
    { cc_string("<c.lime>"),    cc_string("</c>") };

webvtt_tag_t  webvtt_tag_color_blue =
    { cc_string("<c.blue>"),    cc_string("</c>") };

webvtt_tag_t  webvtt_tag_color_cyan =
    { cc_string("<c.cyan>"),    cc_string("</c>") };

webvtt_tag_t  webvtt_tag_color_red =
    { cc_string("<c.red>"),     cc_string("</c>") };

webvtt_tag_t  webvtt_tag_color_yellow =
    { cc_string("<c.yellow>"),  cc_string("</c>") };

webvtt_tag_t  webvtt_tag_color_magenta =
    { cc_string("<c.magenta>"), cc_string("</c>") };


cc_str_t  webvtt_setting_align_left = cc_string("align:left");
cc_str_t  webvtt_setting_line       = cc_string("line");
cc_str_t  webvtt_setting_position   = cc_string("position");


static cc_str_t  webvtt_escape_amp  = cc_string("&amp;");
static cc_str_t  webvtt_escape_lt   = cc_string("&lt;");
static cc_str_t  webvtt_escape_gt   = cc_string("&gt;");


void
webvtt_writer_init(webvtt_writer_t *writer, subtitle_handler_t *handler,
    void *data)
{
    writer->handler = *handler;
    writer->data = data;
    writer->tags_pos = 0;
}


void
webvtt_writer_add_percent_setting(webvtt_writer_t *writer, cc_str_t *setting,
    uint32_t value)
{
    u_char    *p;
    uint32_t   frac;
    cc_str_t   str;
    u_char     buf[64];

    if (setting->len + CC_INT32_LEN + sizeof(":.00%") > sizeof(buf)) {
        return;
    }

    frac = value % 100;
    value /= 100;

    p = buf;

    p = cc_copy(p, setting->data, setting->len);
    *p++ = ':';

    p = cc_sprintf(p, "%uD", value);
    if (frac) {
        p = cc_sprintf(p, ".%02uD", frac);
    }

    *p++ = '%';

    str.data = buf;
    str.len = p - buf;

    writer->handler.add_setting(writer->data, &str);
}


void
webvtt_writer_char(webvtt_writer_t *writer, u_char *ch, size_t len)
{
    cc_str_t  *str;

    if (len == 1) {
        switch (*ch) {

        case '&':
            str = &webvtt_escape_amp;
            writer->handler.write(writer->data, str->data, str->len);
            return;

        case '<':
            str = &webvtt_escape_lt;
            writer->handler.write(writer->data, str->data, str->len);
            return;

        case '>':
            str = &webvtt_escape_gt;
            writer->handler.write(writer->data, str->data, str->len);
            return;
        }
    }

    writer->handler.write(writer->data, ch, len);
}


void
webvtt_writer_push_tag(webvtt_writer_t *writer, webvtt_tag_t *tag)
{
    if (writer->tags_pos >= WEBVTT_TAG_STACK_SIZE) {
        return;
    }

    writer->handler.write(writer->data, tag->open.data, tag->open.len);

    writer->tags[writer->tags_pos++] = tag->close;
}


void
webvtt_writer_pop_tags(webvtt_writer_t *writer)
{
    cc_str_t  *str;

    while (writer->tags_pos > 0) {
        writer->tags_pos--;

        str = &writer->tags[writer->tags_pos];
        writer->handler.write(writer->data, str->data, str->len);
    }
}
