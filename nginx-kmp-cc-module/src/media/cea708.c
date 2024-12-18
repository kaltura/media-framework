/*****************************************************************************
 * cea708.c : CEA708 subtitles decoder
 *****************************************************************************
 * Copyright © 2017 VideoLabs, VideoLAN and VLC authors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#include "cea708.h"
#include "webvtt.h"


/*****************************************************************************
 * Demuxing / Agreggation
 *****************************************************************************/

#define CEA708_DTVCC_MAX_PKT_SIZE 128


struct cea708_demux_t
{
    int8_t  i_pkt_sequence;
    uint8_t i_total_data;
    uint8_t i_data;
    uint8_t data[CEA708_DTVCC_MAX_PKT_SIZE];
    vlc_tick_t i_time;
    cc_log_t *log;
    service_data_handler_t handler;
    void *priv;
};


void CEA708_DTVCC_Demuxer_Flush(cea708_demux_t *h)
{
    h->i_pkt_sequence = -1;
    h->i_total_data = h->i_data = 0;
}

void CEA708_DTVCC_Demuxer_Release(cea708_demux_t *h)
{
    free(h);
}

cea708_demux_t *CEA708_DTVCC_Demuxer_New(cc_log_t *log, void *priv, service_data_handler_t handler)
{
    cea708_demux_t *h = malloc(sizeof(cea708_demux_t));
    if (h)
    {
        h->log = log;
        h->priv = priv;
        h->handler = handler;
        CEA708_DTVCC_Demuxer_Flush(h);
    }

    return h;
}

// ccextractor: dtvcc_process_current_packet
static void CEA708_DTVCC_Demux_ServiceBlocks(cea708_demux_t *h, vlc_tick_t i_start,
                                              uint8_t *p_data, size_t i_data)
{
    uint8_t i_sid;
    uint8_t i_block_size;

    while (i_data >= 2)
    {
        i_sid = *p_data >> 5;
        i_block_size = *p_data & 0x1f;

        p_data++;
        i_data--;

        if (i_sid == 0x07)
        {
            i_sid = *p_data & 0x3f;
            if (i_sid < 0x07)
            {
                ngx_log_error(NGX_LOG_WARN, h->log, 0,
                    "CEA708_DTVCC_Demux_ServiceBlocks: "
                    "invalid extended service number %uD", (uint32_t) i_sid);
                return;
            }

            p_data++;
            i_data--;
        }

        if (i_block_size == 0)
        {
            return;
        }

        if (i_block_size > i_data)
        {
            ngx_log_error(NGX_LOG_WARN, h->log, 0,
                "CEA708_DTVCC_Demux_ServiceBlocks: "
                "block size %uD overflows packet data left %uz",
                (uint32_t) i_block_size, i_data);
            return;
        }

        h->handler(h->priv, i_sid, i_start, p_data, i_block_size);

        p_data += i_block_size;
        i_data -= i_block_size;
    }
}

// ccextractor: dtvcc_process_data
void CEA708_DTVCC_Demuxer_Push(cea708_demux_t *h, vlc_tick_t i_start, uint8_t data[3])
{
    int8_t i_pkt_sequence;
    uint8_t packet_size;

    if ((data[0] & 0x03) == 3) /* Header packet */
    {
        i_pkt_sequence = data[1] >> 6;

        /* pkt loss/discontinuity, trash buffer */
        if (h->i_pkt_sequence > 0 && ((h->i_pkt_sequence + 1) % 4) != i_pkt_sequence)
        {
            ngx_log_error(NGX_LOG_WARN, h->log, 0,
                "CEA708_DTVCC_Demuxer_Push: invalid sequence %uD, prev: %uD",
                (uint32_t) i_pkt_sequence, (uint32_t) h->i_pkt_sequence);

            h->i_total_data = h->i_data = 0;
            h->i_pkt_sequence = i_pkt_sequence;
            return;
        }

        packet_size = data[1] & 0x3f;
        if (packet_size == 0)
            packet_size = 127;
        else
            packet_size = packet_size * 2 - 1;

        h->i_pkt_sequence = i_pkt_sequence;
        h->i_total_data = packet_size;
        h->i_data = 0;
        h->i_time = i_start;
        h->data[h->i_data++] = data[2];
    }
    else if (h->i_total_data > 0)
    {
        h->data[h->i_data++] = data[1];
        h->data[h->i_data++] = data[2];
    }
    else
    {
        /* Not synced to pkt header yet */
        return;
    }

    if (h->i_data >= h->i_total_data)
    {
        /* pkts assembly finished, we have a service block */
        CEA708_DTVCC_Demux_ServiceBlocks(h, h->i_time, h->data, h->i_data);
        h->i_total_data = h->i_data = 0;
    }
}


/*****************************************************************************
 * Input buffer
 *****************************************************************************/

#define CEA708_SERVICE_INPUT_BUFFER    128


typedef struct
{
    uint8_t ringbuffer[CEA708_SERVICE_INPUT_BUFFER];
    uint8_t start;
    uint8_t capacity;
} cea708_input_buffer_t;


static void cea708_input_buffer_init(cea708_input_buffer_t *ib)
{
    ib->capacity = 0;
    ib->start = 0;
}

static uint8_t cea708_input_buffer_size(const cea708_input_buffer_t *ib)
{
    return ib->capacity;
}

static uint8_t cea708_input_buffer_remain(const cea708_input_buffer_t *ib)
{
    return CEA708_SERVICE_INPUT_BUFFER - ib->capacity;
}

static void cea708_input_buffer_add(cea708_input_buffer_t *ib, uint8_t a)
{
    if (cea708_input_buffer_remain(ib) > 0)
        ib->ringbuffer[(ib->start + ib->capacity++) % CEA708_SERVICE_INPUT_BUFFER] = a;
}

static uint8_t cea708_input_buffer_peek(cea708_input_buffer_t *ib, uint8_t off)
{
    if (off >= ib->capacity)
        return 0;

    off = (ib->start + off) % CEA708_SERVICE_INPUT_BUFFER;
    return ib->ringbuffer[off];
}

static uint8_t cea708_input_buffer_get(cea708_input_buffer_t *ib)
{
    uint8_t a = cea708_input_buffer_peek(ib, 0);
    ib->start = (ib->start + 1) % CEA708_SERVICE_INPUT_BUFFER;
    ib->capacity--;
    return a;
}


/*****************************************************************************
* Window
*****************************************************************************/

#define CEA708_PREDEFINED_STYLES        7

#define CEA708_WINDOW_MAX_COLS          42
#define CEA708_WINDOW_MAX_ROWS          15


typedef enum
{
    CEA708_OPACITY_SOLID = 0,
    CEA708_OPACITY_FLASH,
    CEA708_OPACITY_TRANSLUCENT,
    CEA708_OPACITY_TRANSPARENT,
} cea708_opacity_e;

typedef enum
{
    CEA708_EDGE_NONE = 0,
    CEA708_EDGE_RAISED,
    CEA708_EDGE_DEPRESSED,
    CEA708_EDGE_UNIFORM,
    CEA708_EDGE_LEFT_DROP_SHADOW,
    CEA708_EDGE_RIGHT_DROP_SHADOW,
} cea708_edge_e;

typedef enum
{
    CEA708_PEN_SIZE_SMALL = 0,
    CEA708_PEN_SIZE_STANDARD,
    CEA708_PEN_SIZE_LARGE,
} cea708_pen_size_e;

typedef enum
{
    CEA708_FONT_UNDEFINED = 0,
    CEA708_FONT_MONOSPACED,
    CEA708_FONT_PROP,
    CEA708_FONT_MONO_SANS_SERIF,
    CEA708_FONT_PROP_SANS_SERIF,
    CEA708_FONT_CASUAL,
    CEA708_FONT_CURSIVE,
    CEA708_FONT_SMALL_CAPS,
} cea708_font_e;

typedef enum
{
    CEA708_TAG_DIALOG = 0,
    CEA708_TAG_SPEAKER,
    CEA708_TAG_SYNTHETIC_VOICE,
    CEA708_TAG_DIALOG_SECONDARY_LANG,
    CEA708_TAG_VOICEOVER,
    CEA708_TAG_AUDIBLE_TRANSLATION,
    CEA708_TAG_SUBTITLE_TRANSLATION,
    CEA708_TAG_VOICE_QUALITY_DESCRIPTION,
    CEA708_TAG_SONG_LYRICS,
    CEA708_TAG_FX_DESCRIPTION,
    CEA708_TAG_SCORE_DESCRIPTION,
    CEA708_TAG_EXPLETIVE,
    CEA708_TAG_NOT_TO_BE_DISPLAYED = 15,
} cea708_tag_e;

typedef enum
{
    CEA708_PEN_OFFSET_SUBSCRIPT = 0,
    CEA708_PEN_OFFSET_NORMAL,
    CEA708_PEN_OFFSET_SUPERSCRIPT,
} cea708_pen_offset_e;

typedef enum
{
    CEA708_WA_JUSTIFY_LEFT = 0,
    CEA708_WA_JUSTIFY_RIGHT,
    CEA708_WA_JUSTIFY_CENTER,
    CEA708_WA_JUSTIFY_FULL,
} cea708_wa_justify_e;

typedef enum
{
    CEA708_WA_DIRECTION_LTR = 0,
    CEA708_WA_DIRECTION_RTL,
    CEA708_WA_DIRECTION_TB,
    CEA708_WA_DIRECTION_BT,
} cea708_wa_direction_e;

typedef enum
{
    CEA708_WA_EFFECT_SNAP = 0,
    CEA708_WA_EFFECT_FADE,
    CEA708_WA_EFFECT_WIPE,
} cea708_wa_effect_e;

typedef enum
{
    CEA708_ANCHOR_TOP_LEFT = 0,
    CEA708_ANCHOR_TOP_CENTER,
    CEA708_ANCHOR_TOP_RIGHT,
    CEA708_ANCHOR_CENTER_LEFT,
    CEA708_ANCHOR_CENTER_CENTER,
    CEA708_ANCHOR_CENTER_RIGHT,
    CEA708_ANCHOR_BOTTOM_LEFT,
    CEA708_ANCHOR_BOTTOM_CENTER,
    CEA708_ANCHOR_BOTTOM_RIGHT,
} cea708_window_anchor_e;


typedef struct
{
    cea708_pen_size_e size;
    cea708_font_e font;
    cea708_tag_e text_tag;
    cea708_pen_offset_e offset;

    uint8_t b_italics;
    uint8_t b_underline;

    struct
    {
        uint8_t color;
        cea708_opacity_e opacity;
    } foreground, background;

    uint8_t edge_color;
    cea708_edge_e edge_type;
} cea708_pen_style_t;

typedef struct
{
    cea708_wa_justify_e justify;

    cea708_wa_direction_e print_direction;
    cea708_wa_direction_e scroll_direction;
    cea708_wa_direction_e effect_direction;

    uint8_t b_word_wrap;

    cea708_wa_effect_e display_effect;

    uint8_t effect_speed;
    uint8_t fill_color;
    cea708_opacity_e fill_opacity;
    cea708_edge_e border_type;
    uint8_t border_color;
} cea708_window_style_t;

typedef uint8_t cea708_text_char_t[4];

typedef struct
{
    cea708_text_char_t characters[CEA708_WINDOW_MAX_COLS];
    cea708_pen_style_t styles[CEA708_WINDOW_MAX_COLS];
    uint8_t firstcol;
    uint8_t lastcol;
} cea708_text_row_t;

typedef struct
{
    cea708_text_row_t *rows[CEA708_WINDOW_MAX_ROWS];

    cea708_window_anchor_e anchor_point;

    cea708_window_style_t style;
    cea708_pen_style_t    pen;

    uint8_t i_firstrow;
    uint8_t i_lastrow;

    uint8_t i_priority;

    uint8_t i_anchor_offset_v;
    uint8_t i_anchor_offset_h;

    /* Extras row for window scroll */
    uint8_t i_row_count;
    uint8_t i_col_count;

    /* flags */
    uint8_t b_defined;
    uint8_t b_relative;
    uint8_t b_row_lock;
    uint8_t b_column_lock;
    uint8_t b_visible;

    uint8_t row;
    uint8_t col;
} cea708_window_t;


#define DEFAULT_NTSC_STYLE(font, edge, bgopacity)                           \
    {                                                                        \
        CEA708_PEN_SIZE_STANDARD,                                            \
        font,                                                                \
        CEA708_TAG_DIALOG,                                                   \
        CEA708_PEN_OFFSET_NORMAL,                                            \
        false,                                                               \
        false,                                                               \
        { 0x2a,   CEA708_OPACITY_SOLID, },                                   \
        { 0x00,   bgopacity,            },                                   \
        0x00,                                                                \
        edge,                                                                \
    }

static const cea708_pen_style_t cea708_default_pen_styles[CEA708_PREDEFINED_STYLES] =
{
    DEFAULT_NTSC_STYLE(CEA708_FONT_UNDEFINED,       CEA708_EDGE_NONE,    CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_STYLE(CEA708_FONT_MONOSPACED,      CEA708_EDGE_NONE,    CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_STYLE(CEA708_FONT_PROP,            CEA708_EDGE_NONE,    CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_STYLE(CEA708_FONT_MONO_SANS_SERIF, CEA708_EDGE_NONE,    CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_STYLE(CEA708_FONT_PROP_SANS_SERIF, CEA708_EDGE_NONE,    CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_STYLE(CEA708_FONT_MONO_SANS_SERIF, CEA708_EDGE_UNIFORM, CEA708_OPACITY_TRANSPARENT),
    DEFAULT_NTSC_STYLE(CEA708_FONT_PROP_SANS_SERIF, CEA708_EDGE_UNIFORM, CEA708_OPACITY_TRANSPARENT),
};

#undef DEFAULT_NTSC_STYLE


#define DEFAULT_NTSC_WA_STYLE(just, pd, scroll, wrap, opacity)               \
    {                                                                        \
        just,                                                                \
        pd,                                                                  \
        scroll,                                                              \
        CEA708_WA_DIRECTION_LTR,                                             \
        wrap,                                                                \
        CEA708_WA_EFFECT_SNAP,                                               \
        1,                                                                   \
        0x00,                                                                \
        opacity,                                                             \
        CEA708_EDGE_NONE,                                                    \
        0x00,                                                                \
    }

static const cea708_window_style_t cea708_default_window_styles[CEA708_PREDEFINED_STYLES] =
{
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_LEFT,   CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   false, CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_LEFT,   CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   false, CEA708_OPACITY_TRANSPARENT),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_CENTER, CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   false, CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_LEFT,   CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   true,  CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_LEFT,   CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   true,  CEA708_OPACITY_TRANSPARENT),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_CENTER, CEA708_WA_DIRECTION_LTR,
                          CEA708_WA_DIRECTION_BT,   true, CEA708_OPACITY_SOLID),
    DEFAULT_NTSC_WA_STYLE(CEA708_WA_JUSTIFY_LEFT,   CEA708_WA_DIRECTION_TB,
                          CEA708_WA_DIRECTION_RTL,  false, CEA708_OPACITY_SOLID),
};

#undef DEFAULT_NTSC_WA_STYLE


static void cea708_text_row_Delete(cea708_text_row_t *p_row)
{
    free(p_row);
}

static cea708_text_row_t *cea708_text_row_New(void)
{
    cea708_text_row_t *p_row = malloc(sizeof(*p_row));
    if (p_row)
    {
        p_row->firstcol = CEA708_WINDOW_MAX_COLS;
        p_row->lastcol = 0;
        memset(p_row->characters, 0, sizeof(p_row->characters));
    }

    return p_row;
}


static void CEA708_Window_Init(cea708_window_t *p_w)
{
    memset(p_w, 0, sizeof(*p_w));
    p_w->style = cea708_default_window_styles[0];
    p_w->pen = cea708_default_pen_styles[0];
    p_w->i_firstrow = CEA708_WINDOW_MAX_ROWS;
    p_w->b_row_lock = true;
    p_w->b_column_lock = true;
}

static void CEA708_Window_ClearText(cea708_window_t *p_w)
{
    uint8_t i;

    for (i=p_w->i_firstrow; i<=p_w->i_lastrow; i++)
    {
        cea708_text_row_Delete(p_w->rows[i]);
        p_w->rows[i] = NULL;
    }

    p_w->i_lastrow = 0;
    p_w->i_firstrow = CEA708_WINDOW_MAX_ROWS;
}

static void CEA708_Window_Reset(cea708_window_t *p_w)
{
    CEA708_Window_ClearText(p_w);
    CEA708_Window_Init(p_w);
}

static void CEA708_Window_UpdateFirstLastRow(cea708_window_t *p_w)
{
    while (p_w->i_firstrow < CEA708_WINDOW_MAX_ROWS && !p_w->rows[p_w->i_firstrow])
        p_w->i_firstrow++;

    while (p_w->i_lastrow > 0 && !p_w->rows[p_w->i_lastrow])
        p_w->i_lastrow--;
}

static void CEA708_Window_ScrollRight(cea708_window_t *p_w)
{
    cea708_text_row_t *row;
    int i;

    for (i=p_w->i_firstrow; i <= p_w->i_lastrow; i++)
    {
        row = p_w->rows[i];
        if (!row)
            continue;

        if (row->lastcol > CEA708_WINDOW_MAX_COLS - 2)
        {
            row->lastcol = CEA708_WINDOW_MAX_COLS - 2;
        }

        if (row->lastcol < row->firstcol)
        {
            cea708_text_row_Delete(row);
            p_w->rows[i] = NULL;

            CEA708_Window_UpdateFirstLastRow(p_w);
            continue;
        }

        memmove(&row->characters[row->firstcol + 1], &row->characters[row->firstcol],
            (row->lastcol - row->firstcol + 1) * sizeof(cea708_text_char_t));
        memmove(&row->styles[row->firstcol + 1], &row->styles[row->firstcol],
            (row->lastcol - row->firstcol + 1) * sizeof(cea708_pen_style_t));

        row->firstcol++;
        row->lastcol++;
    }
}

static void CEA708_Window_ScrollLeft(cea708_window_t *p_w)
{
    cea708_text_row_t *row;
    int i;

    for (i=p_w->i_firstrow; i <= p_w->i_lastrow; i++)
    {
        row = p_w->rows[i];
        if (!row)
            continue;

        if (row->firstcol < 1)
        {
            row->firstcol = 1;
        }

        if (row->lastcol < row->firstcol)
        {
            cea708_text_row_Delete(row);
            p_w->rows[i] = NULL;

            CEA708_Window_UpdateFirstLastRow(p_w);
            continue;
        }

        memmove(&row->characters[row->firstcol - 1], &row->characters[row->firstcol],
            (row->lastcol - row->firstcol + 1) * sizeof(cea708_text_char_t));
        memmove(&row->styles[row->firstcol - 1], &row->styles[row->firstcol],
            (row->lastcol - row->firstcol + 1) * sizeof(cea708_pen_style_t));

        row->firstcol--;
        row->lastcol--;
    }
}

static void CEA708_Window_ScrollDown(cea708_window_t *p_w)
{
    if (p_w->i_lastrow > CEA708_WINDOW_MAX_ROWS - 2)
    {
        p_w->i_lastrow = CEA708_WINDOW_MAX_ROWS - 2;

        cea708_text_row_Delete(p_w->rows[CEA708_WINDOW_MAX_ROWS - 1]);
        p_w->rows[CEA708_WINDOW_MAX_ROWS - 1] = NULL;

        CEA708_Window_UpdateFirstLastRow(p_w);
    }

    if (p_w->i_lastrow < p_w->i_firstrow)
    {
        return;
    }

    memmove(&p_w->rows[p_w->i_firstrow + 1], &p_w->rows[p_w->i_firstrow],
        (p_w->i_lastrow - p_w->i_firstrow + 1) * sizeof(p_w->rows[0]));
    p_w->rows[p_w->i_firstrow] = NULL;

    p_w->i_firstrow++;
    p_w->i_lastrow++;
}

static void CEA708_Window_ScrollUp(cea708_window_t *p_w)
{
    if (p_w->i_firstrow < 1)
    {
        p_w->i_firstrow = 1;

        cea708_text_row_Delete(p_w->rows[0]);
        p_w->rows[0] = NULL;

        CEA708_Window_UpdateFirstLastRow(p_w);
    }

    if (p_w->i_lastrow < p_w->i_firstrow)
    {
        return;
    }

    memmove(&p_w->rows[p_w->i_firstrow - 1], &p_w->rows[p_w->i_firstrow],
        (p_w->i_lastrow - p_w->i_firstrow + 1) * sizeof(p_w->rows[0]));
    p_w->rows[p_w->i_lastrow] = NULL;

    p_w->i_firstrow--;
    p_w->i_lastrow--;
}

static void CEA708_Window_Scroll(cea708_window_t *p_w)
{
    if (p_w->i_lastrow < p_w->i_firstrow)
        return;

    switch (p_w->style.scroll_direction)
    {
        case CEA708_WA_DIRECTION_LTR:
            CEA708_Window_ScrollRight(p_w);
            break;

        case CEA708_WA_DIRECTION_RTL:
            CEA708_Window_ScrollLeft(p_w);
            break;

        case CEA708_WA_DIRECTION_TB:
            CEA708_Window_ScrollDown(p_w);
            break;

        case CEA708_WA_DIRECTION_BT:
            CEA708_Window_ScrollUp(p_w);
            break;
    }
}

static void CEA708_Window_CarriageReturn(cea708_window_t *p_w)
{
    switch (p_w->style.scroll_direction)
    {
        case CEA708_WA_DIRECTION_LTR:
            if (p_w->col > 0)
                p_w->col--;
            else
                CEA708_Window_Scroll(p_w);

            p_w->row = (p_w->style.print_direction == CEA708_WA_DIRECTION_TB) ?
                       0 : p_w->i_row_count - 1;
            break;

        case CEA708_WA_DIRECTION_RTL:
            if (p_w->col < p_w->i_col_count - 1)
                p_w->col++;
            else
                CEA708_Window_Scroll(p_w);

            p_w->row = (p_w->style.print_direction == CEA708_WA_DIRECTION_TB) ?
                       0 : p_w->i_row_count - 1;
            break;

        case CEA708_WA_DIRECTION_TB:
            if (p_w->row > 0)
                p_w->row--;
            else
                CEA708_Window_Scroll(p_w);

            p_w->col = (p_w->style.print_direction == CEA708_WA_DIRECTION_LTR) ?
                       0 : p_w->i_col_count - 1;
            break;

        case CEA708_WA_DIRECTION_BT:
            if (p_w->row < p_w->i_row_count - 1)
                p_w->row++;
            else
                CEA708_Window_Scroll(p_w);

            p_w->col = (p_w->style.print_direction == CEA708_WA_DIRECTION_LTR) ?
                       0 : p_w->i_col_count - 1;
            break;
    }
}

static void CEA708_Window_Forward(cea708_window_t *p_w)
{
    switch (p_w->style.print_direction)
    {
        case CEA708_WA_DIRECTION_LTR:
            if (p_w->col < p_w->i_col_count - 1)
                p_w->col++;
            else
                CEA708_Window_CarriageReturn(p_w);
            break;

        case CEA708_WA_DIRECTION_RTL:
            if (p_w->col > 0)
                p_w->col--;
            else
                CEA708_Window_CarriageReturn(p_w);
            break;

        case CEA708_WA_DIRECTION_TB:
            if (p_w->row < p_w->i_row_count - 1)
                p_w->row++;
            else
                CEA708_Window_CarriageReturn(p_w);
            break;

        case CEA708_WA_DIRECTION_BT:
            if (p_w->row > 0)
                p_w->row--;
            else
                CEA708_Window_CarriageReturn(p_w);
            break;
    }
}

static void CEA708_Window_Backward(cea708_window_t *p_w)
{
    static const int reverse[] =
    {
        [CEA708_WA_DIRECTION_LTR] = CEA708_WA_DIRECTION_RTL,
        [CEA708_WA_DIRECTION_RTL] = CEA708_WA_DIRECTION_LTR,
        [CEA708_WA_DIRECTION_TB]  = CEA708_WA_DIRECTION_BT,
        [CEA708_WA_DIRECTION_BT]  = CEA708_WA_DIRECTION_TB,
    };
    int save;

    save = p_w->style.print_direction;
    p_w->style.print_direction = reverse[p_w->style.print_direction];

    CEA708_Window_Forward(p_w);

    p_w->style.print_direction = save;
}

static void CEA708_Window_Write(cea708_window_t *p_w, cea708_text_char_t c)
{
    if (!p_w->b_defined)
        return;

    if (p_w->row >= CEA708_WINDOW_MAX_ROWS || p_w->col >= CEA708_WINDOW_MAX_COLS)
    {
        cc_debug_point();
        return;
    }

    cea708_text_row_t *p_row = p_w->rows[p_w->row];

    if (!p_row)
    {
        p_row = cea708_text_row_New();
        if (!p_row)
            return;

        p_w->rows[p_w->row] = p_row;

        if (p_w->i_firstrow > p_w->row)
            p_w->i_firstrow = p_w->row;
        if (p_w->i_lastrow < p_w->row)
            p_w->i_lastrow = p_w->row;
    }

    memcpy(&p_row->characters[p_w->col], c, sizeof(cea708_text_char_t));
    p_row->styles[p_w->col] = p_w->pen;

    if (p_row->firstcol > p_w->col)
        p_row->firstcol = p_w->col;
    if (p_row->lastcol < p_w->col)
        p_row->lastcol = p_w->col;

    CEA708_Window_Forward(p_w);
}


/*****************************************************************************
* Service Data Decoding
*****************************************************************************/

#define CEA708_WINDOWS_COUNT            8

#define POP_COMMAND() (void) cea708_input_buffer_get(ib)
#define POP_ARGS(n) { size_t pops; for (pops=0; pops<(size_t)n;pops++) POP_COMMAND(); }
#define REQUIRE_ARGS(n) if (cea708_input_buffer_size(ib) < n + 1)           \
                            return CEA708_STATUS_STARVING
#define REQUIRE_ARGS_AND_POP_COMMAND(n) REQUIRE_ARGS(n); else POP_COMMAND()

#define cea708_log_command0(h, cmd)                                         \
    cc_log_debug2((h)->log, "CEA708-%uD: [%s]",                             \
        (h)->id,                                                            \
        (cmd))

#define cea708_log_command1(h, cmd)                                         \
    cc_log_debug3((h)->log, "CEA708-%uD: [%s 0x%02uxD]",                    \
        (h)->id,                                                            \
        (cmd),                                                              \
        (uint32_t) cea708_input_buffer_peek(ib, 0))

#define cea708_log_command2(h, cmd)                                         \
    cc_log_debug4((h)->log, "CEA708-%uD: [%s 0x%02uxD 0x%02uxD]",           \
        (h)->id,                                                            \
        (cmd),                                                              \
        (uint32_t) cea708_input_buffer_peek(ib, 0),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 1))

#define cea708_log_command3(h, cmd)                                         \
    cc_log_debug5((h)->log, "CEA708-%uD: [%s 0x%02uxD 0x%02uxD 0x%02uxD]",  \
        (h)->id,                                                            \
        (cmd),                                                              \
        (uint32_t) cea708_input_buffer_peek(ib, 0),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 1),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 2))

#define cea708_log_command4(h, cmd)                                         \
    cc_log_debug6((h)->log, "CEA708-%uD: "                                  \
        "[%s 0x%02uxD 0x%02uxD 0x%02uxD 0x%02uxD]",                         \
        (h)->id,                                                            \
        (cmd),                                                              \
        (uint32_t) cea708_input_buffer_peek(ib, 0),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 1),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 2),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 3))

#define cea708_log_command6(h, cmd)                                         \
    cc_log_debug8((h)->log, "CEA708-%uD: "                                  \
        "[%s 0x%02uxD 0x%02uxD 0x%02uxD 0x%02uxD 0x%02uxD 0x%02uxD]",       \
        (h)->id,                                                            \
        (cmd),                                                              \
        (uint32_t) cea708_input_buffer_peek(ib, 0),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 1),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 2),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 3),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 4),                         \
        (uint32_t) cea708_input_buffer_peek(ib, 5))


enum
{
    CEA708_STATUS_OK       = 1 << 0,
    CEA708_STATUS_STARVING = 1 << 1,
};

enum
{
    CEA708_C0_NUL   = 0x00,
    CEA708_C0_ETX   = 0x03,
    CEA708_C0_BS    = 0x08,
    CEA708_C0_FF    = 0x0c,
    CEA708_C0_CR    = 0x0d,
    CEA708_C0_HCR   = 0x0e,
    CEA708_C0_EXT1  = 0x10,
    CEA708_C0_P16   = 0x18,
};

enum
{
    CEA708_C1_CW0   = 0x80,
    CEA708_C1_CW7   = 0x87,
    CEA708_C1_CLW,
    CEA708_C1_DSW,
    CEA708_C1_HDW,
    CEA708_C1_TGW,
    CEA708_C1_DLW,
    CEA708_C1_DLY,
    CEA708_C1_DLC,
    CEA708_C1_RST,
    CEA708_C1_SPA   = 0x90,
    CEA708_C1_SPC,
    CEA708_C1_SPL,
    CEA708_C1_SWA   = 0x97,
    CEA708_C1_DF0,
    CEA708_C1_DF7   = 0x9f,
};


struct cea708_t
{
    cc_log_t *log;
    uint32_t id;

    subtitle_handler_t handler;
    void *priv;

    webvtt_writer_t webvtt;

    /* Defaults */
    cea708_window_t window[CEA708_WINDOWS_COUNT];
    cea708_input_buffer_t input_buffer;

    /* Decoding context */
    cea708_window_t *p_cw; /* current window */
    vlc_tick_t suspended_deadline;  /* VLC_TICK_INVALID when delay is inactive */
    vlc_tick_t i_start;
    vlc_tick_t i_clock;
};


static const struct {
    uint8_t in;
    cea708_text_char_t out;
} cea708_g2g3_table[] = {
    /* G2 */
    { 0x20,  { 0x20,    0,    0, 0 } },  // Transparent space [*** will need special handling]
    { 0x21,  { 0x20,    0,    0, 0 } },  // Non breaking transparent space [*** will need special handling]
    { 0x25,  { 0xe2, 0x80, 0xa6, 0 } },  // Horizontal ellipsis
    { 0x2a,  { 0xc5, 0xa0,    0, 0 } },  // Latin capital letter S with caron
    { 0x2c,  { 0xc5, 0x92,    0, 0 } },  // Latin capital ligature OE
    { 0x30,  { 0xe2, 0x96, 0x88, 0 } },  // Full block
    { 0x31,  { 0xe2, 0x80, 0x98, 0 } },  // Left single quotation mark
    { 0x32,  { 0xe2, 0x80, 0x99, 0 } },  // Right single quotation mark
    { 0x33,  { 0xe2, 0x80, 0x9c, 0 } },  // Left double quotation mark
    { 0x34,  { 0xe2, 0x80, 0x9d, 0 } },  // Right double quotation mark
    { 0x35,  { 0xe2, 0x80, 0xa2, 0 } },  // Bullet
    { 0x39,  { 0xe2, 0x84, 0xa2, 0 } },  // Trademark symbol (TM)
    { 0x3a,  { 0xc5, 0xa1,    0, 0 } },  // Latin small letter s with caron
    { 0x3c,  { 0xc5, 0x93,    0, 0 } },  // Latin small ligature oe
    { 0x3d,  { 0xe2, 0x84, 0xa0, 0 } },  // Service mark
    { 0x3f,  { 0xc5, 0xb8,    0, 0 } },  // Latin capital letter Y with diaeresis
    { 0x76,  { 0xe2, 0x85, 0x9b, 0 } },  // Vulgar fraction one eighth
    { 0x77,  { 0xe2, 0x85, 0x9c, 0 } },  // Vulgar fraction three eighths
    { 0x78,  { 0xe2, 0x85, 0x9d, 0 } },  // Vulgar fraction five eighths
    { 0x79,  { 0xe2, 0x85, 0x9e, 0 } },  // Vulgar fraction seven eighths
    { 0x7a,  { 0xe2, 0x94, 0x82, 0 } },  // Box drawings light vertical
    { 0x7b,  { 0xe2, 0x94, 0x90, 0 } },  // Box drawings light down and left
    { 0x7c,  { 0xe2, 0x94, 0x94, 0 } },  // Box drawings light up and right
    { 0x7d,  { 0xe2, 0x94, 0x80, 0 } },  // Box drawings light horizontal
    { 0x7e,  { 0xe2, 0x94, 0x98, 0 } },  // Box drawings light up and left
    { 0x7f,  { 0xe2, 0x94, 0x8c, 0 } },  // Box drawings light down and right

    /* G3 */
    { 0xa0,  { 0xf0,0x9f,0x85,0xb2 } },  // CC (replaced with negative squared latin capital letter C)
};


static void CEA708_Decoder_Init(cea708_t *h)
{
    size_t i;

    cea708_input_buffer_init(&h->input_buffer);

    for (i=0; i<CEA708_WINDOWS_COUNT; i++)
        CEA708_Window_Init(&h->window[i]);

    h->p_cw = &h->window[0];
    h->suspended_deadline = VLC_TICK_INVALID;
    h->i_start = VLC_TICK_INVALID;
    h->i_clock = 0;
}

static void CEA708_Decoder_Reset(cea708_t *h)
{
    size_t i;

    for (i=0; i<CEA708_WINDOWS_COUNT; i++)
        CEA708_Window_Reset(&h->window[i]);

    CEA708_Decoder_Init(h);
}

void CEA708_Decoder_Flush(cea708_t *h)
{
    CEA708_Decoder_Reset(h);
}

void CEA708_Decoder_Release(cea708_t *h)
{
    CEA708_Decoder_Reset(h);
    free(h);
}

cea708_t *CEA708_Decoder_New(cc_log_t *log, uint32_t id, void *priv, subtitle_handler_t *handler)
{
    cea708_t *h = malloc(sizeof(cea708_t));
    if (!h)
    {
        return NULL;
    }

    CEA708_Decoder_Init(h);

    h->log = log;
    h->id = id;

    h->handler = *handler;
    h->priv = priv;

    webvtt_writer_init(&h->webvtt, handler, priv);

    return h;
}


static void CEA708_Output_Row(cea708_t *h, const cea708_text_row_t *p_row, bool *wrote)
{
    const cea708_pen_style_t *style;
    const cea708_text_char_t *ch;
    size_t len;
    int i_style;
    int i_last_style;
    int i_start;
    int i_end;
    int i;

    i_start = p_row->firstcol;
    i_end = p_row->lastcol;

    /* Search the start */
    while (i_start <= i_end && p_row->characters[i_start][0] == '\0')
        i_start++;

    /* Search the end */
    while (i_start <= i_end && p_row->characters[i_end][0] == '\0')
        i_end--;

    /* */
    if (i_start > i_end) /* Nothing to render */
        return;

    if (*wrote)
    {
        h->handler.write(h->priv, "\n", 1);
    }
    else
    {
        *wrote = true;
    }

    i_last_style = 0;
    ch = &p_row->characters[i_start];

    for (i=i_start; i<=i_end; i++, ch++)
    {
        if (*ch[0] == '\0')
        {
            h->handler.write(h->priv, " ", 1);
            continue;
        }

        style = &p_row->styles[i];

        i_style = 0;
        if (style->b_italics)
        {
            i_style |= 0x01;
        }
        if (style->b_underline)
        {
            i_style |= 0x02;
        }

        if (i_style != i_last_style)
        {
            webvtt_writer_pop_tags(&h->webvtt);

            if (style->b_italics)
            {
                webvtt_writer_push_tag(&h->webvtt, &webvtt_tag_italics);
            }

            if (style->b_underline)
            {
                webvtt_writer_push_tag(&h->webvtt, &webvtt_tag_underline);
            }

            i_last_style = i_style;
        }

        len = strnlen((char *) *ch, sizeof(cea708_text_char_t));
        webvtt_writer_char(&h->webvtt, (u_char *) *ch, len);
    }

    webvtt_writer_pop_tags(&h->webvtt);
}


static void CEA708_Output_Window(cea708_t *h, const cea708_window_t *p_w, bool *wrote)
{
    int first, last;
    uint8_t i;

    if (p_w->style.scroll_direction == CEA708_WA_DIRECTION_BT)
    {
        /* BT is a bit of a special case since we need to grab the last N
        rows between first and last, rather than the first... */
        last = p_w->i_lastrow;
        if (last >= p_w->i_firstrow + p_w->i_row_count)
            first = last - p_w->i_row_count + 1;
        else
            first = p_w->i_firstrow;
    }
    else
    {
        first = p_w->i_firstrow;
        if (first + p_w->i_row_count <= p_w->i_lastrow)
            last = first + p_w->i_row_count - 1;
        else
            last = p_w->i_lastrow;
    }

    for (i=first; i<=last; i++)
    {
        if (!p_w->rows[i])
            continue;

        CEA708_Output_Row(h, p_w->rows[i], wrote);
    }
}

static void CEA708_Output(cea708_t *h)
{
    cea708_window_t *p_w;
    size_t i;
    bool wrote;

    cc_log_debug2(h->log, "CEA708-%uD: Output, clock: %L", h->id, h->i_clock);

    if (h->i_start >= h->i_clock)
    {
        return;
    }

    wrote = false;

    h->handler.start(h->priv);

    for (i=0; i<CEA708_WINDOWS_COUNT; i++)
    {
        p_w = &h->window[i];
        if (p_w->b_defined && p_w->b_visible && p_w->i_lastrow >= p_w->i_firstrow)
        {
            CEA708_Output_Window(h, p_w, &wrote);
        }
    }

    h->handler.end(h->priv, h->i_start, h->i_clock);
}

static bool CEA708_Output_Empty(cea708_t *h)
{
    cea708_window_t *p_w;
    size_t i;

    for (i=0; i<CEA708_WINDOWS_COUNT; i++)
    {
        p_w = &h->window[i];
        if (p_w->b_defined && p_w->b_visible && p_w->i_lastrow >= p_w->i_firstrow)
        {
            return false;
        }
    }

    return true;
}


static int CEA708_Decode_G0(cea708_t *h, uint8_t code)
{
    cea708_input_buffer_t *ib = &h->input_buffer;

    POP_COMMAND();
    cc_log_debug2(h->log, "CEA708-%uD: [G0 0x%02uxD]", h->id, (uint32_t) code);

    if (!h->p_cw->b_defined)
        return CEA708_STATUS_OK;

    cea708_text_char_t out = { code, 0x00, 0x00, 0x00 };

    if (code == 0x7f) // Music note
    {
        out[0] = 0xe2;
        out[1] = 0x99;
        out[2] = 0xaa;
    }

    CEA708_Window_Write(h->p_cw, out);

    if (h->i_start == VLC_TICK_INVALID && h->p_cw->b_visible)
    {
        h->i_start = h->i_clock;
    }

    return CEA708_STATUS_OK;
}

static int CEA708_Decode_G1(cea708_t *h, uint8_t code)
{
    cea708_input_buffer_t *ib = &h->input_buffer;

    POP_COMMAND();
    cc_log_debug2(h->log, "CEA708-%uD: [G1 0x%02uxD]", h->id, (uint32_t) code);

    if (!h->p_cw->b_defined)
        return CEA708_STATUS_OK;

    cea708_text_char_t out = {
        0xc0 | (code & 0xc0) >> 6,
        0x80 | (code & 0x3f),
        0,
        0
    };

    CEA708_Window_Write(h->p_cw, out);

    if (h->i_start == VLC_TICK_INVALID && h->p_cw->b_visible)
    {
        h->i_start = h->i_clock;
    }

    return CEA708_STATUS_OK;
}

static int CEA708_Decode_G2G3(cea708_t *h, uint8_t code)
{
    cc_log_debug2(h->log, "CEA708-%uD: [G2G3 0x%02uxD]", h->id, (uint32_t) code);

    if (!h->p_cw->b_defined)
        return CEA708_STATUS_OK;

    cea708_text_char_t out = { '?', 0, 0, 0 };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(cea708_g2g3_table) ; i++)
    {
        if (cea708_g2g3_table[i].in == code)
        {
            memcpy(out, cea708_g2g3_table[i].out, sizeof(cea708_text_char_t));
            break;
        }
    }

    CEA708_Window_Write(h->p_cw, out);

    if (h->i_start == VLC_TICK_INVALID && h->p_cw->b_visible)
    {
        h->i_start = h->i_clock;
    }

    return CEA708_STATUS_OK;
}

static int CEA708_Decode_P16(cea708_t *h, uint16_t ucs2)
{
    cc_log_debug2(h->log, "CEA708-%uD: [P16 0x%04uxD]", h->id, (uint32_t) ucs2);

    if (!h->p_cw->b_defined)
        return CEA708_STATUS_OK;

    cea708_text_char_t out = { '?', 0, 0, 0 };

    /* adapted from codepoint conversion from strings.h */
    if (ucs2 <= 0x7f)
    {
        out[0] = ucs2;
    }
    else if (ucs2 <= 0x7ff)
    {
        out[0] = 0xc0 |  (ucs2 >>  6);
        out[1] = 0x80 |  (ucs2        & 0x3f);
    }
    else
    {
        out[0] = 0xe0 |  (ucs2 >> 12);
        out[1] = 0x80 | ((ucs2 >>  6) & 0x3f);
        out[2] = 0x80 |  (ucs2        & 0x3f);
    }

    CEA708_Window_Write(h->p_cw, out);

    if (h->i_start == VLC_TICK_INVALID && h->p_cw->b_visible)
    {
        h->i_start = h->i_clock;
    }

    return CEA708_STATUS_OK;
}

static int CEA708_Decode_EXT1(cea708_t *h)
{
    cea708_input_buffer_t *ib = &h->input_buffer;
    uint8_t v, i;

    REQUIRE_ARGS(1);

    v = cea708_input_buffer_peek(ib, 1);
    cc_log_debug2(h->log, "CEA708-%uD: [EXT1 0x%02uxD]", h->id, (uint32_t) v);

    if (v <= 0x1f)
    {
        /* C2 extended code set */
        if (v >= 0x18)
            i = 3;
        else if (v >= 0x10)
            i = 2;
        else if (v >= 0x08)
            i = 1;
        else
            i = 0;

        REQUIRE_ARGS_AND_POP_COMMAND(1 + i);
        POP_ARGS(1 + i);
    }
    else if (v >= 0x80 && v <= 0x8f)
    {
        /* C3 extended code set */
        if (v >= 0x88)
            i = 5;
        else
            i = 4;

        REQUIRE_ARGS_AND_POP_COMMAND(1 + i);
        POP_ARGS(1 + i);
    }
    else if (v >= 0x90 && v <= 0x9f)
    {
        /* Variable length codes */
        REQUIRE_ARGS(2);

        v = cea708_input_buffer_peek(ib, 2);
        i = v & 0x1f;

        REQUIRE_ARGS_AND_POP_COMMAND(2 + i);
        POP_ARGS(2 + i);
    }
    else
    {
        POP_COMMAND();
        v = cea708_input_buffer_get(ib);
        if (h->p_cw->b_defined)
            return CEA708_Decode_G2G3(h, v);
    }

    return CEA708_STATUS_OK;
}

static int CEA708_Decode_C0(cea708_t *h, uint8_t code)
{
    cea708_input_buffer_t *ib = &h->input_buffer;
    uint16_t u16;
    int i_ret = CEA708_STATUS_OK;

    switch (code)
    {
        case CEA708_C0_NUL:
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [NUL]", h->id);
            break;

        case CEA708_C0_ETX:  /* End Of Text */
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [ETX]", h->id);
            break;

        case CEA708_C0_BS:  /* Back Space */
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [BS]", h->id);
            if (!h->p_cw->b_defined)
                break;

            CEA708_Window_Backward(h->p_cw);
            break;

        case CEA708_C0_FF:
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [FF]", h->id);
            if (!h->p_cw->b_defined)
                break;

            CEA708_Window_ClearText(h->p_cw);
            h->p_cw->col = 0;
            h->p_cw->row = 0;
            break;

        case CEA708_C0_CR:
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [CR]", h->id);
            if (!h->p_cw->b_defined)
                break;

            if (h->p_cw->style.print_direction <= CEA708_WA_DIRECTION_RTL)
            {
                if (h->p_cw->b_visible)
                {
                    CEA708_Output(h);
                }

                CEA708_Window_CarriageReturn(h->p_cw);

                if (h->p_cw->b_visible)
                {
                    h->i_start = !CEA708_Output_Empty(h) ? h->i_clock : VLC_TICK_INVALID;
                }
            }
            break;

        case CEA708_C0_HCR:
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [HCR]", h->id);
            if (!h->p_cw->b_defined)
                break;

            if (h->p_cw->style.print_direction > CEA708_WA_DIRECTION_RTL)
            {
                CEA708_Window_CarriageReturn(h->p_cw);
            }
            break;

        case CEA708_C0_EXT1:
            i_ret |= CEA708_Decode_EXT1(h);
            break;

        case CEA708_C0_P16:
            REQUIRE_ARGS_AND_POP_COMMAND(2);
            u16 = cea708_input_buffer_get(ib) << 8;
            u16 |= cea708_input_buffer_get(ib);

            i_ret |= CEA708_Decode_P16(h, u16);
            break;

        default:
            POP_COMMAND();
            cc_log_debug2(h->log, "CEA708-%uD: [C0-UNK 0x%02uxD]", h->id, (uint32_t) code);
            break;
    }

    return i_ret;
}


static int CEA708_Decode_C1(cea708_t *h, uint8_t code)
{
    cea708_input_buffer_t *ib = &h->input_buffer;
    uint8_t b_output = 0;
    uint8_t v, i;
    int i_ret = CEA708_STATUS_OK;
#if (NGX_DEBUG)
    char cmd[4];
#endif

    switch (code)
    {
        case CEA708_C1_CLW:  /* Clear Windows */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [CLW 0x%02uxD]", h->id, (uint32_t) v);

            for (i = 0; v; v = v >> 1, i++)
            {
                if (v & 1)
                {
                    if (h->window[i].b_defined)
                    {
                        b_output = h->window[i].b_visible;
                    }

                    CEA708_Window_ClearText(&h->window[i]);
                }
            }
            break;

        case CEA708_C1_DSW:  /* Display Windows */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [DSW 0x%02uxD]", h->id, (uint32_t) v);

            for (i = 0; v; v = v >> 1, i++)
            {
                if (v & 1)
                {
                    if (h->window[i].b_defined)
                    {
                        h->window[i].b_visible = true;
                    }
                }
            }
            break;

        case CEA708_C1_HDW:  /* Hide Windows */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [HDW 0x%02uxD]", h->id, (uint32_t) v);

            for (i = 0; v; v = v >> 1, i++)
            {
                if (v & 1)
                {
                    if (h->window[i].b_defined)
                    {
                        b_output = h->window[i].b_visible;
                        h->window[i].b_visible = false;
                    }
                }
            }
            break;

        case CEA708_C1_TGW:  /* Toggle Windows */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [TGW 0x%02uxD]", h->id, (uint32_t) v);

            for (i = 0; v; v = v >> 1, i++)
            {
                if (v & 1)
                {
                    if (h->window[i].b_defined)
                    {
                        b_output = h->window[i].b_visible;
                        h->window[i].b_visible = !h->window[i].b_visible;
                    }
                }
            }
            break;

        case CEA708_C1_DLW:  /* Delete Windows */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [DLW 0x%02uxD]", h->id, (uint32_t) v);

            for (i = 0; v; v = v >> 1, i++)
            {
                if (v & 1)
                {
                    if (h->window[i].b_defined)
                    {
                        b_output = h->window[i].b_visible;
                        CEA708_Window_Reset(&h->window[i]);
                    }
                }
            }
            break;

        case CEA708_C1_DLY:  /* Delay */
            REQUIRE_ARGS_AND_POP_COMMAND(1);
            v = cea708_input_buffer_get(ib);
            cc_log_debug2(h->log, "CEA708-%uD: [DLY %uD]", h->id, (uint32_t) v);

            h->suspended_deadline = h->i_clock + VLC_TICK_FROM_MS((int64_t) v * 100);
            break;

        case CEA708_C1_DLC:  /* Delay Cancel */
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [DLC]", h->id);

            h->suspended_deadline = VLC_TICK_INVALID;
            break;

        case CEA708_C1_RST:  /* Reset */
            POP_COMMAND();
            cc_log_debug1(h->log, "CEA708-%uD: [RST]", h->id);
            /* FIXME */
            break;

        case CEA708_C1_SPA:  /* Set Pen Attributes */
            REQUIRE_ARGS_AND_POP_COMMAND(2);
            cea708_log_command2(h, "SPA");

            if (!h->p_cw->b_defined)
            {
                POP_ARGS(2);
                break;
            }

            v = cea708_input_buffer_get(ib);
            h->p_cw->pen.text_tag = v >> 4;
            h->p_cw->pen.offset = (v >> 2) & 0x03;
            h->p_cw->pen.size = v & 0x03;

            v = cea708_input_buffer_get(ib);
            h->p_cw->pen.b_italics = v & 0x80;
            h->p_cw->pen.b_underline = v & 0x40;
            h->p_cw->pen.edge_type = (v >> 3) & 0x07;
            h->p_cw->pen.font = v & 0x07;
            break;

        case CEA708_C1_SPC:  /* Set Pen Color */
            REQUIRE_ARGS_AND_POP_COMMAND(3);
            cea708_log_command3(h, "SPC");

            if (!h->p_cw->b_defined)
            {
                POP_ARGS(3);
                break;
            }

            v = cea708_input_buffer_get(ib);
            h->p_cw->pen.foreground.opacity = v >> 6;
            h->p_cw->pen.foreground.color = v & 0x3f;

            v = cea708_input_buffer_get(ib);
            h->p_cw->pen.background.opacity = v >> 6;
            h->p_cw->pen.background.color = v & 0x3f;

            v = cea708_input_buffer_get(ib);
            h->p_cw->pen.edge_color = v & 0x3f;
            break;

        case CEA708_C1_SPL:  /* Set Pen Location */
            REQUIRE_ARGS_AND_POP_COMMAND(2);
            cea708_log_command2(h, "SPL");

            if (!h->p_cw->b_defined)
            {
                POP_ARGS(2);
                break;
            }

            v = cea708_input_buffer_get(ib);
            h->p_cw->row = (v & 0x0f) % CEA708_WINDOW_MAX_ROWS;

            v = cea708_input_buffer_get(ib);
            h->p_cw->col = (v & 0x3f) % CEA708_WINDOW_MAX_COLS;
            break;

        case CEA708_C1_SWA:  /* Set Window Attributes */
            REQUIRE_ARGS_AND_POP_COMMAND(4);
            cea708_log_command4(h, "SWA");

            if (!h->p_cw->b_defined)
            {
                POP_ARGS(4);
                break;
            }

            v = cea708_input_buffer_get(ib);
            h->p_cw->style.fill_opacity = v >> 6;
            h->p_cw->style.fill_color = v & 0x3f;

            v = cea708_input_buffer_get(ib);
            h->p_cw->style.border_type = v >> 6;
            h->p_cw->style.border_color = v & 0x3f;

            v = cea708_input_buffer_get(ib);
            h->p_cw->style.border_type |= ((v & 0x80) >> 5);
            h->p_cw->style.b_word_wrap = v & 0x40;
            h->p_cw->style.print_direction = (v >> 4) & 0x03;
            h->p_cw->style.scroll_direction = (v >> 2) & 0x03;
            h->p_cw->style.justify = v & 0x03;

            v = cea708_input_buffer_get(ib);
            h->p_cw->style.effect_speed = v >> 4;
            h->p_cw->style.effect_direction = (v >> 2) & 0x03;
            h->p_cw->style.display_effect = v & 0x03;
            break;

        default:
            if (code >= CEA708_C1_CW0 && code <= CEA708_C1_CW7)
            {
                /* Set Current Window 0-7 */
                POP_COMMAND();
                code -= CEA708_C1_CW0;

#if (NGX_DEBUG)
                cmd[0] = 'C';
                cmd[1] = 'W';
                cmd[2] = '0' + code;
                cmd[3] = '\0';
                cea708_log_command0(h, cmd);
#endif

                if (h->window[code].b_defined)
                    h->p_cw = &h->window[code];
            }
            else if (code >= CEA708_C1_DF0 && code <= CEA708_C1_DF7)
            {
                /* Define Window 0-7 */
                REQUIRE_ARGS_AND_POP_COMMAND(6);
                code -= CEA708_C1_DF0;

                #if (NGX_DEBUG)
                cmd[0] = 'D';
                cmd[1] = 'F';
                cmd[2] = '0' + code;
                cmd[3] = '\0';
                cea708_log_command6(h, cmd);
                #endif

                /* also sets current window */
                h->p_cw = &h->window[code];

                v = cea708_input_buffer_get(ib);
                h->p_cw->b_visible = v & 0x20;
                h->p_cw->b_row_lock = v & 0x10;
                h->p_cw->b_column_lock = v & 0x08;
                h->p_cw->i_priority = v & 0x07;

                v = cea708_input_buffer_get(ib);
                h->p_cw->b_relative = v & 0x80;
                h->p_cw->i_anchor_offset_v = v & 0x7f;

                v = cea708_input_buffer_get(ib);
                h->p_cw->i_anchor_offset_h = v;

                v = cea708_input_buffer_get(ib);
                h->p_cw->anchor_point = v >> 4;
                h->p_cw->i_row_count = (v & 0x0f) + 1;
                if (h->p_cw->i_row_count > CEA708_WINDOW_MAX_ROWS)
                {
                    h->p_cw->i_row_count = CEA708_WINDOW_MAX_ROWS;
                }

                v = cea708_input_buffer_get(ib);
                h->p_cw->i_col_count = (v & 0x3f) + 1;
                if (h->p_cw->i_col_count > CEA708_WINDOW_MAX_COLS)
                {
                    h->p_cw->i_col_count = CEA708_WINDOW_MAX_COLS;
                }

                v = cea708_input_buffer_get(ib);
                /* zero values style set on init, avoid dealing with updt case */
                i = (v >> 3) & 0x07; /* Window style id */
                if (i > 0)
                    h->p_cw->style = cea708_default_window_styles[i-1];
                else if (!h->p_cw->b_defined) /* Set to style #1 or ignore */
                    h->p_cw->style = cea708_default_window_styles[0];

                i = v & 0x07; /* Pen style id */
                if (i > 0)
                    h->p_cw->pen = cea708_default_pen_styles[i-1];
                else if (!h->p_cw->b_defined) /* Set to style #1 or ignore */
                    h->p_cw->pen = cea708_default_pen_styles[0];

                h->p_cw->b_defined = true;
            }
            else
            {
                POP_COMMAND();
                cc_log_debug2(h->log, "CEA708-%uD: [C1-UNK 0x%02uxD]", h->id, (uint32_t) code);
            }
    }

    if (b_output)
    {
        CEA708_Output(h);

        h->i_start = !CEA708_Output_Empty(h) ? h->i_clock : VLC_TICK_INVALID;
    }

    return i_ret;
}

static void CEA708_Decode_ServiceBuffer(cea708_t *h)
{
    cea708_input_buffer_t *ib = &h->input_buffer;
    uint8_t i_consumed;
    uint8_t i_in;
    uint8_t c;
    int i_ret;

    for (;;)
    {
        i_in = cea708_input_buffer_size(ib);
        if (i_in == 0)
            break;

        c = cea708_input_buffer_peek(ib, 0);

        if (c <= 0x1f)
            i_ret = CEA708_Decode_C0(h, c);
        else if (c <= 0x7f)
            i_ret = CEA708_Decode_G0(h, c);
        else if (c <= 0x9f)
            i_ret = CEA708_Decode_C1(h, c);
        else
            i_ret = CEA708_Decode_G1(h, c);

        if (i_ret & CEA708_STATUS_STARVING)
            break;

        /* Update internal clock */
        i_consumed = i_in - cea708_input_buffer_size(ib);
        if (i_consumed)
            h->i_clock += vlc_tick_from_samples(1, 9600) * i_consumed;
    }
}

void CEA708_Decoder_Push(void *ctx, vlc_tick_t i_time, uint8_t *p_data, size_t i_data)
{
    cea708_input_buffer_t *ib;
    cea708_t *h = ctx;
    size_t i, lim;
    size_t i_push;

    ib = &h->input_buffer;

    /* Set new buffer start time */
    h->i_clock = i_time;

    for (i=0; i<i_data;)
    {
        /* Never push more than buffer */
        i_push = cea708_input_buffer_remain(ib);
        if (i_push > (i_data - i))
            i_push = (i_data - i);
        else
            h->suspended_deadline = VLC_TICK_INVALID; /* Full buffer cancels pause */

        lim = i + i_push;
        for (; i < lim; i++)
        {
            cea708_input_buffer_add(ib, p_data[i]);
        }

        if (h->suspended_deadline != VLC_TICK_INVALID)
        {
            /* Decoding is paused */
            if (h->suspended_deadline > h->i_clock)
            {
                /* Increase internal clock */
                if (i_push)
                    h->i_clock += vlc_tick_from_samples(1, 1200) * i_push;
                continue;
            }

            h->suspended_deadline = VLC_TICK_INVALID;
        }

        /* Decode Buffer */
        CEA708_Decode_ServiceBuffer(h);
    }
}
