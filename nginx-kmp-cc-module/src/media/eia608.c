/*****************************************************************************
 * cc.c : CC 608/708 subtitles decoder
 *****************************************************************************
 * Copyright © 2007-2011 Laurent Aimar, VLC authors and VideoLAN
 *             2011-2016 VLC authors and VideoLAN
 *             2016-2017 VideoLabs, VLC authors and VideoLAN
 *
 * Authors: Laurent Aimar < fenrir # via.ecp.fr>
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

/*****************************************************************************
 * Preamble
 *****************************************************************************/
/* The EIA 608 decoder part has been initially based on ccextractor (GPL)
 * and rewritten */

#include "eia608.h"
#include "webvtt.h"


#define EIA608_SCREEN_ROWS 15
#define EIA608_SCREEN_COLUMNS 32

#define EIA608_COLOR_DEFAULT EIA608_COLOR_WHITE


typedef enum
{
    EIA608_MODE_POPUP = 0,
    EIA608_MODE_ROLLUP_2 = 1,
    EIA608_MODE_ROLLUP_3 = 2,
    EIA608_MODE_ROLLUP_4 = 3,
    EIA608_MODE_PAINTON = 4,
    EIA608_MODE_TEXT = 5
} eia608_mode_t;

enum
{
    EIA608_COLOR_WHITE = 0,
    EIA608_COLOR_GREEN = 1,
    EIA608_COLOR_BLUE = 2,
    EIA608_COLOR_CYAN = 3,
    EIA608_COLOR_RED = 4,
    EIA608_COLOR_YELLOW = 5,
    EIA608_COLOR_MAGENTA = 6,
    EIA608_COLOR_USERDEFINED = 7
};

enum
{
    EIA608_FONT_REGULAR    = 0x00,
    EIA608_FONT_ITALICS    = 0x01,
    EIA608_FONT_UNDERLINE  = 0x02,
    EIA608_FONT_UNDERLINE_ITALICS = EIA608_FONT_UNDERLINE | EIA608_FONT_ITALICS
};


typedef uint8_t eia608_color_t;

typedef uint8_t eia608_font_t;

typedef struct
{
    uint8_t ch;
    eia608_color_t color;
    eia608_font_t font;
} eia608_cell_t;

typedef struct
{
    eia608_cell_t cells[EIA608_SCREEN_COLUMNS];
    bool used;
} eia608_row_t;

typedef struct
{
    eia608_row_t rows[EIA608_SCREEN_ROWS];
} eia608_screen_t;

struct eia608_t
{
    /* */
    int i_screen;   /* Displayed screen */
    eia608_screen_t screen[2];

    struct
    {
        int i_row;
        int i_column;
    } cursor;

    /* */
    eia608_mode_t mode;
    eia608_color_t color;
    eia608_font_t font;
    int i_row_rollup;

    /* Last command pair (used to reject duplicated command) */
    struct
    {
        uint8_t d1;
        uint8_t d2;
    } last;

    vlc_tick_t i_start;
    vlc_tick_t i_clock;

    cc_log_t *log;
    uint32_t id;
    subtitle_handler_t handler;
    void *priv;
    webvtt_writer_t webvtt;
};

typedef struct {
    eia608_color_t  i_color;
    eia608_font_t   i_font;
    int             i_column;
} eia608_pac_attribs_t;


static const eia608_pac_attribs_t pac2_attribs[]= {
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_GREEN,   EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_GREEN,   EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_BLUE,    EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_BLUE,    EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_CYAN,    EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_CYAN,    EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_RED,     EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_RED,     EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_YELLOW,  EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_YELLOW,  EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_MAGENTA, EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_MAGENTA, EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_ITALICS,           0 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE_ITALICS, 0 },

    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,           0 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,         0 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,           4 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,         4 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,           8 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,         8 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,          12 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,        12 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,          16 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,        16 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,          20 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,        20 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,          24 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,        24 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_REGULAR,          28 },
    { EIA608_COLOR_WHITE,   EIA608_FONT_UNDERLINE,        28 } ,
};


static cc_str_t eia608_utf8_table[] = {
    cc_string(" "),            /* 20 - ' ' */
    cc_string("!"),            /* 21 - '!' */
    cc_string("\""),           /* 22 - '"' */
    cc_string("#"),            /* 23 - '#' */
    cc_string("$"),            /* 24 - '$' */
    cc_string("%"),            /* 25 - '%' */
    cc_string("&"),            /* 26 - '&' */
    cc_string("'"),            /* 27 - "'" */
    cc_string("("),            /* 28 - '(' */
    cc_string(")"),            /* 29 - ')' */
    cc_string("\xc3\xa1"),     /* 2a - Lowercase a, acute accent */
    cc_string("+"),            /* 2b - '+' */
    cc_string(","),            /* 2c - ',' */
    cc_string("-"),            /* 2d - '-' */
    cc_string("."),            /* 2e - '.' */
    cc_string("/"),            /* 2f - '/' */
    cc_string("0"),            /* 30 - '0' */
    cc_string("1"),            /* 31 - '1' */
    cc_string("2"),            /* 32 - '2' */
    cc_string("3"),            /* 33 - '3' */
    cc_string("4"),            /* 34 - '4' */
    cc_string("5"),            /* 35 - '5' */
    cc_string("6"),            /* 36 - '6' */
    cc_string("7"),            /* 37 - '7' */
    cc_string("8"),            /* 38 - '8' */
    cc_string("9"),            /* 39 - '9' */
    cc_string(":"),            /* 3a - ':' */
    cc_string(";"),            /* 3b - ';' */
    cc_string("<"),            /* 3c - '<' */
    cc_string("="),            /* 3d - '=' */
    cc_string(">"),            /* 3e - '>' */
    cc_string("?"),            /* 3f - '?' */
    cc_string("@"),            /* 40 - '@' */
    cc_string("A"),            /* 41 - 'A' */
    cc_string("B"),            /* 42 - 'B' */
    cc_string("C"),            /* 43 - 'C' */
    cc_string("D"),            /* 44 - 'D' */
    cc_string("E"),            /* 45 - 'E' */
    cc_string("F"),            /* 46 - 'F' */
    cc_string("G"),            /* 47 - 'G' */
    cc_string("H"),            /* 48 - 'H' */
    cc_string("I"),            /* 49 - 'I' */
    cc_string("J"),            /* 4a - 'J' */
    cc_string("K"),            /* 4b - 'K' */
    cc_string("L"),            /* 4c - 'L' */
    cc_string("M"),            /* 4d - 'M' */
    cc_string("N"),            /* 4e - 'N' */
    cc_string("O"),            /* 4f - 'O' */
    cc_string("P"),            /* 50 - 'P' */
    cc_string("Q"),            /* 51 - 'Q' */
    cc_string("R"),            /* 52 - 'R' */
    cc_string("S"),            /* 53 - 'S' */
    cc_string("T"),            /* 54 - 'T' */
    cc_string("U"),            /* 55 - 'U' */
    cc_string("V"),            /* 56 - 'V' */
    cc_string("W"),            /* 57 - 'W' */
    cc_string("X"),            /* 58 - 'X' */
    cc_string("Y"),            /* 59 - 'Y' */
    cc_string("Z"),            /* 5a - 'Z' */
    cc_string("["),            /* 5b - '[' */
    cc_string("\xc3\xa9"),     /* 5c - Lowercase e, acute accent */
    cc_string("]"),            /* 5d - ']' */
    cc_string("\xc3\xad"),     /* 5e - Lowercase i, acute accent */
    cc_string("\xc3\xb3"),     /* 5f - Lowercase o, acute accent */
    cc_string("\xc3\xba"),     /* 60 - Lowercase u, acute accent */
    cc_string("a"),            /* 61 - 'a' */
    cc_string("b"),            /* 62 - 'b' */
    cc_string("c"),            /* 63 - 'c' */
    cc_string("d"),            /* 64 - 'd' */
    cc_string("e"),            /* 65 - 'e' */
    cc_string("f"),            /* 66 - 'f' */
    cc_string("g"),            /* 67 - 'g' */
    cc_string("h"),            /* 68 - 'h' */
    cc_string("i"),            /* 69 - 'i' */
    cc_string("j"),            /* 6a - 'j' */
    cc_string("k"),            /* 6b - 'k' */
    cc_string("l"),            /* 6c - 'l' */
    cc_string("m"),            /* 6d - 'm' */
    cc_string("n"),            /* 6e - 'n' */
    cc_string("o"),            /* 6f - 'o' */
    cc_string("p"),            /* 70 - 'p' */
    cc_string("q"),            /* 71 - 'q' */
    cc_string("r"),            /* 72 - 'r' */
    cc_string("s"),            /* 73 - 's' */
    cc_string("t"),            /* 74 - 't' */
    cc_string("u"),            /* 75 - 'u' */
    cc_string("v"),            /* 76 - 'v' */
    cc_string("w"),            /* 77 - 'w' */
    cc_string("x"),            /* 78 - 'x' */
    cc_string("y"),            /* 79 - 'y' */
    cc_string("z"),            /* 7a - 'z' */
    cc_string("\xc3\xa7"),     /* 7b - Lowercase c with cedilla */
    cc_string("\xc3\xb7"),     /* 7c - Division symbol */
    cc_string("\xc3\x91"),     /* 7d - Uppercase N tilde */
    cc_string("\xc3\xb1"),     /* 7e - Lowercase n tilde */
    cc_string("\x7f"),         /* 7f - '\x7f' */
    cc_string("\xc2\xae"),     /* 80 - Registered symbol (R) */
    cc_string("\xc2\xb0"),     /* 81 - Degree sign */
    cc_string("\xc2\xbd"),     /* 82 - 1/2 symbol */
    cc_string("\xc2\xbf"),     /* 83 - Inverted (open) question mark */
    cc_string("\xe2\x84\xa2"), /* 84 - Trademark symbol (TM) */
    cc_string("\xc2\xa2"),     /* 85 - Cents symbol */
    cc_string("\xc2\xa3"),     /* 86 - Pounds sterling */
    cc_string("\xe2\x99\xaa"), /* 87 - Music note */
    cc_string("\xc3\xa0"),     /* 88 - Lowercase a, grave accent */
    cc_string("\xc2\xa0"),     /* 89 - Transparent space */
    cc_string("\xc3\xa8"),     /* 8a - Lowercase e, grave accent */
    cc_string("\xc3\xa2"),     /* 8b - Lowercase a, circumflex accent */
    cc_string("\xc3\xaa"),     /* 8c - Lowercase e, circumflex accent */
    cc_string("\xc3\xae"),     /* 8d - Lowercase i, circumflex accent */
    cc_string("\xc3\xb4"),     /* 8e - Lowercase o, circumflex accent */
    cc_string("\xc3\xbb"),     /* 8f - Lowercase u, circumflex accent */
    cc_string("\xc3\x81"),     /* 90 - Capital letter A with acute */
    cc_string("\xc3\x89"),     /* 91 - Capital letter E with acute */
    cc_string("\xc3\x93"),     /* 92 - Capital letter O with acute */
    cc_string("\xc3\x9a"),     /* 93 - Capital letter U with acute */
    cc_string("\xc3\x9c"),     /* 94 - Capital letter U with diaeresis */
    cc_string("\xc3\xbc"),     /* 95 - Lowercase letter U with diaeresis */
    cc_string("\x27"),         /* 96 - Apostrophe */
    cc_string("\xc2\xa1"),     /* 97 - Inverted exclamation mark */
    cc_string("\x2a"),         /* 98 - Asterisk */
    cc_string("\x27"),         /* 99 - Apostrophe (yes, duped). See CCADI source code. */
    cc_string("\x2d"),         /* 9a - Hyphen-minus */
    cc_string("\xc2\xa9"),     /* 9b - Copyright sign */
    cc_string("\xe2\x84\xa0"), /* 9c - Service mark */
    cc_string("\x2e"),         /* 9d - Full stop (.) */
    cc_string("\xe2\x80\x9c"), /* 9e - Left quotation mark */
    cc_string("\xe2\x80\x9d"), /* 9f - Right quotation mark */
    cc_string("\xc3\x80"),     /* a0 - Uppercase A, grave accent */
    cc_string("\xc3\x82"),     /* a1 - Uppercase A, circumflex */
    cc_string("\xc3\x87"),     /* a2 - Uppercase C with cedilla */
    cc_string("\xc3\x88"),     /* a3 - Uppercase E, grave accent */
    cc_string("\xc3\x8a"),     /* a4 - Uppercase E, circumflex */
    cc_string("\xc3\x8b"),     /* a5 - Capital letter E with diaeresis */
    cc_string("\xc3\xab"),     /* a6 - Lowercase letter e with diaeresis */
    cc_string("\xc3\x8e"),     /* a7 - Uppercase I, circumflex */
    cc_string("\xc3\x8f"),     /* a8 - Uppercase I, with diaeresis */
    cc_string("\xc3\xaf"),     /* a9 - Lowercase i, with diaeresis */
    cc_string("\xc3\x94"),     /* aa - Uppercase O, circumflex */
    cc_string("\xc3\x99"),     /* ab - Uppercase U, grave accent */
    cc_string("\xc3\xb9"),     /* ac - Lowercase u, grave accent */
    cc_string("\xc3\x9b"),     /* ad - Uppercase U, circumflex */
    cc_string("\xc2\xab"),     /* ae - Left-pointing double angle quotation mark */
    cc_string("\xc2\xbb"),     /* af - Right-pointing double angle quotation mark */
    cc_string("\xc3\x83"),     /* b0 - Uppercase A, tilde */
    cc_string("\xc3\xa3"),     /* b1 - Lowercase a, tilde */
    cc_string("\xc3\x8d"),     /* b2 - Uppercase I, acute accent */
    cc_string("\xc3\x8c"),     /* b3 - Uppercase I, grave accent */
    cc_string("\xc3\xac"),     /* b4 - Lowercase i, grave accent */
    cc_string("\xc3\x92"),     /* b5 - Uppercase O, grave accent */
    cc_string("\xc3\xb2"),     /* b6 - Lowercase o, grave accent */
    cc_string("\xc3\x95"),     /* b7 - Uppercase O, tilde */
    cc_string("\xc3\xb5"),     /* b8 - Lowercase o, tilde */
    cc_string("\x7b"),         /* b9 - Open curly brace */
    cc_string("\x7d"),         /* ba - Closing curly brace */
    cc_string("\x5c"),         /* bb - Backslash */
    cc_string("\x5e"),         /* bc - Caret */
    cc_string("\x5f"),         /* bd - Underscore */
    cc_string("\xc2\xa6"),     /* be - Pipe (broken bar) */
    cc_string("\x7e"),         /* bf - Tilde (utf8 code unsure) */
    cc_string("\xc3\x84"),     /* c0 - Uppercase A, umlaut */
    cc_string("\xc3\xa4"),     /* c1 - Lowercase A, umlaut */
    cc_string("\xc3\x96"),     /* c2 - Uppercase O, umlaut */
    cc_string("\xc3\xb6"),     /* c3 - Lowercase o, umlaut */
    cc_string("\xc3\x9f"),     /* c4 - Esszett (sharp S) */
    cc_string("\xc2\xa5"),     /* c5 - Yen symbol */
    cc_string("\xc2\xa4"),     /* c6 - Currency symbol */
    cc_string("\x7c"),         /* c7 - Vertical bar */
    cc_string("\xc3\x85"),     /* c8 - Uppercase A, ring */
    cc_string("\xc3\xa5"),     /* c9 - Lowercase A, ring */
    cc_string("\xc3\x98"),     /* ca - Uppercase O, slash */
    cc_string("\xc3\xb8"),     /* cb - Lowercase o, slash */
    cc_string("\xe2\x8c\x9c"), /* cc - Upper left corner */
    cc_string("\xe2\x8c\x9d"), /* cd - Upper right corner */
    cc_string("\xe2\x8c\x9e"), /* ce - Lower left corner */
    cc_string("\xe2\x8c\x9f"), /* cf - Lower right corner */
};

static cc_str_t eia608_unknown_char = cc_string("?");


/* must match EIA608_COLOR_XXX */
static webvtt_tag_t *webvtt_color_tags[] = {
    NULL,
    &webvtt_tag_color_lime,
    &webvtt_tag_color_blue,
    &webvtt_tag_color_cyan,
    &webvtt_tag_color_red,
    &webvtt_tag_color_yellow,
    &webvtt_tag_color_magenta,
};


static void Eia608Output(eia608_t *h);


/*****************************************************************************
 *
 *****************************************************************************/

static void Eia608Cursor(eia608_t *h, int dx)
{
    h->cursor.i_column += dx;
    if (h->cursor.i_column < 0)
        h->cursor.i_column = 0;
    else if (h->cursor.i_column > EIA608_SCREEN_COLUMNS-1)
        h->cursor.i_column = EIA608_SCREEN_COLUMNS-1;
}

static void Eia608UpdateRowUsed(eia608_t *h, int i_screen, int i_row, int i_limit)
{
    eia608_screen_t *screen = &h->screen[i_screen];
    eia608_row_t *row = &screen->rows[i_row];
    int i;

    row->used = false;

    for (i = 0; i < i_limit; i++)
    {
        if (row->cells[i].ch != ' ')
        {
            row->used = true;
            break;
        }
    }
}

static bool Eia608GetScreenUsed(eia608_t *h, int i_screen)
{
    eia608_screen_t *screen = &h->screen[i_screen];
    int i_row;

    for (i_row = 0; i_row < EIA608_SCREEN_ROWS; i_row++)
    {
        if (screen->rows[i_row].used)
        {
            return true;
        }
    }

    return false;
}

static void Eia608ClearScreenRowX(eia608_t *h, int i_screen, int i_row, int x)
{
    eia608_screen_t *screen = &h->screen[i_screen];
    eia608_row_t *row = &screen->rows[i_row];
    eia608_cell_t *cell;
    int i;

    Eia608UpdateRowUsed(h, i_screen, i_row, x);

    for (i = x; i < EIA608_SCREEN_COLUMNS; i++)
    {
        cell = &row->cells[i];

        cell->ch = ' ';
        cell->color = EIA608_COLOR_DEFAULT;
        cell->font = EIA608_FONT_REGULAR;
    }
}

static void Eia608ClearScreenRow(eia608_t *h, int i_screen, int i_row)
{
    Eia608ClearScreenRowX(h, i_screen, i_row, 0);
}

static void Eia608ClearScreen(eia608_t *h, int i_screen)
{
    int i;

    for (i = 0; i < EIA608_SCREEN_ROWS; i++)
        Eia608ClearScreenRow(h, i_screen, i);
}

static int Eia608GetWritingScreenIndex(eia608_t *h)
{
    switch (h->mode)
    {
    case EIA608_MODE_POPUP:    // Non displayed screen
        return 1 - h->i_screen;

    case EIA608_MODE_ROLLUP_2: // Displayed screen
    case EIA608_MODE_ROLLUP_3:
    case EIA608_MODE_ROLLUP_4:
    case EIA608_MODE_PAINTON:
        return h->i_screen;

    default:
        /* It cannot happen, else it is a bug */
        return 0;
    }
}

static void Eia608EraseScreen(eia608_t *h, bool b_displayed)
{
    Eia608ClearScreen(h, b_displayed ? h->i_screen : (1-h->i_screen));
}

static void Eia608Write(eia608_t *h, uint8_t c)
{
    eia608_screen_t *screen;
    eia608_row_t *row;
    eia608_cell_t *cell;

    if (h->mode == EIA608_MODE_TEXT)
        return;

    screen = &h->screen[Eia608GetWritingScreenIndex(h)];
    row = &screen->rows[h->cursor.i_row];
    cell = &row->cells[h->cursor.i_column];

    cell->ch = c;
    cell->color = h->color;
    cell->font = h->font;

    if (c != ' ')
    {
        if (h->i_start == VLC_TICK_INVALID)
        {
            h->i_start = h->i_clock;
        }

        row->used = true;
    }

    Eia608Cursor(h, 1);
}

static void Eia608Erase(eia608_t *h)
{
    eia608_screen_t *screen;
    eia608_row_t *row;
    eia608_cell_t *cell;
    int i_screen;
    int i_row;
    int i_column;

    if (h->mode == EIA608_MODE_TEXT)
        return;

    i_row = h->cursor.i_row;
    i_column = h->cursor.i_column - 1;
    if (i_column < 0)
        return;

    i_screen = Eia608GetWritingScreenIndex(h);

    screen = &h->screen[i_screen];
    row = &screen->rows[i_row];
    cell = &row->cells[i_column];

    cell->ch = ' ';
    cell->color = EIA608_COLOR_DEFAULT;
    cell->font = EIA608_FONT_REGULAR;

    Eia608UpdateRowUsed(h, i_screen, i_row, EIA608_SCREEN_COLUMNS);

    Eia608Cursor(h, -1);
}

static void Eia608EraseToEndOfRow(eia608_t *h)
{
    if (h->mode == EIA608_MODE_TEXT)
        return;

    Eia608ClearScreenRowX(h, Eia608GetWritingScreenIndex(h), h->cursor.i_row, h->cursor.i_column);
}

static void Eia608RollUp(eia608_t *h)
{
    eia608_screen_t *screen;
    int keep_lines;
    int i_screen;
    int i_row;
    int i;

    /* Window size */
    switch (h->mode)
    {
    case EIA608_MODE_ROLLUP_2:
        keep_lines = 2;
        break;

    case EIA608_MODE_ROLLUP_3:
        keep_lines = 3;
        break;

    case EIA608_MODE_ROLLUP_4:
        keep_lines = 4;
        break;

    default:
        return;
    }

    i_screen = Eia608GetWritingScreenIndex(h);
    screen = &h->screen[i_screen];

    /* Reset the cursor */
    h->cursor.i_column = 0;

    /* Erase lines above our window */
    for (i = 0; i < h->cursor.i_row - keep_lines + 1; i++)
    {
        if (!h->screen[i_screen].rows[i].used)
        {
            continue;
        }

        Eia608ClearScreenRow(h, i_screen, i);
    }

    /* Move up */
    for (i = 0; i < keep_lines-1; i++)
    {
        i_row = h->cursor.i_row - keep_lines + 1 + i;
        if (i_row < 0)
            continue;

        cc_assert(i_row+1 < EIA608_SCREEN_ROWS);

        screen->rows[i_row] = screen->rows[i_row+1];
    }

    /* Reset current row */
    Eia608ClearScreenRow(h, i_screen, h->cursor.i_row);
}

static void Eia608ParseTextAttribute(eia608_t *h, uint8_t d2)
{
    int i_index = d2 - 0x20;

    cc_assert(d2 >= 0x20 && d2 <= 0x2f);

    cc_log_debug2(h->log, "EIA608-%uD: [TA %d]", h->id, i_index);

    h->color = pac2_attribs[i_index].i_color;
    h->font  = pac2_attribs[i_index].i_font;
    Eia608Cursor(h, 1);
}

static void Eia608ParseSingle(eia608_t *h, uint8_t dx)
{
    cc_assert(dx >= 0x20);

    cc_log_debug6(h->log, "EIA608-%uD: [SGL %xd->'%c'] %dx%d, m: %d",
        h->id, (int) dx, dx, h->cursor.i_row, h->cursor.i_column, (int) h->mode);

    Eia608Write(h, dx);
}

static void Eia608ParseDouble(eia608_t *h, uint8_t d2)
{
    cc_assert(d2 >= 0x30 && d2 <= 0x3f);

    d2 += 0x50;

    cc_log_debug6(h->log, "EIA608-%uD: [DBL %xd->'%c'] %dx%d, m: %d",
        h->id, (int) d2, d2, h->cursor.i_row, h->cursor.i_column, (int) h->mode);

    Eia608Write(h, d2); /* We use characters 0x80...0x8f */
}

static void Eia608ParseExtended(eia608_t *h, uint8_t d1, uint8_t d2)
{
    cc_assert(d2 >= 0x20 && d2 <= 0x3f);
    cc_assert(d1 == 0x12 || d1 == 0x13);

    if (d1 == 0x12)
        d2 += 0x70; /* We use characters 0x90-0xaf */
    else
        d2 += 0x90; /* We use characters 0xb0-0xcf */

    cc_log_debug6(h->log, "EIA608-%uD: [EXT %xd->'%c'] %dx%d, m: %d",
        h->id, (int) d2, d2, h->cursor.i_row, h->cursor.i_column, (int) h->mode);

    /* The extended characters replace the previous one with a more
     * advanced one */
    Eia608Cursor(h, -1);
    Eia608Write(h, d2);
}

static void Eia608ParseCommand0x14(eia608_t *h, uint8_t d2)
{
    eia608_mode_t proposed_mode;

    switch (d2)
    {
    case 0x20:  /* Resume caption loading */
        cc_log_debug1(h->log, "EIA608-%uD: [RCL]", h->id);
        h->mode = EIA608_MODE_POPUP;
        break;

    case 0x21:  /* Backspace */
        cc_log_debug1(h->log, "EIA608-%uD: [BS]", h->id);
        Eia608Erase(h);
        break;

    case 0x22:  /* Reserved */
    case 0x23:
        cc_log_debug2(h->log, "EIA608-%uD: [ALARM %d]", h->id, (int) (d2 - 0x22));
        break;

    case 0x24:  /* Delete to end of row */
        cc_log_debug1(h->log, "EIA608-%uD: [DER]", h->id);
        Eia608EraseToEndOfRow(h);
        break;

    case 0x25:  /* Rollup 2 */
    case 0x26:  /* Rollup 3 */
    case 0x27:  /* Rollup 4 */
        cc_log_debug2(h->log, "EIA608-%uD: [RU%d]", h->id, (int) (d2 - 0x23));
        if (h->mode == EIA608_MODE_POPUP || h->mode == EIA608_MODE_PAINTON)
        {
            Eia608Output(h);

            Eia608EraseScreen(h, true);
            Eia608EraseScreen(h, false);
            h->i_start = VLC_TICK_INVALID;
        }

        if (d2 == 0x25)
            proposed_mode = EIA608_MODE_ROLLUP_2;
        else if (d2 == 0x26)
            proposed_mode = EIA608_MODE_ROLLUP_3;
        else
            proposed_mode = EIA608_MODE_ROLLUP_4;

        if (proposed_mode != h->mode)
        {
            h->mode = proposed_mode;
            h->cursor.i_column = 0;
            h->cursor.i_row = h->i_row_rollup;
        }
        break;

    case 0x28:  /* Flash on */
        cc_log_debug1(h->log, "EIA608-%uD: [FON]", h->id);
        /* TODO */
        break;

    case 0x29:  /* Resume direct captioning */
        cc_log_debug1(h->log, "EIA608-%uD: [RDC]", h->id);
        h->mode = EIA608_MODE_PAINTON;
        break;

    case 0x2a:  /* Text restart */
        cc_log_debug1(h->log, "EIA608-%uD: [TR]", h->id);
        /* TODO */
        break;

    case 0x2b: /* Resume text display */
        cc_log_debug1(h->log, "EIA608-%uD: [RTD]", h->id);
        h->mode = EIA608_MODE_TEXT;
        break;

    case 0x2c: /* Erase displayed memory */
        cc_log_debug1(h->log, "EIA608-%uD: [EDM]", h->id);
        Eia608Output(h);
        Eia608EraseScreen(h, true);
        h->i_start = VLC_TICK_INVALID;
        break;

    case 0x2d: /* Carriage return */
        cc_log_debug1(h->log, "EIA608-%uD: [CR]", h->id);
        Eia608Output(h);
        Eia608RollUp(h);
        h->i_start = Eia608GetScreenUsed(h, h->i_screen) ? h->i_clock : VLC_TICK_INVALID;
        break;

    case 0x2e: /* Erase non displayed memory */
        cc_log_debug1(h->log, "EIA608-%uD: [ENM]", h->id);
        Eia608EraseScreen(h, false);
        break;

    case 0x2f: /* End of caption (flip screen if not paint on) */
        cc_log_debug1(h->log, "EIA608-%uD: [EOC]", h->id);
        Eia608Output(h);
        if (h->mode != EIA608_MODE_PAINTON)
            h->i_screen = 1 - h->i_screen;
        h->i_start = Eia608GetScreenUsed(h, h->i_screen) ? h->i_clock : VLC_TICK_INVALID;
        h->mode = EIA608_MODE_POPUP;
        h->cursor.i_column = 0;
        h->cursor.i_row = 0;
        h->color = EIA608_COLOR_DEFAULT;
        h->font = EIA608_FONT_REGULAR;
        break;
    }
}

static bool Eia608ParseCommand0x17(eia608_t *h, uint8_t d2)
{
    switch (d2)
    {
    case 0x21:  /* Tab offset 1 */
    case 0x22:  /* Tab offset 2 */
    case 0x23:  /* Tab offset 3 */
        cc_log_debug2(h->log, "EIA608-%uD: [TO%d]", h->id, (int) (d2 - 0x20));
        Eia608Cursor(h, d2 - 0x20);
        break;
    }
    return false;
}

static bool Eia608ParsePac(eia608_t *h, uint8_t d1, uint8_t d2)
{
    static const int pi_row[] = {
        11, -1, 1, 2, 3, 4, 12, 13, 14, 15, 5, 6, 7, 8, 9, 10
    };
    int i_row_index = ((d1<<1) & 0x0e) | ((d2>>5) & 0x01);

    cc_log_debug2(h->log, "EIA608-%uD: [PAC,%d]", h->id, i_row_index);

    cc_assert(d2 >= 0x40 && d2 <= 0x7f);

    if (pi_row[i_row_index] <= 0)
        return false;

    /* Row */
    if (h->mode != EIA608_MODE_TEXT)
        h->cursor.i_row = pi_row[i_row_index] - 1;
    h->i_row_rollup = pi_row[i_row_index] - 1;

    /* Column */
    if (d2 >= 0x60)
        d2 -= 0x60;
    else if (d2 >= 0x40)
        d2 -= 0x40;

    h->cursor.i_column = pac2_attribs[d2].i_column;
    h->color = pac2_attribs[d2].i_color;
    h->font  = pac2_attribs[d2].i_font;

    return false;
}

static void Eia608ParseData(eia608_t *h, uint8_t d1, uint8_t d2)
{
    cc_log_debug3(h->log, "EIA608-%uD: input: %02uxD %02uxD", h->id, (uint32_t) d1, (uint32_t) d2);

    if (d1 >= 0x18 && d1 <= 0x1f)
        d1 -= 8;

    switch (d1)
    {
    case 0x11:
        if (d2 >= 0x20 && d2 <= 0x2f) Eia608ParseTextAttribute(h, d2);
        else if (d2 >= 0x30 && d2 <= 0x3f) Eia608ParseDouble(h, d2);
        break;

    case 0x12: case 0x13:
        if (d2 >= 0x20 && d2 <= 0x3f) Eia608ParseExtended(h, d1, d2);
        break;

    case 0x14: case 0x15:
        if (d2 >= 0x20 && d2 <= 0x2f) Eia608ParseCommand0x14(h, d2);
        break;

    case 0x17:
        if (d2 >= 0x21 && d2 <= 0x23) Eia608ParseCommand0x17(h, d2);
        else if (d2 >= 0x2e && d2 <= 0x2f) Eia608ParseTextAttribute(h, d2);
        break;
    }

    if (d1 == 0x10)
    {
        if (d2 >= 0x40 && d2 <= 0x5f) Eia608ParsePac(h, d1, d2);
    }
    else if (d1 >= 0x11 && d1 <= 0x17)
    {
        if (d2 >= 0x40 && d2 <= 0x7f) Eia608ParsePac(h, d1, d2);
    }

    if (d1 >= 0x20)
    {
        Eia608ParseSingle(h, d1);
        if (d2 >= 0x20)
        {
            Eia608ParseSingle(h, d2);
        }
    }
}

static cc_str_t *Eia608TextUtf8(uint8_t c)
{
    if (c < 0x20 || c >= 0xd0)
    {
        return &eia608_unknown_char;
    }

    return &eia608_utf8_table[c - 0x20];
}

static void Eia608OutputRow(eia608_t *h, eia608_screen_t *screen, int i_row, int i_start, bool *wrote)
{
    eia608_row_t *row = &screen->rows[i_row];
    eia608_cell_t *cell;
    eia608_color_t color;
    eia608_font_t font;
    cc_str_t *str;
    int i_end;
    int x;

    /* Search the end */
    i_end = EIA608_SCREEN_COLUMNS-1;
    while (i_start <= i_end && row->cells[i_end].ch == ' ')
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

    color = EIA608_COLOR_DEFAULT;
    font = EIA608_FONT_REGULAR;

    for (x = i_start; x <= i_end; x++)
    {
        cell = &row->cells[x];

        if (cell->ch == ' ')
        {
            h->handler.write(h->priv, " ", 1);
            continue;
        }

        if (cell->font != font || cell->color != color)
        {
            webvtt_writer_pop_tags(&h->webvtt);

            font = cell->font;
            color = cell->color;

            if (color > EIA608_COLOR_WHITE && color < ARRAY_SIZE(webvtt_color_tags))
            {
                webvtt_writer_push_tag(&h->webvtt, webvtt_color_tags[color]);
            }

            if (font & EIA608_FONT_ITALICS)
            {
                webvtt_writer_push_tag(&h->webvtt, &webvtt_tag_italics);
            }

            if (font & EIA608_FONT_UNDERLINE)
            {
                webvtt_writer_push_tag(&h->webvtt, &webvtt_tag_underline);
            }
        }

        str = Eia608TextUtf8(cell->ch);
        webvtt_writer_char(&h->webvtt, str->data, str->len);
    }

    webvtt_writer_pop_tags(&h->webvtt);
}

static void Eia608OutputGetStartPos(eia608_t *h, int *i_min_row, int *i_min_col)
{
    eia608_screen_t *screen = &h->screen[h->i_screen];
    eia608_row_t *row;
    int i_row;
    int i_col;

    *i_min_row = EIA608_SCREEN_ROWS;
    *i_min_col = EIA608_SCREEN_COLUMNS;

    for (i_row = 0; i_row < EIA608_SCREEN_ROWS; i_row++)
    {
        row = &screen->rows[i_row];

        if (!row->used)
            continue;

        for (i_col = 0; i_col < EIA608_SCREEN_COLUMNS; i_col++)
        {
            if (row->cells[i_col].ch == ' ')
            {
                continue;
            }

            if (*i_min_row > i_row)
            {
                *i_min_row = i_row;
            }

            if (*i_min_col > i_col)
            {
                *i_min_col = i_col;
            }

            break;
        }
    }
}

static void Eia608Output(eia608_t *h)
{
    eia608_screen_t *screen;
    uint32_t value;
    bool wrote;
    int i_min_row;
    int i_min_col;
    int i;

    if (h->i_start >= h->i_clock)
    {
        return;
    }

    Eia608OutputGetStartPos(h, &i_min_row, &i_min_col);

    if (i_min_row >= EIA608_SCREEN_ROWS)
    {
        return;
    }

    h->handler.start(h->priv);

    /* Note: the line/position calculation spreads the chars/lines between 10% and 90% */
    value = 1000 + i_min_row * 8000 / EIA608_SCREEN_ROWS;
    webvtt_writer_add_percent_setting(&h->webvtt, &webvtt_setting_line, value);

    value = 1000 + i_min_col * 8000 / EIA608_SCREEN_COLUMNS;
    webvtt_writer_add_percent_setting(&h->webvtt, &webvtt_setting_position, value);

    h->handler.add_setting(h->priv, &webvtt_setting_align_left);

    screen = &h->screen[h->i_screen];
    wrote = false;

    for (i = i_min_row; i < EIA608_SCREEN_ROWS; i++)
    {
        if (!screen->rows[i].used)
            continue;

        Eia608OutputRow(h, screen, i, i_min_col, &wrote);
    }

    h->handler.end(h->priv, h->i_start, h->i_clock);
}

/* */
eia608_t *Eia608New(cc_log_t *log, uint32_t id, void *priv, subtitle_handler_t *handler)
{
    eia608_t *h;

    h = calloc(1, sizeof(*h));
    if (h == NULL)
    {
        return NULL;
    }

    Eia608ClearScreen(h, 0);
    Eia608ClearScreen(h, 1);

    h->mode = EIA608_MODE_POPUP;
    h->color = EIA608_COLOR_DEFAULT;
    h->font = EIA608_FONT_REGULAR;
    h->i_row_rollup = EIA608_SCREEN_ROWS-1;
    h->i_start = VLC_TICK_INVALID;

    h->log = log;
    h->id = id;

    h->handler = *handler;
    h->priv = priv;
    webvtt_writer_init(&h->webvtt, handler, priv);

    return h;
}

void Eia608Release(eia608_t *h)
{
    free(h);
}

void Eia608Parse(void *ctx, vlc_tick_t tick, uint8_t *p_data, size_t i_data)
{
    eia608_t *h = ctx;
    uint8_t *p_end;
    uint8_t d1, d2;

    for (p_end = p_data + i_data; p_data + 1 < p_end; p_data += 2)
    {
        /* Remove parity bit */
        d1 = p_data[0] & 0x7f;
        d2 = p_data[1] & 0x7f;

        h->i_clock = tick;

        if (d1 >= 0x10)
        {
            if (d1 < 0x20 && d1 == h->last.d1 && d2 == h->last.d2)
            {
                /* Command codes can be repeated */
                continue;
            }

            Eia608ParseData(h, d1, d2);

            h->last.d1 = d1;
            h->last.d2 = d2;
        }
        else if ((d1 >= 0x01 && d1 <= 0x0e) || d1 == 0x0f)
        {
            /* XDS block / End of XDS block */
        }
    }
}
