#include <ngx_config.h>
#include <ngx_core.h>
#include <ctype.h>
#include "ngx_json_parser.h"


#define NGX_JSON_MAX_ELEMENTS           (524288)
#define NGX_JSON_MAX_RECURSION_DEPTH    (32)
#define NGX_JSON_PART_FIRST_COUNT       (5)
#define NGX_JSON_PART_MAX_SIZE          (65536)


#define ASSERT_CHAR(state, ch)                                               \
    if (*(state)->cur_pos != ch) {                                           \
        ngx_snprintf(state->error, state->error_size,                        \
            "expected 0x%xd got 0x%xd%Z",                                    \
            (int) ch, (int) *(state)->cur_pos);                              \
        return NGX_JSON_BAD_DATA;                                            \
    }

#define EXPECT_CHAR(state, ch)                                               \
    ASSERT_CHAR(state, ch)                                                   \
    (state)->cur_pos++;

#define EXPECT_STRING(state, str)                                            \
    if (ngx_strncmp((state)->cur_pos, str, sizeof(str) - 1) != 0) {          \
        ngx_snprintf(state->error, state->error_size,                        \
            "expected %s%Z", str);                                           \
        return NGX_JSON_BAD_DATA;                                            \
    }                                                                        \
    (state)->cur_pos += sizeof(str) - 1;


typedef struct {
    ngx_pool_t          *pool;
    u_char              *cur_pos;
    int                  depth;
    u_char              *error;
    size_t               error_size;
} ngx_json_parser_state_t;


typedef struct {
    int                  type;
    size_t               size;
    ngx_json_status_t  (*parser)(ngx_json_parser_state_t *state, void *result);
} ngx_json_type_t;


static ngx_json_status_t ngx_json_parse_value(ngx_json_parser_state_t *state,
    ngx_json_value_t *result);

static ngx_json_status_t ngx_json_parser_string(
    ngx_json_parser_state_t *state, void *result);
static ngx_json_status_t ngx_json_parser_array(
    ngx_json_parser_state_t *state, void *result);
static ngx_json_status_t ngx_json_parser_object(
    ngx_json_parser_state_t *state, void *result);
static ngx_json_status_t ngx_json_parser_bool(
    ngx_json_parser_state_t *state, void *result);
static ngx_json_status_t ngx_json_parser_frac(
    ngx_json_parser_state_t *state, void *result);
static ngx_json_status_t ngx_json_parser_int(
    ngx_json_parser_state_t *state, void *result);


static ngx_json_type_t  ngx_json_string = {
    NGX_JSON_STRING, sizeof(ngx_json_esc_str_t), ngx_json_parser_string
};


static ngx_json_type_t  ngx_json_array = {
    NGX_JSON_ARRAY, sizeof(ngx_json_array_t), ngx_json_parser_array
};


static ngx_json_type_t  ngx_json_object = {
    NGX_JSON_OBJECT, sizeof(ngx_json_object_t), ngx_json_parser_object
};


static ngx_json_type_t  ngx_json_bool = {
    NGX_JSON_BOOL, sizeof(ngx_flag_t), ngx_json_parser_bool
};


static ngx_json_type_t  ngx_json_frac = {
    NGX_JSON_FRAC, sizeof(ngx_json_fraction_t), ngx_json_parser_frac
};


static ngx_json_type_t  ngx_json_int = {
    NGX_JSON_INT, sizeof(int64_t), ngx_json_parser_int
};


static ngx_json_status_t
ngx_json_get_value_type(ngx_json_parser_state_t *state,
    ngx_json_type_t **result)
{
    u_char  *cur_pos = state->cur_pos;

    switch (*cur_pos) {

    case '"':
        *result = &ngx_json_string;
        return NGX_JSON_OK;

    case '[':
        *result = &ngx_json_array;
        return NGX_JSON_OK;

    case '{':
        *result = &ngx_json_object;
        return NGX_JSON_OK;

    case 'f':
    case 't':
        *result = &ngx_json_bool;
        return NGX_JSON_OK;

    default:
        break;      /* handled outside the switch */
    }

    if (*cur_pos == '-') {
        cur_pos++;
    }

    if (!isdigit(*cur_pos)) {
        ngx_snprintf(state->error, state->error_size,
            "expected digit got 0x%xd%Z", (int) *cur_pos);
        return NGX_JSON_BAD_DATA;
    }

    while (isdigit(*cur_pos)) {
        cur_pos++;
    }

    if (*cur_pos == '.') {
        *result = &ngx_json_frac;

    } else {
        *result = &ngx_json_int;
    }

    return NGX_JSON_OK;
}


static void
ngx_json_skip_spaces(ngx_json_parser_state_t *state)
{
    for (; *state->cur_pos && isspace(*state->cur_pos); state->cur_pos++);
}


static ngx_json_status_t
ngx_json_parse_string(ngx_json_parser_state_t *state,
    ngx_json_esc_str_t *result)
{
    u_char  c;

    state->cur_pos++;       /* skip the " */

    result->escape = 0;
    result->s.data = state->cur_pos;

    for ( ;; ) {

        c = *state->cur_pos;
        if (!c) {
            break;
        }

        switch (c) {

        case '\\':
            state->cur_pos++;
            if (!*state->cur_pos) {
                ngx_snprintf(state->error, state->error_size,
                    "end of data while parsing string (1)%Z");
                return NGX_JSON_BAD_DATA;
            }

            result->escape = 1;
            break;

        case '"':
            result->s.len = state->cur_pos - result->s.data;
            state->cur_pos++;
            return NGX_JSON_OK;
        }

        state->cur_pos++;
    }

    ngx_snprintf(state->error, state->error_size,
        "end of data while parsing string (2)%Z");
    return NGX_JSON_BAD_DATA;
}


static ngx_json_status_t
ngx_json_parse_object_key(ngx_json_parser_state_t *state,
    ngx_json_key_value_t *result)
{
    u_char      c;
    ngx_uint_t  hash = 0;

    EXPECT_CHAR(state, '\"');

    result->key.data = state->cur_pos;

    for ( ;; ) {

        c = *state->cur_pos;
        if (!c) {
            break;
        }

        if (c >= 'A' && c <= 'Z') {
            c |= 0x20;          /* tolower */
            *state->cur_pos = c;
        }

        switch (c) {

        case '\\':
            state->cur_pos++;
            if (!*state->cur_pos) {
                ngx_snprintf(state->error, state->error_size,
                    "end of data while parsing string (1)%Z");
                return NGX_JSON_BAD_DATA;
            }
            break;

        case '"':
            result->key.len = state->cur_pos - result->key.data;
            result->key_hash = hash;
            state->cur_pos++;
            return NGX_JSON_OK;
        }

        hash = ngx_hash(hash, c);

        state->cur_pos++;
    }

    ngx_snprintf(state->error, state->error_size,
        "end of data while parsing string (2)%Z");
    return NGX_JSON_BAD_DATA;
}


static ngx_json_status_t
ngx_json_parse_int(ngx_json_parser_state_t *state, int64_t *result,
    ngx_flag_t *negative)
{
    int64_t  value;

    if (*state->cur_pos == '-') {
        *negative = 1;
        state->cur_pos++;

    } else {
        *negative = 0;
    }

    if (!isdigit(*state->cur_pos)) {
        ngx_snprintf(state->error, state->error_size,
            "expected digit got 0x%xd%Z", (int) *state->cur_pos);
        return NGX_JSON_BAD_DATA;
    }

    value = 0;

    do {
        if (value > LLONG_MAX / 10 - 1) {
            ngx_snprintf(state->error, state->error_size,
                "number value overflow (1)%Z");
            return NGX_JSON_BAD_DATA;
        }

        value = value * 10 + (*state->cur_pos - '0');
        state->cur_pos++;
    } while (isdigit(*state->cur_pos));

    *result = value;

    return NGX_JSON_OK;
}


static ngx_json_status_t
ngx_json_parse_fraction(ngx_json_parser_state_t *state,
    ngx_json_fraction_t *result)
{
    int64_t            value;
    uint64_t           denom = 1;
    ngx_flag_t         negative;
    ngx_json_status_t  rc;

    rc = ngx_json_parse_int(state, &value, &negative);
    if (rc != NGX_JSON_OK) {
        return rc;
    }

    if (*state->cur_pos == '.') {
        state->cur_pos++;

        if (!isdigit(*state->cur_pos)) {
            ngx_snprintf(state->error, state->error_size,
                "expected digit got 0x%xd%Z", (int) *state->cur_pos);
            return NGX_JSON_BAD_DATA;
        }

        do {
            if (value > LLONG_MAX / 10 - 1 || denom > ULLONG_MAX / 10) {
                ngx_snprintf(state->error, state->error_size,
                    "number value overflow (2)%Z");
                return NGX_JSON_BAD_DATA;
            }

            value = value * 10 + (*state->cur_pos - '0');
            denom *= 10;
            state->cur_pos++;
        } while (isdigit(*state->cur_pos));
    }

    if (negative) {
        value = -value;
    }

    result->num = value;
    result->denom = denom;

    return NGX_JSON_OK;
}


static ngx_json_status_t
ngx_json_parse_array(ngx_json_parser_state_t *state, ngx_json_array_t *result)
{
    void               *cur_item;
    size_t              part_size;
    size_t              initial_part_count;
    ngx_json_type_t    *type;
    ngx_array_part_t   *part;
    ngx_json_status_t   rc;

    state->cur_pos++;       /* skip the [ */
    ngx_json_skip_spaces(state);

    if (*state->cur_pos == ']') {
        result->type = NGX_JSON_NULL;
        result->count = 0;
        result->part.first = NULL;
        result->part.last = NULL;
        result->part.count = 0;
        result->part.next = NULL;

        state->cur_pos++;
        return NGX_JSON_OK;
    }

    if (state->depth >= NGX_JSON_MAX_RECURSION_DEPTH) {
        ngx_snprintf(state->error, state->error_size,
            "max recursion depth exceeded%Z");
        return NGX_JSON_BAD_DATA;
    }

    state->depth++;

    rc = ngx_json_get_value_type(state, &type);
    if (rc != NGX_JSON_OK) {
        return rc;
    }

    initial_part_count = 0;

    /* initialize the result and first part */
    result->type = type->type;
    result->count = 0;
    part = &result->part;
    part_size = type->size * NGX_JSON_PART_FIRST_COUNT;
    cur_item = ngx_palloc(state->pool, part_size);
    if (cur_item == NULL) {
        return NGX_JSON_ALLOC_FAILED;
    }

    part->first = cur_item;
    part->last = (u_char *) cur_item + part_size;

    for ( ;; ) {

        if (result->count >= NGX_JSON_MAX_ELEMENTS) {
            ngx_snprintf(state->error, state->error_size,
                "array elements count exceeds the limit%Z");
            return NGX_JSON_BAD_DATA;
        }

        if (cur_item >= part->last) {
            /* update the part count */
            part->count = result->count - initial_part_count;
            initial_part_count = result->count;

            /* allocate another part */
            if (part_size < (NGX_JSON_PART_MAX_SIZE - sizeof(*part)) / 2) {
                part_size *= 2;
            }

            part->next = ngx_palloc(state->pool, sizeof(*part) + part_size);
            if (part->next == NULL) {
                return NGX_JSON_ALLOC_FAILED;
            }

            part = part->next;
            cur_item = part + 1;
            part->first = cur_item;
            part->last = (u_char *) cur_item + part_size;
        }

        rc = type->parser(state, cur_item);
        if (rc != NGX_JSON_OK) {
            return rc;
        }

        cur_item = (u_char *) cur_item + type->size;
        result->count++;

        ngx_json_skip_spaces(state);

        switch (*state->cur_pos) {

        case ']':
            state->cur_pos++;
            goto done;

        case ',':
            state->cur_pos++;
            ngx_json_skip_spaces(state);
            continue;
        }

        ngx_snprintf(state->error, state->error_size,
            "expected , or ] while parsing array, got 0x%xd%Z",
            (int) *state->cur_pos);
        return NGX_JSON_BAD_DATA;
    }

done:

    part->last = cur_item;
    part->count = result->count - initial_part_count;
    part->next = NULL;

    state->depth--;
    return NGX_JSON_OK;
}


static ngx_json_status_t
ngx_json_parse_object(ngx_json_parser_state_t *state,
    ngx_json_object_t *result)
{
    ngx_int_t              rc;
    ngx_json_key_value_t  *cur_item;

    state->cur_pos++;       /* skip the { */
    ngx_json_skip_spaces(state);

    if (*state->cur_pos == '}') {
        result->nelts = 0;
        result->size = sizeof(*cur_item);
        result->nalloc = 0;
        result->pool = state->pool;
        result->elts = NULL;

        state->cur_pos++;
        return NGX_JSON_OK;
    }

    if (state->depth >= NGX_JSON_MAX_RECURSION_DEPTH) {
        ngx_snprintf(state->error, state->error_size,
            "max recursion depth exceeded%Z");
        return NGX_JSON_BAD_DATA;
    }

    state->depth++;

    rc = ngx_array_init(result, state->pool, 5, sizeof(*cur_item));
    if (rc != NGX_OK) {
        return NGX_JSON_ALLOC_FAILED;
    }

    for ( ;; ) {
        if (result->nelts >= NGX_JSON_MAX_ELEMENTS) {
            ngx_snprintf(state->error, state->error_size,
                "object elements count exceeds the limit%Z");
            return NGX_JSON_BAD_DATA;
        }

        cur_item = (ngx_json_key_value_t *) ngx_array_push(result);
        if (cur_item == NULL) {
            return NGX_JSON_ALLOC_FAILED;
        }

        rc = ngx_json_parse_object_key(state, cur_item);
        if (rc != NGX_JSON_OK) {
            return rc;
        }

        ngx_json_skip_spaces(state);
        EXPECT_CHAR(state, ':');
        ngx_json_skip_spaces(state);

        rc = ngx_json_parse_value(state, &cur_item->value);
        if (rc != NGX_JSON_OK) {
            return rc;
        }

        ngx_json_skip_spaces(state);
        switch (*state->cur_pos) {

        case '}':
            state->cur_pos++;
            state->depth--;
            return NGX_JSON_OK;

        case ',':
            state->cur_pos++;
            ngx_json_skip_spaces(state);
            continue;
        }

        ngx_snprintf(state->error, state->error_size,
            "expected , or } while parsing object, got 0x%xd%Z",
            (int) *state->cur_pos);
        return NGX_JSON_BAD_DATA;
    }
}


static ngx_json_status_t
ngx_json_parser_string(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '"');
    return ngx_json_parse_string(state, (ngx_json_esc_str_t *) result);
}


static ngx_json_status_t
ngx_json_parser_array(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '[');
    return ngx_json_parse_array(state, (ngx_json_array_t *) result);
}


static ngx_json_status_t
ngx_json_parser_object(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '{');
    return ngx_json_parse_object(state, (ngx_json_object_t *) result);
}


static ngx_json_status_t
ngx_json_parser_bool(ngx_json_parser_state_t *state, void *result)
{
    switch (*state->cur_pos) {

    case 't':
        EXPECT_STRING(state, "true");
        *(ngx_flag_t *) result = 1;
        return NGX_JSON_OK;

    case 'f':
        EXPECT_STRING(state, "false");
        *(ngx_flag_t *) result = 0;
        return NGX_JSON_OK;
    }

    ngx_snprintf(state->error, state->error_size, "expected true or false%Z");
    return NGX_JSON_BAD_DATA;
}


static ngx_json_status_t
ngx_json_parser_frac(ngx_json_parser_state_t *state, void *result)
{
    return ngx_json_parse_fraction(state, (ngx_json_fraction_t *) result);
}


static ngx_json_status_t
ngx_json_parser_int(ngx_json_parser_state_t *state, void *result)
{
    ngx_flag_t         negative;
    ngx_json_status_t  rc;

    rc = ngx_json_parse_int(state, (int64_t *) result, &negative);

    if (negative) {
        *(int64_t *) result = -(*(int64_t *) result);
    }

    return rc;
}


static ngx_json_status_t
ngx_json_parse_value(ngx_json_parser_state_t *state, ngx_json_value_t *result)
{
    ngx_json_status_t  rc;

    switch (*state->cur_pos) {

    case '"':
        result->type = NGX_JSON_STRING;
        return ngx_json_parse_string(state, &result->v.str);

    case '[':
        result->type = NGX_JSON_ARRAY;
        return ngx_json_parse_array(state, &result->v.arr);

    case '{':
        result->type = NGX_JSON_OBJECT;
        return ngx_json_parse_object(state, &result->v.obj);

    case 'n':
        EXPECT_STRING(state, "null");
        result->type = NGX_JSON_NULL;
        return NGX_JSON_OK;

    case 't':
        EXPECT_STRING(state, "true");
        result->type = NGX_JSON_BOOL;
        result->v.boolean = 1;
        return NGX_JSON_OK;

    case 'f':
        EXPECT_STRING(state, "false");
        result->type = NGX_JSON_BOOL;
        result->v.boolean = 0;
        return NGX_JSON_OK;

    default:
        rc = ngx_json_parse_fraction(state, &result->v.num);
        if (rc != NGX_JSON_OK) {
            return rc;
        }

        result->type = result->v.num.denom == 1 ? NGX_JSON_INT : NGX_JSON_FRAC;
        return NGX_JSON_OK;
    }
}


ngx_json_status_t
ngx_json_parse(ngx_pool_t *pool, u_char *string, ngx_json_value_t *result,
    u_char *error, size_t error_size)
{
    ngx_json_status_t        rc;
    ngx_json_parser_state_t  state;

    state.pool = pool;
    state.cur_pos = string;
    state.depth = 0;
    state.error = error;
    state.error_size = error_size;
    error[0] = '\0';

    ngx_json_skip_spaces(&state);
    rc = ngx_json_parse_value(&state, result);
    if (rc != NGX_JSON_OK) {
        goto error;
    }

    ngx_json_skip_spaces(&state);
    if (*state.cur_pos) {
        ngx_snprintf(error, error_size, "trailing data after json value%Z");
        rc = NGX_JSON_BAD_DATA;
        goto error;
    }

    return NGX_JSON_OK;

error:

    error[error_size - 1] = '\0';       /* make sure it's null terminated */
    return rc;
}


static u_char *
ngx_json_unicode_hex_to_utf8(u_char *dest, u_char *src)
{
    ngx_int_t  ch;

    ch = ngx_hextoi(src, 4);
    if (ch < 0) {
        return NULL;
    }

    if (ch < 0x80) {
        *dest++ = (u_char) ch;

    } else if (ch < 0x800) {
        *dest++ = (ch >> 6) | 0xC0;
        *dest++ = (ch & 0x3F) | 0x80;

    } else if (ch < 0x10000) {
        *dest++ = (ch >> 12) | 0xE0;
        *dest++ = ((ch >> 6) & 0x3F) | 0x80;
        *dest++ = (ch & 0x3F) | 0x80;

    } else if (ch < 0x110000) {
        *dest++ = (ch >> 18) | 0xF0;
        *dest++ = ((ch >> 12) & 0x3F) | 0x80;
        *dest++ = ((ch >> 6) & 0x3F) | 0x80;
        *dest++ = (ch & 0x3F) | 0x80;

    } else {
        return NULL;
    }

    return dest;
}


ngx_json_status_t
ngx_json_decode_string(ngx_str_t *dest, ngx_str_t *src)
{
    u_char  *end_pos;
    u_char  *cur_pos;
    u_char  *p = dest->data + dest->len;

    cur_pos = src->data;
    end_pos = cur_pos + src->len;
    for (; cur_pos < end_pos; cur_pos++) {

        if (*cur_pos != '\\') {
            *p++ = *cur_pos;
            continue;
        }

        cur_pos++;
        if (cur_pos >= end_pos) {
            return NGX_JSON_BAD_DATA;
        }

        switch (*cur_pos) {

        case '"':
            *p++ = '"';
            break;

        case '\\':
            *p++ = '\\';
            break;

        case '/':
            *p++ = '/';
            break;

        case 'b':
            *p++ = '\b';
            break;

        case 'f':
            *p++ = '\f';
            break;

        case 'n':
            *p++ = '\n';
            break;

        case 'r':
            *p++ = '\r';
            break;

        case 't':
            *p++ = '\t';
            break;

        case 'u':
            if (cur_pos + 5 > end_pos) {
                return NGX_JSON_BAD_DATA;
            }

            p = ngx_json_unicode_hex_to_utf8(p, cur_pos + 1);
            if (p == NULL) {
                return NGX_JSON_BAD_DATA;
            }

            cur_pos += 4;
            break;

        default:
            return NGX_JSON_BAD_DATA;
        }
    }

    dest->len = p - dest->data;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_get_string(ngx_str_t *dst, ngx_json_esc_str_t *src)
{
    if (src->escape) {
        dst->data = src->s.data;
        dst->len = 0;

        return ngx_json_decode_string(dst, &src->s);

    } else {
        *dst = src->s;
    }

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_object_parse(ngx_pool_t *pool, ngx_json_object_t *object,
    ngx_json_prop_t **hash, ngx_uint_t size, void *dest)
{
    ngx_json_prop_t       *prop;
    ngx_json_status_t      rc;
    ngx_json_key_value_t  *cur;
    ngx_json_key_value_t  *last;

    cur = object->elts;
    last = cur + object->nelts;

    for (; cur < last; cur++) {
        prop = hash[cur->key_hash % size];
        if (prop == NULL) {
            continue;
        }

        if (prop->type != cur->value.type
            || prop->key_hash != cur->key_hash
            || prop->key.len != cur->key.len
            || ngx_strncmp(prop->key.data, cur->key.data, cur->key.len) != 0)
        {
            continue;
        }

        rc = prop->set(pool, &cur->value, prop, dest);
        if (rc != NGX_JSON_OK) {
            return rc;
        }
    }

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_num_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char     *p = dest;
    int64_t  *np;

    np = (int64_t *) (p + prop->offset);

    if (*np != NGX_JSON_UNSET) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_num_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    *np = value->v.num.num;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_flag_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char        *p = dest;
    ngx_flag_t  *fp;

    fp = (ngx_flag_t *) (p + prop->offset);

    if (*fp != NGX_JSON_UNSET) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_flag_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    *fp = value->v.boolean;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_str_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char       *p = dest;
    ngx_str_t  *sp;

    sp = (ngx_str_t *) (p + prop->offset);

    if (sp->data != NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_str_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    if (ngx_json_get_string(sp, &value->v.str) != NGX_JSON_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_str_slot: failed to decode string \"%V\"",
            &value->v.str.s);
        return NGX_JSON_BAD_DATA;
    }

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_raw_str_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char       *p = dest;
    ngx_str_t  *sp;

    sp = (ngx_str_t *) (p + prop->offset);

    if (sp->data != NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_raw_str_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    *sp = value->v.str.s;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_obj_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char                *p = dest;
    ngx_json_object_t  **op;

    op = (ngx_json_object_t **) (p + prop->offset);

    if (*op != NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_obj_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    *op = &value->v.obj;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_arr_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char               *p = dest;
    ngx_json_array_t  **ap;

    ap = (ngx_json_array_t **) (p + prop->offset);

    if (*ap != NGX_JSON_UNSET_PTR) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_arr_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    *ap = &value->v.arr;

    return NGX_JSON_OK;
}


ngx_json_status_t
ngx_json_set_enum_slot(ngx_pool_t *pool, ngx_json_value_t *value,
    ngx_json_prop_t *prop, void *dest)
{
    char        *p = dest;
    ngx_str_t   *e;
    ngx_uint_t  *np, i;

    np = (ngx_uint_t *) (p + prop->offset);

    if (*np != NGX_JSON_UNSET_UINT) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_json_set_enum_slot: duplicate key \"%V\"", &prop->key);
        return NGX_JSON_BAD_DATA;
    }

    e = prop->post;

    for (i = 0; e[i].len != 0; i++) {
        if (e[i].len != value->v.str.s.len
            || ngx_strncasecmp(e[i].data, value->v.str.s.data, e[i].len) != 0)
        {
            continue;
        }

        *np = i;

        return NGX_JSON_OK;
    }

    ngx_log_error(NGX_LOG_ERR, pool->log, 0,
        "ngx_json_set_enum_slot: invalid value \"%V\" for \"%V\" field",
        &value->v.str.s, &prop->key);
    return NGX_JSON_BAD_DATA;
}
