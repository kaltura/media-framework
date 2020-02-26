#include <ngx_config.h>
#include <ngx_core.h>
#include <ctype.h>
#include "ngx_json_parser.h"


// constants
#define NGX_JSON_MAX_ELEMENTS           (524288)
#define NGX_JSON_MAX_RECURSION_DEPTH    (32)
#define NGX_JSON_PART_FIRST_COUNT       (5)
#define NGX_JSON_PART_MAX_SIZE          (65536)


// macros
#define ASSERT_CHAR(state, ch)                                      \
    if (*(state)->cur_pos != ch) {                                  \
        ngx_snprintf(state->error, state->error_size,               \
            "expected 0x%xd got 0x%xd%Z",                           \
            (int)ch, (int)*(state)->cur_pos);                       \
        return NGX_JSON_BAD_DATA;                                   \
    }

#define EXPECT_CHAR(state, ch)                                      \
    ASSERT_CHAR(state, ch)                                          \
    (state)->cur_pos++;

#define EXPECT_STRING(state, str)                                   \
    if (ngx_strncmp((state)->cur_pos, str, sizeof(str) - 1) != 0) { \
        ngx_snprintf(state->error, state->error_size,               \
            "expected %s%Z", str);                                  \
        return NGX_JSON_BAD_DATA;                                   \
    }                                                               \
    (state)->cur_pos += sizeof(str) - 1;


// typedefs
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

// forward declarations
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


// globals
static ngx_json_type_t  ngx_json_string = {
    NGX_JSON_STRING, sizeof(ngx_str_t), ngx_json_parser_string
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
        break;      // handled outside the switch
    }

    if (*cur_pos == '-') {
        cur_pos++;
    }

    if (!isdigit(*cur_pos)) {
        ngx_snprintf(state->error, state->error_size,
            "expected digit got 0x%xd%Z", (int)*cur_pos);
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
ngx_json_parse_string(ngx_json_parser_state_t *state, ngx_str_t *result)
{
    u_char  c;

    state->cur_pos++;       // skip the "

    result->data = state->cur_pos;

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
            break;

        case '"':
            result->len = state->cur_pos - result->data;
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
    ngx_uint_t  hash = 0;
    u_char      c;

    EXPECT_CHAR(state, '\"');

    result->key.data = state->cur_pos;

    for ( ;; ) {

        c = *state->cur_pos;
        if (!c) {
            break;
        }

        if (c >= 'A' && c <= 'Z') {
            c |= 0x20;          // tolower
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
            "expected digit got 0x%xd%Z", (int)*state->cur_pos);
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
    ngx_json_status_t  rc;
    int64_t            value;
    uint64_t           denom = 1;
    ngx_flag_t         negative;

    rc = ngx_json_parse_int(state, &value, &negative);
    if (rc != NGX_JSON_OK) {
        return rc;
    }

    if (*state->cur_pos == '.') {
        state->cur_pos++;

        if (!isdigit(*state->cur_pos)) {
            ngx_snprintf(state->error, state->error_size,
                "expected digit got 0x%xd%Z", (int)*state->cur_pos);
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

    return NGX_OK;
}

static ngx_json_status_t
ngx_json_parse_array(ngx_json_parser_state_t *state, ngx_json_array_t *result)
{
    ngx_array_part_t   *part;
    ngx_json_status_t   rc;
    ngx_json_type_t    *type;
    size_t              initial_part_count;
    size_t              part_size;
    void               *cur_item;

    state->cur_pos++;       // skip the [
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

    // initialize the result and first part
    result->type = type->type;
    result->count = 0;
    part = &result->part;
    part_size = type->size * NGX_JSON_PART_FIRST_COUNT;
    cur_item = ngx_palloc(state->pool, part_size);
    if (cur_item == NULL) {
        return NGX_JSON_ALLOC_FAILED;
    }
    part->first = cur_item;
    part->last = (u_char*)cur_item + part_size;

    for ( ;; ) {
        if (result->count >= NGX_JSON_MAX_ELEMENTS) {
            ngx_snprintf(state->error, state->error_size,
                "array elements count exceeds the limit%Z");
            return NGX_JSON_BAD_DATA;
        }

        if (cur_item >= part->last) {
            // update the part count
            part->count = result->count - initial_part_count;
            initial_part_count = result->count;

            // allocate another part
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
            part->last = (u_char*)cur_item + part_size;
        }

        rc = type->parser(state, cur_item);
        if (rc != NGX_JSON_OK) {
            return rc;
        }

        cur_item = (u_char*)cur_item + type->size;
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
            (int)*state->cur_pos);
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
    ngx_json_key_value_t  *cur_item;
    ngx_int_t              rc;

    state->cur_pos++;       // skip the {
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

        cur_item = (ngx_json_key_value_t*)ngx_array_push(result);
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
            (int)*state->cur_pos);
        return NGX_JSON_BAD_DATA;
    }
}

static ngx_json_status_t
ngx_json_parser_string(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '"');
    return ngx_json_parse_string(state, (ngx_str_t*)result);
}

static ngx_json_status_t
ngx_json_parser_array(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '[');
    return ngx_json_parse_array(state, (ngx_json_array_t*)result);
}

static ngx_json_status_t
ngx_json_parser_object(ngx_json_parser_state_t *state, void *result)
{
    ASSERT_CHAR(state, '{');
    return ngx_json_parse_object(state, (ngx_json_object_t*)result);
}

static ngx_json_status_t
ngx_json_parser_bool(ngx_json_parser_state_t *state, void *result)
{
    switch (*state->cur_pos) {

    case 't':
        EXPECT_STRING(state, "true");
        *(ngx_flag_t*)result = 1;
        return NGX_JSON_OK;

    case 'f':
        EXPECT_STRING(state, "false");
        *(ngx_flag_t*)result = 0;
        return NGX_JSON_OK;
    }

    ngx_snprintf(state->error, state->error_size, "expected true or false%Z");
    return NGX_JSON_BAD_DATA;
}

static ngx_json_status_t
ngx_json_parser_frac(ngx_json_parser_state_t *state, void *result)
{
    return ngx_json_parse_fraction(state, (ngx_json_fraction_t*)result);
}

static ngx_json_status_t
ngx_json_parser_int(ngx_json_parser_state_t *state, void *result)
{
    ngx_json_status_t  rc;
    ngx_flag_t         negative;

    rc = ngx_json_parse_int(state, (int64_t*)result, &negative);

    if (negative) {
        *(int64_t*)result = -(*(int64_t*)result);
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
    ngx_json_parser_state_t  state;
    ngx_json_status_t        rc;

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

    error[error_size - 1] = '\0';           // make sure it's null terminated
    return rc;
}

static u_char*
ngx_json_unicode_hex_to_utf8(u_char *dest, u_char *src)
{
    ngx_int_t  ch;

    ch = ngx_hextoi(src, 4);
    if (ch < 0) {
        return NULL;
    }

    if (ch < 0x80) {
        *dest++ = (u_char)ch;

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

    return NGX_OK;
}

void
ngx_json_get_object_values(ngx_json_object_t *object,
    ngx_json_object_key_def_t *key_defs, ngx_json_value_t **result)
{
    ngx_json_key_value_t       *cur_element = object->elts;
    ngx_json_key_value_t       *last_element = cur_element + object->nelts;
    ngx_json_object_key_def_t  *key_def;

    for (; cur_element < last_element; cur_element++) {

        for (key_def = key_defs; key_def->key.len != 0; key_def++) {
            if (key_def->key.len == cur_element->key.len &&
                ngx_memcmp(key_def->key.data, cur_element->key.data,
                    cur_element->key.len) == 0) {
                break;
            }
        }

        if (key_def->key.len == 0) {
            continue;
        }

        if (cur_element->value.type == key_def->type ||
            (cur_element->value.type == NGX_JSON_INT &&
                key_def->type == NGX_JSON_FRAC)) {  // allow int for a fraction
            result[key_def->index] = &cur_element->value;
        }
    }
}

#if 0       // XXXXX
ngx_status_t
ngx_json_init_hash(ngx_pool_t *pool, ngx_pool_t *temp_pool, char *hash_name,
    void *elements, size_t element_size, ngx_hash_t *result)
{
    ngx_array_t       elements_arr;
    ngx_hash_key_t   *hash_key;
    ngx_hash_init_t   hash;
    ngx_str_t        *cur_key;
    u_char           *element;

    if (ngx_array_init(&elements_arr, temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK) {
        return ngx_palloc_FAILED;
    }

    for (element = elements; ; element += element_size) {
        cur_key = (ngx_str_t*)element;
        if (cur_key->len == 0) {
            break;
        }

        hash_key = ngx_array_push(&elements_arr);
        if (hash_key == NULL) {
            return ngx_palloc_FAILED;
        }

        hash_key->key = *cur_key;
        hash_key->key_hash = ngx_hash_key_lc(cur_key->data, cur_key->len);
        hash_key->value = element;
    }

    hash.hash = result;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = hash_name;
    hash.pool = pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, elements_arr.elts, elements_arr.nelts)
        != NGX_OK) {
        return ngx_palloc_FAILED;
    }

    return NGX_OK;
}

void
ngx_json_get_object_values(ngx_json_object_t *object, ngx_hash_t *values_hash,
    ngx_json_value_t **result)
{
    ngx_json_key_value_t       *cur_element = object->elts;
    ngx_json_key_value_t       *last_element = cur_element + object->nelts;
    ngx_json_object_key_def_t  *key_def;

    for (; cur_element < last_element; cur_element++) {
        key_def = ngx_hash_find(
            values_hash,
            cur_element->key_hash,
            cur_element->key.data,
            cur_element->key.len);
        if (key_def == NULL) {
            continue;
        }

        if (cur_element->value.type == key_def->type ||
            (cur_element->value.type == NGX_JSON_INT &&
                key_def->type == NGX_JSON_FRAC)) {  // allow int for fraction
            result[key_def->index] = &cur_element->value;
        }
    }
}

ngx_status_t
ngx_json_parse_object_values(ngx_json_object_t *object,
    ngx_hash_t *values_hash, void *context, void *result)
{
    ngx_json_key_value_t     *cur_element = object->elts;
    ngx_json_key_value_t     *last_element = cur_element + object->nelts;
    json_object_value_def_t  *parser;
    ngx_status_t              rc;

    for (; cur_element < last_element; cur_element++) {

        parser = ngx_hash_find(
            values_hash,
            cur_element->key_hash,
            cur_element->key.data,
            cur_element->key.len);
        if (parser == NULL) {
            continue;
        }

        if (cur_element->value.type != parser->type &&
            (cur_element->value.type != NGX_JSON_INT ||
                parser->type != NGX_JSON_FRAC)) {
            continue;
        }

        rc = parser->parse(context, &cur_element->value,
            (u_char*)result + parser->offset);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

ngx_status_t
ngx_json_parse_union(request_context_t *request_context,
    ngx_json_object_t *object, ngx_str_t *type_field,
    ngx_uint_t type_field_hash, ngx_hash_t *union_hash, void *context,
    void **dest)
{
    u_char                         c;
    u_char                        *cur_pos;
    u_char                        *type_end;
    ngx_str_t                      type = ngx_null_string;
    ngx_uint_t                     key;
    ngx_json_key_value_t          *cur;
    ngx_json_key_value_t          *last;
    json_parser_union_type_def_t  *type_def;

    // get the object type
    cur = (ngx_json_key_value_t*)object->elts;
    last = cur + object->nelts;

    for (; cur < last; cur++) {
        if (cur->key_hash != type_field_hash ||
            cur->key.len != type_field->len ||
            ngx_memcmp(cur->key.data, type_field->data, type_field->len)
            != 0) {
            continue;
        }

        if (cur->value.type != NGX_JSON_STRING) {
            ngx_log_error(NGX_LOG_ERR, request_context->log, 0,
                "ngx_json_parse_union: \"%V\" field has an invalid type %d",
                type_field, cur->value.type);
            return NGX_BAD_REQUEST;
        }

        type = cur->value.v.str;
        break;
    }

    if (type.len == 0) {
        ngx_log_error(NGX_LOG_ERR, request_context->log, 0,
            "ngx_json_parse_union: missing \"%V\" field", type_field);
        return NGX_BAD_REQUEST;
    }

    // calculate key and to lower
    key = 0;

    type_end = type.data + type.len;
    for (cur_pos = type.data; cur_pos < type_end; cur_pos++) {
        c = *cur_pos;
        if (c >= 'A' && c <= 'Z') {
            c |= 0x20;          // tolower
            *cur_pos = c;
        }

        key = ngx_hash(key, c);
    }

    // find the type definition
    type_def = ngx_hash_find(
        union_hash,
        key,
        type.data,
        type.len);
    if (type_def == NULL) {
        ngx_log_error(NGX_LOG_ERR, request_context->log, 0,
            "ngx_json_parse_union: unknown object type \"%V\"", &type);
        return NGX_BAD_REQUEST;
    }

    return type_def->parser(context, object, dest);
}

static ngx_json_key_value_t*
ngx_json_get_object_value(ngx_json_object_t *object, ngx_uint_t key_hash,
    ngx_str_t *key)
{
    ngx_json_key_value_t  *cur_element = object->elts;
    ngx_json_key_value_t  *last_element = cur_element + object->nelts;

    for (; cur_element < last_element; cur_element++) {
        if (cur_element->key_hash == key_hash &&
            cur_element->key.len == key->len &&
            ngx_memcmp(cur_element->key.data, key->data, key->len) == 0) {
            return cur_element;
        }
    }

    return NULL;
}

static ngx_status_t
ngx_json_replace_object(ngx_json_object_t *object1, ngx_json_object_t *object2)
{
    ngx_json_key_value_t  *cur_element;
    ngx_json_key_value_t  *last_element;
    ngx_json_key_value_t  *dest_element;

    cur_element = object2->elts;
    last_element = cur_element + object2->nelts;
    for (; cur_element < last_element; cur_element++) {

        dest_element = ngx_json_get_object_value(object1,
            cur_element->key_hash, &cur_element->key);
        if (dest_element != NULL) {
            ngx_json_replace(&dest_element->value, &cur_element->value);
            continue;
        }

        dest_element = (ngx_json_key_value_t*)ngx_array_push(object1);
        if (dest_element == NULL) {
            return ngx_palloc_FAILED;
        }

        *dest_element = *cur_element;
    }

    return NGX_OK;
}

static ngx_status_t
ngx_json_replace_array(ngx_json_array_t *array1, ngx_json_array_t *array2)
{
    ngx_json_object_t  *cur_object1;
    ngx_json_object_t  *cur_object2;
    ngx_array_part_t   *part1;
    ngx_array_part_t   *part2;
    ngx_status_t        rc;

    if (array1->type != NGX_JSON_OBJECT || array2->type != NGX_JSON_OBJECT) {
        *array1 = *array2;
        return NGX_OK;
    }

    part1 = &array1->part;
    part2 = &array2->part;

    for (cur_object1 = part1->first, cur_object2 = part2->first;
        ;
        cur_object1++, cur_object2++) {
        if ((void*)cur_object2 >= part2->last) {
            if (part2->next == NULL) {
                break;
            }

            part2 = part2->next;
            cur_object2 = part2->first;
        }

        if ((void*)cur_object1 >= part1->last) {
            if (part1->next == NULL) {
                // append the second array to the first
                part2->first = cur_object2;
                part2->count = (ngx_json_object_t*)part2->last - cur_object2;
                part1->next = part2;
                array1->count = array2->count;
                break;
            }

            part1 = part1->next;
            cur_object1 = part1->first;
        }

        rc = ngx_json_replace_object(cur_object1, cur_object2);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

ngx_status_t
ngx_json_replace(ngx_json_value_t *json1, ngx_json_value_t *json2)
{
    if (json1->type != json2->type) {
        *json1 = *json2;
        return NGX_OK;
    }

    switch (json1->type) {

    case NGX_JSON_OBJECT:
        return ngx_json_replace_object(&json1->v.obj, &json2->v.obj);

    case NGX_JSON_ARRAY:
        return ngx_json_replace_array(&json1->v.arr, &json2->v.arr);

    default:
        *json1 = *json2;
        break;
    }

    return NGX_OK;
}
#endif