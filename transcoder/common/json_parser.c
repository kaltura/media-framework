
#include "json_parser.h"
#include "core.h"

// constants
#ifndef TRUE
#define TRUE (1)
#endif // TRUE

#ifndef FALSE
#define FALSE (0)
#endif // FALSE

// constants
#define MAX_JSON_ELEMENTS (65536)
#define MAX_RECURSION_DEPTH (32)

// macros
#define json_hash(key, c)   ((uintptr_t) key * 31 + c)

#define ASSERT_CHAR(state, ch)                                        \
if (*(state)->cur_pos != ch)                                    \
{                                                                \
snprintf(state->error, state->error_size, "expected 0x%xd got 0x%xd (%s)", (int)ch, (int)*(state)->cur_pos,(state)->cur_pos); \
return JSON_BAD_DATA;                                    \
}

#define EXPECT_CHAR(state, ch)                                        \
ASSERT_CHAR(state, ch)                                            \
(state)->cur_pos++;

#define EXPECT_STRING(state, str)                                    \
if (strncmp((state)->cur_pos, str, sizeof(str) - 1) != 0)    \
{                                                                \
snprintf(state->error, state->error_size, "expected %s", str); \
return JSON_BAD_DATA;                                    \
}                                                                \
(state)->cur_pos += sizeof(str) - 1;

// typedefs
typedef struct {
    pool_t* pool;
    char* cur_pos;
    int depth;
    char* error;
    size_t error_size;
} json_parser_state_t;

typedef struct {
    int type;
    size_t size;
    json_status_t (*parser)(json_parser_state_t* state, void* result);
} json_type_t;

// forward declarations
static json_status_t json_parse_value(json_parser_state_t* state, json_value_t* result);

static json_status_t json_parser_string(json_parser_state_t* state, void* result);
static json_status_t json_parser_array(json_parser_state_t* state, void* result);
static json_status_t json_parser_object(json_parser_state_t* state, void* result);
static json_status_t json_parser_bool(json_parser_state_t* state, void* result);
static json_status_t json_parser_frac(json_parser_state_t* state, void* result);
static json_status_t json_parser_int(json_parser_state_t* state, void* result);

// globals
static json_type_t json_string = {
    JSON_STRING, sizeof(str_t), json_parser_string
};

static json_type_t json_array = {
    JSON_ARRAY, sizeof(json_array_value_t), json_parser_array
};

static json_type_t json_object = {
    JSON_OBJECT, sizeof(json_object_t), json_parser_object
};

static json_type_t json_bool = {
    JSON_BOOL, sizeof(bool_t), json_parser_bool
};

static json_type_t json_frac = {
    JSON_FRAC, sizeof(json_fraction_t), json_parser_frac
};

static json_type_t json_int = {
    JSON_INT, sizeof(int64_t), json_parser_int
};

static void *
json_alloc(pool_t* pool, size_t size)
{
    return malloc(size);
}

static int
json_array_init(json_array_t *array, pool_t* pool, unsigned n, size_t size)
{
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    
    array->elts = json_alloc(pool, n * size);
    if (array->elts == NULL)
    {
        return JSON_ALLOC_FAILED;
    }
    
    return JSON_OK;
}

static void*
json_array_push(json_array_t *a)
{
    void *elt, *new_elts;
    
    if (a->nelts >= a->nalloc)
    {
        new_elts = realloc(a->elts, a->size * a->nalloc * 2);
        if (new_elts == NULL)
        {
            return NULL;
        }
        a->elts = new_elts;
        a->nalloc *= 2;
    }
    
    elt = (char *) a->elts + a->size * a->nelts;
    a->nelts++;
    
    return elt;
}

static json_status_t
json_get_value_type(json_parser_state_t* state, json_type_t** result)
{
    char* cur_pos = state->cur_pos;
    
    switch (*cur_pos)
    {
        case '"':
            *result = &json_string;
            return JSON_OK;
            
        case '[':
            *result = &json_array;
            return JSON_OK;
            
        case '{':
            *result = &json_object;
            return JSON_OK;
            
        case 'f':
        case 't':
            *result = &json_bool;
            return JSON_OK;
            
        default:
            break;        // handled outside the switch
    }
    
    if (*cur_pos == '-')
    {
        cur_pos++;
    }
    
    if (!isdigit(*cur_pos))
    {
        snprintf(state->error, state->error_size, "expected digit got 0x%xd", (int)*cur_pos);
        return JSON_BAD_DATA;
    }
    
    while (isdigit(*cur_pos))
    {
        cur_pos++;
    }
    
    if (*cur_pos == '.')
    {
        *result = &json_frac;
    }
    else
    {
        *result = &json_int;
    }
    return JSON_OK;
}

static void
json_skip_spaces(json_parser_state_t* state)
{
    for (; *state->cur_pos && isspace(*state->cur_pos); state->cur_pos++);
}

static json_status_t
json_parse_string(json_parser_state_t* state, str_t* result)
{
    char c;
    
    state->cur_pos++;        // skip the "
    
    result->data = state->cur_pos;
    
    for (;;)
    {
        c = *state->cur_pos;
        if (!c)
        {
            break;
        }
        
        switch (c)
        {
            case '\\':
                state->cur_pos++;
                if (!*state->cur_pos)
                {
                    snprintf(state->error, state->error_size, "end of data while parsing string (1)");
                    return JSON_BAD_DATA;
                }
                break;
                
            case '"':
                result->len = state->cur_pos - result->data;
                state->cur_pos++;
                return JSON_OK;
        }
        
        state->cur_pos++;
    }
    snprintf(state->error, state->error_size, "end of data while parsing string (2)");
    return JSON_BAD_DATA;
}

static json_status_t
json_parse_object_key(json_parser_state_t* state, json_key_value_t* result)
{
    uintptr_t hash = 0;
    char c;
    
    EXPECT_CHAR(state, '\"');
    
    result->key.data = state->cur_pos;
    
    for (;;)
    {
        c = *state->cur_pos;
        if (!c)
        {
            break;
        }
        
        if (c >= 'A' && c <= 'Z')
        {
            c |= 0x20;            // tolower
            *state->cur_pos = c;
        }
        
        switch (c)
        {
            case '\\':
                state->cur_pos++;
                if (!*state->cur_pos)
                {
                    snprintf(state->error, state->error_size, "end of data while parsing string (1)");
                    return JSON_BAD_DATA;
                }
                break;
                
            case '"':
                result->key.len = state->cur_pos - result->key.data;
                result->key_hash = hash;
                state->cur_pos++;
                return JSON_OK;
        }
        
        hash = json_hash(hash, c);
        
        state->cur_pos++;
    }
    
    snprintf(state->error, state->error_size, "end of data while parsing string (2)");
    return JSON_BAD_DATA;
}

static json_status_t
json_parse_int(json_parser_state_t* state, int64_t* result, bool_t* negative)
{
    int64_t value;
    
    if (*state->cur_pos == '-')
    {
        *negative = TRUE;
        state->cur_pos++;
    }
    else
    {
        *negative = FALSE;
    }
    
    if (!isdigit(*state->cur_pos))
    {
        snprintf(state->error, state->error_size, "expected digit got 0x%xd", (int)*state->cur_pos);
        return JSON_BAD_DATA;
    }
    
    value = 0;
    
    do
    {
        if (value > LLONG_MAX / 10 - 1)
        {
            snprintf(state->error, state->error_size, "number value overflow (1)");
            return JSON_BAD_DATA;
        }
        
        value = value * 10 + (*state->cur_pos - '0');
        state->cur_pos++;
    } while (isdigit(*state->cur_pos));
    
    *result = value;
    
    return JSON_OK;
}

static json_status_t
json_parse_fraction(json_parser_state_t* state, json_fraction_t* result)
{
    json_status_t rc;
    int64_t value;
    uint64_t denom = 1;
    bool_t negative;
    
    rc = json_parse_int(state, &value, &negative);
    if (rc != JSON_OK)
    {
        return rc;
    }
    
    if (*state->cur_pos == '.')
    {
        state->cur_pos++;
        
        if (!isdigit(*state->cur_pos))
        {
            snprintf(state->error, state->error_size, "expected digit got 0x%xd", (int)*state->cur_pos);
            return JSON_BAD_DATA;
        }
        
        do
        {
            if (value > LLONG_MAX / 10 - 1 || denom > ULLONG_MAX / 10)
            {
                snprintf(state->error, state->error_size, "number value overflow (2)");
                return JSON_BAD_DATA;
            }
            
            value = value * 10 + (*state->cur_pos - '0');
            denom *= 10;
            state->cur_pos++;
        } while (isdigit(*state->cur_pos));
    }
    
    if (negative)
    {
        value = -value;
    }
    
    result->num = value;
    result->denom = denom;
    
    return JSON_OK;
}

static json_status_t
json_parse_array(json_parser_state_t* state, json_array_value_t* result)
{
    json_type_t* type;
    void* cur_item;
    json_status_t rc;
    
    state->cur_pos++;        // skip the [
    json_skip_spaces(state);
    if (*state->cur_pos == ']')
    {
        result->type = JSON_NULL;
        result->items.nelts = 0;
        result->items.size = sizeof(*cur_item);
        result->items.nalloc = 0;
        result->items.pool = state->pool;
        result->items.elts = NULL;
        state->cur_pos++;
        return JSON_OK;
    }
    
    if (state->depth >= MAX_RECURSION_DEPTH)
    {
        snprintf(state->error, state->error_size, "max recursion depth exceeded");
        return JSON_BAD_DATA;
    }
    state->depth++;
    
    rc = json_get_value_type(state, &type);
    if (rc != JSON_OK)
    {
        return rc;
    }
    
    // initialize the result
    result->type = type->type;
    
    rc = json_array_init(&result->items, state->pool, 5, type->size);
    if (rc != JSON_OK)
    {
        return rc;
    }
    
    for (;;)
    {
        if (result->items.nelts >= MAX_JSON_ELEMENTS)
        {
            snprintf(state->error, state->error_size, "array elements count exceeds the limit");
            return JSON_BAD_DATA;
        }
        
        cur_item = json_array_push(&result->items);
        if (cur_item == NULL)
        {
            return JSON_ALLOC_FAILED;
        }
        
        rc = type->parser(state, cur_item);
        if (rc != JSON_OK)
        {
            return rc;
        }
        
        json_skip_spaces(state);
        switch (*state->cur_pos)
        {
            case ']':
                state->cur_pos++;
                goto done;
                
            case ',':
                state->cur_pos++;
                json_skip_spaces(state);
                continue;
        }
        
        snprintf(state->error, state->error_size, "expected , or ] while parsing array, got 0x%xd", (int)*state->cur_pos);
        return JSON_BAD_DATA;
    }
    
done:
    
    state->depth--;
    return JSON_OK;
}

static json_status_t
json_parse_object(json_parser_state_t* state, json_object_t* result)
{
    json_key_value_t* cur_item;
    json_status_t rc;
    
    state->cur_pos++;        // skip the {
    json_skip_spaces(state);
    if (*state->cur_pos == '}')
    {
        result->nelts = 0;
        result->size = sizeof(*cur_item);
        result->nalloc = 0;
        result->pool = state->pool;
        result->elts = NULL;
        
        state->cur_pos++;
        return JSON_OK;
    }
    
    if (state->depth >= MAX_RECURSION_DEPTH)
    {
        snprintf(state->error, state->error_size, "max recursion depth exceeded");
        return JSON_BAD_DATA;
    }
    state->depth++;
    
    rc = json_array_init(result, state->pool, 5, sizeof(*cur_item));
    if (rc != JSON_OK)
    {
        return rc;
    }
    
    for (;;)
    {
        if (result->nelts >= MAX_JSON_ELEMENTS)
        {
            snprintf(state->error, state->error_size, "object elements count exceeds the limit");
            return JSON_BAD_DATA;
        }
        
        cur_item = (json_key_value_t*)json_array_push(result);
        if (cur_item == NULL)
        {
            return JSON_ALLOC_FAILED;
        }
        
        rc = json_parse_object_key(state, cur_item);
        if (rc != JSON_OK)
        {
            return rc;
        }
        
        json_skip_spaces(state);
        EXPECT_CHAR(state, ':');
        json_skip_spaces(state);
        
        rc = json_parse_value(state, &cur_item->value);
        if (rc != JSON_OK)
        {
            return rc;
        }
        
        json_skip_spaces(state);
        switch (*state->cur_pos)
        {
            case '}':
                state->cur_pos++;
                state->depth--;
                return JSON_OK;
                
            case ',':
                state->cur_pos++;
                json_skip_spaces(state);
                continue;
        }
        
        snprintf(state->error, state->error_size, "expected , or } while parsing object, got 0x%xd (%s)", (int)*state->cur_pos,state->cur_pos);
        return JSON_BAD_DATA;
    }
}

static json_status_t
json_parser_string(json_parser_state_t* state, void* result)
{
    ASSERT_CHAR(state, '"');
    return json_parse_string(state, (str_t*)result);
}

static json_status_t
json_parser_array(json_parser_state_t* state, void* result)
{
    ASSERT_CHAR(state, '[');
    return json_parse_array(state, (json_array_value_t*)result);
}

static json_status_t
json_parser_object(json_parser_state_t* state, void* result)
{
    ASSERT_CHAR(state, '{');
    return json_parse_object(state, (json_object_t*)result);
}

static json_status_t
json_parser_bool(json_parser_state_t* state, void* result)
{
    switch (*state->cur_pos)
    {
        case 't':
            EXPECT_STRING(state, "true");
            *(bool_t*)result = TRUE;
            return JSON_OK;
            
        case 'f':
            EXPECT_STRING(state, "false");
            *(bool_t*)result = FALSE;
            return JSON_OK;
    }
    
    snprintf(state->error, state->error_size, "expected true or false");
    return JSON_BAD_DATA;
}

static json_status_t
json_parser_frac(json_parser_state_t* state, void* result)
{
    return json_parse_fraction(state, (json_fraction_t*)result);
}

static json_status_t
json_parser_int(json_parser_state_t* state, void* result)
{
    json_status_t rc;
    bool_t negative;
    
    rc = json_parse_int(state, (int64_t*)result, &negative);
    
    if (negative)
    {
        *(int64_t*)result = -(*(int64_t*)result);
    }
    
    return rc;
}

static json_status_t
json_parse_value(json_parser_state_t* state, json_value_t* result)
{
    json_status_t rc;
    
    switch (*state->cur_pos)
    {
        case '"':
            result->type = JSON_STRING;
            return json_parse_string(state, &result->v.str);
            
        case '[':
            result->type = JSON_ARRAY;
            return json_parse_array(state, &result->v.arr);
            
        case '{':
            result->type = JSON_OBJECT;
            return json_parse_object(state, &result->v.obj);
            
        case 'n':
            EXPECT_STRING(state, "null");
            result->type = JSON_NULL;
            return JSON_OK;
            
        case 't':
            EXPECT_STRING(state, "true");
            result->type = JSON_BOOL;
            result->v.boolean = TRUE;
            return JSON_OK;
            
        case 'f':
            EXPECT_STRING(state, "false");
            result->type = JSON_BOOL;
            result->v.boolean = FALSE;
            return JSON_OK;
            
        default:
            rc = json_parse_fraction(state, &result->v.num);
            if (rc != JSON_OK)
            {
                return rc;
            }
            
            result->type = result->v.num.denom == 1 ? JSON_INT : JSON_FRAC;
            return JSON_OK;
    }
}

json_status_t
json_parse(pool_t* pool, char* string, json_value_t* result, char* error, size_t error_size)
{
    json_parser_state_t state;
    json_status_t rc;
    
    state.pool = pool;
    state.cur_pos = string;
    state.depth = 0;
    state.error = error;
    state.error_size = error_size;
    error[0] = '\0';
    
    json_skip_spaces(&state);
    rc = json_parse_value(&state, result);
    if (rc != JSON_OK)
    {
        goto error;
    }
    json_skip_spaces(&state);
    if (*state.cur_pos)
    {
        snprintf(error, error_size, "trailing data after json value");
        rc = JSON_BAD_DATA;
        goto error;
    }
    
    return JSON_OK;
    
error:
    
    error[error_size - 1] = '\0';            // make sure it's null terminated
    return rc;
}

static intptr_t
json_hextoi(char *line, size_t n)
{
    char c, ch;
    intptr_t value, cutoff;
    
    if (n == 0)
    {
        return -1;
    }
    
    cutoff = LONG_MAX / 16;
    
    for (value = 0; n--; line++)
    {
        if (value > cutoff)
        {
            return -1;
        }
        
        ch = *line;
        
        if (ch >= '0' && ch <= '9')
        {
            value = value * 16 + (ch - '0');
            continue;
        }
        
        c = (u_char) (ch | 0x20);
        
        if (c >= 'a' && c <= 'f')
        {
            value = value * 16 + (c - 'a' + 10);
            continue;
        }
        
        return -1;
    }
    
    return value;
}

static char*
json_unicode_hex_to_utf8(char* dest, char* src)
{
    intptr_t ch;
    
    ch = json_hextoi(src, 4);
    if (ch < 0)
    {
        return NULL;
    }
    
    if (ch < 0x80)
    {
        *dest++ = (char)ch;
    }
    else if (ch < 0x800)
    {
        *dest++ = (ch >> 6) | 0xC0;
        *dest++ = (ch & 0x3F) | 0x80;
    }
    else if (ch < 0x10000)
    {
        *dest++ = (ch >> 12) | 0xE0;
        *dest++ = ((ch >> 6) & 0x3F) | 0x80;
        *dest++ = (ch & 0x3F) | 0x80;
    }
    else if (ch < 0x110000)
    {
        *dest++ = (ch >> 18) | 0xF0;
        *dest++ = ((ch >> 12) & 0x3F) | 0x80;
        *dest++ = ((ch >> 6) & 0x3F) | 0x80;
        *dest++ = (ch & 0x3F) | 0x80;
    }
    else
    {
        return NULL;
    }
    
    return dest;
}

json_status_t
json_decode_string(str_t* dest, str_t* src)
{
    char* end_pos;
    char* cur_pos;
    char* p = dest->data + dest->len;
    
    cur_pos = src->data;
    end_pos = cur_pos + src->len;
    for (; cur_pos < end_pos; cur_pos++)
    {
        if (*cur_pos != '\\')
        {
            *p++ = *cur_pos;
            continue;
        }
        
        cur_pos++;
        if (cur_pos >= end_pos)
        {
            return JSON_BAD_DATA;
        }
        
        switch (*cur_pos)
        {
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
                if (cur_pos + 5 > end_pos)
                {
                    return JSON_BAD_DATA;
                }
                
                p = json_unicode_hex_to_utf8(p, cur_pos + 1);
                if (p == NULL)
                {
                    return JSON_BAD_DATA;
                }
                cur_pos += 4;
                break;
            default:
                return JSON_BAD_DATA;
        }
    }
    
    dest->len = p - dest->data;
    
    return JSON_OK;
}

int strlen2(char *str,size_t count)
{
    int len=0;
    while (str[len]!='.' && str[len]!=0 && len<count) {
        len++;
    }
    return len;
}

json_status_t json_get(const json_value_t* obj,char* path,const json_value_t** result)
{
    if (path==NULL || *path==0) {
        *result=obj;
        return JSON_OK;
    }
    char* key=path;
    
    for (;;)
    {
        if (*path== '.' || *path==0)
        {
            //*path=0;
            if (obj->type==JSON_OBJECT) {
                json_object_t nobj=obj->v.obj;
                json_key_value_t* elobj=(json_key_value_t*)nobj.elts;
                for (int i=0;i<nobj.nelts;i++)
                {
                    char* k=elobj->key.data;
                    size_t count=elobj->key.len;
                    if (strncasecmp(key,k,count)==0 && strlen2(key,100)==strlen2(k,count)) {
                        if (*path=='.')
                            path++;
                        return json_get(&elobj->value,path,result);
                    }
                    elobj+=1;
                }
            }
            if (obj->type==JSON_ARRAY) {
                return json_get_array_index(obj,0,result);
            }
            return JSON_BAD_DATA;
        }
        path++;
    } 
    return JSON_OK;
}
size_t json_get_array_count(const json_value_t* obj) {
    if (obj->type!=JSON_ARRAY)
        return 0;
    
    return (size_t)obj->v.arr.items.nelts;
}

json_status_t json_get_array_index(const json_value_t* obj,int index,  json_value_t* result)
{
    if (obj->type!=JSON_ARRAY)
        return JSON_BAD_DATA;
    
    result->type = obj->v.arr.type;

    void* data=obj->v.arr.items.elts + obj->v.arr.items.size*index;

    if (result->type ==JSON_OBJECT) {
        json_object_t* item=(json_object_t*)data;
        result->v.obj=*item;
        return JSON_OK;

    }
    return JSON_OK;

}
json_status_t json_get_string(const json_value_t* obj,char* path,const char* defaultValue,char* result)
{
    const json_value_t* jresult;
    json_status_t ret=json_get(obj,path,&jresult);
    if (ret!=JSON_OK){
        strcpy(result,defaultValue);
        return ret;
    }
    
    if (jresult->type!=JSON_STRING) {
        return JSON_BAD_DATA;
    }
    char *str=malloc(jresult->v.str.len+1);
    memcpy(str,jresult->v.str.data,jresult->v.str.len);
    str[jresult->v.str.len]=0;
    strcpy(result,str);
    return JSON_OK;
}

json_status_t json_get_int(const json_value_t* obj,char* path,int defaultValue,int* result)
{
    int64_t t;
    json_status_t ret=json_get_int64(obj,path,defaultValue,&t);
    if (ret!=JSON_OK){
        *result=defaultValue;
        return ret;
    }
    
    *result=(int)t;
    return JSON_OK;
}

json_status_t json_get_int64(const json_value_t* obj,char* path,int64_t defaultValue,int64_t* result)
{
    json_value_t* jresult;
    json_status_t ret=json_get(obj,path,&jresult);
    if (ret!=JSON_OK){
        *result=defaultValue;
        return ret;
    }
    
    if (jresult->type!=JSON_INT) {
        return JSON_BAD_DATA;
    }
    *result=jresult->v.num.num;
    return JSON_OK;
}



json_status_t json_get_bool(const json_value_t* obj,char* path,bool defaultValue,bool* result)
{
    json_value_t* jresult;
    json_status_t ret=json_get(obj,path,&jresult);
    if (ret!=JSON_OK){
        *result=defaultValue;
        return ret;
    }
    
    if (jresult->type!=JSON_BOOL) {
        return JSON_BAD_DATA;
    }
    *result=jresult->v.boolean;
    return JSON_OK;
}

json_status_t json_get_double(const json_value_t* obj,char* path,double defaultValue,double* result)
{
    json_value_t* jresult;
    json_status_t ret=json_get(obj,path,&jresult);
    if (ret!=JSON_OK){
        *result=defaultValue;
        return ret;
    }
    
    if (jresult->type!=JSON_FRAC) {
        return JSON_BAD_DATA;
    }
    *result = ((double)jresult->v.num.denom) / ((double)jresult->v.num.num);
    return JSON_OK;
}
