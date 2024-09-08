#ifndef __JSON_PARSER_H__
#define __JSON_PARSER_H__

// includes
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
// enums
enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_INT,
    JSON_FRAC,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
};

enum {
    JSON_OK = 0,
    JSON_BAD_DATA = -1,
    JSON_ALLOC_FAILED = -2,
    JSON_BAD_LENGTH = -3,
    JSON_BAD_TYPE = -4,
};

// typedefs
typedef intptr_t bool_t;
typedef intptr_t json_status_t;
typedef void pool_t;

typedef struct {
    size_t len;
    char *data;
} str_t;

typedef struct {
    int64_t num;
    uint64_t denom;
} json_fraction_t;

typedef struct {
    void *elts;
    uintptr_t nelts;
    size_t size;
    uintptr_t nalloc;
    pool_t* pool;
} json_array_t;

typedef struct {
    int type;
    json_array_t items;
} json_array_value_t;

typedef json_array_t json_object_t;

typedef struct {
    int type;
    union {
        bool_t boolean;
        json_fraction_t num;
        str_t str;            // Note: the string is escaped (e.g. may contain \n, \t etc.)
        json_array_value_t arr;
        json_object_t obj;    // of json_key_value_t
    } v;
} json_value_t;

typedef struct {
    uintptr_t key_hash;
    str_t key;
    json_value_t value;
} json_key_value_t;

// functions
json_status_t json_parse(
                         pool_t* pool,
                         char* string,
                         json_value_t* result,
                         char* error,
                         size_t error_size);

json_status_t json_decode_string(str_t* dest, str_t* src);


json_status_t json_get(const json_value_t* obj,char* path,const json_value_t** result);
json_status_t json_get_string(const json_value_t* obj,char* path,const char* defaultValue,char* result,size_t maxlen);
json_status_t json_get_int(const json_value_t* obj,char* path,int defaultValue,int* result);
json_status_t json_get_int64(const json_value_t* obj,char* path,int64_t defaultValue,int64_t* result);
json_status_t json_get_bool(const json_value_t* obj,char* path,bool defaultValue,bool* result);
json_status_t json_get_double(const json_value_t* obj,char* path,double defaultValue,double* result);

size_t json_get_array_count(const json_value_t* obj);
json_status_t json_get_array_index(const json_value_t* obj,int index, json_value_t* result);

typedef struct {
    char *start, *cur, *end;
    bool shouldAddComma;
}json_writer_ctx_s,  *json_writer_ctx_t;

#define JSON_SERIALIZE_INIT(buf,size) \
  json_writer_ctx_s js_s = {.start = buf, .cur = buf,.end = buf + size,.shouldAddComma = false}; \
  json_writer_ctx_t js = &js_s; \
  JSON_SERIALIZE_SCOPE_BEGIN();

#define JSON_WRITE(args...) js->cur += snprintf(js->cur,js->end-js->cur,args);
#define JSON_WRITTEN()  (js->cur-js->start)
#define ADD_COMMA() if (js->shouldAddComma) { JSON_WRITE(","); js->shouldAddComma=false;}

#define JSON_SERIALIZE_SCOPE_BEGIN()      ADD_COMMA() JSON_WRITE("{");
#define JSON_SERIALIZE_END()              JSON_WRITE("}");  js->shouldAddComma=true;
#define JSON_SERIALIZE_OBJECT_BEGIN(key)  ADD_COMMA() JSON_WRITE("\"%s\": {",key); js->shouldAddComma=false;
#define JSON_SERIALIZE_OBJECT_END         JSON_SERIALIZE_END
#define JSON_SERIALIZE_ARRAY_START(key)   ADD_COMMA() JSON_WRITE("\"%s\": [",key);  js->shouldAddComma=false;
#define JSON_SERIALIZE_ARRAY_ITEM()       js->shouldAddComma = true;
#define JSON_SERIALIZE_ARRAY_END()        JSON_WRITE("]"); js->shouldAddComma=true;

#define JSON_SERIALIZE_STRING(key,value)  ADD_COMMA() JSON_WRITE("\"%s\": \"%s\"",key,value); js->shouldAddComma=true;
#define JSON_SERIALIZE_INT(key,value)     ADD_COMMA() JSON_WRITE("\"%s\": %d",key,value); js->shouldAddComma=true;
#define JSON_SERIALIZE_INT64(key,value)   ADD_COMMA() JSON_WRITE("\"%s\": %ld",key,value); js->shouldAddComma=true;
#define JSON_SERIALIZE_BOOL(key,value)    ADD_COMMA() JSON_WRITE("\"%s\": %s",key,value ? "true" : "false"); js->shouldAddComma=true;
#define JSON_SERIALIZE_DOUBLE(key,value)  ADD_COMMA() JSON_WRITE("\"%s\": %.2lf",key,value); js->shouldAddComma=true;

#endif // __JSON_PARSER_H__
