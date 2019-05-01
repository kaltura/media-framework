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
json_status_t json_get_string(const json_value_t* obj,char* path,const char* defaultValue,char* result);
json_status_t json_get_int(const json_value_t* obj,char* path,int defaultValue,int* result);
json_status_t json_get_int64(const json_value_t* obj,char* path,int64_t defaultValue,int64_t* result);
json_status_t json_get_bool(const json_value_t* obj,char* path,bool defaultValue,bool* result);
json_status_t json_get_double(const json_value_t* obj,char* path,double defaultValue,double* result);

size_t json_get_array_count(const json_value_t* obj);
json_status_t json_get_array_index(const json_value_t* obj,int index, json_value_t* result);


#define JSON_SERIALIZE_INIT(buf) char * jsbuffer=buf; int n=0; bool shouldAddComma=false; n+=sprintf(jsbuffer,"{");
#define ADD_COMMA() if (shouldAddComma) { n+=sprintf(jsbuffer+n,","); shouldAddComma=false;}
#define JSON_SERIALIZE_STRING(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": \"%s\"",key,value); shouldAddComma=true;
#define JSON_SERIALIZE_INT(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": %d",key,value); shouldAddComma=true;
#define JSON_SERIALIZE_INT64(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": %lld",key,value); shouldAddComma=true;
#define JSON_SERIALIZE_BOOL(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": %s",key,value ? "true" : "false"); shouldAddComma=true;
#define JSON_SERIALIZE_DOUBLE(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": %.2lf",key,value); shouldAddComma=true;
#define JSON_SERIALIZE_OBJECT(key,value)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": %s",key,value); shouldAddComma=true;
#define JSON_SERIALIZE_OBJECT_BEGIN(key)  ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": {",key); shouldAddComma=false;
#define JSON_SERIALIZE_OBJECT_END()  n+=sprintf(jsbuffer+n,"}"); shouldAddComma=true;

#define JSON_SERIALIZE_ARRAY_START(key) ADD_COMMA() n+=sprintf(jsbuffer+n,"\"%s\": [",key); shouldAddComma=false;
#define JSON_SERIALIZE_ARRAY_ITEM(item) ADD_COMMA() n+=sprintf(jsbuffer+n,"%s",item); shouldAddComma=true;
#define JSON_SERIALIZE_ARRAY_END()  n+=sprintf(jsbuffer+n,"]"); shouldAddComma=true;
#define JSON_SERIALIZE_END()  n+=sprintf(jsbuffer+n,"}"); shouldAddComma=true;


#endif // __JSON_PARSER_H__
