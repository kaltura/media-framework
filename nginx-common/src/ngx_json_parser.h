#ifndef _NGX_JSON_PARSER_H_INCLUDED_
#define _NGX_JSON_PARSER_H_INCLUDED_

// includes
#include <ngx_config.h>
#include <ngx_core.h>

// enums
enum {
    NGX_JSON_NULL,
    NGX_JSON_BOOL,
    NGX_JSON_INT,
    NGX_JSON_FRAC,
    NGX_JSON_STRING,
    NGX_JSON_ARRAY,
    NGX_JSON_OBJECT,
};

enum {
    NGX_JSON_OK             = 0,
    NGX_JSON_BAD_DATA       = -1,
    NGX_JSON_ALLOC_FAILED   = -2,
    NGX_JSON_BAD_LENGTH     = -3,
    NGX_JSON_BAD_TYPE       = -4,
};

// typedefs
typedef ngx_int_t ngx_json_status_t;

typedef struct {
    int64_t                   num;
    uint64_t                  denom;
} ngx_json_fraction_t;

typedef struct ngx_array_part_s {
    void                     *first;
    void                     *last;
    size_t                    count;
    struct ngx_array_part_s  *next;
} ngx_array_part_t;

typedef struct {
    int                       type;
    size_t                    count;
    ngx_array_part_t          part;
} ngx_json_array_t;

typedef ngx_array_t ngx_json_object_t;

typedef struct {
    int                       type;
    union {
        ngx_flag_t            boolean;
        ngx_json_fraction_t   num;
        ngx_str_t             str;  // Note: the string may be json escaped
        ngx_json_array_t      arr;
        ngx_json_object_t     obj;  // of ngx_json_key_value_t
    } v;
} ngx_json_value_t;

typedef struct {
    ngx_uint_t                key_hash;
    ngx_str_t                 key;
    ngx_json_value_t          value;
} ngx_json_key_value_t;


// functions
ngx_json_status_t ngx_json_parse(ngx_pool_t *pool, u_char *string,
    ngx_json_value_t *result, u_char *error, size_t error_size);

ngx_json_status_t ngx_json_decode_string(ngx_str_t *dest, ngx_str_t *src);

// key extraction - use when the fields have to be parsed in a certain order
typedef struct {
    ngx_str_t                 key;
    int                       type;
    int                       index;
} json_object_key_def_t;

void ngx_json_get_object_values(ngx_json_object_t *object,
    json_object_key_def_t *key_defs, ngx_json_value_t **result);

#endif /*_NGX_JSON_PARSER_H_INCLUDED_ */
