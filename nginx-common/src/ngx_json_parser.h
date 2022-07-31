#ifndef _NGX_JSON_PARSER_H_INCLUDED_
#define _NGX_JSON_PARSER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_JSON_UNSET       -1
#define NGX_JSON_UNSET_UINT  (ngx_uint_t) -1
#define NGX_JSON_UNSET_PTR   (void *) -1


#define ngx_json_set_value(dest, json)                                       \
    if (json != NGX_JSON_UNSET) {                                            \
        dest = json;                                                         \
    }

#define ngx_json_set_uint_value(dest, json)                                  \
    if (json != NGX_JSON_UNSET_UINT) {                                       \
        dest = json;                                                         \
    }

#define ngx_json_set_str_value(dest, json)                                   \
    if (json.data != NGX_JSON_UNSET_PTR) {                                   \
        dest = json;                                                         \
    }


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
};


typedef ngx_int_t                ngx_json_status_t;
typedef ngx_array_t              ngx_json_object_t;
typedef struct ngx_array_part_s  ngx_array_part_t;
typedef struct ngx_json_prop_s   ngx_json_prop_t;


typedef struct {
    int64_t                   num;
    uint64_t                  denom;
} ngx_json_fraction_t;


struct ngx_array_part_s {
    void                     *first;
    void                     *last;
    size_t                    count;
    ngx_array_part_t         *next;
};


typedef struct {
    int                       type;
    size_t                    count;
    ngx_array_part_t          part;
} ngx_json_array_t;


/* Note: when 'escape' is set, the string needs to be decoded */
typedef struct {
    ngx_str_t                 s;
    unsigned                  escape:1;
} ngx_json_esc_str_t;


typedef struct {
    int                       type;
    union {
        ngx_flag_t            boolean;
        ngx_json_fraction_t   num;
        ngx_json_esc_str_t    str;
        ngx_json_array_t      arr;
        ngx_json_object_t     obj;  /* ngx_json_key_value_t */
    } v;
} ngx_json_value_t;


typedef struct {
    ngx_uint_t                key_hash;
    ngx_str_t                 key;
    ngx_json_value_t          value;
} ngx_json_key_value_t;


struct ngx_json_prop_s {
    ngx_str_t                 key;
    ngx_uint_t                key_hash;
    ngx_int_t                 type;
    ngx_json_status_t       (*set)(ngx_pool_t *pool, ngx_json_value_t *value,
                                   ngx_json_prop_t *prop, void *dest);
    ngx_uint_t                offset;
    void                     *post;
};


ngx_json_status_t ngx_json_parse(ngx_pool_t *pool, u_char *string,
    ngx_json_value_t *result, u_char *error, size_t error_size);

ngx_json_status_t ngx_json_decode_string(ngx_str_t *dest, ngx_str_t *src);


ngx_json_status_t ngx_json_object_parse(ngx_pool_t *pool,
    ngx_json_object_t *object, ngx_json_prop_t **hash, ngx_uint_t size,
    void *dest);


ngx_json_status_t ngx_json_set_num_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_flag_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_str_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_raw_str_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_obj_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_arr_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

ngx_json_status_t ngx_json_set_enum_slot(ngx_pool_t *pool,
    ngx_json_value_t *value, ngx_json_prop_t *prop, void *dest);

#endif /*_NGX_JSON_PARSER_H_INCLUDED_ */
