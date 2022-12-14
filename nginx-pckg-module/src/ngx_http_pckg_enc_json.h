/* auto-generated by generate_json_header.py */

#ifndef ngx_array_entries
#define ngx_array_entries(x)     (sizeof(x) / sizeof(x[0]))
#endif

/* ngx_pckg_enc_json reader */

typedef struct {
    ngx_str_t           key_id;
    ngx_str_t           key;
    ngx_str_t           iv;
    ngx_json_object_t  *systems;
} ngx_pckg_enc_json_t;


static ngx_json_prop_t  ngx_pckg_enc_json_key_id = {
    ngx_string("key_id"),
    3160294139ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_pckg_enc_json_t, key_id),
    NULL
};


static ngx_json_prop_t  ngx_pckg_enc_json_key = {
    ngx_string("key"),
    106079ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_pckg_enc_json_t, key),
    NULL
};


static ngx_json_prop_t  ngx_pckg_enc_json_iv = {
    ngx_string("iv"),
    3373ULL,
    NGX_JSON_STRING,
    ngx_json_set_str_slot,
    offsetof(ngx_pckg_enc_json_t, iv),
    NULL
};


static ngx_json_prop_t  ngx_pckg_enc_json_systems = {
    ngx_string("systems"),
    105636811812ULL,
    NGX_JSON_OBJECT,
    ngx_json_set_obj_slot,
    offsetof(ngx_pckg_enc_json_t, systems),
    NULL
};


static ngx_json_prop_t  *ngx_pckg_enc_json[] = {
    &ngx_pckg_enc_json_systems,
    &ngx_pckg_enc_json_key,
    &ngx_pckg_enc_json_key_id,
    NULL,
    NULL,
    NULL,
    &ngx_pckg_enc_json_iv,
};
