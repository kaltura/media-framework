#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "ngx_live_store_http.h"


#define NGX_LIVE_STORE_S3_SHA256_HEX_LEN   (SHA256_DIGEST_LENGTH * 2)
#define NGX_LIVE_STORE_S3_HMAC_HEX_LEN     (EVP_MAX_MD_SIZE * 2)

#define NGX_LIVE_STORE_S3_AMZ_TIME_FORMAT  ("%Y%m%dT%H%M%SZ")
#define NGX_LIVE_STORE_S3_AMZ_TIME_LEN     (sizeof("YYYYmmddTHHMMSSZ"))

#define NGX_LIVE_STORE_S3_AMZ_DATE_FORMAT  ("%Y%m%d")
#define NGX_LIVE_STORE_S3_AMZ_DATE_LEN     (sizeof("YYYYmmdd"))


#define NGX_LIVE_STORE_S3_EMPTY_SHA256                                       \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


static char *ngx_live_store_s3_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_live_store_s3_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_live_store_s3_set_url_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_live_store_s3_header_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_live_store_s3_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_store_s3_create_main_conf(ngx_conf_t *cf);

static void *ngx_live_store_s3_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_store_s3_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);


enum {
    NGX_LIVE_STORE_S3_HEADER_HOST,
    NGX_LIVE_STORE_S3_HEADER_DATE,
    NGX_LIVE_STORE_S3_HEADER_RANGE,
    NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA,
    NGX_LIVE_STORE_S3_HEADER_CONTENT_LEN,
    NGX_LIVE_STORE_S3_HEADER_BUILTIN_COUNT,

    NGX_LIVE_STORE_S3_HEADER_STATIC,
    NGX_LIVE_STORE_S3_HEADER_COMPLEX,

    NGX_LIVE_STORE_S3_HEADER_SIGNED = 0x80000000,
};


typedef struct {
    ngx_uint_t                 flags;
    ngx_str_t                  key;
    u_char                    *lowcase_key;
    ngx_live_complex_value_t   value;
} ngx_live_store_s3_header_t;


typedef struct {
    ngx_array_t               *conf;  /* ngx_live_store_s3_header_t */
    ngx_str_t                  builtin[NGX_LIVE_STORE_S3_HEADER_BUILTIN_COUNT];
    u_char                     date_buf[NGX_LIVE_STORE_S3_AMZ_TIME_LEN];
    ngx_str_t                 *values;
    ngx_str_t                  sign;
    size_t                     size;
} ngx_live_store_s3_headers_t;


typedef struct {
    ngx_queue_t                queue;

    ngx_json_str_t             name;

    /* conf */
    ngx_url_t                 *url;
    ngx_str_t                  host;
    ngx_str_t                  access_key;
    ngx_str_t                  secret_key;
    ngx_str_t                  service;
    ngx_str_t                  region;

    /* derivatives */
    ngx_str_t                  secret_key_prefix;
    ngx_str_t                  signing_key_date;
    ngx_str_t                  signing_key;
    ngx_str_t                  key_scope;
    ngx_str_t                  key_scope_suffix;

    ngx_live_store_stats_t     read_stats;
    ngx_live_store_stats_t     write_stats;
} ngx_live_store_s3_ctx_t;


typedef struct {
    ngx_live_store_s3_ctx_t   *ctx;
    ngx_array_t                put_headers;  /* ngx_live_store_s3_header_t */
} ngx_live_store_s3_preset_conf_t;


typedef struct {
    ngx_queue_t                blocks;   /* ngx_live_store_s3_ctx_t * */
} ngx_live_store_s3_main_conf_t;


static ngx_command_t  ngx_live_store_s3_commands[] = {

    { ngx_string("store_s3"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE1,
      ngx_live_store_s3_set,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_s3_preset_conf_t, ctx),
      NULL },

    { ngx_string("store_s3_block"),
      NGX_LIVE_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_live_store_s3_block,
      NGX_LIVE_MAIN_CONF_OFFSET,
      offsetof(ngx_live_store_s3_main_conf_t, blocks),
      NULL },

    { ngx_string("store_s3_put_add_header"),
      NGX_LIVE_MAIN_CONF|NGX_LIVE_PRESET_CONF|NGX_CONF_TAKE2,
      ngx_live_store_s3_header_slot,
      NGX_LIVE_PRESET_CONF_OFFSET,
      offsetof(ngx_live_store_s3_preset_conf_t, put_headers),
      NULL },

      ngx_null_command
};


static ngx_command_t  ngx_live_store_s3_block_commands[] = {

    { ngx_string("url"),
      NGX_CONF_TAKE1,
      ngx_live_store_s3_set_url_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, url),
      NULL },

    { ngx_string("host"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, host),
      NULL },

    { ngx_string("access_key"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, access_key),
      NULL },

    { ngx_string("secret_key"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, secret_key),
      NULL },

    { ngx_string("service"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, service),
      NULL },

    { ngx_string("region"),
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_live_store_s3_ctx_t, region),
      NULL },

      ngx_null_command
};


static ngx_live_module_t  ngx_live_store_s3_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_live_store_s3_postconfiguration,      /* postconfiguration */

    ngx_live_store_s3_create_main_conf,       /* create main configuration */
    NULL,                                     /* init main configuration */

    ngx_live_store_s3_create_preset_conf,     /* create preset configuration */
    ngx_live_store_s3_merge_preset_conf       /* merge preset configuration */
};


ngx_module_t  ngx_live_store_s3_module = {
    NGX_MODULE_V1,
    &ngx_live_store_s3_module_ctx,            /* module context */
    ngx_live_store_s3_commands,               /* module directives */
    NGX_LIVE_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_live_store_s3_aws4_request =
    ngx_string("aws4_request");

static ngx_str_t  ngx_live_store_s3_aws4 =
    ngx_string("AWS4");


/* must be sorted by lowcase_key */
static ngx_live_store_s3_header_t  ngx_live_store_s3_get_headers[] = {

    { NGX_LIVE_STORE_S3_HEADER_STATIC,
      ngx_string("Connection"),
      (u_char *) "connection",
      ngx_live_static_complex_value("Close") },

    { NGX_LIVE_STORE_S3_HEADER_HOST|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("Host"),
      (u_char *) "host",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_RANGE,
      ngx_string("Range"),
      (u_char *) "range",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("X-Amz-Content-SHA256"),
      (u_char *) "x-amz-content-sha256",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_DATE|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("X-Amz-Date"),
      (u_char *) "x-amz-date",
      ngx_live_null_complex_value },

};


/* must be sorted by lowcase_key */
static ngx_live_store_s3_header_t  ngx_live_store_s3_put_headers[] = {

    { NGX_LIVE_STORE_S3_HEADER_STATIC,
      ngx_string("Connection"),
      (u_char *) "connection",
      ngx_live_static_complex_value("Close") },

    { NGX_LIVE_STORE_S3_HEADER_CONTENT_LEN,
      ngx_string("Content-Length"),
      (u_char *) "content-length",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_STATIC,
      ngx_string("Expect"),
      (u_char *) "expect",
      ngx_live_static_complex_value("100-continue") },

    { NGX_LIVE_STORE_S3_HEADER_HOST|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("Host"),
      (u_char *) "host",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("X-Amz-Content-SHA256"),
      (u_char *) "x-amz-content-sha256",
      ngx_live_null_complex_value },

    { NGX_LIVE_STORE_S3_HEADER_DATE|NGX_LIVE_STORE_S3_HEADER_SIGNED,
      ngx_string("X-Amz-Date"),
      (u_char *) "x-amz-date",
      ngx_live_null_complex_value },

};


static ngx_str_t  ngx_live_store_s3_method_get = ngx_string("GET");
static ngx_str_t  ngx_live_store_s3_method_put = ngx_string("PUT");

static ngx_str_t  ngx_live_store_s3_host = ngx_string("host");
static ngx_str_t  ngx_live_store_s3_amz_prefix = ngx_string("x-amz-");


#include "ngx_live_store_s3_json.h"


static ngx_url_t *
ngx_live_store_s3_parse_url(ngx_conf_t *cf, ngx_str_t *url)
{
    size_t      add;
    ngx_url_t  *u;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    add = 0;
    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }

    return u;
}


static char *
ngx_live_store_s3_set_url_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t   *value;
    ngx_url_t  **u;

    u = (ngx_url_t **) (p + cmd->offset);
    if (*u != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *u = ngx_live_store_s3_parse_url(cf, &value[1]);
    if (*u == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_flag_t
ngx_live_store_s3_header_signed(ngx_live_store_s3_header_t *header)
{
    if (header->key.len == ngx_live_store_s3_host.len &&
        ngx_strncmp(header->lowcase_key, ngx_live_store_s3_host.data,
            ngx_live_store_s3_host.len) == 0)
    {
        return 1;

    } else if (header->key.len > ngx_live_store_s3_amz_prefix.len &&
        ngx_strncmp(header->lowcase_key, ngx_live_store_s3_amz_prefix.data,
            ngx_live_store_s3_amz_prefix.len) == 0)
    {
        return 1;
    }

    return 0;
}


static char *
ngx_live_store_s3_header_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t                         *value;
    ngx_array_t                       *a;
    ngx_conf_post_t                   *post;
    ngx_live_store_s3_header_t        *h;
    ngx_live_compile_complex_value_t   ccv;

    a = (ngx_array_t *) (p + cmd->offset);

    if (a->nelts == 0) {
        if (ngx_array_init(a, cf->pool, 4, sizeof(ngx_live_store_s3_header_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(a);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    h->flags = NGX_LIVE_STORE_S3_HEADER_COMPLEX;
    h->key = value[1];

    h->lowcase_key = ngx_pnalloc(cf->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    ngx_memzero(&ccv, sizeof(ngx_live_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &h->value;

    if (ngx_live_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_live_store_s3_header_signed(h)) {
        h->flags |= NGX_LIVE_STORE_S3_HEADER_SIGNED;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, h);
    }

    return NGX_CONF_OK;
}


static void
ngx_live_store_s3_sha256_hex_buf(ngx_str_t *message, u_char *digest)
{
    u_char      hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX  sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message->data, message->len);
    SHA256_Final(hash, &sha256);

    ngx_hex_dump(digest, hash, sizeof(hash));
}


static void
ngx_live_store_s3_sha256_hex_chain(ngx_chain_t *cl, u_char *digest)
{
    u_char       hash[SHA256_DIGEST_LENGTH];
    ngx_buf_t   *b;
    SHA256_CTX   sha256;

    SHA256_Init(&sha256);

    for (; cl; cl = cl->next) {
        b = cl->buf;
        SHA256_Update(&sha256, b->pos, b->last - b->pos);
    }

    SHA256_Final(hash, &sha256);

    ngx_hex_dump(digest, hash, sizeof(hash));
}


static ngx_int_t
ngx_live_store_s3_hmac_sha256(ngx_log_t *log, ngx_str_t *key,
    ngx_str_t *message, ngx_str_t *dest)
{
    unsigned   hash_len;
    HMAC_CTX  *hmac;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX   hmac_buf;

    hmac = &hmac_buf;
    HMAC_CTX_init(hmac);
#else
    hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_store_s3_hmac_sha256: HMAC_CTX_new failed");
        return NGX_ERROR;
    }
#endif

    HMAC_Init_ex(hmac, key->data, key->len, EVP_sha256(), NULL);
    HMAC_Update(hmac, message->data, message->len);
    HMAC_Final(hmac, dest->data, &hash_len);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(hmac);
#else
    HMAC_CTX_free(hmac);
#endif

    dest->len = hash_len;

    return NGX_OK;
}


static ngx_int_t
ngx_live_store_s3_hmac_sha256_hex(ngx_log_t *log, ngx_str_t *key,
    ngx_str_t *message, ngx_str_t *dest)
{
    u_char     hash_buf[EVP_MAX_MD_SIZE];
    ngx_str_t  hash;

    hash.data = hash_buf;

    if (ngx_live_store_s3_hmac_sha256(log, key, message, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    dest->len = ngx_hex_dump(dest->data, hash.data, hash.len) - dest->data;
    return NGX_OK;
}


static char *
ngx_live_store_s3_init_ctx(ngx_conf_t *cf, ngx_live_store_s3_ctx_t *ctx)
{
    u_char  *p;

    /* check required params */
    if (ctx->url == NGX_CONF_UNSET_PTR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "url not set in store_s3_block");
        return NGX_CONF_ERROR;
    }

    if (ctx->access_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "access_key not set in store_s3_block");
        return NGX_CONF_ERROR;
    }

    if (ctx->secret_key.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "secret_key not set in store_s3_block");
        return NGX_CONF_ERROR;
    }

    if (ctx->service.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "service not set in store_s3_block");
        return NGX_CONF_ERROR;
    }

    if (ctx->region.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "region not set in store_s3_block");
        return NGX_CONF_ERROR;
    }

    /* add prefix to secret key */
    ctx->secret_key_prefix.data = ngx_pnalloc(cf->pool,
        ngx_live_store_s3_aws4.len + ctx->secret_key.len);
    if (ctx->secret_key_prefix.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ctx->secret_key_prefix.data;
    p = ngx_copy_str(p, ngx_live_store_s3_aws4);
    p = ngx_copy_str(p, ctx->secret_key);
    ctx->secret_key_prefix.len = p - ctx->secret_key_prefix.data;

    /* init key scope suffix */
    ctx->key_scope_suffix.data = ngx_pnalloc(cf->pool, ctx->region.len +
        ctx->service.len + ngx_live_store_s3_aws4_request.len + 3);
    if (ctx->key_scope_suffix.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ctx->key_scope_suffix.data;
    *p++ = '/';
    p = ngx_copy_str(p, ctx->region);
    *p++ = '/';
    p = ngx_copy_str(p, ctx->service);
    *p++ = '/';
    p = ngx_copy_str(p, ngx_live_store_s3_aws4_request);
    ctx->key_scope_suffix.len = p - ctx->key_scope_suffix.data;

    /* alloc additional buffers */
    p = ngx_pnalloc(cf->pool, NGX_LIVE_STORE_S3_AMZ_DATE_LEN +
        EVP_MAX_MD_SIZE + NGX_LIVE_STORE_S3_AMZ_DATE_LEN +
        ctx->key_scope_suffix.len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->signing_key_date.data = p;
    p += NGX_LIVE_STORE_S3_AMZ_DATE_LEN;

    ctx->signing_key.data = p;
    p += EVP_MAX_MD_SIZE;

    ctx->key_scope.data = p;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_live_store_s3_generate_signing_key(ngx_live_store_s3_ctx_t *ctx,
    ngx_log_t *log)
{
    u_char     *p;
    u_char      date_buf[NGX_LIVE_STORE_S3_AMZ_DATE_LEN];
    struct tm   tm;
    ngx_str_t   date;
    ngx_str_t  *signing_key;

    /* get the GMT date */
    ngx_libc_gmtime(ngx_time(), &tm);
    date.len = strftime((char *) date_buf, sizeof(date_buf),
        NGX_LIVE_STORE_S3_AMZ_DATE_FORMAT, &tm);
    if (date.len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_live_store_s3_generate_signing_key: strftime failed");
        return NGX_ERROR;
    }

    date.data = date_buf;

    /* check whether date changed since last time */
    if (ctx->signing_key_date.len == date.len &&
        ngx_memcmp(date.data, ctx->signing_key_date.data, date.len) == 0)
    {
        return NGX_OK;
    }

    /* generate a key */
    ctx->signing_key_date.len = 0;

    signing_key = &ctx->signing_key;

    if (ngx_live_store_s3_hmac_sha256(log, &ctx->secret_key_prefix, &date,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_store_s3_hmac_sha256(log, signing_key, &ctx->region,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_store_s3_hmac_sha256(log, signing_key, &ctx->service,
        signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_live_store_s3_hmac_sha256(log, signing_key,
        &ngx_live_store_s3_aws4_request, signing_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* save the date and key scope */
    ctx->signing_key_date.len = date.len;
    ngx_memcpy(ctx->signing_key_date.data, date.data, date.len);

    p = ngx_copy_str(ctx->key_scope.data, ctx->signing_key_date);
    p = ngx_copy_str(p, ctx->key_scope_suffix);
    ctx->key_scope.len = p - ctx->key_scope.data;

    return NGX_OK;
}


static ngx_live_store_s3_ctx_t *
ngx_live_store_s3_get_ctx(ngx_queue_t *blocks, ngx_str_t *name)
{
    ngx_queue_t              *q;
    ngx_live_store_s3_ctx_t  *ctx;

    for (q = ngx_queue_head(blocks);
        q != ngx_queue_sentinel(blocks);
        q = ngx_queue_next(q))
    {
        ctx = ngx_queue_data(q, ngx_live_store_s3_ctx_t, queue);

        if (ctx->name.s.len == name->len &&
            ngx_strncasecmp(ctx->name.s.data, name->data, name->len) == 0)
        {
            return ctx;
        }
    }

    return NULL;
}


static char *
ngx_live_store_s3_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    ngx_str_t                   name;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_queue_t                *blocks = conf;
    ngx_live_store_s3_ctx_t    *ctx;
    ngx_live_block_conf_ctx_t   conf_ctx;

    value = cf->args->elts;

    /* get context name */
    name = value[1];

    if (ngx_live_store_s3_get_ctx(blocks, &name) != NULL) {
        return "is duplicate";
    }

    /* initialize the context */
    ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->url = NGX_CONF_UNSET_PTR;

    /* parse the block */
    conf_ctx.cmds = ngx_live_store_s3_block_commands;
    conf_ctx.cf = &save;

    save = *cf;

    cf->ctx = &conf_ctx;
    cf->handler = ngx_live_block_command_handler;
    cf->handler_conf = (void *) ctx;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* initialize and add the context */
    rv = ngx_live_store_s3_init_ctx(cf, ctx);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ctx->name.s = name;
    ngx_json_str_set_escape(&ctx->name);

    ngx_queue_insert_tail(blocks, &ctx->queue);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_live_store_s3_init_headers(ngx_live_variables_ctx_t *vctx,
    ngx_pool_t *pool, ngx_live_store_s3_headers_t *h)
{
    size_t                       date_len;
    size_t                       signed_size;
    u_char                      *p;
    struct tm                    tm;
    ngx_str_t                    value;
    ngx_uint_t                   i, n;
    ngx_uint_t                   type;
    ngx_live_store_s3_header_t  *hdr, *hdrs;

    /* initialize the date header */

    ngx_libc_gmtime(ngx_time(), &tm);
    date_len = strftime((char *) h->date_buf, sizeof(h->date_buf),
        NGX_LIVE_STORE_S3_AMZ_TIME_FORMAT, &tm);
    if (date_len == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_store_s3_init_headers: strftime failed");
        return NGX_ERROR;
    }

    h->builtin[NGX_LIVE_STORE_S3_HEADER_DATE].len = date_len;
    h->builtin[NGX_LIVE_STORE_S3_HEADER_DATE].data = h->date_buf;


    /* initialize the values */

    h->values = ngx_palloc(pool, h->conf->nelts * sizeof(ngx_str_t));
    if (h->values == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_init_headers: alloc header values failed");
        return NGX_ERROR;
    }

    signed_size = 0;

    hdrs = h->conf->elts;
    n = h->conf->nelts;

    for (i = 0; i < n; i++) {
        hdr = &hdrs[i];

        type = hdr->flags & ~NGX_LIVE_STORE_S3_HEADER_SIGNED;
        switch (type) {

        case NGX_LIVE_STORE_S3_HEADER_STATIC:
            value = hdr->value.value;
            break;

        case NGX_LIVE_STORE_S3_HEADER_COMPLEX:
            if (ngx_live_complex_value(vctx, &hdr->value, &value) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                    "ngx_live_store_s3_init_headers: complex value failed");
                return NGX_ERROR;
            }
            break;

        default:
            value = h->builtin[type];
        }

        h->values[i] = value;
        if (value.len == 0) {
            continue;
        }

        h->size += hdr->key.len + value.len + sizeof(": \r\n") - 1;
        if (hdr->flags & NGX_LIVE_STORE_S3_HEADER_SIGNED) {
            signed_size += hdr->key.len + 1;
        }
    }

    /* build the list of signed headers */

    p = ngx_pnalloc(pool, signed_size);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_init_headers: alloc signed headers failed");
        return NGX_ERROR;
    }

    h->sign.data = p;

    for (i = 0; i < n; i++) {
        hdr = &hdrs[i];
        if (!(hdr->flags & NGX_LIVE_STORE_S3_HEADER_SIGNED)
            || h->values[i].len == 0)
        {
            continue;
        }

        if (p > h->sign.data) {
            *p++ = ';';
        }

        p = ngx_copy(p, hdr->lowcase_key, hdr->key.len);
    }

    h->sign.len = p - h->sign.data;

    return NGX_OK;
}


static u_char *
ngx_live_store_s3_write_headers(u_char *p,
    ngx_live_store_s3_headers_t *headers)
{
    ngx_uint_t                   i, n;
    ngx_live_store_s3_header_t  *hdrs;

    hdrs = headers->conf->elts;
    n = headers->conf->nelts;

    for (i = 0; i < n; i++) {
        if (headers->values[i].len == 0) {
            continue;
        }

        p = ngx_copy_str(p, hdrs[i].key);
        *p++ = ':';
        *p++ = ' ';
        p = ngx_copy_str(p, headers->values[i]);
        *p++ = '\r';
        *p++ = '\n';
    }

    return p;
}


static ngx_int_t
ngx_live_store_s3_get_canonical_hash(ngx_pool_t *pool, ngx_str_t *method,
    ngx_str_t *uri, ngx_live_store_s3_headers_t *headers, u_char *out)
{
    u_char                      *p;
    size_t                       size;
    ngx_str_t                    content_sha;
    ngx_str_t                    canonical_request;
    ngx_uint_t                   i, n;
    ngx_live_store_s3_header_t  *hdr, *hdrs;

    /* get the canonical request size */

    content_sha = headers->builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA];
    size = method->len + uri->len + headers->sign.len + content_sha.len
        + sizeof("\n\n\n\n\n");

    hdrs = headers->conf->elts;
    n = headers->conf->nelts;

    for (i = 0; i < n; i++) {
        hdr = &hdrs[i];
        if (!(hdr->flags & NGX_LIVE_STORE_S3_HEADER_SIGNED)
            || headers->values[i].len == 0)
        {
            continue;
        }

        size += hdr->key.len + headers->values[i].len + sizeof(":\n") - 1;
    }

    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_canonical_hash: "
            "alloc canonical request failed");
        return NGX_ERROR;
    }

    /* build the canonical request */

    canonical_request.data = p;

    p = ngx_copy_str(p, *method);
    *p++ = '\n';

    p = ngx_copy_str(p, *uri);
    *p++ = '\n';

    *p++ = '\n';

    for (i = 0; i < n; i++) {
        hdr = &hdrs[i];
        if (!(hdr->flags & NGX_LIVE_STORE_S3_HEADER_SIGNED)
            || headers->values[i].len == 0)
        {
            continue;
        }

        p = ngx_copy(p, hdr->lowcase_key, hdr->key.len);
        *p++ = ':';
        p = ngx_copy_str(p, headers->values[i]);
        *p++ = '\n';
    }

    *p++ = '\n';

    p = ngx_copy_str(p, headers->sign);
    *p++ = '\n';

    p = ngx_copy_str(p, content_sha);

    canonical_request.len = p - canonical_request.data;

    if (canonical_request.len > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_get_canonical_hash: "
            "buffer size %uz greater than allocated length %uz",
            canonical_request.len, size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_get_canonical_hash: canonical request \"%V\"",
        &canonical_request);

    /* hash the canonical request */

    ngx_live_store_s3_sha256_hex_buf(&canonical_request, out);

    ngx_free(canonical_request.data);

    return NGX_OK;
}


static ngx_int_t
ngx_live_store_s3_sign(ngx_pool_t *pool, ngx_live_store_s3_ctx_t *ctx,
    ngx_str_t *date, ngx_str_t *canonical_sha, ngx_str_t *signature)
{
    static const char  string_to_sign_template[] =
        "AWS4-HMAC-SHA256\n"
        "%V\n"
        "%V\n"
        "%V";

    u_char     *p;
    size_t      size;
    ngx_int_t   rc;
    ngx_str_t   string_to_sign;

    /* build the string to sign */

    size = sizeof(string_to_sign_template) +
        date->len + ctx->key_scope.len + canonical_sha->len;

    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_sign: alloc failed");
        return NGX_ERROR;
    }

    string_to_sign.data = p;

    p = ngx_sprintf(p, string_to_sign_template,
        date, &ctx->key_scope, canonical_sha);

    string_to_sign.len = p - string_to_sign.data;

    if (string_to_sign.len > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_sign: "
            "buffer size %uz greater than allocated length %uz",
            string_to_sign.len, size);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_sign: string to sign \"%V\"", &string_to_sign);

    /* calc the signature */

    rc = ngx_live_store_s3_hmac_sha256_hex(pool->log, &ctx->signing_key,
        &string_to_sign, signature);

    ngx_free(string_to_sign.data);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_sign: failed to sign");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_live_store_s3_build_request(ngx_pool_t *pool, ngx_live_store_s3_ctx_t *ctx,
    ngx_str_t *method, ngx_str_t *uri, ngx_live_store_s3_headers_t *headers,
    ngx_buf_t **result)
{
    static const char  request_template[] =
        "%V %V HTTP/1.1\r\n";

    static const char  authorization_template[] =
        "Authorization: AWS4-HMAC-SHA256 Credential=%V/%V, "
        "SignedHeaders=%V, "
        "Signature=%V\r\n"
        "\r\n";

    u_char     *p;
    size_t      size;
    ngx_buf_t  *b;
    ngx_str_t   date;
    ngx_str_t   signature;
    ngx_str_t   canonical_sha;

    u_char  signature_buf[NGX_LIVE_STORE_S3_HMAC_HEX_LEN];
    u_char  canonical_sha_buf[NGX_LIVE_STORE_S3_SHA256_HEX_LEN];

    /* generate signing key */

    if (ngx_live_store_s3_generate_signing_key(ctx, pool->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_build_request: generate signing key failed");
        return NGX_ERROR;
    }

    /* get the canonical request hash */

    if (ngx_live_store_s3_get_canonical_hash(pool, method, uri, headers,
        canonical_sha_buf) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_build_request: "
            "failed to get canonical request hash");
        return NGX_ERROR;
    }

    canonical_sha.data = canonical_sha_buf;
    canonical_sha.len = sizeof(canonical_sha_buf);

    signature.data = signature_buf;
    date = headers->builtin[NGX_LIVE_STORE_S3_HEADER_DATE];
    if (ngx_live_store_s3_sign(pool, ctx, &date, &canonical_sha, &signature)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_build_request: failed to sign");
        return NGX_ERROR;
    }

    /* build the request */

    size = sizeof(request_template) + method->len + uri->len + headers->size
        + sizeof(authorization_template) + ctx->access_key.len
        + ctx->key_scope.len + headers->sign.len + signature.len;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_build_request: alloc buf failed");
        return NGX_ERROR;
    }

    p = ngx_sprintf(b->last, request_template, method, uri);

    p = ngx_live_store_s3_write_headers(p, headers);

    p = ngx_sprintf(p, authorization_template,
        &ctx->access_key, &ctx->key_scope, &headers->sign, &signature);

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_build_request: "
            "buffer size %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NGX_ERROR;
    }

    b->last = p;
    *result = b;

    return NGX_OK;
}


static ngx_int_t
ngx_live_store_s3_get_request(ngx_pool_t *pool, void *arg, ngx_str_t *host,
    ngx_str_t *uri, off_t range_start, off_t range_end, ngx_buf_t **result)
{
    size_t                        range_len;
    ngx_array_t                   headers_arr;
    ngx_live_store_s3_ctx_t      *ctx = arg;
    ngx_live_store_s3_headers_t   headers;

    u_char  range_buf[sizeof("bytes=-") + 2 * NGX_OFF_T_LEN];

    ngx_memzero(&headers, sizeof(headers));

    headers_arr.elts = ngx_live_store_s3_get_headers;
    headers_arr.nelts = ngx_array_entries(ngx_live_store_s3_get_headers);
    headers.conf = &headers_arr;

    if (ctx->host.len > 0) {
        headers.builtin[NGX_LIVE_STORE_S3_HEADER_HOST] = ctx->host;

    } else {
        headers.builtin[NGX_LIVE_STORE_S3_HEADER_HOST] = *host;
    }

    if (range_end != -1) {
        range_len = ngx_sprintf(range_buf, "bytes=%O-%O",
            range_start, range_end) - range_buf;
        headers.builtin[NGX_LIVE_STORE_S3_HEADER_RANGE].data = range_buf;
        headers.builtin[NGX_LIVE_STORE_S3_HEADER_RANGE].len = range_len;
    }

    ngx_str_set(&headers.builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA],
        NGX_LIVE_STORE_S3_EMPTY_SHA256);
    ngx_str_set(&headers.builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_LEN], "0");

    if (ngx_live_store_s3_init_headers(NULL, pool, &headers) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: init headers failed");
        return NGX_ERROR;
    }

    if (ngx_live_store_s3_build_request(pool, ctx,
        &ngx_live_store_s3_method_get, uri, &headers, result) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: build request failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_live_store_s3_get_info(ngx_live_channel_t *channel, ngx_str_t *name)
{
    ngx_live_store_s3_ctx_t          *ctx;
    ngx_live_store_s3_preset_conf_t  *conf;

    conf = ngx_live_get_module_preset_conf(channel, ngx_live_store_s3_module);

    ctx = conf->ctx;

    *name = ctx->name.s;
}


static void *
ngx_live_store_s3_read_init(ngx_live_store_read_request_t *request)
{
    ngx_live_store_s3_ctx_t          *ctx;
    ngx_live_store_s3_preset_conf_t  *conf;

    conf = ngx_live_get_module_preset_conf(request->channel,
        ngx_live_store_s3_module);

    ctx = conf->ctx;

    return ngx_live_store_http_read_init(request, ctx->url,
        ngx_live_store_s3_get_request, ctx, &ctx->read_stats);
}


static ngx_int_t
ngx_live_store_s3_write(ngx_live_store_write_request_t *request)
{
    size_t                            content_len_size;
    ngx_buf_t                        *b;
    ngx_str_t                        *builtin;
    ngx_pool_t                       *pool;
    ngx_chain_t                      *cl;
    ngx_live_channel_t               *channel;
    ngx_live_store_s3_ctx_t          *ctx;
    ngx_live_store_s3_headers_t       headers;
    ngx_live_store_s3_preset_conf_t  *conf;

    u_char  content_sha_buf[NGX_LIVE_STORE_S3_SHA256_HEX_LEN];
    u_char  content_len_buf[NGX_SIZE_T_LEN];

    channel = request->channel;
    conf = ngx_live_get_module_preset_conf(channel, ngx_live_store_s3_module);

    ctx = conf->ctx;

    pool = request->pool;

    ngx_memzero(&headers, sizeof(headers));
    headers.conf = &conf->put_headers;

    builtin = headers.builtin;

    if (ctx->host.len > 0) {
        builtin[NGX_LIVE_STORE_S3_HEADER_HOST] = ctx->host;

    } else {
        builtin[NGX_LIVE_STORE_S3_HEADER_HOST] = ctx->url->host;
    }

    ngx_live_store_s3_sha256_hex_chain(request->cl, content_sha_buf);
    builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA].data = content_sha_buf;
    builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_SHA].len =
        sizeof(content_sha_buf);

    content_len_size = ngx_sprintf(content_len_buf, "%uz", request->size)
        - content_len_buf;
    builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_LEN].data = content_len_buf;
    builtin[NGX_LIVE_STORE_S3_HEADER_CONTENT_LEN].len = content_len_size;

    if (ngx_live_store_s3_init_headers(request->vctx, pool, &headers)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_write: init headers failed");
        return NGX_ERROR;
    }

    if (ngx_live_store_s3_build_request(pool, ctx,
        &ngx_live_store_s3_method_put, &request->path, &headers, &b)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_store_s3_write: build request failed");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_store_s3_write: alloc chain failed");
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    return ngx_live_store_http_write(request, ctx->url, cl, request->cl,
        &ctx->write_stats);
}


static ngx_live_store_t  ngx_live_store_s3 = {
    ngx_live_store_s3_get_info,
    ngx_live_store_s3_read_init,
    ngx_live_store_http_read,
    ngx_live_store_s3_write,
};


static char *
ngx_live_store_s3_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t                      *value;
    ngx_live_conf_ctx_t            *live_ctx;
    ngx_live_store_s3_ctx_t        *ctx, **pctx;
    ngx_live_store_s3_main_conf_t  *smcf;

    pctx = (ngx_live_store_s3_ctx_t **) (p + cmd->offset);

    if (*pctx != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    live_ctx = cf->ctx;

    /* get the ctx */
    smcf = ngx_live_get_module_main_conf(live_ctx, ngx_live_store_s3_module);

    ctx = ngx_live_store_s3_get_ctx(&smcf->blocks, &value[1]);
    if (ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "unknown store_s3_block \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    *pctx = ctx;

    /* register the store */
    return ngx_live_persist_set_store(cf, &ngx_live_store_s3);
}


static ngx_live_json_writer_def_t  ngx_live_store_s3_json_writers[] = {
    { { ngx_live_store_s3_json_get_size,
        ngx_live_store_s3_json_write },
      NGX_LIVE_JSON_CTX_STORE },

      ngx_live_null_json_writer
};


static ngx_int_t
ngx_live_store_s3_postconfiguration(ngx_conf_t *cf)
{
    if (ngx_live_core_json_writers_add(cf,
        ngx_live_store_s3_json_writers) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_live_store_s3_create_main_conf(ngx_conf_t *cf)
{
    ngx_live_store_s3_main_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_live_store_s3_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    ngx_queue_init(&smcf->blocks);

    return smcf;
}


static void *
ngx_live_store_s3_create_preset_conf(ngx_conf_t *cf)
{
    ngx_live_store_s3_preset_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_live_store_s3_preset_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->ctx = NGX_CONF_UNSET_PTR;

    return conf;
}


static ngx_flag_t
ngx_live_store_s3_header_exists(ngx_array_t *conf,
    ngx_live_store_s3_header_t *header)
{
    ngx_uint_t                   i, n;
    ngx_live_store_s3_header_t  *hdrs;

    hdrs = conf->elts;
    n = conf->nelts;

    for (i = 0; i < n; i++) {
        if (hdrs[i].key.len == header->key.len &&
            ngx_strncmp(hdrs[i].lowcase_key, header->lowcase_key,
                header->key.len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static int ngx_libc_cdecl
ngx_live_store_s3_compare_headers(const void *one, const void *two)
{
    size_t                             len;
    ngx_int_t                          rc;
    const ngx_live_store_s3_header_t  *h1 = one;
    const ngx_live_store_s3_header_t  *h2 = two;

    len = ngx_min(h1->key.len, h2->key.len);
    rc = ngx_memcmp(h1->lowcase_key, h2->lowcase_key, len);
    if (rc != 0) {
        return rc;
    }

    if (h1->key.len < h2->key.len) {
        return -1;
    }

    if (h1->key.len > h2->key.len) {
        return 1;
    }

    return 0;
}


static ngx_int_t
ngx_live_store_s3_merge_headers(ngx_array_t *conf, ngx_array_t *prev,
    ngx_live_store_s3_header_t *builtin, ngx_uint_t nbuiltin)
{
    ngx_uint_t                   i;
    ngx_live_store_s3_header_t  *header;

    if (conf->nelts == 0) {
        if (prev->nelts == 0) {
            conf->elts = builtin;
            conf->nelts = nbuiltin;
            return NGX_OK;
        }

        *conf = *prev;
    }

    for (i = 0; i < nbuiltin; i++) {

        if (ngx_live_store_s3_header_exists(conf, &builtin[i])) {
            continue;
        }

        header = ngx_array_push(conf);
        if (header == NULL) {
            return NGX_ERROR;
        }

        *header = builtin[i];
    }

    ngx_qsort(conf->elts, conf->nelts, sizeof(ngx_live_store_s3_header_t),
        ngx_live_store_s3_compare_headers);

    return NGX_OK;
}


static char *
ngx_live_store_s3_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_store_s3_preset_conf_t  *prev = parent;
    ngx_live_store_s3_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->ctx,
                             prev->ctx, NULL);

    if (ngx_live_store_s3_merge_headers(&conf->put_headers, &prev->put_headers,
        ngx_live_store_s3_put_headers,
        ngx_array_entries(ngx_live_store_s3_put_headers)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
