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

static ngx_int_t ngx_live_store_s3_postconfiguration(ngx_conf_t *cf);

static void *ngx_live_store_s3_create_main_conf(ngx_conf_t *cf);

static void *ngx_live_store_s3_create_preset_conf(ngx_conf_t *cf);
static char *ngx_live_store_s3_merge_preset_conf(ngx_conf_t *cf, void *parent,
    void *child);


typedef struct {
    ngx_queue_t               queue;

    ngx_json_str_t            name;

    /* conf */
    ngx_url_t                *url;
    ngx_str_t                 host;
    ngx_str_t                 access_key;
    ngx_str_t                 secret_key;
    ngx_str_t                 service;
    ngx_str_t                 region;

    /* derivatives */
    ngx_str_t                 secret_key_prefix;
    ngx_str_t                 signing_key_date;
    ngx_str_t                 signing_key;
    ngx_str_t                 key_scope;
    ngx_str_t                 key_scope_suffix;

    ngx_live_store_stats_t    read_stats;
    ngx_live_store_stats_t    write_stats;
} ngx_live_store_s3_ctx_t;


typedef struct {
    ngx_live_store_s3_ctx_t  *ctx;
} ngx_live_store_s3_preset_conf_t;


typedef struct {
    ngx_queue_t               blocks;   /* ngx_live_store_s3_ctx_t * */
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
ngx_live_store_s3_get_request(ngx_pool_t *pool, void *arg, ngx_str_t *host,
    ngx_str_t *uri, off_t range_start, off_t range_end, ngx_buf_t **result)
{
    static const char  request_template[] =
        "GET %V HTTP/1.1\r\n"
        "Connection: Close\r\n"
        "Host: %V\r\n"
        "X-Amz-Content-SHA256: " NGX_LIVE_STORE_S3_EMPTY_SHA256 "\r\n"
        "X-Amz-Date: %V\r\n"
        "Authorization: AWS4-HMAC-SHA256 Credential=%V/%V, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=%V\r\n";

    static const char  range_header[] =
        "Range: bytes=%O-%O\r\n";

    static const char  canonical_request_template[] =
        "GET\n"
        "%V\n"
        "\n"
        "host:%V\n"
        "x-amz-content-sha256:" NGX_LIVE_STORE_S3_EMPTY_SHA256 "\n"
        "x-amz-date:%V\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        NGX_LIVE_STORE_S3_EMPTY_SHA256;

    static const char  string_to_sign_template[] =
        "AWS4-HMAC-SHA256\n"
        "%V\n"
        "%V\n"
        "%V";

    u_char                   *p;
    u_char                   *temp_buf;
    size_t                    size;
    size_t                    temp_size;
    struct tm                 tm;
    ngx_str_t                 date;
    ngx_str_t                 signature;
    ngx_str_t                 string_to_sign;
    ngx_str_t                 canonical_sha;
    ngx_str_t                 canonical_request;
    ngx_buf_t                *b;
    ngx_int_t                 rc;
    ngx_live_store_s3_ctx_t  *ctx = arg;

    u_char  date_buf[NGX_LIVE_STORE_S3_AMZ_TIME_LEN];
    u_char  signature_buf[NGX_LIVE_STORE_S3_HMAC_HEX_LEN];
    u_char  canonical_sha_buf[NGX_LIVE_STORE_S3_SHA256_HEX_LEN];

    if (ctx->host.len > 0) {
        host = &ctx->host;
    }

    /* get the request date */
    ngx_libc_gmtime(ngx_time(), &tm);
    date.len = strftime((char *) date_buf, sizeof(date_buf),
        NGX_LIVE_STORE_S3_AMZ_TIME_FORMAT, &tm);
    if (date.len == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_store_s3_get_request: strftime failed");
        return NGX_ERROR;
    }

    date.data = date_buf;

    /* generate signing key */
    if (ngx_live_store_s3_generate_signing_key(ctx, pool->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: generate signing key failed");
        return NGX_ERROR;
    }

    /* allocate a temp buffer */
    temp_size =
        sizeof(canonical_request_template) + uri->len + host->len + date.len +
        sizeof(string_to_sign_template) + date.len + ctx->key_scope.len +
        sizeof(canonical_sha_buf);

    temp_buf = ngx_alloc(temp_size, pool->log);
    if (temp_buf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: alloc temp failed");
        return NGX_ERROR;
    }

    p = temp_buf;

    /* build the canonical request */
    canonical_request.data = p;

    p = ngx_sprintf(p, canonical_request_template, uri, host, &date);

    canonical_request.len = p - canonical_request.data;

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_get_request: canonical request \"%V\"",
        &canonical_request);

    /* get the canonical request hash */
    ngx_live_store_s3_sha256_hex_buf(&canonical_request, canonical_sha_buf);

    canonical_sha.data = canonical_sha_buf;
    canonical_sha.len = sizeof(canonical_sha_buf);

    /* build the string to sign */
    string_to_sign.data = p;

    p = ngx_sprintf(p, string_to_sign_template, &date, &ctx->key_scope,
        &canonical_sha);

    string_to_sign.len = p - string_to_sign.data;

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_get_request: string to sign \"%V\"",
        &string_to_sign);

    if ((size_t) (p - temp_buf) > temp_size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_get_request: "
            "temp size %uz greater than allocated length %uz",
            (size_t) (p - temp_buf), temp_size);
        return NGX_ERROR;
    }

    /* get the signature */
    signature.data = signature_buf;

    rc = ngx_live_store_s3_hmac_sha256_hex(pool->log, &ctx->signing_key,
        &string_to_sign, &signature);

    ngx_free(temp_buf);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: failed to sign");
        return NGX_ERROR;
    }

    /* build the request */
    size = sizeof(request_template) + uri->len + host->len +
        date.len + ctx->access_key.len + ctx->key_scope.len + signature.len +
        sizeof(CRLF) - 1;

    if (range_end != -1) {
        size += sizeof(range_header) - 1 + 2 * NGX_OFF_T_LEN;
    }

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_get_request: alloc buf failed");
        return NGX_ERROR;
    }

    p = b->last;

    p = ngx_sprintf(p, request_template, uri, host, &date,
        &ctx->access_key, &ctx->key_scope, &signature);

    if (range_end != -1) {
        p = ngx_sprintf(p, range_header, range_start, range_end);
    }

    *p++ = CR; *p++ = LF;

    if ((size_t) (p - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_get_request: "
            "buffer size %uz greater than allocated length %uz",
            (size_t) (p - b->pos), size);
        return NGX_ERROR;
    }

    b->last = p;

    *result = b;

    return NGX_OK;
}


static ngx_int_t
ngx_live_store_s3_put_request(ngx_pool_t *pool, void *arg, ngx_str_t *host,
    ngx_str_t *uri, ngx_chain_t *body, size_t content_length,
    ngx_buf_t **result, ngx_str_t *tag_header)
{
    static const char request_template[] =
        "PUT %V HTTP/1.1\r\n"
        "Connection: Close\r\n"
        "Content-Length: %uz\r\n"
        "Expect: 100-continue\r\n"
        "Host: %V\r\n"
        "X-Amz-Content-SHA256: %V\r\n"
        "X-Amz-Date: %V\r\n"
        "X-Amz-Tagging: %V\r\n"
        "Authorization: AWS4-HMAC-SHA256 Credential=%V/%V, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-tagging, "
        "Signature=%V\r\n"
        "\r\n";

    static const char canonical_request_template[] =
        "PUT\n"
        "%V\n"
        "\n"
        "host:%V\n"
        "x-amz-content-sha256:%V\n"
        "x-amz-date:%V\n"
        "x-amz-tagging:%V\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date;x-amz-tagging\n"
        "%V";

    static const char string_to_sign_template[] =
        "AWS4-HMAC-SHA256\n"
        "%V\n"
        "%V\n"
        "%V";

    u_char                   *p;
    u_char                   *temp_buf;
    size_t                    size;
    size_t                    temp_size;
    struct tm                 tm;
    ngx_str_t                 date;
    ngx_str_t                 signature;
    ngx_str_t                 content_sha;
    ngx_str_t                 canonical_sha;
    ngx_str_t                 string_to_sign;
    ngx_str_t                 canonical_request;
    ngx_buf_t                *b;
    ngx_int_t                 rc;
    ngx_live_store_s3_ctx_t  *ctx = arg;

    u_char  date_buf[NGX_LIVE_STORE_S3_AMZ_TIME_LEN];
    u_char  signature_buf[NGX_LIVE_STORE_S3_HMAC_HEX_LEN];
    u_char  content_sha_buf[NGX_LIVE_STORE_S3_SHA256_HEX_LEN];
    u_char  canonical_sha_buf[NGX_LIVE_STORE_S3_SHA256_HEX_LEN];

    if (ctx->host.len > 0) {
        host = &ctx->host;
    }

    /* get the request date */
    ngx_libc_gmtime(ngx_time(), &tm);
    date.len = strftime((char *) date_buf, sizeof(date_buf),
        NGX_LIVE_STORE_S3_AMZ_TIME_FORMAT, &tm);
    if (date.len == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_live_store_s3_put_request: strftime failed");
        return NGX_ERROR;
    }

    date.data = date_buf;

    /* generate signing key */
    if (ngx_live_store_s3_generate_signing_key(ctx, pool->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_put_request: generate signing key failed");
        return NGX_ERROR;
    }

    /* allocate a temp buffer */
    temp_size =
        sizeof(canonical_request_template) + uri->len + host->len +
            2 * sizeof(content_sha_buf) + date.len +
        sizeof(string_to_sign_template) + date.len + ctx->key_scope.len +
            sizeof(canonical_sha_buf);

    temp_buf = ngx_alloc(temp_size, pool->log);
    if (temp_buf == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_put_request: alloc temp failed");
        return NGX_ERROR;
    }

    p = temp_buf;

    /* get the content sha256 + hex */
    ngx_live_store_s3_sha256_hex_chain(body, content_sha_buf);
    content_sha.data = content_sha_buf;
    content_sha.len = sizeof(content_sha_buf);

    /* build the canonical request */
    canonical_request.data = p;

    p = ngx_sprintf(p, canonical_request_template,
        uri, host, &content_sha, &date, tag_header, &content_sha);

    canonical_request.len = p - canonical_request.data;

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_put_request: canonical request \"%V\"",
        &canonical_request);

    /* get the canonical request hash */
    ngx_live_store_s3_sha256_hex_buf(&canonical_request, canonical_sha_buf);

    canonical_sha.data = canonical_sha_buf;
    canonical_sha.len = sizeof(canonical_sha_buf);

    /* build the string to sign */
    string_to_sign.data = p;

    p = ngx_sprintf(p, string_to_sign_template,
        &date, &ctx->key_scope, &canonical_sha);

    string_to_sign.len = p - string_to_sign.data;

    ngx_log_debug1(NGX_LOG_DEBUG_LIVE, pool->log, 0,
        "ngx_live_store_s3_put_request: string to sign \"%V\"",
        &string_to_sign);

    if ((size_t) (p - temp_buf) > temp_size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_put_request: "
            "temp size %uz greater than allocated length %uz",
            (size_t) (p - temp_buf), temp_size);
        return NGX_ERROR;
    }

    /* get the signature */
    signature.data = signature_buf;

    rc = ngx_live_store_s3_hmac_sha256_hex(pool->log, &ctx->signing_key,
        &string_to_sign, &signature);

    ngx_free(temp_buf);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_put_request: failed to sign");
        return NGX_ERROR;
    }

    /* build the request */
    size = sizeof(request_template) + uri->len + NGX_SIZE_T_LEN +
        host->len + content_sha.len + date.len + ctx->access_key.len +
        ctx->key_scope.len + signature.len;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
            "ngx_live_store_s3_put_request: alloc buf failed");
        return NGX_ERROR;
    }

    b->last = ngx_sprintf(b->last, request_template,
        uri, content_length, host, &content_sha, &date, tag_header,
        &ctx->access_key, &ctx->key_scope, &signature);

    if ((size_t) (b->last - b->pos) > size) {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
            "ngx_live_store_s3_put_request: "
            "buffer size %uz greater than allocated length %uz",
            (size_t) (b->last - b->pos), size);
        return NGX_ERROR;
    }

ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                                "AAAA host %V",  host);
    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                                "AAAA SHA %V",  &content_sha);

    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                            "AAAA date %V",  &date);

    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                            "AAAA access %V",  &ctx->access_key);
    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                            "AAAA key scope %V",  &ctx->key_scope);
    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                        "AAAA sig %V",  &signature);

ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                        "AAAA signing key %V",  &ctx->signing_key);
ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                        "AAAA str to sigh %V",  &string_to_sign);


    *result = b;

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
    ngx_buf_t                        *b;
    ngx_pool_t                       *pool;
    ngx_chain_t                      *cl;
    ngx_live_channel_t               *channel;
    ngx_live_store_s3_ctx_t          *ctx;
    ngx_live_store_s3_preset_conf_t  *conf;

    channel = request->channel;
    conf = ngx_live_get_module_preset_conf(channel, ngx_live_store_s3_module);

    ctx = conf->ctx;

    pool = request->pool;
//    ngx_str_t tag_header = ngx_string("tag=test2");
//    ngx_str_t* tag_header_p = &tag_header;
    if (ngx_live_store_s3_put_request(pool, ctx, &ctx->url->host,
        &request->path, request->cl, request->size, &b, &request->tag_value) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, &channel->log, 0,
            "ngx_live_store_s3_write: create request failed");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, pool->log, 0,
                                "FFFFFFF %V",  &request->tag_value);
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


static char *
ngx_live_store_s3_merge_preset_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_live_store_s3_preset_conf_t  *prev = parent;
    ngx_live_store_s3_preset_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->ctx,
                             prev->ctx, NULL);

    return NGX_CONF_OK;
}
