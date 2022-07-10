#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_persist.h"


#define ngx_persist_block_id_key(id)                                         \
    ngx_hash(ngx_hash(ngx_hash(                                              \
        ( (id)        & 0xff) ,                                              \
        (((id) >> 8)  & 0xff)),                                              \
        (((id) >> 16) & 0xff)),                                              \
        (((id) >> 24) & 0xff))


typedef struct {
    ngx_hash_t                hash;
    ngx_array_t               arr;
    ngx_hash_keys_arrays_t   *keys;
} ngx_persist_block_ctx_t;

struct ngx_persist_conf_s {
    ngx_uint_t                ctx_count;
    ngx_persist_block_ctx_t   blocks[1];        /* must be last */
};


ngx_persist_conf_t *
ngx_persist_conf_create(ngx_conf_t *cf, ngx_uint_t ctx_count)
{
    ngx_uint_t               i;
    ngx_persist_conf_t      *conf;
    ngx_hash_keys_arrays_t  *keys;

    conf = ngx_palloc(cf->pool, offsetof(ngx_persist_conf_t, blocks) +
        sizeof(conf->blocks[0]) * ctx_count);
    if (conf == NULL) {
        return NULL;
    }

    conf->ctx_count = ctx_count;

    for (i = 0; i < ctx_count; i++) {
        if (ngx_array_init(&conf->blocks[i].arr, cf->pool, 5,
            sizeof(ngx_persist_block_t)) != NGX_OK)
        {
            return NULL;
        }

        keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (keys == NULL) {
            return NULL;
        }

        keys->pool = cf->pool;
        keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(keys, NGX_HASH_SMALL) != NGX_OK) {
            return NULL;
        }

        conf->blocks[i].keys = keys;
    }

    return conf;
}


static ngx_int_t
ngx_persist_conf_add_block(ngx_conf_t *cf, ngx_persist_conf_t *conf,
    ngx_persist_block_t *block)
{
    ngx_int_t             rc;
    ngx_str_t             id;
    ngx_persist_block_t  *blk;

    if (block->ctx >= conf->ctx_count) {
        ngx_conf_log_error(NGX_LOG_ALERT, cf, 0,
            "invalid block ctx %uD", block->ctx);
        return NGX_ERROR;
    }

    if (block->write != NULL) {
        blk = ngx_array_push(&conf->blocks[block->ctx].arr);
        if (blk == NULL) {
            return NGX_ERROR;
        }

        *blk = *block;
    }

    if (block->read == NULL) {
        return NGX_OK;
    }

    id.data = (u_char *) &block->id;
    id.len = sizeof(block->id);

    rc = ngx_hash_add_key(conf->blocks[block->ctx].keys, &id, block,
        NGX_HASH_READONLY_KEY);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "conflicting block name \"%V\"", &id);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_conf_add_blocks(ngx_conf_t *cf, ngx_persist_conf_t *conf,
    ngx_persist_block_t *blocks)
{
    ngx_persist_block_t  *block;

    for (block = blocks; block->id; block++) {
        if (ngx_persist_conf_add_block(cf, conf, block) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_conf_init(ngx_conf_t *cf, ngx_persist_conf_t *conf)
{
    ngx_uint_t       i;
    ngx_hash_init_t  hash;

    hash.key = ngx_hash_key;
    hash.max_size = 1024;
    hash.bucket_size = 64;
    hash.name = "blocks_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    for (i = 0; i < conf->ctx_count; i++) {
        hash.hash = &conf->blocks[i].hash;

        if (ngx_hash_init(&hash, conf->blocks[i].keys->keys.elts,
            conf->blocks[i].keys->keys.nelts) != NGX_OK)
        {
            return NGX_ERROR;
        }

        conf->blocks[i].keys = NULL;
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_conf_write_blocks(ngx_persist_conf_t *conf,
    ngx_persist_write_ctx_t *write_ctx, ngx_uint_t block_ctx, void *obj)
{
    ngx_array_t          *arr;
    ngx_persist_block_t  *cur;
    ngx_persist_block_t  *last;

    /* set the header size explicitly in case there are no child blocks */
    ngx_persist_write_block_set_header(write_ctx,
        NGX_PERSIST_HEADER_FLAG_CONTAINER);

    arr = &conf->blocks[block_ctx].arr;
    cur = arr->elts;
    last = cur + arr->nelts;

    for (; cur < last; cur++) {

        if (!(cur->flags & NGX_PERSIST_FLAG_SINGLE)) {
            if (cur->write(write_ctx, obj) != NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx),
                    0, "ngx_persist_conf_write_blocks: "
                    "write failed, id: %*s",
                    (size_t) sizeof(cur->id), &cur->id);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_persist_write_block_open(write_ctx, cur->id) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
                "ngx_persist_conf_write_blocks: open failed, id: %*s",
                (size_t) sizeof(cur->id), &cur->id);
            return NGX_ERROR;
        }

        if (cur->write(write_ctx, obj) != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, ngx_persist_write_log(write_ctx), 0,
                "ngx_persist_conf_write_blocks: write failed, id: %*s",
                (size_t) sizeof(cur->id), &cur->id);
            return NGX_ERROR;
        }

        ngx_persist_write_block_close(write_ctx);
    }

    return NGX_OK;
}


ngx_int_t
ngx_persist_conf_read_blocks(ngx_persist_conf_t *conf, ngx_uint_t ctx,
    ngx_mem_rstream_t *rs, void *obj)
{
    ngx_hash_t                  *hash;
    ngx_int_t                    rc;
    ngx_uint_t                   key;
    ngx_mem_rstream_t            block_rs;
    ngx_persist_block_t         *block;
    ngx_persist_block_header_t  *header;

    hash = &conf->blocks[ctx].hash;

    while (!ngx_mem_rstream_eof(rs)) {

        header = ngx_persist_read_block(rs, &block_rs);
        if (header == NULL) {
            return NGX_BAD_DATA;
        }

        key = ngx_persist_block_id_key(header->id);
        block = ngx_hash_find(hash, key, (u_char *) &header->id,
            sizeof(header->id));
        if (block == NULL) {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, rs->log, 0,
            "ngx_persist_conf_read_blocks: "
            "reading block, ctx: %ui, id: %*s",
            ctx, (size_t) sizeof(header->id), &header->id);

        rc = block->read(header, &block_rs, obj);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, rs->log, 0,
                "ngx_persist_conf_read_blocks: "
                "read failed, ctx: %ui, id: %*s",
                ctx, (size_t) sizeof(header->id), &header->id);
            return rc;
        }
    }

    return NGX_OK;
}
