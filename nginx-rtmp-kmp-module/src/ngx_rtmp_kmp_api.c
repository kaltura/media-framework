#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>

#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_kmp_module.h"
#include "ngx_kmp_out_track.h"


static size_t ngx_rtmp_kmp_api_streams_json_get_size(ngx_rtmp_session_t *s);
static u_char *ngx_rtmp_kmp_api_streams_json_write(u_char *p,
    ngx_rtmp_session_t *s);

static size_t ngx_rtmp_kmp_api_tracks_json_get_size(
    ngx_kmp_out_track_t **tracks);
static u_char *ngx_rtmp_kmp_api_tracks_json_write(u_char *p,
    ngx_kmp_out_track_t **tracks);


/* must match NGX_RTMP_TYPE3_EXT_TS_XXX */
ngx_str_t  ngx_rtmp_type3_ext_ts_str[] = {
    ngx_string("off"),
    ngx_string("on"),
    ngx_string("unknown"),
    ngx_null_string
};


#include "ngx_rtmp_kmp_api_json.h"


static size_t
ngx_rtmp_kmp_api_streams_json_get_size(ngx_rtmp_session_t *s)
{
    size_t                      result = 0;
    ngx_int_t                   i;
    ngx_rtmp_stream_t          *in_stream;
    ngx_rtmp_live_ctx_t        *live_ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_kmp_stream_ctx_t  *kmp_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cscf->max_streams; i++) {

        in_stream = &s->in_streams[i];
        if (in_stream->ctx == NULL) {
            continue;
        }

        kmp_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_kmp_module);
        if (kmp_ctx == NULL) {
            continue;
        }

        live_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_live_module);
        if (live_ctx == NULL || live_ctx->stream == NULL) {
            continue;
        }

        result += ngx_rtmp_kmp_api_stream_json_get_size(kmp_ctx,
            live_ctx->stream) + 1;
    }

    return result;
}


static u_char *
ngx_rtmp_kmp_api_streams_json_write(u_char *p, ngx_rtmp_session_t *s)
{
    u_char                     *start = p;
    ngx_int_t                   i;
    ngx_rtmp_stream_t          *in_stream;
    ngx_rtmp_live_ctx_t        *live_ctx;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_kmp_stream_ctx_t  *kmp_ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (i = 0; i < cscf->max_streams; i++) {

        in_stream = &s->in_streams[i];
        if (in_stream->ctx == NULL) {
            continue;
        }

        kmp_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_kmp_module);
        if (kmp_ctx == NULL) {
            continue;
        }

        live_ctx = ngx_rtmp_get_module_ctx(in_stream, ngx_rtmp_live_module);
        if (live_ctx == NULL || live_ctx->stream == NULL) {
            continue;
        }

        if (p > start) {
            *p++ = ',';
        }

        p = ngx_rtmp_kmp_api_stream_json_write(p, kmp_ctx, live_ctx->stream);
    }

    return p;
}


static size_t
ngx_rtmp_kmp_api_tracks_json_get_size(ngx_kmp_out_track_t **tracks)
{
    size_t                result = 0;
    ngx_kmp_out_track_t  *track;

    track = tracks[KMP_MEDIA_VIDEO];
    if (track != NULL) {
        result += sizeof("\"video\":") - 1;
        result += ngx_kmp_out_track_json_get_size(track);
    }

    track = tracks[KMP_MEDIA_AUDIO];
    if (track != NULL) {
        result++;      /* ',' */

        result += sizeof("\"audio\":") - 1;
        result += ngx_kmp_out_track_json_get_size(track);
    }

    return result;
}


static u_char *
ngx_rtmp_kmp_api_tracks_json_write(u_char *p, ngx_kmp_out_track_t **tracks)
{
    u_char               *start = p;
    ngx_kmp_out_track_t  *track;

    track = tracks[KMP_MEDIA_VIDEO];
    if (track != NULL) {
        p = ngx_copy_fix(p, "\"video\":");
        p = ngx_kmp_out_track_json_write(p, track);
    }

    track = tracks[KMP_MEDIA_AUDIO];
    if (track != NULL) {
        if (p > start) {
            *p++ = ',';
        }

        p = ngx_copy_fix(p, "\"audio\":");
        p = ngx_kmp_out_track_json_write(p, track);
    }

    return p;
}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_application_get_session(ngx_uint_t connection,
    ngx_rtmp_core_app_conf_t *app_conf)
{
    ngx_queue_t              *q;
    ngx_rtmp_kmp_ctx_t       *cur;
    ngx_rtmp_session_t       *s;
    ngx_rtmp_kmp_app_conf_t  *kacf;

    kacf = ngx_rtmp_get_module_app_conf(app_conf, ngx_rtmp_kmp_module);
    if (kacf == NULL) {
        return NULL;
    }

    for (q = ngx_queue_head(&kacf->sessions);
        q != ngx_queue_sentinel(&kacf->sessions);
        q = ngx_queue_next(q))
    {
        cur = ngx_queue_data(q, ngx_rtmp_kmp_ctx_t, queue);

        s = cur->s;
        if (s->connection->number == connection) {
            return s;
        }
    }

    return NULL;

}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_server_get_session(ngx_uint_t connection,
    ngx_rtmp_core_srv_conf_t *srv_conf)
{
    ngx_uint_t                  n;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_app_conf_t  **cacfp;

    cacfp = srv_conf->applications.elts;
    for (n = 0; n < srv_conf->applications.nelts; n++) {
        s = ngx_rtmp_kmp_api_application_get_session(connection, cacfp[n]);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


static ngx_rtmp_session_t *
ngx_rtmp_kmp_api_get_session(ngx_rtmp_core_main_conf_t *cmcf,
    ngx_uint_t connection)
{
    ngx_uint_t                  n;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t  **cscfp;

    cscfp = cmcf->servers.elts;
    for (n = 0; n < cmcf->servers.nelts; n++) {
        s = ngx_rtmp_kmp_api_server_get_session(connection, cscfp[n]);
        if (s != NULL) {
            return s;
        }
    }

    return NULL;
}


ngx_int_t
ngx_rtmp_kmp_api_finalize_session(ngx_uint_t connection, ngx_log_t *log)
{
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_core_main_conf;
    if (cmcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_api_finalize_session: "
            "failed to get rtmp conf");
        return NGX_ERROR;
    }

    s = ngx_rtmp_kmp_api_get_session(cmcf, connection);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_rtmp_kmp_api_finalize_session: "
            "connection %ui not found", connection);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "ngx_rtmp_kmp_api_finalize_session: "
        "dropping connection %ui", connection);
    ngx_rtmp_finalize_session(s);

    return NGX_OK;
}
