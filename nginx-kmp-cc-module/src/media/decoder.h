#ifndef DECODER_H_
#define DECODER_H_


#include <ngx_config.h>
#include <ngx_core.h>


/* VLC definitions */

#define ARRAY_SIZE(x)  (sizeof(x) / sizeof((x)[0]))

#define VLC_TICK_INVALID  LLONG_MAX  /* defined as 0 in VLC */
#define VLC_TICK_FROM_MS(ms)  ((CLOCK_FREQ / INT64_C(1000)) * (ms))
#define CLOCK_FREQ INT64_C(1000000)


#define false       0
#define true        1

#define bool        int

#define int8_t      char
#define uint8_t     unsigned char


typedef int64_t     vlc_tick_t;


/* nginx wrappers */

#define CC_INT32_LEN  NGX_INT32_LEN

#define cc_string   ngx_string
#define cc_copy     ngx_copy

#define cc_str_t    ngx_str_t
#define cc_log_t    ngx_log_t

#define cc_sprintf  ngx_sprintf
                                                                             \
#define cc_log_debug0(log, fmt)                                              \
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, (log), 0, fmt)
#define cc_log_debug1(log, fmt, arg1)                                        \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1)
#define cc_log_debug2(log, fmt, arg1, arg2)                                  \
    ngx_log_debug2(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2)
#define cc_log_debug3(log, fmt, arg1, arg2, arg3)                            \
    ngx_log_debug3(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2, arg3)
#define cc_log_debug4(log, fmt, arg1, arg2, arg3, arg4)                      \
    ngx_log_debug4(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2, arg3,      \
                   arg4)
#define cc_log_debug5(log, fmt, arg1, arg2, arg3, arg4, arg5)                \
    ngx_log_debug5(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2, arg3,      \
                   arg4, arg5)
#define cc_log_debug6(log, fmt, arg1, arg2, arg3, arg4, arg5, arg6)          \
    ngx_log_debug6(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2, arg3,      \
                   arg4, arg5, arg6)
#define cc_log_debug8(log, fmt, arg1, arg2, arg3, arg4, arg5, arg6, arg7,    \
                      arg8)                                                  \
    ngx_log_debug8(NGX_LOG_DEBUG_CORE, (log), 0, fmt, arg1, arg2, arg3,      \
                   arg4, arg5, arg6, arg7, arg8)

#define cc_debug_point  ngx_debug_point

#define cc_assert(x)  if (!(x)) { cc_debug_point(); }


typedef struct
{
    void (*start)(void *priv);
    void (*add_setting)(void *priv, ngx_str_t *str);
    void (*write)(void *priv, void *buf, size_t len);
    void (*end)(void *priv, vlc_tick_t start, vlc_tick_t end);
} subtitle_handler_t;


static ngx_inline vlc_tick_t
vlc_tick_from_samples(int64_t samples, int samp_rate)
{
    return CLOCK_FREQ * samples / samp_rate;
}

#endif
