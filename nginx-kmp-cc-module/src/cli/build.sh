NGX_ROOT=/usr/local/src/nginx
LIVE_ROOT=../../..

CC=${CC:-gcc}
CC_OPT=${CC_OPT:--O0 -g -Wall}

$CC -o main $CC_OPT                               \
    -I$NGX_ROOT/src/core/                         \
    -I$NGX_ROOT/src/event/                        \
    -I$NGX_ROOT/src/os/unix/                      \
    -I$NGX_ROOT/objs/                             \
    -I$LIVE_ROOT/nginx-common/src                 \
    -I$LIVE_ROOT/nginx-kmp-out-module/src         \
    -I$LIVE_ROOT/nginx-kmp-in-module/src          \
    $NGX_ROOT/src/core/ngx_palloc.c               \
    $NGX_ROOT/src/core/ngx_rbtree.c               \
    $NGX_ROOT/src/core/ngx_string.c               \
    $NGX_ROOT/src/core/ngx_times.c                \
    $NGX_ROOT/src/os/unix/ngx_alloc.c             \
    $NGX_ROOT/src/os/unix/ngx_time.c              \
    $LIVE_ROOT/nginx-common/src/ngx_buf_chain.c   \
    ../media/cea708.c                             \
    ../media/eia608.c                             \
    ../media/webvtt.c                             \
    ../ngx_buf_chain_reader.c                     \
    ../ngx_kmp_cc.c                               \
    main.c
