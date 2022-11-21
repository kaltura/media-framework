#!/bin/sh

if [ ! -x auto/configure ]
then
    echo "configure not found, run this script from the nginx source folder"
    exit 1
fi

MEDIA_FRAMEWORK=`dirname $0`/..

for arg
do EXTRA_MODULES="$EXTRA_MODULES --add-module=$arg"
done

auto/configure                                            \
    --with-stream                                         \
    --with-threads                                        \
    --with-http_dav_module                                \
    --add-module=$MEDIA_FRAMEWORK/nginx-common            \
    --add-module=$MEDIA_FRAMEWORK/nginx-kmp-in-module     \
    --add-module=$MEDIA_FRAMEWORK/nginx-kmp-out-module    \
    --add-module=$MEDIA_FRAMEWORK/nginx-rtmp-module       \
    --add-module=$MEDIA_FRAMEWORK/nginx-rtmp-kmp-module   \
    --add-module=$MEDIA_FRAMEWORK/nginx-mpegts-module     \
    --add-module=$MEDIA_FRAMEWORK/nginx-mpegts-kmp-module \
    --add-module=$MEDIA_FRAMEWORK/nginx-kmp-cc-module     \
    --add-module=$MEDIA_FRAMEWORK/nginx-kmp-rtmp-module   \
    --add-module=$MEDIA_FRAMEWORK/nginx-live-module       \
    --add-module=$MEDIA_FRAMEWORK/nginx-pckg-module       \
    $EXTRA_MODULES
