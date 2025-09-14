#!/bin/sh
set -eo nounset                              # Treat unset variables as an error
echo "lala"
BASE_DOWNLOAD_URI=http://nginx.org/download
echo $BASE_DOWNLOAD_URI
NGINX_VERSION=`curl -L "http://nginx.org/en/download.html" |
   grep -oP 'href="/download/nginx-\K[0-9]+\.[0-9]+\.[0-9]+' |
   sort -t. -rn -k1,1 -k2,2 -k3,3 | head -1`
echo $NGINX_VERSION
NGINX_URI="$BASE_DOWNLOAD_URI/nginx-$NGINX_VERSION.tar.gz"

if [ ! -x "`which curl 2>/dev/null`" ];then
        echo "Need to install curl."
        exit 2
fi


if [ -n "$1" ] ;then
    NGINX_MODULE_FLAG=$1
fi
MEDIA_FRAMEWORK=media-framework
BUILDDIR=/tmp/builddir/${MEDIA_FRAMEWORK}_$$
rm -rf $BUILDDIR
mkdir -p $BUILDDIR
cp -r . $BUILDDIR/$MEDIA_FRAMEWORK
cd $BUILDDIR
curl $NGINX_URI > kaltura-nginx-$NGINX_VERSION.tar.gz
tar zxf kaltura-nginx-$NGINX_VERSION.tar.gz
mv nginx-$NGINX_VERSION build_nginx
cd build_nginx

MEDIA_FRAMEWORK_MODULE_LIST="nginx-common nginx-kmp-in-module nginx-kmp-out-module nginx-rtmp-module nginx-rtmp-kmp-module nginx-mpegts-module nginx-mpegts-kmp-module nginx-kmp-cc-module nginx-kmp-rtmp-module nginx-live-module nginx-pckg-module"
MEDIA_FRAMEWORK_MODULE_ARGS=''

for MODULE in $MEDIA_FRAMEWORK_MODULE_LIST; do
    MEDIA_FRAMEWORK_MODULE_ARGS="$MEDIA_FRAMEWORK_MODULE_ARGS $NGINX_MODULE_FLAG=../$MEDIA_FRAMEWORK/$MODULE"
done

./configure \
        --prefix=/etc/nginx \
        --sbin-path=/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/log/nginx/error.log \
        --http-log-path=/var/log/log/nginx/access.log \
        --pid-path=/var/log/run/nginx.pid \
        --lock-path=/var/log/run/nginx.lock \
        --http-client-body-temp-path=/var/log/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/log/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/log/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/log/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/log/cache/nginx/scgi_temp \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_stub_status_module \
        --with-http_auth_request_module \
        --with-mail \
        --with-mail_ssl_module \
        --with-file-aio \
        --with-ipv6 \
        --with-debug \
        --with-threads \
	--with-stream \
        --with-cc-opt="-O3" \
        $MEDIA_FRAMEWORK_MODULE_ARGS
make -j $(nproc)
sudo make install
