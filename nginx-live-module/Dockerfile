# docker run   --name live-packager --rm   --cap-add=SYS_PTRACE --security-opt seccomp=unconfined   -v /Users/guyjacubovski/dev/live/nginx-packager.conf:/usr/local/nginx/conf/nginx.conf -v /Users/guyjacubovski/dev/live/s3/:/s3/ -p 6543:6543 -p 8003:8003 -p 20000:80 kaltura/live-packager 
# add  for debug:   gdb ../sbin/nginx
ARG ALPINE_VER=3.11.3
FROM alpine:$ALPINE_VER as builder

RUN apk --update add wget git procps   openssl-dev pcre-dev zlib-dev build-base libaio-dev linux-headers

WORKDIR /tmp/build

ARG NGINX_VERSION=1.17.8
ARG NGX_DEVEL_KIT_VERSION=v0.3.1
ARG SET_MISC_NGINX_MODULE_VERSION=v0.32

#echo "pulling nginx source code"
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz && \
    rm nginx-${NGINX_VERSION}.tar.gz -f && \
    mv nginx-${NGINX_VERSION} nginx && \
    cd /tmp/build

RUN git clone --branch ${NGX_DEVEL_KIT_VERSION} https://github.com/simplresty/ngx_devel_kit
RUN git clone --branch ${SET_MISC_NGINX_MODULE_VERSION} https://github.com/kaltura/set-misc-nginx-module

COPY nginx-live-module nginx-live-module
COPY nginx-pckg-module nginx-pckg-module
COPY nginx-common nginx-common

ARG APP_VERSION="0.1"
ARG LIVE_VERSION="${APP_VERSION}"

ENV RTMP_KMP_VERSION="${APP_VERSION}"

RUN cd /tmp/build/nginx && \
    ./configure --with-http_secure_link_module \
            --with-http_stub_status_module \
            --add-module=/tmp/build/nginx-common \
            --add-module=/tmp/build/nginx-live-module \
            --add-module=/tmp/build/nginx-pckg-module \
            --add-module=/tmp/build/ngx_devel_kit \
            --add-module=/tmp/build/set-misc-nginx-module \
            --with-file-aio \
            --with-http_dav_module \
            --with-stream \
            --with-http_ssl_module \
            --with-cc-opt="-O2" \
            --with-threads && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install

FROM alpine:$ALPINE_VER

RUN apk add --update \
    pcre gdb curl python3 \
    && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/nginx /usr/local/nginx

RUN pip3 install redis boto3

EXPOSE 6543
EXPOSE 8003
EXPOSE 80
STOPSIGNAL SIGTERM

RUN mkdir /var/log/nginx
# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

WORKDIR /usr/local/nginx/conf/
# TODO: Swap chmod for more elegant solution
CMD chmod 777 /tmp/dumps && /usr/local/nginx/sbin/nginx
