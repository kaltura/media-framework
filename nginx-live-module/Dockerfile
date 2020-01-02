# docker run   --name live-packager --rm   --cap-add=SYS_PTRACE --security-opt seccomp=unconfined   -v /Users/guyjacubovski/dev/live/nginx-packager.conf:/usr/local/nginx/conf/nginx.conf -v /Users/guyjacubovski/dev/live/s3/:/s3/ -p 6543:6543 -p 8003:8003 -p 20000:80 kaltura/live-packager 
# add  for debug:   gdb ../sbin/nginx
ARG ALPINE_VER=3.9.4
FROM alpine:$ALPINE_VER as builder

RUN apk --update add wget git procps   openssl-dev pcre-dev zlib-dev build-base libaio-dev linux-headers

WORKDIR /tmp/build

ARG NGINX_VERSION=1.17.0

#echo "pulling nginx source code"
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz && \
    rm nginx-${NGINX_VERSION}.tar.gz -f && \
    mv nginx-${NGINX_VERSION} nginx && \
    cd /tmp/build

COPY nginx-live-module nginx-live-module
COPY nginx-common nginx-common

ARG APP_VERSION="0.1"

ENV RTMP_KMP_VERSION="${APP_VERSION}"

RUN cd /tmp/build/nginx && \
    ./configure --with-http_secure_link_module \
            --with-http_stub_status_module \
            --add-module=/tmp/build/nginx-common \
            --add-module=/tmp/build/nginx-live-module \
            --with-file-aio \
            --with-debug \
            --with-http_dav_module \
            --with-stream \
            --with-http_ssl_module \
            --with-cc-opt="-Wimplicit-fallthrough=0" \
            --with-threads && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install

FROM alpine:$ALPINE_VER

RUN apk add --update \
    pcre gdb curl \
    && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/nginx /usr/local/nginx
COPY --from=redis:5.0-alpine /usr/local/bin/redis-cli /usr/local/bin/redis-cli

EXPOSE 6543
EXPOSE 8003
EXPOSE 80
STOPSIGNAL SIGTERM

RUN mkdir /var/log/nginx
# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

WORKDIR /usr/local/nginx/conf/
CMD ["/usr/local/nginx/sbin/nginx"]
