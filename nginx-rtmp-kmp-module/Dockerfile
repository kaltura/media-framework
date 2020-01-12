#docker run  -it --name live-rtmp --rm  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined   -v /Users/guyjacubovski/dev/live/nginx-rtmp.conf:/usr/local/nginx/conf/nginx.conf -p 1935:1935 -p 8001:8001 kaltura/live-nginx-rtmp 
#for debug: add gdb ../sbin/nginx
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

COPY nginx-rtmp-module nginx-rtmp-module
COPY nginx-rtmp-kmp-module nginx-rtmp-kmp-module
COPY nginx-common nginx-common

ARG APP_VERSION=1.0

ENV RTMP_KMP_VERSION="${APP_VERSION}"

RUN cd /tmp/build/nginx &&  \
    ./configure --with-http_secure_link_module \
            --with-http_stub_status_module \
            --add-module=/tmp/build/nginx-common \
            --add-module=/tmp/build/nginx-rtmp-module \
            --add-module=/tmp/build/nginx-rtmp-kmp-module \
            --with-debug \
            --with-file-aio \
            --with-http_ssl_module \
            --with-cc-opt="-Wimplicit-fallthrough=0" \
            --with-threads && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install

FROM alpine:$ALPINE_VER

RUN apk add --update \
    pcre  curl gdb python3\
    && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/nginx /usr/local/nginx
RUN pip3 install redis


EXPOSE 1935
EXPOSE 8001
STOPSIGNAL SIGTERM


RUN mkdir /var/log/nginx
# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log


WORKDIR /usr/local/nginx/conf/


CMD ["/usr/local/nginx/sbin/nginx"]
