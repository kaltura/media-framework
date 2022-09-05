#docker run  -it --name live-rtmp --rm  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined   -v /Users/guyjacubovski/dev/live/nginx-rtmp.conf:/usr/local/nginx/conf/nginx.conf -p 1935:1935 -p 8001:8001 kaltura/live-nginx-rtmp 
#for debug: add gdb ../sbin/nginx
ARG ALPINE_VER=3.16
FROM alpine:$ALPINE_VER as builder

RUN apk --update add wget git procps   openssl-dev pcre-dev zlib-dev build-base libaio-dev linux-headers tcl cmake

WORKDIR /tmp/build

ARG NGINX_VERSION=1.21.0

# get srt lib
RUN git clone https://github.com/Haivision/srt/ && cd srt && ./configure && make && make install

#echo "pulling nginx source code"
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz && \
    rm nginx-${NGINX_VERSION}.tar.gz -f && \
    mv nginx-${NGINX_VERSION} nginx && \
    cd /tmp/build

COPY nginx-common nginx-common
COPY nginx-rtmp-module nginx-rtmp-module
COPY nginx-kmp-out-module nginx-kmp-out-module
COPY nginx-rtmp-kmp-module nginx-rtmp-kmp-module
COPY nginx-mpegts-module nginx-mpegts-module
COPY nginx-mpegts-kmp-module nginx-mpegts-kmp-module
RUN git clone https://github.com/kaltura/nginx-srt-module

ARG APP_VERSION=1.0

ARG DEBUG_BUILD=0

ENV RTMP_KMP_VERSION="${APP_VERSION}"
ENV MPEGTS_KMP_VERSION="${APP_VERSION}"

RUN [ "${DEBUG_BUILD}" -eq "1" ] && debug_option=--with-debug; \
    cd /tmp/build/nginx &&  \
    ./configure --with-http_secure_link_module \
            --with-http_stub_status_module \
            --add-module=/tmp/build/nginx-common \
            --add-module=/tmp/build/nginx-rtmp-module \
            --add-module=/tmp/build/nginx-kmp-out-module \
            --add-module=/tmp/build/nginx-rtmp-kmp-module \
            --add-module=/tmp/build/nginx-mpegts-module \
            --add-module=/tmp/build/nginx-mpegts-kmp-module \
            --add-module=/tmp/build/nginx-srt-module \
            --with-file-aio \
            --with-stream \
            --with-http_ssl_module \
            --with-stream_ssl_module  $debug_option \
            $debug_option \
            --with-cc-opt="-O2" \
            --with-threads && \
    make -j $(getconf _NPROCESSORS_ONLN) && \
    make install

FROM alpine:$ALPINE_VER

RUN apk add --update \
    pcre  curl gdb python3 tcpdump\
    && rm -rf /var/cache/apk/*

COPY --from=builder /usr/local/nginx /usr/local/nginx
COPY --from=builder /usr/local/lib /usr/local/lib

RUN apk add cmd:pip3
RUN pip3 install redis
ENV LD_LIBRARY_PATH="/usr/local/lib"


EXPOSE 1935
EXPOSE 8001
EXPOSE 7045/udp
STOPSIGNAL SIGTERM


RUN mkdir /var/log/nginx
# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log


WORKDIR /usr/local/nginx/conf/

# TODO: Swap chmod for more elegant solution
CMD chmod 777 /tmp/dumps && /usr/local/nginx/sbin/nginx
