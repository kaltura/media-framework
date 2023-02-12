ARG BUILD_TAG=latest
ARG IMAGE_NAMESPACE=kaltura
ARG PYTHON_VERSION=3.8

FROM $IMAGE_NAMESPACE/transcoder-dev:$BUILD_TAG as dev

FROM python:${PYTHON_VERSION}-slim-buster

ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES video,compute,utility

RUN python3 -m pip install redis aiohttp psutil
RUN apt update && apt install -y curl
#uncomment this line if you wish to debug python inside container
# note 1: that there is no redis dbg available , so you will have to disable it
# note 2: currently python releases python:3.8-slim-buster, however no 3.8 python3-dbg  is available on buster!
#RUN apt update && apt install curl procps less vim gdb python3-dbg -y python3-psutil-dbg python3-aiohttp-dbg

WORKDIR /build
COPY --from=dev /usr/lib/x86_64-linux-gnu/libx264.s* /usr/lib/x86_64-linux-gnu/
COPY --from=dev /usr/lib/x86_64-linux-gnu/libx265.s* /usr/lib/x86_64-linux-gnu/libnuma.s* /usr/lib/x86_64-linux-gnu/
COPY --from=dev /build/transcoder  /build/
