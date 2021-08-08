ARG BUILD_TAG=latest
ARG IMAGE_NAMESPACE=kaltura
ARG PYTHON_VERSION=3.8

FROM $IMAGE_NAMESPACE/transcoder-dev:$BUILD_TAG as dev

FROM python:${PYTHON_VERSION}-slim-buster

ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES video,compute,utility

RUN python3 -m pip install redis && ln -sf /usr/local/bin/python3 /usr/bin/
WORKDIR /build
COPY --from=dev /usr/lib/x86_64-linux-gnu/libx264.s* /usr/lib/x86_64-linux-gnu/
COPY --from=dev /build/transcoder  /build/


