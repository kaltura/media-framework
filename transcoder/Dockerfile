# NB: duplicate declaration!
ARG CUDA_VERSION="11.0"
ARG BUILD_TAG=latest
ARG IMAGE_NAMESPACE=kaltura
FROM $IMAGE_NAMESPACE/transcoder-dev:$BUILD_TAG as dev

FROM nvidia/cuda:${CUDA_VERSION}-base

RUN apt-get update && apt-get install -y sudo python3 python3-pip
RUN pip3 install redis

WORKDIR /build
COPY --from=dev /usr/lib/x86_64-linux-gnu/libx264.s* /usr/lib/x86_64-linux-gnu/
COPY --from=dev /build/transcoder  /build/

ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES video,compute,utility
