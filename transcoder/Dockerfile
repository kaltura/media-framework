
ARG  CUDA_VERSION="10.0"

FROM nvidia/cuda:${CUDA_VERSION}-devel 

WORKDIR /build

RUN apt-get update && apt-get install -y sudo git build-essential gdbserver vim yasm cmake libtool autogen dh-autoreconf libbz2-dev libc6 libc6-dev unzip wget libnuma1 libnuma-dev frei0r-plugins-dev libgnutls28-dev libass-dev libmp3lame-dev libopencore-amrnb-dev libopencore-amrwb-dev libopus-dev librtmp-dev libsoxr-dev libspeex-dev libtheora-dev libvo-amrwbenc-dev libvorbis-dev libvpx-dev libwebp-dev libx264-dev libx265-dev libxvidcore-dev

ARG  FFMPEG_VERSION="n4.1.1"
ARG  NVIDIA_CODEC_HEADERS_VERSION="n8.1.24.9"

RUN git clone --branch ${NVIDIA_CODEC_HEADERS_VERSION} https://github.com/FFmpeg/nv-codec-headers.git
RUN cd nv-codec-headers && \
    make && \
    sudo make install

RUN git clone --branch ${FFMPEG_VERSION}  https://github.com/ffmpeg/ffmpeg.git && \ 
        cd ffmpeg


#RUN  cd ffmpeg && ./configure --disable-doc --enable-nonfree --disable-shared --enable-nvenc --enable-cuda --enable-cuvid --enable-libnpp --extra-cflags=-Ilocal/include --enable-gpl --enable-version3 --disable-debug --disable-ffplay --disable-indev=sndio --disable-outdev=sndio --enable-fontconfig --enable-frei0r --enable-gnutls --enable-gray --enable-libass --enable-libfreetype --enable-libfribidi --enable-libmp3lame --enable-libopencore-amrnb --enable-libopencore-amrwb --enable-libopus --enable-librtmp --enable-libsoxr --enable-libspeex --enable-libtheora --enable-libvo-amrwbenc --enable-libvorbis --enable-libvpx --enable-libwebp --enable-libx264 --enable-libx265 --enable-libxvid  --extra-cflags=-I/usr/local/cuda/include --extra-ldflags=-L/usr/local/cuda/lib64 && \
#        make -j 8 && \
#        make install


RUN  cd ffmpeg && ./configure --disable-doc --enable-nonfree --disable-shared --enable-nvenc --enable-cuda --enable-cuvid --enable-libnpp --extra-cflags=-Ilocal/include --enable-gpl --enable-version3 --disable-debug --disable-ffplay --disable-indev=sndio --disable-outdev=sndio     --enable-libx264    --extra-cflags=-I/usr/local/cuda/include --extra-ldflags=-L/usr/local/cuda/lib64 && \
        make -j 8 && \
        make install

COPY . . 

ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES video,compute,utility

#RUN cmake -DSTATICCOMPILE=ON   -DSTATIC=true . && make
RUN make clean && make && make install

RUN ./transcoder || true