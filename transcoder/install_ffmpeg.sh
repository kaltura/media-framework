#!/bin/sh

#  install_ffmpeg.sh
#  livetranscoder
#
#  Created by Guy.Jacubovski on 30/12/2018.
#  Copyright © 2018 Kaltura. All rights reserved.
set -ex


#export PATH="$HOME/compiled/bin":$PATH
#export PKG_CONFIG_PATH=$HOME/compiled/lib/pkgconfig

BASE_DIR="$(dirname "$0")/ThirdParty"

BASE_DIR="/Users/guyjacubovski/dev/live-transcoder/ThirdParty"

export PATH="$BASE_DIR/compiled/bin":$PATH
export PKG_CONFIG_PATH=$BASE_DIR/compiled/lib/pkgconfig

echo $BASE_DIR
mkdir -p "$BASE_DIR/compiled"

if [ ! -f "$BASE_DIR/nasm/nasm" ]; then
    rm -rf "$BASE_DIR/nasm"
    # sudo apt-get -y install asciidoc xmlto # this fails :(
    git clone -b nasm-2.14.02 http://repo.or.cz/nasm.git "$BASE_DIR/nasm"
    cd "$BASE_DIR/nasm"
    ./autogen.sh
    ./configure --prefix="$BASE_DIR/compiled"
    make
    make install || echo "Installing docs fails but should be OK otherwise"
fi

#if [ ! -f "$BASE_DIR/x264/x264" ]; then
#    rm -rf "$BASE_DIR/x264"
#git clone http://git.videolan.org/git/x264.git "$BASE_DIR/x264"
    cd "$BASE_DIR/x264"
    # git master as of this writing
    git checkout master
    ./configure --enable-debug --prefix="$BASE_DIR/compiled" --enable-pic --enable-static
    make
    make install-lib-static
#fi

#if [ ! -f "$BASE_DIR/ffmpeg/libavcodec/libavcodec.a" ]; then
#   rm -rf "$BASE_DIR/ffmpeg"
#   git clone -b n4.1 https://git.ffmpeg.org/ffmpeg.git "$BASE_DIR/ffmpeg" || echo "FFmpeg dir already exists"
    cd "$BASE_DIR/ffmpeg"
    ./configure --prefix="$BASE_DIR/compiled"  --enable-debug --enable-libx264 --enable-gpl --enable-static #--enable-gnutls
    make
    make install
#fi
