#!/bin/sh

# Copyright (C) Ngwsx


CYGWIN=/cygdrive/j
WINDOWS=j:
VS=tools/vc2008
VS_COMMON_DIR=$VS/Common7
MS_DEV_DIR=$VS_COMMON_DIR/IDE
MS_VC_DIR=$VS/VC

export CC=cl
export INCLUDE="$WINDOWS/$MS_VC_DIR/PlatformSDK/Include;$WINDOWS/$MS_VC_DIR/Include"
export LIB="$WINDOWS/$MS_VC_DIR/PlatformSDK/Lib;$WINDOWS/$MS_VC_DIR/lib"
export PATH=$CYGWIN/$MS_DEV_DIR:$CYGWIN/$MS_VC_DIR/bin:$PATH


make clean

./configure \
	--crossbuild=win32 \
	--prefix= \
	--conf-path=conf/nginx.conf \
	--pid-path=logs/nginx.pid \
	--http-log-path=logs/access.log \
	--error-log-path=logs/error.log \
	--sbin-path=nginx.exe \
	--http-client-body-temp-path=temp/client_body_temp \
	--http-proxy-temp-path=temp/proxy_temp \
	--http-fastcgi-temp-path=temp/fastcgi_temp \
	--with-cc-opt="-DFD_SETSIZE=1024 -D_CRT_SECURE_NO_WARNINGS" \
	--without-http-cache \
	--without-http_rewrite_module \
	--without-http_auth_basic_module \
	--without-http_gzip_module

make -f objs/Makefile
