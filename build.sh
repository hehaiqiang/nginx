#!/bin/sh

# Copyright (C) Ngwsx


VS=/j/tools/vc2008
#VS=/c/Program\ Files/Microsoft\ Visual\ Studio\ 8
IDE_DIR=$VS/Common7/IDE
VC_DIR=$VS/VC


export CC=cl
export INCLUDE=$VC_DIR/PlatformSDK/Include:$VC_DIR/Include:$INCLUDE
export LIB=$VC_DIR/PlatformSDK/Lib:$VC_DIR/lib:$LIB
export PATH=$IDE_DIR:$VC_DIR/bin:$PATH


#nmake -f objs/Makefile
#exit


rm -f nginx.exe

nmake clean

./configure \
	--crossbuild=win32 \
	--prefix= \
	--sbin-path=nginx.exe \
	--conf-path=conf/nginx.conf \
	--pid-path=logs/nginx.pid \
	--error-log-path=logs/error.log \
	--http-log-path=logs/access.log \
	--http-client-body-temp-path=temp/client_body_temp \
	--http-proxy-temp-path=temp/proxy_temp \
	--http-fastcgi-temp-path=temp/fastcgi_temp \
	--with-cc-opt="-DFD_SETSIZE=1024 -D_CRT_SECURE_NO_WARNINGS" \
	--with-select_module \
	--with-file-aio \
	--with-ipv6 \
	--with-http_realip_module \
	--with-http_addition_module \
	--with-http_sub_module \
	--with-http_dav_module \
	--with-http_flv_module \
	--with-http_gzip_static_module \
	--with-http_random_index_module \
	--with-http_secure_link_module \
	--with-http_stub_status_module \
	--with-http_ssl_module \
	--without-http_auth_basic_module \
	--with-mail \
	--with-mail_ssl_module \
	--with-openssl=lib/openssl \
	--with-openssl-opt=enable-tlsext \
	--with-pcre=lib/pcre \
	--with-zlib=lib/zlib \
	--with-debug

nmake -f objs/Makefile

cp objs/nginx.exe nginx.exe
