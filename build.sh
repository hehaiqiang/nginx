#!/bin/sh

# Copyright (C) Ngwsx


make clean

./configure --builddir=objs.msvc8 --crossbuild=win32 --with-debug --prefix= --conf-path=conf/nginx.conf --pid-path=logs/nginx.pid --http-log-path=logs/access.log --error-log-path=logs/error.log --sbin-path=nginx.exe --with-cc=mingw32-gcc --with-cc-opt="-DFD_SETSIZE=1024 -mno-cygwin" --with-select_module --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_dav_module --with-http_stub_status_module --with-http_flv_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-mail --with-ipv6

make -f objs.msvc8/Makefile
