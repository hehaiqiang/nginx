#!/bin/sh

# Copyright (C) Ngwsx


#. vc8.sh
#. vc9.sh
. vc10.sh

export CC=cl
export INCLUDE=$SDK/include:$VC/include:$INCLUDE
export LIB=$SDK/lib:$VC/lib:$LIB
export PATH=$IDE:$VC/bin:$PATH


rm -f gui.exe objs/gui.exe
rm -f objs/ngx_gui.obj
rm -f objs/ngx_gui.res

nmake -f src/gui/Makefile

cp objs/gui.exe gui.exe
