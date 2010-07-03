#!/bin/sh

# Copyright (C) Ngwsx


. vc.sh


rm -f gui.exe objs/gui.exe
rm -f objs/ngx_gui.obj
rm -f objs/ngx_gui.res

nmake -f src/gui/Makefile

cp objs/gui.exe gui.exe
