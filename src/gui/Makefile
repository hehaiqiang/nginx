
CC = cl
CFLAGS = -O2 -W3 -WX -nologo -MT
LINK =	$(CC)
RC = rc


objs/gui.exe:	objs/ngx_gui.obj \
	objs/ngx_gui.res
	$(LINK) @<<
	-link -nodefaultlib:oldnames.lib -verbose:lib -subsystem:windows
	-Feobjs/gui
	objs/ngx_gui.obj objs/ngx_gui.res
	kernel32.lib user32.lib advapi32.lib shell32.lib
<<


objs/ngx_gui.obj:	src/gui/ngx_gui.h \
	src/gui/ngx_gui.c
	$(CC) -c $(CFLAGS) -I src/gui \
		-Foobjs/ngx_gui.obj \
		src/gui/ngx_gui.c


objs/ngx_gui.res:	src/gui/ngx_gui.ico \
	src/gui/ngx_gui.rc
	$(RC) -I src/gui \
		-foobjs/ngx_gui.res \
		src/gui/ngx_gui.rc
