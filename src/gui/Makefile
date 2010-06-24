
CC =	cl
CFLAGS =  -O2  -W3 -WX -nologo -MT
CPP =	
LINK =	$(CC)


objs/gui.exe:	objs/ngx_gui.obj \
	objs/ngx_gui.res
	$(LINK) @<<
	-Feobjs/gui
	objs/ngx_gui.obj
	kernel32.lib user32.lib advapi32.lib shell32.lib
	objs/ngx_gui.res -link -nodefaultlib:oldnames.lib -verbose:lib -subsystem:windows
	
<<


objs/ngx_gui.obj:	src/gui/ngx_gui.h \
	src/gui/ngx_gui.c
	$(CC) -c $(CFLAGS) -I src/gui \
		-Foobjs/ngx_gui.obj \
		src/gui/ngx_gui.c


objs/ngx_gui.res:	 src/gui/ngx_gui.ico \
	src/gui/ngx_gui_tray.ico \
	src/gui/ngx_gui.rc
	rc -foobjs/ngx_gui.res -I src/gui src/gui/ngx_gui.rc
