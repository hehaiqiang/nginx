
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_DLFCN_H_INCLUDED_
#define _NGX_DLFCN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define ngx_dlopen(file, mode)   LoadLibrary(file)
#define ngx_dlopen_n             "LoadLibrary()"

#define ngx_dlsym(handle, name)  ((void *) GetProcAddress(handle, name))
#define ngx_dlsym_n              "GetProcAddress()"

#define ngx_dlclose(handle)                                                    \
    (FreeLibrary(handle) != 0 ? NGX_OK : NGX_ERROR)


#endif /* _NGX_DLFCN_H_INCLUDED_ */