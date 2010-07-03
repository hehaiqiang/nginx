
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    DWORD      h, l;
    ULONGLONG  size;

    size = (ULONGLONG) shm->size;
    l = (DWORD) (size & 0xffffffff);
    h = (DWORD) (size >> 32);

    shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                    PAGE_READWRITE, h, l, NULL);
    if (shm->handle == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CreateFileMapping(%uz) failed", shm->size);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm->log, 0,
                   "CreateFileMapping(%uz): %p) successfully",
                   shm->size, shm->handle);

    shm->addr = MapViewOfFile(shm->handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (shm->addr == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "MapViewOfFile(%p, %uz) failed", shm->handle, shm->size);

        CloseHandle(shm->handle);
        shm->handle = NULL;

        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    if (UnmapViewOfFile(shm->addr) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "UnmapViewOfFile(%p, %p, %uz) failed",
                      shm->handle, shm->addr, shm->size);
    }

    shm->addr = NULL;

    if (CloseHandle(shm->handle) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CloseHandle(%p) failed", shm->handle);
    }

    shm->handle = NULL;
}