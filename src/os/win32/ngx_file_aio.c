
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_HAVE_FILE_AIO)


static void ngx_file_aio_event_handler(ngx_event_t *ev);


ssize_t
ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    int               rc;
    ssize_t           n;
    ngx_err_t         err;
    OVERLAPPED       *ovlp;
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if ((ngx_event_flags & NGX_USE_IOCP_EVENT) == 0 || !ngx_file_aio) {
        return ngx_read_file(file, buf, size, offset);
    }

    aio = file->aio;

    if (aio == NULL) {
        aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
        if (aio == NULL) {
            return NGX_ERROR;
        }

        aio->file = file;
        aio->fd = file->fd;
        aio->event.data = aio;
        aio->event.ready = 1;
        aio->event.log = file->log;
#if (NGX_HAVE_AIO_SENDFILE)
        aio->last_offset = -1;
#endif
        file->aio = aio;
    }

    ev = &aio->event;

    if (!ev->active) {
        if (ngx_iocp_add_file(file) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                          "ngx_iocp_add_file() failed");
            return NGX_ERROR;
        }
    }

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%z %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;

        if (ev->error) {
            return NGX_ERROR;
        }

        n = ev->available;
        ev->available = 0;

        return n;
    }

    ev->handler = ngx_file_aio_event_handler;
    ev->ovlp.event = ev;

    ovlp = (OVERLAPPED *) &ev->ovlp;
    ovlp->Offset = (DWORD) offset;
    ovlp->OffsetHigh = (DWORD) (((ULONGLONG) offset) >> 32);

    /* ReadFileEx */

    rc = ReadFile(file->fd, buf, (DWORD) size, NULL, ovlp);

    err = ngx_errno;

    if (rc || err == ERROR_IO_PENDING) {
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    return NGX_ERROR;
}


ssize_t
ngx_file_aio_write(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    int               rc;
    ssize_t           n;
    ngx_err_t         err;
    OVERLAPPED       *ovlp;
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    aio = file->aio;

    if (aio == NULL) {
        aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
        if (aio == NULL) {
            return NGX_ERROR;
        }

        aio->file = file;
        aio->fd = file->fd;
        aio->event.data = aio;
        aio->event.ready = 1;
        aio->event.log = file->log;
#if (NGX_HAVE_AIO_SENDFILE)
        aio->last_offset = -1;
#endif
        file->aio = aio;
    }

    ev = &aio->event;

    if (!ev->active) {
        if (ngx_iocp_add_file(file) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                          "ngx_iocp_add_file() failed");
            return NGX_ERROR;
        }
    }

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%z %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;

        if (ev->error) {
            return NGX_ERROR;
        }

        n = ev->available;
        ev->available = 0;

        return n;
    }

    ev->handler = ngx_file_aio_event_handler;
    ev->ovlp.event = ev;

    ovlp = (OVERLAPPED *) &ev->ovlp;
    ovlp->Offset = (DWORD) offset;
    ovlp->OffsetHigh = (DWORD) (((ULONGLONG) offset) >> 32);

    /* WriteFileEx */

    rc = WriteFile(file->fd, buf, (DWORD) size, NULL, ovlp);

    err = ngx_errno;

    if (rc || err == ERROR_IO_PENDING) {
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    return NGX_ERROR;
}


static void
ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}


#endif /* NGX_HAVE_FILE_AIO */