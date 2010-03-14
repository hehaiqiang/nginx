
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t
ngx_win32_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    int             rc;
    WSABUF          wsabuf;
    ssize_t         n;
    ngx_err_t       err;
    ngx_event_t    *wev;
    WSAOVERLAPPED  *ovlp;

    wev = c->write;

    if (wev->closed) {
        return 0;
    }

    if (wev->error) {
        return NGX_ERROR;
    }

#if (NGX_HAVE_IOCP)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        n = wev->available;

        if (wev->ready && n > 0) {
            wev->available = 0;
            return n;
        }

        wev->ovlp.event = wev;
        ovlp = (WSAOVERLAPPED *) &wev->ovlp;

    } else {
        ovlp = NULL;
    }

#else
    ovlp = NULL;
#endif

    wsabuf.buf = buf;
    wsabuf.len = (DWORD) size;
    n = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSASend() fd:%d, size:%uz", c->fd, size);

    rc = WSASend(c->fd, &wsabuf, 1, (DWORD *) &n, 0, ovlp, NULL);

    err = ngx_socket_errno;

    if (rc == 0) {
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            wev->ready = 0;
            return NGX_AGAIN;
        }

        if ((size_t) n < size) {
            wev->ready = 0;
        }

        if (n == 0) {
            wev->eof = 1;
        }

        return n;
    }

    if (err == WSA_IO_PENDING || err == WSAEWOULDBLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");
        wev->ready = 0;
        return NGX_AGAIN;
    }

    ngx_connection_error(c, err, "WSASend() failed");

    wev->ready = 0;
    wev->error = 1;

    return NGX_ERROR;
}
