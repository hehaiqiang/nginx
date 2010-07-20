
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 1

ssize_t
ngx_udp_win32_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int             flags, rc;
    WSABUF          wsabuf;
    ssize_t         n;
    ngx_err_t       err;
    ngx_event_t    *rev;
    WSAOVERLAPPED  *ovlp;

    rev = c->read;

    if (rev->eof || rev->closed) {
        return 0;
    }

    if (rev->error) {
        return NGX_ERROR;
    }

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        if (rev->available) {
            n = rev->available;

            rev->available = 0;
            rev->ready = 0;

            return n;
        }

        ovlp = (WSAOVERLAPPED *) &rev->ovlp;

    } else {
        ovlp = NULL;
    }

    wsabuf.buf = buf;
    wsabuf.len = (ULONG) size;

    n = 0;
    flags = 0;

    rc = WSARecv(c->fd, &wsabuf, 1, (DWORD *) &n, &flags, ovlp, NULL);

    err = ngx_socket_errno;

    if (rc == 0) {
        if (ovlp != NULL) {
            rev->ready = 0;
            return NGX_AGAIN;
        }

#if 0
        if ((size_t) n < size) {
            rev->ready = 0;
        }
#endif

        if (n == 0) {
            rev->eof = 1;
        }

        return n;
    }

    if (err == WSA_IO_PENDING) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSARecv() not ready");
        rev->ready = 0;
        return NGX_AGAIN;
    }

    if (err == WSAEWOULDBLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSARecv() not ready");
        rev->ready = 0;
        return NGX_AGAIN;
    }

    ngx_connection_error(c, err, "WSARecv() failed");

    rev->ready = 0;
    rev->error = 1;

    return NGX_ERROR;
}

#else

ssize_t
ngx_udp_win32_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int             flags, rc;
    WSABUF          wsabuf;
    ssize_t         n;
    ngx_err_t       err;
    ngx_event_t    *rev;
    WSAOVERLAPPED  *ovlp;

    rev = c->read;

    if (rev->closed) {
        return 0;
    }

    if (rev->error) {
        return NGX_ERROR;
    }

#if (NGX_HAVE_IOCP)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        n = rev->available;

        if (rev->ready && n > 0) {
            rev->available = 0;
            return n;
        }

        rev->ovlp.event = rev;
        ovlp = (WSAOVERLAPPED *) &rev->ovlp;

    } else {
        ovlp = NULL;
    }

#else
    ovlp = NULL;
#endif

    wsabuf.buf = buf;
    wsabuf.len = (DWORD) size;
    n = 0;
    flags = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecvFrom() fd:%d, size:%uz", c->fd, size);

    rc = WSARecvFrom(c->fd, &wsabuf, 1, (DWORD *) &n, &flags, NULL, NULL, ovlp,
                     NULL);

    err = ngx_socket_errno;

    if (rc == 0) {
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            rev->ready = 0;
            return NGX_AGAIN;
        }

        if ((size_t) n < size) {
            rev->ready = 0;
        }

        if (n == 0) {
            rev->eof = 1;
        }

        return n;
    }

    if (err == WSA_IO_PENDING) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                       "WSARecvFrom() not ready");
        rev->ready = 0;
        return NGX_AGAIN;
    }

    ngx_connection_error(c, err, "WSARecvFrom() failed");

    rev->ready = 0;
    rev->error = 1;

    return NGX_ERROR;
}

#endif
