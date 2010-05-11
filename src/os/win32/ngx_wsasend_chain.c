
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (IOV_MAX > 64)
#define NGX_IOVS  64
#else
#define NGX_IOVS  IOV_MAX
#endif


#if 1

ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int             rc;
    off_t           size, send;
    u_char         *prev;
    WSABUF         *buf, bufs[NGX_IOVS];
    ssize_t         n;
    ngx_err_t       err;
    ngx_array_t     vec;
    ngx_chain_t    *cl;
    ngx_event_t    *wev;
    WSAOVERLAPPED  *ovlp;

    wev = c->write;

    if (wev->closed) {
        return NULL;
    }

    if (wev->error) {
        return NGX_CHAIN_ERROR;
    }

retry:

    vec.nelts = 0;
    vec.elts = bufs;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NGX_IOVS;
    vec.pool = c->pool;

    if (ngx_event_flags & NGX_USE_IOCP_EVENT && !wev->ovlp.posted_zero_byte) {
        ovlp = (WSAOVERLAPPED *) &wev->ovlp;

        /* overlapped io */

        buf = ngx_array_push(&vec);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR;
        }

        buf->buf = NULL;
        buf->len = 0;

    } else {
        ovlp = NULL;

        /* non-blocking io */

        /* the maximum limit size is the maximum size_t value - the page size */

        if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize))
        {
            limit = NGX_MAX_SIZE_T_VALUE - (off_t) ngx_pagesize;
        }

        /* create the WSABUF and coalesce the neighbouring bufs */

        prev = NULL;
        send = 0;

        for (cl = in; cl && vec.nelts < NGX_IOVS && send < limit; cl = cl->next)
        {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            size = (off_t) (cl->buf->last - cl->buf->pos);

            if (send + size > limit) {
                size = limit - send;
            }

            if (prev == cl->buf->pos) {
                buf->len += (ULONG) size;

            } else {
                buf = ngx_array_push(&vec);
                if (buf == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                buf->buf = cl->buf->pos;
                buf->len = (ULONG) size;
            }

            send += size;
            prev = cl->buf->pos + size;
        }
    }

    n = 0;

    rc = WSASend(c->fd, vec.elts, (DWORD) vec.nelts, (DWORD *) &n, 0, ovlp,
                 NULL);

    err = ngx_socket_errno;

    if (rc == 0) {
        if (ovlp != NULL) {
            wev->ovlp.posted_zero_byte = 1;
            wev->ready = 0;
            return in;
        }

#if 0
        if (n < send) {
            wev->ready = 0;
        }
#endif

        c->sent += (off_t) n;

        for (cl = in; cl; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (n == 0) {
                break;
            }

            size = (off_t) (cl->buf->last - cl->buf->pos);

            if (n >= size) {
                n -= size;
                cl->buf->pos = cl->buf->last;

                continue;
            }

            cl->buf->pos += n;

            break;
        }

        wev->ovlp.posted_zero_byte = 0;

        return cl;
    }

    if (err == WSA_IO_PENDING) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");
        wev->ovlp.posted_zero_byte = 1;
        wev->ready = 0;
        return in;
    }

    if (err == WSAEWOULDBLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");

        if (!wev->ovlp.posted_zero_byte) {
            wev->ready = 0;
            return in;
        }

        /* post another overlapped-io WSASend() */
        wev->ovlp.posted_zero_byte = 0;
        goto retry;
    }

    ngx_connection_error(c, err, "WSASend() failed");

    wev->ready = 0;
    wev->error = 1;

    return NGX_CHAIN_ERROR;
}

#else

ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int             rc;
    off_t           size, send, sent;
    u_char         *prev;
    WSABUF         *buf, bufs[NGX_IOVS];
    ssize_t         n;
    ngx_err_t       err;
    ngx_array_t     vec;
    ngx_chain_t    *cl;
    ngx_event_t    *wev;
    WSAOVERLAPPED  *ovlp;

    wev = c->write;

    if (wev->closed) {
        return NULL;
    }

    if (wev->error) {
        return NGX_CHAIN_ERROR;
    }

#if (NGX_HAVE_IOCP)
    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        sent = wev->available;

        if (wev->ready && sent > 0) {

            wev->available = 0;
            c->sent += sent;

            for (cl = in; cl; cl = cl->next) {

                if (ngx_buf_special(cl->buf)) {
                    continue;
                }

                if (sent == 0) {
                    break;
                }

                size = (off_t) (cl->buf->last - cl->buf->pos);

                if (sent >= size) {
                    sent -= size;
                    cl->buf->pos = cl->buf->last;

                    continue;
                }

                cl->buf->pos += sent;

                break;
            }

            return cl;
        }

        wev->ovlp.event = wev;
        ovlp = (WSAOVERLAPPED *) &wev->ovlp;

    } else {
        ovlp = NULL;
    }

#else
    ovlp = NULL;
#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - (off_t) ngx_pagesize;
    }

    vec.nelts = 0;
    vec.elts = bufs;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NGX_IOVS;
    vec.pool = c->pool;

    /* create the WSABUF and coalesce the neighbouring bufs */

    prev = NULL;
    send = 0;

    for (cl = in; cl && vec.nelts < NGX_IOVS && send < limit;
         cl = cl->next)
    {
        if (ngx_buf_special(cl->buf)) {
            continue;
        }

        size = (off_t) (cl->buf->last - cl->buf->pos);

        if (send + size > limit) {
            size = limit - send;
        }

        if (prev == cl->buf->pos) {
            buf->len += size;

        } else {
            buf = ngx_array_push(&vec);
            if (buf == NULL) {
                return NGX_CHAIN_ERROR;
            }

            buf->buf = cl->buf->pos;
            buf->len = size;
        }

        send += size;
        prev = cl->buf->pos + size;
    }

    n = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSASend() fd:%d, size:%uz", c->fd, send);

    rc = WSASend(c->fd, vec.elts, (DWORD) vec.nelts, (DWORD *) &n, 0, ovlp,
                 NULL);

    err = ngx_socket_errno;

    if (rc == 0) {
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            wev->ready = 0;
            return in;
        }

        if (n < send) {
            wev->ready = 0;
        }

        if (n == 0) {
            wev->eof = 1;
        }

        c->sent += (off_t) n;

        for (cl = in; cl; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (n == 0) {
                break;
            }

            size = (off_t) (cl->buf->last - cl->buf->pos);

            if (n >= size) {
                n -= size;
                cl->buf->pos = cl->buf->last;

                continue;
            }

            cl->buf->pos += n;

            break;
        }

        return cl;
    }

    if (err == WSA_IO_PENDING || err == WSAEWOULDBLOCK) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");
        wev->ready = 0;
        return in;
    }

    ngx_connection_error(c, err, "WSASend() failed");

    wev->ready = 0;
    wev->error = 1;

    return NGX_CHAIN_ERROR;
}

#endif
