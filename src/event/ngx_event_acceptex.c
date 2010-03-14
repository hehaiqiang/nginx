
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_close_accepted_connection(ngx_connection_t *c);


void
ngx_event_acceptex(ngx_event_t *ev)
{
    u_char            *buf, *local_sa, *remote_sa;
    socklen_t          socklen, local_socklen, remote_socklen;
    ngx_log_t         *log;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_listening_t   *ls;
    ngx_connection_t  *c, *lc;
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    buf = lc->buffer->start;
    ngx_memcpy(&s, buf, sizeof(ngx_socket_t));
    buf += sizeof(ngx_socket_t);

    /* SO_UPDATE_ACCEPT_CONTEXT */

    socklen = NGX_SOCKADDRLEN + 16;

    ngx_get_acceptex_sockaddrs(buf, (DWORD) ls->post_accept_buffer_size,
                               socklen, socklen,
                               (LPSOCKADDR *) &local_sa, &local_socklen,
                               (LPSOCKADDR *) &remote_sa, &remote_socklen);

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

    ngx_accept_disabled = ngx_cycle->connection_n / 8
                          - ngx_cycle->free_connection_n;

    ev->log->data = &ls->addr_text;

    c = ngx_get_connection(s, ev->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        goto post_acceptex;
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    c->pool = ngx_create_pool(ls->pool_size, ev->log);
    if (c->pool == NULL) {
        ngx_close_accepted_connection(c);
        goto post_acceptex;
    }

    c->sockaddr = ngx_palloc(c->pool, remote_socklen);
    if (c->sockaddr == NULL) {
        ngx_close_accepted_connection(c);
        goto post_acceptex;
    }

    ngx_memcpy(c->sockaddr, remote_sa, remote_socklen);

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_close_accepted_connection(c);
        goto post_acceptex;
    }

    /* set a blocking mode for aio and non-blocking mode for others */

    if (ngx_inherited_nonblocking) {
        if (ngx_event_flags & NGX_USE_AIO_EVENT) {
            if (ngx_blocking(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_blocking_n " failed");
                ngx_close_accepted_connection(c);
                goto post_acceptex;
            }
        }

    } else {
        if (!(ngx_event_flags & (NGX_USE_AIO_EVENT|NGX_USE_RTSIG_EVENT))) {
            if (ngx_nonblocking(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_nonblocking_n " failed");
                ngx_close_accepted_connection(c);
                goto post_acceptex;
            }
        }
    }

    *log = ls->log;

    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;

    c->log = log;
    c->pool->log = log;

    c->socklen = remote_socklen;
    c->listening = ls;
    c->local_sockaddr = ls->sockaddr;

    c->unexpected_eof = 1;

#if (NGX_HAVE_UNIX_DOMAIN)
    if (c->sockaddr->sa_family == AF_UNIX) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
        c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
    }
#endif

    rev = c->read;
    wev = c->write;

    wev->ready = 1;

    if (ngx_event_flags & (NGX_USE_AIO_EVENT|NGX_USE_RTSIG_EVENT)) {
        /* rtsig, aio, iocp */
        rev->ready = 1;
    }

    if (ev->deferred_accept) {
        rev->ready = 1;
    }

    rev->log = log;
    wev->log = log;

    /*
     * TODO: MT: - ngx_atomic_fetch_add()
     *             or protection by critical section or light mutex
     *
     * TODO: MP: - allocated in a shared memory
     *           - ngx_atomic_fetch_add()
     *             or protection by critical section or light mutex
     */

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

#if (NGX_THREADS)
    rev->lock = &c->lock;
    wev->lock = &c->lock;
    rev->own_lock = &c->lock;
    wev->own_lock = &c->lock;
#endif

    if (ls->addr_ntop) {
        c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
        if (c->addr_text.data == NULL) {
            ngx_close_accepted_connection(c);
            goto post_acceptex;
        }

        c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->addr_text.data,
                                         ls->addr_text_max_len, 0);
        if (c->addr_text.len == 0) {
            ngx_close_accepted_connection(c);
            goto post_acceptex;
        }
    }

#if (NGX_DEBUG)
    {

    in_addr_t            i;
    ngx_event_debug_t   *dc;
    struct sockaddr_in  *sin;

    sin = (struct sockaddr_in *) remote_sa;
    dc = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if ((sin->sin_addr.s_addr & dc[i].mask) == dc[i].addr) {
            log->log_level = NGX_LOG_DEBUG_CONNECTION|NGX_LOG_DEBUG_ALL;
            break;
        }
    }

    }
#endif

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                   "*%d accept: %V fd:%d", c->number, &c->addr_text, s);

    if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            ngx_close_accepted_connection(c);
            goto post_acceptex;
        }
    }

    log->data = NULL;
    log->handler = NULL;

    ls->handler(c);

post_acceptex:

    ngx_event_post_acceptex(ls, 1);
}


ngx_int_t
ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n)
{
    int                rc;
    u_char            *buf;
    size_t             size;
    socklen_t          socklen;
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    c = ls->connection;

    socklen = NGX_SOCKADDRLEN + 16;

    if (c->buffer == NULL) {
        size = sizeof(ngx_socket_t) + ls->post_accept_buffer_size + socklen * 2;

        c->pool = ngx_create_pool(size * 2, c->log);
        if (c->pool == NULL) {
            return NGX_ERROR;
        }

        c->buffer = ngx_create_temp_buf(c->pool, size);
        if (c->buffer == NULL) {
            return NGX_ERROR;
        }
    }

    s = ngx_socket(ls->sockaddr->sa_family, ls->type, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_EMERG, c->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    buf = c->buffer->start;
    buf = ngx_cpymem(buf, &s, sizeof(ngx_socket_t));

    rev = c->read;
    rev->ovlp.event = rev;

    rc = ngx_acceptex(c->fd, s, buf, (DWORD) ls->post_accept_buffer_size,
                      socklen, socklen, NULL, (LPOVERLAPPED) &rev->ovlp);

    err = ngx_socket_errno;

    if (rc != 0) {
        return NGX_OK;
    }

    return NGX_OK;
}


static void
ngx_close_accepted_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


u_char *
ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    return ngx_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}
