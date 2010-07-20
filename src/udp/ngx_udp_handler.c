
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_udp.h>


typedef struct {
    ngx_rbtree_t          rbtree;
    ngx_rbtree_node_t     sentinel;
    ngx_queue_t           queue;
    ngx_event_t          *ev;
} ngx_udp_send_queue_t;


static u_char *ngx_udp_log_error(ngx_log_t *log, u_char *buf, size_t len);


void
ngx_udp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t                i;
    ngx_udp_port_t           *port;
    struct sockaddr          *sa;
    ngx_udp_log_ctx_t        *ctx;
    ngx_udp_session_t        *s;
    ngx_udp_in_addr_t        *addr;
    struct sockaddr_in       *sin;
    ngx_udp_addr_conf_t      *addr_conf;
    ngx_udp_core_srv_conf_t  *cscf;
#if (NGX_HAVE_INET6)
    ngx_udp_in6_addr_t       *addr6;
    struct sockaddr_in6      *sin6;
#endif

    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_udp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_udp_session_t));
    if (s == NULL) {
        ngx_udp_close_connection(c);
        return;
    }

    c->data = s;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    s->connection = c;
    s->buffer = c->buffer;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_udp_log_ctx_t));
    if (ctx == NULL) {
        ngx_udp_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_udp_log_error;
    c->log->data = ctx;
    c->log->action = "initializing session";

    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_udp_max_module);
    if (s->ctx == NULL) {
        ngx_udp_close_connection(c);
        return;
    }

    cscf = ngx_udp_get_module_srv_conf(s, ngx_udp_core_module);

    if (cscf->protocol->init_session(s) != NGX_OK) {
        ngx_udp_close_connection(c);
        return;
    }

    c->log->action = "processing session";

    cscf->protocol->process_session(s);
}


ssize_t
ngx_udp_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t  n;

    n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);

    if (n == -1) {
        ngx_connection_error(c, ngx_socket_errno, "sendto() failed");
        return NGX_ERROR;
    }

    if ((size_t) n != size) {
        ngx_log_error(NGX_LOG_CRIT, c->log, 0,
                      "sendto() incomplete n:%z size:uz", n, size);
        return NGX_ERROR;
    }

    return n;
}


void
ngx_udp_internal_server_error(ngx_udp_session_t *s)
{
    ngx_udp_core_srv_conf_t  *cscf;

    cscf = ngx_udp_get_module_srv_conf(s, ngx_udp_core_module);

    cscf->protocol->internal_server_error(s);

    ngx_udp_close_connection(s->connection);
}


void
ngx_udp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t               *pool;
    ngx_udp_session_t        *s;
    ngx_udp_core_srv_conf_t  *cscf;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "close udp connection: %d", c->fd);

    s = c->data;

    if (s != NULL) {
        cscf = ngx_udp_get_module_srv_conf(s, ngx_udp_core_module);

        cscf->protocol->close_session(s);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (ngx_del_conn) {
        ngx_del_conn(c, NGX_CLOSE_EVENT);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

#if (NGX_THREADS)

    /*
     * we have to clean the connection information before the closing
     * because another thread may reopen the same file descriptor
     * before we clean the connection
     */

    ngx_mutex_lock(ngx_posted_events_mutex);

    if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    if (c->single_connection) {
        ngx_unlock(&c->lock);
        c->read->locked = 0;
        c->write->locked = 0;
    }

    ngx_mutex_unlock(ngx_posted_events_mutex);

#else

    if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

#endif

    ngx_free_connection(c);

    ngx_destroy_pool(pool);
}


static u_char *
ngx_udp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char             *p;
    ngx_udp_session_t  *s;
    ngx_udp_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V", s->addr_text);

    return p;
}
