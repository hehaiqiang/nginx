
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_udp.h>


typedef struct {
    size_t        buffer_size;
    ngx_msec_t    timeout;
} ngx_udp_proxy_srv_conf_t;


ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);


static void ngx_udp_proxy_read_response(ngx_event_t *rev);
static void ngx_udp_proxy_internal_server_error(ngx_udp_session_t *s);
static void ngx_udp_proxy_close_session(ngx_udp_session_t *s);

static void *ngx_udp_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_udp_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_udp_proxy_commands[] = {

    { ngx_string("proxy_buffer"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_proxy_srv_conf_t, timeout),
      NULL },

      ngx_null_command
};


static ngx_udp_module_t  ngx_udp_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_udp_proxy_create_conf,             /* create server configuration */
    ngx_udp_proxy_merge_conf               /* merge server configuration */
};


ngx_module_t  ngx_udp_proxy_module = {
    NGX_MODULE_V1,
    &ngx_udp_proxy_module_ctx,             /* module context */
    ngx_udp_proxy_commands,                /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


void
ngx_udp_proxy_init(ngx_udp_session_t *s, ngx_addr_t *peer)
{
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_udp_proxy_t           *p;
    ngx_connection_t          *c;
    ngx_udp_proxy_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    p = ngx_pcalloc(c->pool, sizeof(ngx_udp_proxy_t));
    if (p == NULL) {
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->uc.sockaddr = peer->sockaddr;
    p->uc.socklen = peer->socklen;
    p->uc.log = *c->log;

    rc = ngx_udp_connect(&p->uc);

    if (rc == NGX_ERROR) {
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    c->log->action = "sending request to upstream";

    p->uc.connection->read->handler = ngx_udp_proxy_read_response;
    p->uc.connection->data = s;
    p->uc.connection->pool = c->pool;

    pscf = ngx_udp_get_module_srv_conf(s, ngx_udp_proxy_module);

    s->proxy->buffer = ngx_create_temp_buf(c->pool, pscf->buffer_size);
    if (s->proxy->buffer == NULL) {
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    n = ngx_udp_send(p->uc.connection, s->buffer->pos,
                     s->buffer->last - s->buffer->pos);

    if (n == NGX_ERROR) {
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    c->log->action = "reading response from upstream";

    ngx_udp_proxy_read_response(p->uc.connection->read);
}


static void
ngx_udp_proxy_read_response(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_udp_session_t         *s;
    ngx_udp_core_srv_conf_t   *cscf;
    ngx_udp_proxy_srv_conf_t  *pscf;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, rev->log, 0,
                   "udp proxy read response from upstream");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "udp upstream timed out");
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    b = s->proxy->buffer;

    n = ngx_udp_recv(c, b->last, b->end - b->last);

    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            pscf = ngx_udp_get_module_srv_conf(s, ngx_udp_proxy_module);
            ngx_add_timer(rev, pscf->timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_udp_proxy_internal_server_error(s);
        }

        return;
    }

    if (n == 0 || n == NGX_ERROR) {
        ngx_udp_proxy_internal_server_error(s);
        return;
    }

    b->last += n;

    ngx_udp_proxy_close_session(s);

    cscf = ngx_udp_get_module_srv_conf(s, ngx_udp_core_module);

    cscf->protocol->process_proxy_response(s, b->pos, b->last - b->pos);
}


static void
ngx_udp_proxy_internal_server_error(ngx_udp_session_t *s)
{
    if (s->proxy->uc.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                       "close udp proxy connection: %d",
                       s->proxy->uc.connection->fd);

        ngx_close_connection(s->proxy->uc.connection);
    }

    ngx_udp_internal_server_error(s);
}


static void
ngx_udp_proxy_close_session(ngx_udp_session_t *s)
{
    if (s->proxy->uc.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, s->connection->log, 0,
                       "close udp proxy connection: %d",
                       s->proxy->uc.connection->fd);

        ngx_close_connection(s->proxy->uc.connection);
    }
}


static void *
ngx_udp_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_udp_proxy_srv_conf_t  *pscf;

    pscf = ngx_pcalloc(cf->pool, sizeof(ngx_udp_proxy_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    pscf->buffer_size = NGX_CONF_UNSET_SIZE;
    pscf->timeout = NGX_CONF_UNSET_MSEC;

    return pscf;
}


static char *
ngx_udp_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_udp_proxy_srv_conf_t *prev = parent;
    ngx_udp_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 30000);

    return NGX_CONF_OK;
}
