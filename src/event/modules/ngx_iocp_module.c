
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_iocp_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_iocp_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_iocp_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_iocp_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

static void *ngx_iocp_create_conf(ngx_cycle_t *cycle);
static char *ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf);


static HANDLE             iocp;
static OVERLAPPED_ENTRY  *event_list;
static ngx_uint_t         nevents;


static ngx_str_t  iocp_name = ngx_string("iocp");


static ngx_command_t  ngx_iocp_commands[] = {

    { ngx_string("iocp_concurrent_threads"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, concurrent_threads),
      NULL },

    { ngx_string("iocp_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, events),
      NULL },

    { ngx_string("iocp_post_acceptex"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, post_acceptex),
      NULL },

    { ngx_string("iocp_acceptex_read"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_iocp_conf_t, acceptex_read),
      NULL },

    { ngx_string("iocp_post_udp_recv"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, post_udp_recv),
      NULL },

      ngx_null_command
};


static ngx_event_module_t  ngx_iocp_module_ctx = {
    &iocp_name,
    ngx_iocp_create_conf,                /* create configuration */
    ngx_iocp_init_conf,                  /* init configuration */

    {
        ngx_iocp_add_event,              /* add an event */
        ngx_iocp_del_event,              /* delete an event */
        ngx_iocp_add_event,              /* enable an event */
        ngx_iocp_del_event,              /* disable an event */
        ngx_iocp_add_connection,         /* add an connection */
        ngx_iocp_del_connection,         /* delete an connection */
        NULL,                            /* process the changes */
        ngx_iocp_process_events,         /* process the events */
        ngx_iocp_init,                   /* init the events */
        ngx_iocp_done,                   /* done the events */
    }
};


ngx_module_t  ngx_iocp_module = {
    NGX_MODULE_V1,
    &ngx_iocp_module_ctx,                /* module context */
    ngx_iocp_commands,                   /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static struct sockaddr_in  sa;
ngx_addr_t                 ngx_iocp_local_addr;


static ngx_int_t
ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_iocp_conf_t  *iocpcf;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(0);

    ngx_iocp_local_addr.sockaddr = (struct sockaddr *) &sa;
    ngx_iocp_local_addr.socklen = sizeof(struct sockaddr_in);
    ngx_iocp_local_addr.name.len = sizeof("INADDR_ANY") - 1;
    ngx_iocp_local_addr.name.data = (u_char *) "INADDR_ANY";

    iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);

    if (iocp == NULL) {
        iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
                                      (DWORD) iocpcf->concurrent_threads);

        if (iocp == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "CreateIoCompletionPort() failed");
            return NGX_ERROR;
        }
    }

    if (nevents < iocpcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(OVERLAPPED_ENTRY) * iocpcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = iocpcf->events;

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_iocp_module_ctx.actions;

    ngx_event_flags = NGX_USE_IOCP_EVENT|NGX_USE_AIO_EVENT;

    return NGX_OK;
}


static void
ngx_iocp_done(ngx_cycle_t *cycle)
{
    if (CloseHandle(iocp) == 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "iocp CloseHandle() failed");
    }

    iocp = NULL;

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
}


#if (NGX_HAVE_FILE_AIO)

ngx_int_t
ngx_iocp_add_file(ngx_file_t *file)
{
    if (CreateIoCompletionPort(file->fd, iocp, 0, 0) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    file->aio->event.active = 1;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    /* TODO: flags == NGX_IOCP_ACCEPT */

    ev->ovlp.event = ev;

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, (ULONG_PTR) c, 0) == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iocp_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    return NGX_OK;
}


static ngx_int_t
ngx_iocp_add_connection(ngx_connection_t *c)
{
    ngx_event_t  *rev, *wev;

    rev = c->read;
    wev = c->write;

    rev->ovlp.event = rev;
    wev->ovlp.event = wev;

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, (ULONG_PTR) c, 0) == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iocp_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    return NGX_OK;
}


static ngx_int_t
ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                rc, events;
    size_t             n;
    ngx_int_t          i;
    ngx_err_t          err;
    ngx_event_t       *ev, **queue;
    ngx_connection_t  *c;
    ngx_event_ovlp_t  *ovlp;

    ngx_set_errno(0);

    if (ngx_win32_ver >= NGX_WIN32_VER_600) {
        events = 0;

        rc = ngx_get_queued_completion_status_ex(iocp, event_list,
                                                 (ULONG) nevents,
                                                 (PULONG) &events,
                                                 (DWORD) timer, FALSE);

    } else {

        c = NULL;

        rc = GetQueuedCompletionStatus(iocp, (LPDWORD) &n, (ULONG_PTR *) &c,
                                       (OVERLAPPED **) &ovlp, (DWORD) timer);

        if (ovlp != NULL) {
            events = 1;

            event_list[0].lpCompletionKey = (ULONG_PTR) c;
            event_list[0].lpOverlapped = (OVERLAPPED *) ovlp;
            event_list[0].dwNumberOfBytesTransferred = (DWORD) n;

        } else {
            events = 0;
        }
    }

    err = ngx_errno;

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    /* TODO: err == ERROR_SEM_TIMEOUT */

    if (err == WAIT_TIMEOUT) {
        return NGX_OK;
    }

    for (i = 0; i < events; i++) {

        c = (ngx_connection_t *) event_list[i].lpCompletionKey;
        ovlp = (ngx_event_ovlp_t *) event_list[i].lpOverlapped;
        n = event_list[i].dwNumberOfBytesTransferred;

        if (c != NULL && c->fd == -1) {
            continue;
        }

        ev = ovlp->event;
        ev->complete = 1;

        if (rc != 0) {
            ev->available = (int) n;
            ev->error = 0;

            if (n == 0 && !ev->accept && !ev->write && !ovlp->posted_zero_byte)
            {
                ev->eof = 1;

            } else {
                ev->eof = 0;
            }

        } else {

            ev->available = 0;
            ev->error = 1;

            ev->ovlp.error = err;
        }

        if ((flags & NGX_POST_THREAD_EVENTS) && (ev->write || !ev->accept)) {
            ev->posted_ready = 1;

        } else {
            ev->ready = 1;
        }

        if (flags & NGX_POST_EVENTS) {
            queue = (ngx_event_t **) (ev->accept ?
                                &ngx_posted_accept_events : &ngx_posted_events);

            ngx_locked_post_event(ev, queue);

        } else {
            ev->handler(ev);
        }
    }

    return NGX_OK;
}


static void *
ngx_iocp_create_conf(ngx_cycle_t *cycle)
{
    ngx_iocp_conf_t  *iocpcf;

    iocpcf = ngx_palloc(cycle->pool, sizeof(ngx_iocp_conf_t));
    if (iocpcf == NULL) {
        return NULL;
    }

    iocpcf->concurrent_threads = NGX_CONF_UNSET_UINT;
    iocpcf->events = NGX_CONF_UNSET_UINT;

    iocpcf->post_acceptex = NGX_CONF_UNSET_UINT;
    iocpcf->acceptex_read = NGX_CONF_UNSET;

    iocpcf->post_udp_recv = NGX_CONF_UNSET_UINT;

    return iocpcf;
}


static char *
ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_iocp_conf_t *iocpcf = conf;

    ngx_conf_init_uint_value(iocpcf->concurrent_threads, 0);
    ngx_conf_init_uint_value(iocpcf->events, 512);

    ngx_conf_init_uint_value(iocpcf->post_acceptex, 512);
    ngx_conf_init_value(iocpcf->acceptex_read, 0);

    ngx_conf_init_uint_value(iocpcf->post_udp_recv, 512);

    return NGX_CONF_OK;
}
