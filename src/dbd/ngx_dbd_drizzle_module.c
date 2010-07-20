
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_dbd.h>


#if (NGX_DBD_DRIZZLE)


#include <libdrizzle/common.h>


static ngx_int_t ngx_dbd_drizzle_init(ngx_cycle_t *cycle);
static void ngx_dbd_drizzle_done(ngx_cycle_t *cycle);

static ngx_dbd_v2_t *ngx_dbd_drizzle_create(ngx_pool_t *pool, ngx_log_t *log);
static void ngx_dbd_drizzle_destroy(ngx_dbd_v2_t *dbd);
static ngx_uint_t ngx_dbd_drizzle_get_options(ngx_dbd_v2_t *dbd);
static ngx_int_t ngx_dbd_drizzle_set_options(ngx_dbd_v2_t *dbd,
    ngx_uint_t opts);

static ngx_err_t ngx_dbd_drizzle_error_code(ngx_dbd_v2_t *dbd);
static u_char *ngx_dbd_drizzle_error(ngx_dbd_v2_t *dbd);

static ngx_dbd_conn_v2_t *ngx_dbd_drizzle_conn_create(ngx_dbd_v2_t *dbd);
static void ngx_dbd_drizzle_conn_destroy(ngx_dbd_conn_v2_t *conn);
static ngx_uint_t ngx_dbd_drizzle_conn_get_options(ngx_dbd_conn_v2_t *conn);
static ngx_int_t ngx_dbd_drizzle_conn_set_options(ngx_dbd_conn_v2_t *conn,
    ngx_uint_t opts);
static ngx_int_t ngx_dbd_drizzle_conn_set_tcp(ngx_dbd_conn_v2_t *conn,
    u_char *host, ngx_uint_t port);
static ngx_int_t ngx_dbd_drizzle_conn_set_auth(ngx_dbd_conn_v2_t *conn,
    u_char *user, u_char *passwd);
static ngx_int_t ngx_dbd_drizzle_conn_set_db(ngx_dbd_conn_v2_t *conn,
    u_char *db);
static ngx_int_t ngx_dbd_drizzle_conn_set_handler(ngx_dbd_conn_v2_t *conn,
    ngx_dbd_conn_handler_pt handler, void *data);
static ngx_int_t ngx_dbd_drizzle_conn_connect(ngx_dbd_conn_v2_t *conn);
static ngx_int_t ngx_dbd_drizzle_conn_close(ngx_dbd_conn_v2_t *conn);

static size_t ngx_dbd_drizzle_escape_string(ngx_dbd_conn_v2_t *conn,
    u_char *dst, u_char *src, size_t src_size);

static ngx_dbd_query_t *ngx_dbd_drizzle_query_create(ngx_dbd_conn_v2_t *conn);
static void ngx_dbd_drizzle_query_destroy(ngx_dbd_query_t *query);
static ngx_int_t ngx_dbd_drizzle_query_set_string(ngx_dbd_query_t *query,
    u_char *query_str, size_t size);
static ngx_int_t ngx_dbd_drizzle_query_result(ngx_dbd_query_t *query,
    ngx_dbd_result_t *res);

static ngx_dbd_result_t *ngx_dbd_drizzle_result_create(ngx_dbd_conn_v2_t *conn);
static void ngx_dbd_drizzle_result_destroy(ngx_dbd_result_t *res);
static ngx_uint_t ngx_dbd_drizzle_result_column_count(ngx_dbd_result_t *res);
static ngx_uint_t ngx_dbd_drizzle_result_row_count(ngx_dbd_result_t *res);
static ngx_uint_t ngx_dbd_drizzle_result_affected_rows(ngx_dbd_result_t *res);
static ngx_uint_t ngx_dbd_drizzle_result_insert_id(ngx_dbd_result_t *res);

static ngx_dbd_column_t *ngx_dbd_drizzle_column_create(ngx_dbd_result_t *res);
static void ngx_dbd_drizzle_column_destroy(ngx_dbd_column_t *col);
static ngx_int_t ngx_dbd_drizzle_column_read(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_catalog(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_db(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_table(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_orig_table(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_name(ngx_dbd_column_t *col);
static u_char *ngx_dbd_drizzle_column_orig_name(ngx_dbd_column_t *col);
static ngx_uint_t ngx_dbd_drizzle_column_charset(ngx_dbd_column_t *col);
static size_t ngx_dbd_drizzle_column_size(ngx_dbd_column_t *col);
static size_t ngx_dbd_drizzle_column_max_size(ngx_dbd_column_t *col);
static ngx_uint_t ngx_dbd_drizzle_column_type(ngx_dbd_column_t *col);
static ngx_uint_t ngx_dbd_drizzle_column_flags(ngx_dbd_column_t *col);

static ngx_dbd_row_v2_t *ngx_dbd_drizzle_row_create(ngx_dbd_result_t *res);
static void ngx_dbd_drizzle_row_destroy(ngx_dbd_row_v2_t *row);
static ngx_int_t ngx_dbd_drizzle_row_read(ngx_dbd_row_v2_t *row);

static ngx_int_t ngx_dbd_drizzle_field_read(ngx_dbd_row_v2_t *row,
    u_char **value, off_t *offset, size_t *size, size_t *total);

static void ngx_dbd_drizzle_read_event_handler(ngx_event_t *rev);
static void ngx_dbd_drizzle_write_event_handler(ngx_event_t *wev);

#if (NGX_WIN32)
static ngx_int_t ngx_dbd_drizzle_get_peer(ngx_peer_connection_t *pc,
    void *data);
#endif


static ngx_str_t  ngx_dbd_drizzle_driver_name = ngx_string("drizzle");


ngx_dbd_driver_t  ngx_dbd_drizzle_driver = {
    &ngx_dbd_drizzle_driver_name,
    ngx_dbd_drizzle_init,
    ngx_dbd_drizzle_done,
    ngx_dbd_drizzle_create,
    ngx_dbd_drizzle_destroy,
    ngx_dbd_drizzle_get_options,
    ngx_dbd_drizzle_set_options,
    ngx_dbd_drizzle_error_code,
    ngx_dbd_drizzle_error,
    ngx_dbd_drizzle_conn_create,
    ngx_dbd_drizzle_conn_destroy,
    ngx_dbd_drizzle_conn_get_options,
    ngx_dbd_drizzle_conn_set_options,
    ngx_dbd_drizzle_conn_set_tcp,
    ngx_dbd_drizzle_conn_set_auth,
    ngx_dbd_drizzle_conn_set_db,
    ngx_dbd_drizzle_conn_set_handler,
    ngx_dbd_drizzle_conn_connect,
    ngx_dbd_drizzle_conn_close,
    ngx_dbd_drizzle_escape_string,
    ngx_dbd_drizzle_query_create,
    ngx_dbd_drizzle_query_destroy,
    ngx_dbd_drizzle_query_set_string,
    ngx_dbd_drizzle_query_result,
    ngx_dbd_drizzle_result_create,
    ngx_dbd_drizzle_result_destroy,
    ngx_dbd_drizzle_result_column_count,
    ngx_dbd_drizzle_result_row_count,
    ngx_dbd_drizzle_result_affected_rows,
    ngx_dbd_drizzle_result_insert_id,
    ngx_dbd_drizzle_column_create,
    ngx_dbd_drizzle_column_destroy,
    ngx_dbd_drizzle_column_read,
    ngx_dbd_drizzle_column_catalog,
    ngx_dbd_drizzle_column_db,
    ngx_dbd_drizzle_column_table,
    ngx_dbd_drizzle_column_orig_table,
    ngx_dbd_drizzle_column_name,
    ngx_dbd_drizzle_column_orig_name,
    ngx_dbd_drizzle_column_charset,
    ngx_dbd_drizzle_column_size,
    ngx_dbd_drizzle_column_max_size,
    ngx_dbd_drizzle_column_type,
    ngx_dbd_drizzle_column_flags,
    ngx_dbd_drizzle_row_create,
    ngx_dbd_drizzle_row_destroy,
    ngx_dbd_drizzle_row_read,
    ngx_dbd_drizzle_field_read
};


struct ngx_dbd_v2_s {
    drizzle_st                drizzle;

    ngx_pool_t               *pool;
    ngx_log_t                *log;
    ngx_uint_t                options;
    ngx_err_t                 error_code;
    u_char                   *error;

    ngx_dbd_conn_v2_t        *conn;
};


struct ngx_dbd_conn_v2_s {
    drizzle_con_st            con;
    ngx_uint_t                connected;

    ngx_dbd_v2_t             *dbd;
    ngx_peer_connection_t     pc;
    ngx_dbd_conn_handler_pt   handler;
    void                     *data;

    ngx_dbd_query_t          *query;
    ngx_dbd_result_t         *result;
};


struct ngx_dbd_query_s {
    ngx_str_t                 query;
    size_t                    valid_size;

    ngx_dbd_conn_v2_t        *conn;
};


struct ngx_dbd_result_s {
    drizzle_result_st         res;

    ngx_dbd_conn_v2_t        *conn;

    ngx_dbd_column_t         *column;
    ngx_dbd_row_v2_t         *row;
};


struct ngx_dbd_column_s {
    drizzle_column_st         col;

    ngx_dbd_result_t         *res;
};


struct ngx_dbd_row_v2_s {
    ngx_dbd_result_t         *res;
};


static ngx_int_t
ngx_dbd_drizzle_init(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "ngx_dbd_drizzle_init()");

    return NGX_OK;
}


static void
ngx_dbd_drizzle_done(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "ngx_dbd_drizzle_done()");
}


static ngx_dbd_v2_t *
ngx_dbd_drizzle_create(ngx_pool_t *pool, ngx_log_t *log)
{
    ngx_dbd_v2_t  *dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "ngx_dbd_drizzle_create()");

    dbd = ngx_pcalloc(pool, sizeof(ngx_dbd_v2_t));
    if (dbd == NULL) {
        return NULL;
    }

    if (drizzle_create(&dbd->drizzle) == NULL) {
        return NULL;
    }

    /* TODO: xxx */
#if 0
    drizzle_set_timeout(&dbd->drizzle, 0);
#endif

    dbd->pool = pool;
    dbd->log = log;

    return dbd;
}


static void
ngx_dbd_drizzle_destroy(ngx_dbd_v2_t *dbd)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_destroy()");

    drizzle_free(&dbd->drizzle);
}


static ngx_uint_t
ngx_dbd_drizzle_get_options(ngx_dbd_v2_t *dbd)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_get_options()");

    return dbd->options;
}


static ngx_int_t
ngx_dbd_drizzle_set_options(ngx_dbd_v2_t *dbd, ngx_uint_t opts)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_set_options()");

    dbd->options = opts;

    if (opts & NGX_DBD_OPTION_NON_BLOCKING) {
        drizzle_set_options(&dbd->drizzle, DRIZZLE_NON_BLOCKING);
    }

    return NGX_OK;
}


static ngx_err_t
ngx_dbd_drizzle_error_code(ngx_dbd_v2_t *dbd)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_error_code()");

    return dbd->error_code;
}


static u_char *
ngx_dbd_drizzle_error(ngx_dbd_v2_t *dbd)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0, "ngx_dbd_drizzle_error()");

    return dbd->error;
}


static ngx_dbd_conn_v2_t *
ngx_dbd_drizzle_conn_create(ngx_dbd_v2_t *dbd)
{
    ngx_dbd_conn_v2_t      *conn;
    ngx_peer_connection_t  *pc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_create()");

    conn = dbd->conn;

    if (conn == NULL) {
        conn = ngx_pcalloc(dbd->pool, sizeof(ngx_dbd_conn_v2_t));
        if (conn == NULL) {
            return NULL;
        }

        dbd->conn = conn;
    }

    pc = &conn->pc;

    pc->log = dbd->log;
    pc->rcvbuf = DRIZZLE_DEFAULT_SOCKET_RECV_SIZE;
#if (NGX_WIN32)
    pc->get = ngx_dbd_drizzle_get_peer;
#endif
    pc->data = conn;

    if (drizzle_con_create(&dbd->drizzle, &conn->con) == NULL) {
        return NULL;
    }

    drizzle_con_set_context(&conn->con, conn);

    /* TODO: xxx */

    drizzle_con_add_options(&conn->con, DRIZZLE_CON_MYSQL);

    conn->dbd = dbd;

    return conn;
}


static void
ngx_dbd_drizzle_conn_destroy(ngx_dbd_conn_v2_t *conn)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_destroy()");

    drizzle_con_free(&conn->con);
}


static ngx_uint_t
ngx_dbd_drizzle_conn_get_options(ngx_dbd_conn_v2_t *conn)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_get_options()");

    /* TODO: xxx */

    return 0;
}


static ngx_int_t
ngx_dbd_drizzle_conn_set_options(ngx_dbd_conn_v2_t *conn, ngx_uint_t opts)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_set_options()");

    /* TODO: xxx */

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_set_tcp(ngx_dbd_conn_v2_t *conn, u_char *host,
    ngx_uint_t port)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_set_tcp()");

    drizzle_con_set_tcp(&conn->con, (const char *) host, (in_port_t) port);

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_set_auth(ngx_dbd_conn_v2_t *conn, u_char *user,
    u_char *passwd)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_set_auth()");

    drizzle_con_set_auth(&conn->con, (const char *) user,
                         (const char *) passwd);

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_set_db(ngx_dbd_conn_v2_t *conn, u_char *db)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_set_db()");

    drizzle_con_set_db(&conn->con, (const char *) db);

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_set_handler(ngx_dbd_conn_v2_t *conn,
    ngx_dbd_conn_handler_pt handler, void *data)
{
    ngx_dbd_v2_t      *dbd;
    ngx_connection_t  *c;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_set_handler()");

    conn->handler = handler;
    conn->data = data;

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        return NGX_OK;
    }

    c = conn->pc.connection;

    if ((drizzle_options(&dbd->drizzle) & DRIZZLE_NON_BLOCKING) == 0
        || c == NULL)
    {
        return NGX_OK;
    }

    if (handler == NULL) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT);
        }

        if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_DISABLE_EVENT);
        }

        if (c->read->prev) {
            ngx_delete_posted_event(c->read);
        }

        if (c->write->prev) {
            ngx_delete_posted_event(c->write);
        }

    } else {
        if (!c->read->active) {
            ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT);
        }

        if (!c->write->active) {
            ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_connect(ngx_dbd_conn_v2_t *conn)
{
#if !(NGX_WIN32)
    int                fd;
    ngx_int_t          event;
    ngx_event_t       *rev, *wev;
#endif
    ngx_dbd_v2_t      *dbd;
    drizzle_return_t   rv;
#if !(NGX_WIN32)
    ngx_connection_t  *c;
#endif

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_connect()");

    if (conn->connected) {
        return NGX_OK;
    }

    rv = drizzle_con_connect(&conn->con);

    if (rv != DRIZZLE_RETURN_OK && rv != DRIZZLE_RETURN_IO_WAIT) {
        dbd->error_code = drizzle_con_error_code(&conn->con);
        dbd->error = (u_char *) drizzle_con_error(&conn->con);

        ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                      "drizzle_con_connect() failed (%d: %s)",
                      dbd->error_code, dbd->error);
        return NGX_ERROR;
    }

#if !(NGX_WIN32)

    if (drizzle_options(&dbd->drizzle) & DRIZZLE_NON_BLOCKING
        && conn->pc.connection == NULL)
    {
        fd = drizzle_con_fd(&conn->con);
        if (fd == -1) {
            ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                          "drizzle_con_fd() failed (%d: %s)",
                          drizzle_con_errno(&conn->con),
                          drizzle_con_error(&conn->con));
            drizzle_con_close(&conn->con);
            return NGX_ERROR;
        }

        c = ngx_get_connection(fd, dbd->log);
        if (c == NULL) {
            ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                          "ngx_get_connection() failed");
            drizzle_con_close(&conn->con);
            return NGX_ERROR;
        }

        rev = c->read;
        wev = c->write;

        rev->log = dbd->log;
        wev->log = dbd->log;

        rev->handler = ngx_dbd_drizzle_read_event_handler;
        wev->handler = ngx_dbd_drizzle_write_event_handler;

        /* TODO:
         * using ngx_add_conn() instead of ngx_add_event() for some event model.
         */

        if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
            event = NGX_CLEAR_EVENT;

        } else {
            event = NGX_LEVEL_EVENT;
        }

        if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
            ngx_free_connection(c);
            drizzle_con_close(&conn->con);
            return NGX_ERROR;
        }

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            ngx_free_connection(c);
            drizzle_con_close(&conn->con);
            return NGX_ERROR;
        }

        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        c->data = conn;

        conn->pc.connection = c;

    } else if (conn->pc.connection != NULL) {
        c = conn->pc.connection;

        rev = c->read;
        wev = c->write;

    } else {
        wev = NULL;
    }

#endif

    if (rv == DRIZZLE_RETURN_IO_WAIT) {
        /* TODO: set timeout */
        return NGX_AGAIN;
    }

    /* rv == DRIZZLE_RETURN_OK */

#if !(NGX_WIN32)

    if (wev != NULL) {
        wev->ready = 1;
    }

#endif

    conn->connected = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_conn_close(ngx_dbd_conn_v2_t *conn)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_conn_close()");

    /* TODO: conn->pc */

    if (conn->pc.connection != NULL) {
        ngx_close_connection(conn->pc.connection);
        conn->pc.connection = NULL;
    }

    drizzle_con_close(&conn->con);

    conn->connected = 0;

    return NGX_OK;
}


static size_t
ngx_dbd_drizzle_escape_string(ngx_dbd_conn_v2_t *conn, u_char *dst, u_char *src,
    size_t src_size)
{
    ngx_dbd_v2_t  *dbd;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_escape_string()");

    return drizzle_escape_string((char *) dst, (const char *) src, src_size);
}


static ngx_dbd_query_t *
ngx_dbd_drizzle_query_create(ngx_dbd_conn_v2_t *conn)
{
    ngx_dbd_v2_t     *dbd;
    ngx_dbd_query_t  *query;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_query_create()");

    query = conn->query;

    if (query == NULL) {
        query = ngx_pcalloc(dbd->pool, sizeof(ngx_dbd_query_t));
        if (query == NULL) {
            return NULL;
        }

        conn->query = query;
    }

    query->conn = conn;

    return query;
}


static void
ngx_dbd_drizzle_query_destroy(ngx_dbd_query_t *query)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = query->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_query_destroy()");
}


static ngx_int_t
ngx_dbd_drizzle_query_set_string(ngx_dbd_query_t *query, u_char *query_str,
    size_t size)
{
    ngx_str_t          *str;
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = query->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_query_set_string()");

    str = &query->query;

    if (str->len < size) {
        str->data = ngx_palloc(dbd->pool, size);
        if (str->data == NULL) {
            return NGX_ERROR;
        }

        str->len = size;
    }

    ngx_memcpy(str->data, query_str, size);

    query->valid_size = size;

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_query_result(ngx_dbd_query_t *query, ngx_dbd_result_t *res)
{
    ngx_str_t          *str;
    ngx_dbd_v2_t       *dbd;
    drizzle_return_t    rv;
    ngx_dbd_conn_v2_t  *conn;

    conn = query->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_query_result()");

    str = &query->query;
    rv = DRIZZLE_RETURN_OK;

    drizzle_query(&conn->con, &res->res, (const char *) str->data,
                  query->valid_size, &rv);

    if (rv == DRIZZLE_RETURN_IO_WAIT) {
        return NGX_AGAIN;
    }

    if (rv != DRIZZLE_RETURN_OK) {
        dbd->error_code = drizzle_result_error_code(&res->res);
        dbd->error = (u_char *) drizzle_result_error(&res->res);

        ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                      "drizzle_query() failed (%d: %s)",
                      dbd->error_code, dbd->error);
        return NGX_ERROR;
    }

    /* rv == DRIZZLE_RETURN_OK */

    return NGX_OK;
}


static ngx_dbd_result_t *
ngx_dbd_drizzle_result_create(ngx_dbd_conn_v2_t *conn)
{
    ngx_dbd_v2_t      *dbd;
    ngx_dbd_result_t  *res;

    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_create()");

    res = conn->result;

    if (res == NULL) {
        res = ngx_pcalloc(dbd->pool, sizeof(ngx_dbd_result_t));
        if (res == NULL) {
            return NULL;
        }

        conn->result = res;
    }

    if (drizzle_result_create(&conn->con, &res->res) == NULL) {
        return NULL;
    }

    res->conn = conn;

    return res;
}


static void
ngx_dbd_drizzle_result_destroy(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_destroy()");

#if 1
    res->res.column_list = NULL;
#endif

    drizzle_result_free(&res->res);
}


static ngx_uint_t
ngx_dbd_drizzle_result_column_count(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_column_count()");

    return drizzle_result_column_count(&res->res);
}


static ngx_uint_t
ngx_dbd_drizzle_result_row_count(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_row_count()");

    return (ngx_uint_t) drizzle_result_row_count(&res->res);
}


static ngx_uint_t
ngx_dbd_drizzle_result_affected_rows(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_affected_rows()");

    return (ngx_uint_t) drizzle_result_affected_rows(&res->res);
}


static ngx_uint_t
ngx_dbd_drizzle_result_insert_id(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_result_insert_id()");

    return (ngx_uint_t) drizzle_result_insert_id(&res->res);
}


static ngx_dbd_column_t *
ngx_dbd_drizzle_column_create(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_column_t   *col;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_create()");

    col = res->column;

    if (col == NULL) {
        col = ngx_pcalloc(dbd->pool, sizeof(ngx_dbd_column_t));
        if (col == NULL) {
            return NULL;
        }

        res->column = col;
    }

    if (drizzle_column_create(&res->res, &col->col) == NULL) {
        return NULL;
    }

    col->res = res;

    return col;
}


static void
ngx_dbd_drizzle_column_destroy(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_destroy()");

#if 0
    drizzle_column_free(&col->col);
#endif
}


static ngx_int_t
ngx_dbd_drizzle_column_read(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    drizzle_return_t    rv;
    drizzle_column_st  *column;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_read()");

    rv = DRIZZLE_RETURN_OK;

    column = drizzle_column_read(&res->res, &col->col, &rv);

    if (rv == DRIZZLE_RETURN_IO_WAIT) {
        return NGX_AGAIN;
    }

    if (rv != DRIZZLE_RETURN_OK) {
        ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                      "drizzle_column_read() failed (%d: %s)",
                      drizzle_con_errno(&conn->con),
                      drizzle_con_error(&conn->con));
        return NGX_ERROR;
    }

    /* rv == DRIZZLE_RETURN_OK */

    if (column == NULL) {
        return NGX_DONE;
    }

    return NGX_OK;
}


static u_char *
ngx_dbd_drizzle_column_catalog(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_catalog()");

    return (u_char *) drizzle_column_catalog(&col->col);
}


static u_char *
ngx_dbd_drizzle_column_db(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_db()");

    return (u_char *) drizzle_column_db(&col->col);
}


static u_char *
ngx_dbd_drizzle_column_table(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_table()");

    return (u_char *) drizzle_column_table(&col->col);
}


static u_char *
ngx_dbd_drizzle_column_orig_table(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_orig_table()");

    return (u_char *) drizzle_column_orig_table(&col->col);
}


static u_char *
ngx_dbd_drizzle_column_name(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_name()");

    return (u_char *) drizzle_column_name(&col->col);
}


static u_char *
ngx_dbd_drizzle_column_orig_name(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_orig_name()");

    return (u_char *) drizzle_column_orig_name(&col->col);
}


static ngx_uint_t
ngx_dbd_drizzle_column_charset(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_charset()");

    return drizzle_column_charset(&col->col);
}


static size_t
ngx_dbd_drizzle_column_size(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_size()");

    return drizzle_column_size(&col->col);
}


static size_t
ngx_dbd_drizzle_column_max_size(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_max_size()");

    return drizzle_column_max_size(&col->col);
}


static ngx_uint_t
ngx_dbd_drizzle_column_type(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_type()");

    return drizzle_column_type(&col->col);
}


static ngx_uint_t
ngx_dbd_drizzle_column_flags(ngx_dbd_column_t *col)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = col->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_column_flags()");

    return drizzle_column_flags(&col->col);
}


static ngx_dbd_row_v2_t *
ngx_dbd_drizzle_row_create(ngx_dbd_result_t *res)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_row_v2_t   *row;
    ngx_dbd_conn_v2_t  *conn;

    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_row_create()");

    row = res->row;

    if (row == NULL) {
        row = ngx_palloc(dbd->pool, sizeof(ngx_dbd_row_v2_t));
        if (row == NULL) {
            return NULL;
        }

        res->row = row;
    }

    row->res = res;

    return row;
}


static void
ngx_dbd_drizzle_row_destroy(ngx_dbd_row_v2_t *row)
{
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    ngx_dbd_conn_v2_t  *conn;

    res = row->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_row_destroy()");
}


static ngx_int_t
ngx_dbd_drizzle_row_read(ngx_dbd_row_v2_t *row)
{
    int                 row_num;
    ngx_dbd_v2_t       *dbd;
    ngx_dbd_result_t   *res;
    drizzle_return_t    rv;
    ngx_dbd_conn_v2_t  *conn;

    res = row->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_row_read()");

    row_num = (int) drizzle_row_read(&res->res, &rv);

    if (rv == DRIZZLE_RETURN_IO_WAIT) {
        return NGX_AGAIN;
    }

    if (rv != DRIZZLE_RETURN_OK) {
        ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                      "drizzle_row_read() failed (%d: %s)",
                      drizzle_con_errno(&conn->con),
                      drizzle_con_error(&conn->con));
        return NGX_ERROR;
    }

    /* rv == DRIZZLE_RETURN_OK */

    if (row_num == 0) {
        return NGX_DONE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_dbd_drizzle_field_read(ngx_dbd_row_v2_t *row, u_char **value, off_t *offset,
    size_t *size, size_t *total)
{
    ngx_dbd_v2_t       *dbd;
    drizzle_field_t     field;
    ngx_dbd_result_t   *res;
    drizzle_return_t    rv;
    ngx_dbd_conn_v2_t  *conn;

    res = row->res;
    conn = res->conn;
    dbd = conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_field_read()");

    field = drizzle_field_read(&res->res, (size_t *) offset, size, total, &rv);

    if (rv == DRIZZLE_RETURN_IO_WAIT) {
        return NGX_AGAIN;
    }

    if (rv == DRIZZLE_RETURN_ROW_END) {
        return NGX_DONE;
    }

    if (rv != DRIZZLE_RETURN_OK) {
        ngx_log_error(NGX_LOG_ALERT, dbd->log, 0,
                      "drizzle_field_read() failed (%d: %s)",
                      drizzle_con_errno(&conn->con),
                      drizzle_con_error(&conn->con));
        return NGX_ERROR;
    }

    /* rv == DRIZZLE_RETURN_OK */

    *value = (u_char *) field;

    return NGX_OK;
}


static void
ngx_dbd_drizzle_read_event_handler(ngx_event_t *rev)
{
    short               revents;
    ngx_connection_t   *c;
    ngx_dbd_conn_v2_t  *conn;

    c = rev->data;
    conn = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "ngx_dbd_drizzle_read_event_handler()");

    /* TODO: error handling */

    if (rev->error) {
        revents = POLLERR;

    } else {
        revents = POLLIN;
    }

    drizzle_con_set_revents(&conn->con, revents);

    if (conn->handler != NULL) {
        conn->handler(conn->data);
    }
}


static void
ngx_dbd_drizzle_write_event_handler(ngx_event_t *wev)
{
    short               revents;
    ngx_connection_t   *c;
    ngx_dbd_conn_v2_t  *conn;

    c = wev->data;
    conn = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "ngx_dbd_drizzle_write_event_handler()");

    /* TODO: error handling */

    if (wev->error) {
        revents = POLLERR;

    } else {
        revents = POLLOUT;
    }

    drizzle_con_set_revents(&conn->con, revents);

    if (conn->handler != NULL) {
        conn->handler(conn->data);
    }
}


#if (NGX_WIN32)

static ngx_int_t
ngx_dbd_drizzle_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_dbd_conn_v2_t *dbd_conn = data;

    ngx_dbd_v2_t    *dbd;
    drizzle_con_st  *con;

    dbd = dbd_conn->dbd;
    con = &dbd_conn->con;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0,
                   "ngx_dbd_drizzle_get_peer()");

    pc->sockaddr = con->addrinfo_next->ai_addr;
    pc->socklen = con->addrinfo_next->ai_addrlen;

    return NGX_OK;
}


drizzle_return_t
drizzle_state_connect(drizzle_con_st *con)
{
    ngx_int_t               rc;
    ngx_err_t               err;
    ngx_dbd_v2_t           *dbd;
    struct addrinfo        *ai;
    ngx_connection_t       *c;
    ngx_dbd_conn_v2_t      *dbd_conn;
    ngx_peer_connection_t  *pc;

    dbd_conn = drizzle_con_context(con);

    dbd = dbd_conn->dbd;
    pc = &dbd_conn->pc;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0, "drizzle_state_connect");

    /* TODO: close previous socket descriptor */

    if (con->fd != -1) {
        if (con->drizzle->options & DRIZZLE_NON_BLOCKING) {
            ngx_free_connection(pc->connection);

            pc->connection = NULL;

        } else {
            ngx_close_socket(con->fd);
        }

        con->fd = -1;
    }

    ai = con->addrinfo_next;

    if (ai == NULL) {
        drizzle_set_error(con->drizzle, "drizzle_state_connect",
                          "could not connect");
        drizzle_state_reset(con);
        return DRIZZLE_RETURN_COULD_NOT_CONNECT;
    }

    if (con->drizzle->options & DRIZZLE_NON_BLOCKING) {

        rc = ngx_event_connect_peer(pc);

        if (rc == NGX_ERROR) {
            drizzle_set_error(con->drizzle, "drizzle_state_connect",
                              "ngx_event_connect_peer() failed");
            con->drizzle->last_errno = ngx_socket_errno;
            return DRIZZLE_RETURN_ERRNO;
        }

        /* TODO: NGX_BUSY and NGX_DECLINED */

        if (rc == NGX_BUSY || rc == NGX_DECLINED) {
            con->addrinfo_next = ai->ai_next;
            return DRIZZLE_RETURN_OK;
        }

        c = pc->connection;

        c->log_error = NGX_ERROR_INFO;
        c->data = dbd_conn;

        c->read->handler = ngx_dbd_drizzle_read_event_handler;
        c->write->handler = ngx_dbd_drizzle_write_event_handler;

        con->fd = c->fd;

        /* TODO: setting socket options */

        if (rc == NGX_AGAIN) {
            drizzle_state_pop(con);
            drizzle_state_push(con, drizzle_state_connecting);
            return DRIZZLE_RETURN_OK;
        }

        /* rc == NGX_OK */

    } else {

        con->fd = ngx_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (con->fd == -1) {
            drizzle_set_error(con->drizzle, "drizzle_state_connect",
                              ngx_socket_n " failed");
            con->drizzle->last_errno = ngx_socket_errno;
            return DRIZZLE_RETURN_ERRNO;
        }

        /* TODO: setting socket options */

#if !(NGX_WIN32)

retry:

#endif

        rc = connect(con->fd, ai->ai_addr, ai->ai_addrlen);

        if (rc == -1) {
            err = ngx_socket_errno;

#if !(NGX_WIN32)
            if (err == NGX_EAGAIN || err == NGX_EINTR) {
                goto retry;
            }
#endif

            if (err == NGX_EINPROGRESS
#if (NGX_WIN32)
                || err == NGX_EAGAIN
#endif
                )
            {
                drizzle_state_pop(con);
                drizzle_state_push(con, drizzle_state_connecting);
                return DRIZZLE_RETURN_OK;
            }

            if (err == NGX_ECONNREFUSED
                || err == NGX_ENETUNREACH
                || err == NGX_ETIMEDOUT)
            {
                con->addrinfo_next = ai->ai_next;
                return DRIZZLE_RETURN_OK;
            }

            drizzle_set_error(con->drizzle, "drizzle_state_connect",
                              "connect() failed");
            con->drizzle->last_errno = err;
            return DRIZZLE_RETURN_ERRNO;
        }

        /* rc == 0 */
    }

    con->addrinfo_next = NULL;

    drizzle_state_pop(con);

    return DRIZZLE_RETURN_OK;
}


drizzle_return_t
drizzle_state_read(drizzle_con_st *con)
{
    u_char             *buf;
    size_t              size;
    ssize_t             n;
    ngx_err_t           err;
    ngx_dbd_v2_t       *dbd;
    drizzle_return_t    rv;
    ngx_connection_t   *c;
    ngx_dbd_conn_v2_t  *dbd_conn;

    dbd_conn = drizzle_con_context(con);

    dbd = dbd_conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0, "drizzle_state_read");

    if (con->buffer_size == 0) {
        con->buffer_ptr = con->buffer;

    } else if (con->buffer_ptr - con->buffer > DRIZZLE_MAX_BUFFER_SIZE / 2) {
        /* TODO: memmove */
        memmove(con->buffer, con->buffer_ptr, con->buffer_size);

        con->buffer_ptr = con->buffer;
    }

    buf = con->buffer_ptr + con->buffer_size;
    size = con->buffer + DRIZZLE_MAX_BUFFER_SIZE - buf;

    if (con->drizzle->options & DRIZZLE_NON_BLOCKING) {

        c = dbd_conn->pc.connection;

        n = c->recv(c, buf, size);

        if (n == 0) {
            drizzle_set_error(con->drizzle, "drizzle_state_read",
                              "lost connection to server (EOF)");
            return DRIZZLE_RETURN_LOST_CONNECTION;
        }

        if (n == NGX_ERROR) {
            drizzle_set_error(con->drizzle, "drizzle_state_read",
                              "recv() failed");
            con->drizzle->last_errno = errno;
            return DRIZZLE_RETURN_ERRNO;
        }

        if (n == NGX_AGAIN) {
            rv = drizzle_con_set_events(con, POLLIN);
            if (rv != DRIZZLE_RETURN_OK) {
                return rv;
            }

            return DRIZZLE_RETURN_IO_WAIT;
        }

        /* n > 0 */

    } else {

retry:

        n = recv(con->fd, buf, size, 0);

        if (n == 0) {
            drizzle_set_error(con->drizzle, "drizzle_state_read",
                              "lost connection to server (EOF)");
            return DRIZZLE_RETURN_LOST_CONNECTION;
        }

        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                rv = drizzle_con_set_events(con, POLLIN);
                if (rv != DRIZZLE_RETURN_OK) {
                    return rv;
                }

                rv = drizzle_con_wait(con->drizzle);
                if (rv != DRIZZLE_RETURN_OK) {
                    return rv;
                }

                goto retry;
            }

            if (err == NGX_ECONNREFUSED) {
                con->revents = 0;

                drizzle_state_pop(con);
                drizzle_state_push(con, drizzle_state_connect);

                con->addrinfo_next = con->addrinfo_next->ai_next;

                return DRIZZLE_RETURN_OK;
            }

            if (err == NGX_EINTR) {
                goto retry;
            }

            if (err == NGX_ECONNRESET
#if !(NGX_WIN32)
                || err == NGX_EPIPE
#endif
                )
            {
                drizzle_set_error(con->drizzle, "drizzle_state_read",
                                  "lost connection to server");
                return DRIZZLE_RETURN_LOST_CONNECTION;
            }

            drizzle_set_error(con->drizzle, "drizzle_state_read",
                              "recv() failed");
            con->drizzle->last_errno = err;
            return DRIZZLE_RETURN_ERRNO;
        }

        /* n > 0 */
    }

    con->buffer_size += n;

    drizzle_state_pop(con);

    return DRIZZLE_RETURN_OK;
}


drizzle_return_t
drizzle_state_write(drizzle_con_st *con)
{
    ssize_t             n;
    ngx_err_t           err;
    ngx_dbd_v2_t       *dbd;
    drizzle_return_t    rv;
    ngx_connection_t   *c;
    ngx_dbd_conn_v2_t  *dbd_conn;

    dbd_conn = drizzle_con_context(con);

    dbd = dbd_conn->dbd;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, dbd->log, 0, "drizzle_state_write");

    while (con->buffer_size > 0) {

        if (con->drizzle->options & DRIZZLE_NON_BLOCKING) {

            c = dbd_conn->pc.connection;

            n = c->send(c, con->buffer_ptr, con->buffer_size);

            if (n == 0) {
                drizzle_set_error(con->drizzle, "drizzle_state_write",
                                  "lost connection to server (EOF)");
                return DRIZZLE_RETURN_LOST_CONNECTION;
            }

            if (n == NGX_ERROR) {
                drizzle_set_error(con->drizzle, "drizzle_state_write",
                                  "send() failed");
                con->drizzle->last_errno = errno;
                return DRIZZLE_RETURN_ERRNO;
            }

            if (n == NGX_AGAIN) {
                rv = drizzle_con_set_events(con, POLLOUT);
                if (rv != DRIZZLE_RETURN_OK) {
                    return rv;
                }

                return DRIZZLE_RETURN_IO_WAIT;
            }

            /* n > 0 */

        } else {

            n = send(con->fd, con->buffer_ptr, con->buffer_size, 0);

            if (n == 0) {
                drizzle_set_error(con->drizzle, "drizzle_state_write",
                                  "lost connection to server (EOF)");
                return DRIZZLE_RETURN_LOST_CONNECTION;
            }

            if (n == -1) {
                err = ngx_socket_errno;

                if (err == NGX_EAGAIN) {
                    rv = drizzle_con_set_events(con, POLLOUT);
                    if (rv != DRIZZLE_RETURN_OK) {
                        return rv;
                    }

                    rv = drizzle_con_wait(con->drizzle);
                    if (rv != DRIZZLE_RETURN_OK) {
                        return rv;
                    }

                    continue;
                }

                if (err == NGX_EINTR) {
                    continue;
                }

                if (err == NGX_ECONNRESET
#if !(NGX_WIN32)
                    || err == NGX_EPIPE
#endif
                    )
                {
                    drizzle_set_error(con->drizzle, "drizzle_state_read",
                                      "lost connection to server");
                    return DRIZZLE_RETURN_LOST_CONNECTION;
                }

                drizzle_set_error(con->drizzle, "drizzle_state_read",
                                  "recv() failed");
                con->drizzle->last_errno = err;
                return DRIZZLE_RETURN_ERRNO;
            }

            /* n > 0 */
        }

        con->buffer_ptr += n;
        con->buffer_size -= n;
    }

    con->buffer_ptr = con->buffer;

    drizzle_state_pop(con);

    return DRIZZLE_RETURN_OK;
}

#endif


#endif /* NGX_DBD_DRIZZLE */
