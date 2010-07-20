
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_php_module.h>


static void ngx_http_php_log_error(int type, const char *error_filename,
    const uint error_lineno, const char *format, va_list args);

static int ngx_http_php_sapi_startup(sapi_module_struct *sapi);
static int ngx_http_php_sapi_ub_write(const char *str,
    unsigned int str_length TSRMLS_DC);
static void ngx_http_php_sapi_flush(void *server_context);
static struct stat *ngx_http_php_sapi_get_stat(TSRMLS_D);
static char *ngx_http_php_sapi_getenv(char *name, size_t name_len TSRMLS_DC);
static void ngx_http_php_sapi_error(int type, const char *error_msg, ...);
static int ngx_http_php_sapi_header_handler(sapi_header_struct *sapi_header,
    sapi_headers_struct *sapi_headers TSRMLS_DC);
static int ngx_http_php_sapi_send_headers(
    sapi_headers_struct *sapi_headers TSRMLS_DC);
static void ngx_http_php_sapi_send_header(sapi_header_struct *sapi_header,
    void *server_context TSRMLS_DC);
static int ngx_http_php_sapi_read_post(char *buffer,
    uint count_bytes TSRMLS_DC);
static char *ngx_http_php_sapi_read_cookies(TSRMLS_D);
static void ngx_http_php_sapi_register_server_variables(
    zval *track_vars_array TSRMLS_DC);
static void ngx_http_php_sapi_log_message(char *message);
static time_t ngx_http_php_sapi_get_request_time(TSRMLS_D);


sapi_module_struct  ngx_http_php_sapi = {
    "ngx_http_php_sapi",                         /* name */
    "php sapi module for nginx",                 /* pretty_name */
    ngx_http_php_sapi_startup,                   /* startup */
    php_module_shutdown_wrapper,                 /* shutdown */
    NULL,                                        /* activate */
    NULL,                                        /* deactivate */
    ngx_http_php_sapi_ub_write,                  /* ub_write */
#if 0
    ngx_http_php_sapi_flush,                     /* flush */
#else
    NULL,                                        /* flush */
#endif
#if 0
    ngx_http_php_sapi_get_stat,                  /* get_stat */
#else
    NULL,                                        /* get_stat */
#endif
#if 0
    ngx_http_php_sapi_getenv,                    /* getenv */
#else
    NULL,                                        /* getenv */
#endif
#if 0
    ngx_http_php_sapi_error,                     /* sapi_error */
#else
    php_error,                                   /* sapi_error */
#endif
    ngx_http_php_sapi_header_handler,            /* header_handler */
    ngx_http_php_sapi_send_headers,              /* send_headers */
#if 0
    ngx_http_php_sapi_send_header,               /* send_header */
#else
    NULL,                                        /* send_header */
#endif
    ngx_http_php_sapi_read_post,                 /* read_post */
    ngx_http_php_sapi_read_cookies,              /* read_cookies */
    ngx_http_php_sapi_register_server_variables, /* register_server_variables */
#if 0
    ngx_http_php_sapi_log_message,               /* log_message */
    ngx_http_php_sapi_get_request_time,          /* get_request_time */
#else
    NULL,
    NULL,
#endif
    STANDARD_SAPI_MODULE_PROPERTIES
};


static void
ngx_http_php_log_error(int type, const char *error_filename,
    const uint error_lineno, const char *format, va_list args)
{
    u_char               errstr[NGX_MAX_ERROR_STR], *p, *last;
    ngx_uint_t           level;
    ngx_http_request_t  *r;

    TSRMLS_FETCH();

    r = SG(server_context);

    /* TODO: type => level */

    switch (type) {

    case E_ERROR:
        level = NGX_LOG_ERR;
        break;

    case E_WARNING:
        level = NGX_LOG_WARN;
        break;

    case E_PARSE:
        level = NGX_LOG_ALERT;
        break;

    case E_NOTICE:
        level = NGX_LOG_NOTICE;
        break;

    case E_CORE_ERROR:
        level = NGX_LOG_ERR;
        break;

    case E_CORE_WARNING:
        level = NGX_LOG_WARN;
        break;

    case E_COMPILE_ERROR:
        level = NGX_LOG_ERR;
        break;

    case E_COMPILE_WARNING:
        level = NGX_LOG_WARN;
        break;

    case E_USER_ERROR:
        level = NGX_LOG_ERR;
        break;

    case E_USER_WARNING:
        level = NGX_LOG_WARN;
        break;

    case E_USER_NOTICE:
        level = NGX_LOG_NOTICE;
        break;

    case E_STRICT:
        level = NGX_LOG_ALERT;
        break;

    case E_RECOVERABLE_ERROR:
        level = NGX_LOG_ERR;
        break;

    default:
        level = NGX_LOG_ALERT;
        break;
    }

    last = errstr + NGX_MAX_ERROR_STR;

    p = ngx_vslprintf(errstr, last, format, args);

    p = ngx_slprintf(p, last, " (%s:%d)", error_filename, error_lineno);

    ngx_log_error(level, r->connection->log, 0, "%*s", p - errstr, errstr);
}


static int
ngx_http_php_sapi_startup(sapi_module_struct *sapi)
{
    if (php_module_startup(sapi, &ngx_http_php_zend_dbd, 1) != SUCCESS) {
        return FAILURE;
    }

    zend_error_cb = ngx_http_php_log_error;

    return SUCCESS;
}


static int
ngx_http_php_sapi_ub_write(const char *str, unsigned int str_length TSRMLS_DC)
{
    size_t               len, size;
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_http_request_t  *r;
    ngx_http_php_ctx_t  *ctx;

    r = SG(server_context);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

#if 0
    if (str_length == 0) {
        return str_length;
    }
#endif

    cl = ctx->last;

    if (cl != NULL) {
        b = cl->buf;
        size = b->end - b->last;

    } else {
        b = NULL;
        size = 0;
    }

    len = str_length;

    if (size < str_length) {
        if (size > 0) {
            b->last = ngx_cpymem(b->last, str, size);

            str += size;
            str_length -= size;

            ctx->size += size;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return str_length;
        }

        size = ngx_max(str_length, ngx_pagesize);

        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            return str_length;
        }

        cl->buf = b;
        cl->next = NULL;

        if (ctx->last != NULL) {
            ctx->last->next = cl;
            ctx->last = cl;

        } else {
            ctx->out = cl;
            ctx->last = cl;
        }
    }

    if (b != NULL) {
        b->last = ngx_cpymem(b->last, str, str_length);
    }

    ctx->size += str_length;

    return len;
}


static void
ngx_http_php_sapi_flush(void *server_context)
{
    ngx_http_request_t *r = server_context;

    TSRMLS_FETCH();

    if (r == NULL) {
        return;
    }

    sapi_send_headers(TSRMLS_C);

    r->headers_out.status = SG(sapi_headers).http_response_code;

    SG(headers_sent) = 1;

    /* TODO: xxx ~ ap_rflush() */
}


static struct stat *
ngx_http_php_sapi_get_stat(TSRMLS_D)
{
    return NULL;
}


static char *
ngx_http_php_sapi_getenv(char *name, size_t name_len TSRMLS_DC)
{
    return NULL;
}


static void
ngx_http_php_sapi_error(int type, const char *error_msg, ...)
{
    ngx_http_request_t  *r;

    TSRMLS_FETCH();

    r = SG(server_context);
}


static int
ngx_http_php_sapi_header_handler(sapi_header_struct *sapi_header,
    sapi_headers_struct *sapi_headers TSRMLS_DC)
{
#if 0
    sapi_free_header(sapi_header);
#endif

    return SAPI_HEADER_ADD;
}


static int
ngx_http_php_sapi_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    return SAPI_HEADER_SENT_SUCCESSFULLY;
}


static void
ngx_http_php_sapi_send_header(sapi_header_struct *sapi_header,
    void *server_context TSRMLS_DC)
{
}


static int
ngx_http_php_sapi_read_post(char *buffer, uint count_bytes TSRMLS_DC)
{
    size_t               n, size;
    u_char              *p;
    ngx_buf_t           *b;
    ngx_http_request_t  *r;
    ngx_http_php_ctx_t  *ctx;

    r = SG(server_context);

    if (r->headers_in.content_length_n <= 0) {
        return 0;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    /* TODO: r->request_body_in_file_only */

#if 0
    r->request_body_in_file_only;

    r->request_body_in_single_buf;
#endif

    p = buffer;
    n = 0;

    while (ctx->in_buf != NULL) {

        b = ctx->in_buf->buf;

        size = ngx_min((uint) (b->last - b->pos), count_bytes);

        p = ngx_cpymem(p, b->pos, size);

        b->pos += size;
        count_bytes -= size;
        n += size;

        if (b->pos == b->last) {
            ctx->in_buf = ctx->in_buf->next;
        }

        if (count_bytes == 0) {
            break;
        }
    }

#if 0
    if (n > 0) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%*s", n, buffer);
    }
#endif

    return n;
}


static char *
ngx_http_php_sapi_read_cookies(TSRMLS_D)
{
#if 0
    size_t                size;
#endif
    ngx_uint_t            i;
    ngx_table_elt_t     **cookies;
    ngx_http_request_t   *r;
    ngx_http_php_ctx_t   *ctx;

    r = SG(server_context);

    if (r->headers_in.cookies.nelts == 0) {
        return NULL;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->cookies == NULL) {

        cookies = r->headers_in.cookies.elts;

        /* TODO: xxx */

        for (i = 0; i < r->headers_in.cookies.nelts; i++) {
#if 0
            cookies[i]->key;
            cookies[i]->value;
#else
            ctx->cookies = cookies[i]->value.data;
#endif
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_php_sapi_read_cookies() %s", ctx->cookies);

    return ctx->cookies;
}


static void
ngx_http_php_sapi_register_server_variables(zval *track_vars_array TSRMLS_DC)
{
    u_char               buf[256], *p;
#if 0
    size_t               len;
    ngx_uint_t           i;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;
#endif
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = SG(server_context);
    c = r->connection;

    php_register_variable("SERVER_ADDR", "127.0.0.1", track_vars_array TSRMLS_CC);

    p = ngx_cpymem(buf, c->addr_text.data, c->addr_text.len);
    *p = '\0';
    php_register_variable("REMOTE_ADDR", buf, track_vars_array TSRMLS_CC);

    p = ngx_cpymem(buf, r->method_name.data, r->method_name.len);
    *p = '\0';
    php_register_variable("REQUEST_METHOD", buf, track_vars_array TSRMLS_CC);

    p = ngx_cpymem(buf, r->uri.data, r->uri.len);
    *p = '\0';
    php_register_variable("REQUEST_URI", buf, track_vars_array TSRMLS_CC);
    php_register_variable("SCRIPT_NAME", buf, track_vars_array TSRMLS_CC);
    php_register_variable("PHP_SELF", buf, track_vars_array TSRMLS_CC);

    p = ngx_cpymem(buf, r->args.data, r->args.len);
    *p = '\0';
    php_register_variable("QUERY_STRING", buf, track_vars_array TSRMLS_CC);

    p = ngx_cpymem(buf, r->http_protocol.data, r->http_protocol.len);
    *p = '\0';
    php_register_variable("SERVER_PROTOCOL", buf, track_vars_array TSRMLS_CC);

#if 0
    len = 0;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        len += ((sizeof("HTTP_") - 1 + header[i].key.len > 127) ? 4 : 1)
            + ((header[i].value.len > 127) ? 4 : 1)
            + sizeof("HTTP_") - 1 + header[i].key.len + header[i].value.len;
    }
#endif
}


static void
ngx_http_php_sapi_log_message(char *message)
{
    ngx_log_t           *log;
    ngx_http_request_t  *r;

    TSRMLS_FETCH();

    r = SG(server_context);

    if (r == NULL) {
        log = ngx_cycle->log;

    } else {
        log = r->connection->log;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0,
                  "ngx_http_php_sapi_log_message() %s", message);
}


static time_t
ngx_http_php_sapi_get_request_time(TSRMLS_D)
{
    time_t               t;
    ngx_time_t          *tp;
    ngx_http_request_t  *r;

    r = SG(server_context);

    tp = ngx_timeofday();
    t = tp->sec - r->start_sec;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_php_sapi_get_request_time() %T", t);

    return t;
}