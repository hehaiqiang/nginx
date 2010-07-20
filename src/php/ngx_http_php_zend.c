
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_dbd.h>
#include <ngx_http_php_module.h>


static PHP_MINIT_FUNCTION(dbd);
static PHP_MSHUTDOWN_FUNCTION(dbd);
static PHP_MINFO_FUNCTION(dbd);


static PHP_FUNCTION(ngx_dbd_get_driver);

static PHP_FUNCTION(ngx_dbd_create);
static PHP_FUNCTION(ngx_dbd_destroy);
static PHP_FUNCTION(ngx_dbd_get_options);
static PHP_FUNCTION(ngx_dbd_set_options);
static PHP_FUNCTION(ngx_dbd_error_code);
static PHP_FUNCTION(ngx_dbd_error);

static PHP_FUNCTION(ngx_dbd_conn_create);
static PHP_FUNCTION(ngx_dbd_conn_destroy);
static PHP_FUNCTION(ngx_dbd_conn_get_options);
static PHP_FUNCTION(ngx_dbd_conn_set_options);
static PHP_FUNCTION(ngx_dbd_conn_set_tcp);
static PHP_FUNCTION(ngx_dbd_conn_set_auth);
static PHP_FUNCTION(ngx_dbd_conn_set_db);
static PHP_FUNCTION(ngx_dbd_conn_set_handler);
static PHP_FUNCTION(ngx_dbd_conn_connect);
static PHP_FUNCTION(ngx_dbd_conn_close);

static PHP_FUNCTION(ngx_dbd_escape_string);

static PHP_FUNCTION(ngx_dbd_query_create);
static PHP_FUNCTION(ngx_dbd_query_destroy);
static PHP_FUNCTION(ngx_dbd_query_set_string);
static PHP_FUNCTION(ngx_dbd_query_result);

static PHP_FUNCTION(ngx_dbd_result_create);
static PHP_FUNCTION(ngx_dbd_result_destroy);
static PHP_FUNCTION(ngx_dbd_result_column_count);
static PHP_FUNCTION(ngx_dbd_result_row_count);
static PHP_FUNCTION(ngx_dbd_result_affected_rows);
static PHP_FUNCTION(ngx_dbd_result_insert_id);

static PHP_FUNCTION(ngx_dbd_column_create);
static PHP_FUNCTION(ngx_dbd_column_destroy);
static PHP_FUNCTION(ngx_dbd_column_read);
static PHP_FUNCTION(ngx_dbd_column_catalog);
static PHP_FUNCTION(ngx_dbd_column_db);
static PHP_FUNCTION(ngx_dbd_column_table);
static PHP_FUNCTION(ngx_dbd_column_orig_table);
static PHP_FUNCTION(ngx_dbd_column_name);
static PHP_FUNCTION(ngx_dbd_column_orig_name);
static PHP_FUNCTION(ngx_dbd_column_charset);
static PHP_FUNCTION(ngx_dbd_column_size);
static PHP_FUNCTION(ngx_dbd_column_max_size);
static PHP_FUNCTION(ngx_dbd_column_type);
static PHP_FUNCTION(ngx_dbd_column_flags);

static PHP_FUNCTION(ngx_dbd_row_create);
static PHP_FUNCTION(ngx_dbd_row_destroy);
static PHP_FUNCTION(ngx_dbd_row_read);

static PHP_FUNCTION(ngx_dbd_field_read);

static void ngx_http_php_zend_dbd_conn_handler(void *data);


static zend_function_entry  ngx_http_php_zend_dbd_funcs[] = {
    PHP_FE(ngx_dbd_get_driver, NULL)

    PHP_FE(ngx_dbd_create, NULL)
    PHP_FE(ngx_dbd_destroy, NULL)
    PHP_FE(ngx_dbd_get_options, NULL)
    PHP_FE(ngx_dbd_set_options, NULL)
    PHP_FE(ngx_dbd_error_code, NULL)
    PHP_FE(ngx_dbd_error, NULL)

    PHP_FE(ngx_dbd_conn_create, NULL)
    PHP_FE(ngx_dbd_conn_destroy, NULL)
    PHP_FE(ngx_dbd_conn_get_options, NULL)
    PHP_FE(ngx_dbd_conn_set_options, NULL)
    PHP_FE(ngx_dbd_conn_set_tcp, NULL)
    PHP_FE(ngx_dbd_conn_set_auth, NULL)
    PHP_FE(ngx_dbd_conn_set_db, NULL)
    PHP_FE(ngx_dbd_conn_set_handler, NULL)
    PHP_FE(ngx_dbd_conn_connect, NULL)
    PHP_FE(ngx_dbd_conn_close, NULL)

    PHP_FE(ngx_dbd_escape_string, NULL)

    PHP_FE(ngx_dbd_query_create, NULL)
    PHP_FE(ngx_dbd_query_destroy, NULL)
    PHP_FE(ngx_dbd_query_set_string, NULL)
    PHP_FE(ngx_dbd_query_result, NULL)

    PHP_FE(ngx_dbd_result_create, NULL)
    PHP_FE(ngx_dbd_result_destroy, NULL)
    PHP_FE(ngx_dbd_result_column_count, NULL)
    PHP_FE(ngx_dbd_result_row_count, NULL)
    PHP_FE(ngx_dbd_result_affected_rows, NULL)
    PHP_FE(ngx_dbd_result_insert_id, NULL)

    PHP_FE(ngx_dbd_column_create, NULL)
    PHP_FE(ngx_dbd_column_destroy, NULL)
    PHP_FE(ngx_dbd_column_read, NULL)
    PHP_FE(ngx_dbd_column_catalog, NULL)
    PHP_FE(ngx_dbd_column_db, NULL)
    PHP_FE(ngx_dbd_column_table, NULL)
    PHP_FE(ngx_dbd_column_orig_table, NULL)
    PHP_FE(ngx_dbd_column_name, NULL)
    PHP_FE(ngx_dbd_column_orig_name, NULL)
    PHP_FE(ngx_dbd_column_charset, NULL)
    PHP_FE(ngx_dbd_column_size, NULL)
    PHP_FE(ngx_dbd_column_max_size, NULL)
    PHP_FE(ngx_dbd_column_type, NULL)
    PHP_FE(ngx_dbd_column_flags, NULL)

    PHP_FE(ngx_dbd_row_create, NULL)
    PHP_FE(ngx_dbd_row_destroy, NULL)
    PHP_FE(ngx_dbd_row_read, NULL)

    PHP_FE(ngx_dbd_field_read, NULL)

    { NULL, NULL, NULL }
};


zend_module_entry  ngx_http_php_zend_dbd = {
    STANDARD_MODULE_HEADER,
    "dbd",
    ngx_http_php_zend_dbd_funcs,
    PHP_MINIT(dbd),
    PHP_MSHUTDOWN(dbd),
    NULL,
    NULL,
    PHP_MINFO(dbd),
    NO_VERSION_YET,
    STANDARD_MODULE_PROPERTIES
};


static PHP_MINIT_FUNCTION(dbd)
{
    REGISTER_LONG_CONSTANT("NGX_OK", NGX_OK, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_ERROR", NGX_ERROR, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_AGAIN", NGX_AGAIN, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_BUSY", NGX_BUSY, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_DONE", NGX_DONE, CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_DECLINED", NGX_DECLINED,
                           CONST_CS|CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("NGX_ABORT", NGX_ABORT, CONST_CS|CONST_PERSISTENT);

    return SUCCESS;
}


static PHP_MSHUTDOWN_FUNCTION(dbd)
{
    return SUCCESS;
}


static PHP_MINFO_FUNCTION(dbd)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "dbd", "enabled");
    php_info_print_table_end();
}


#if 0
RETURN_LONG
RETURN_STRING
#endif


static PHP_FUNCTION(ngx_dbd_get_driver)
{
    ngx_str_t          name;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name.data,
                              &name.len)
        == FAILURE)
    {
        return;
    }

    drv = ngx_dbd_get_driver(&name);

    RETURN_LONG((long) drv);
}


static PHP_FUNCTION(ngx_dbd_create)
{
    ngx_dbd_v2_t        *dbd;
    ngx_dbd_driver_t    *drv;
    ngx_http_request_t  *r;

    r = SG(server_context);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &drv) == FAILURE)
    {
        return;
    }

    dbd = ngx_dbd_create(drv, r->pool, r->connection->log);

    ngx_dbd_set_options(drv, dbd, NGX_DBD_OPTION_NON_BLOCKING);

    /* TODO: xxx */

    RETURN_LONG((long) dbd);
}


static PHP_FUNCTION(ngx_dbd_destroy)
{
    ngx_dbd_v2_t      *dbd;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &dbd)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_destroy(drv, dbd);
}


static PHP_FUNCTION(ngx_dbd_get_options)
{
}


static PHP_FUNCTION(ngx_dbd_set_options)
{
}


static PHP_FUNCTION(ngx_dbd_error_code)
{
}


static PHP_FUNCTION(ngx_dbd_error)
{
}


static PHP_FUNCTION(ngx_dbd_conn_create)
{
    ngx_dbd_v2_t        *dbd;
    ngx_dbd_driver_t    *drv;
    ngx_dbd_conn_v2_t   *conn;
    ngx_http_request_t  *r;

    r = SG(server_context);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &dbd)
        == FAILURE)
    {
        return;
    }

    conn = ngx_dbd_conn_create(drv, dbd);

    ngx_dbd_conn_set_handler(drv, conn, ngx_http_php_zend_dbd_conn_handler, r);

    /* TODO: xxx */

    RETURN_LONG((long) conn);
}


static PHP_FUNCTION(ngx_dbd_conn_destroy)
{
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &conn)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_conn_destroy(drv, conn);
}


static PHP_FUNCTION(ngx_dbd_conn_get_options)
{
}


static PHP_FUNCTION(ngx_dbd_conn_set_options)
{
}


static PHP_FUNCTION(ngx_dbd_conn_set_tcp)
{
    long                port;
    ngx_str_t           host;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|s|l", &drv,
                              &conn, &host.data, &host.len, &port)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_conn_set_tcp(drv, conn, host.data, (in_port_t) port);
}


static PHP_FUNCTION(ngx_dbd_conn_set_auth)
{
    ngx_str_t           user, passwd;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|s|s", &drv,
                              &conn, &user.data, &user.len, &passwd.data,
                              &passwd.len)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_conn_set_auth(drv, conn, user.data, passwd.data);
}


static PHP_FUNCTION(ngx_dbd_conn_set_db)
{
    ngx_str_t           db;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|s", &drv,
                              &conn, &db.data, &db.len)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_conn_set_db(drv, conn, db.data);
}


static PHP_FUNCTION(ngx_dbd_conn_set_handler)
{
}


static PHP_FUNCTION(ngx_dbd_conn_connect)
{
    ngx_int_t           rc;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &conn)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_conn_connect(drv, conn);

    RETURN_LONG(rc);
}


static PHP_FUNCTION(ngx_dbd_conn_close)
{
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &conn)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_conn_close(drv, conn);
}


static PHP_FUNCTION(ngx_dbd_escape_string)
{
}


static PHP_FUNCTION(ngx_dbd_query_create)
{
    ngx_dbd_query_t    *query;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &conn)
        == FAILURE)
    {
        return;
    }

    query = ngx_dbd_query_create(drv, conn);

    /* TODO: xxx */

    RETURN_LONG((long) query);
}


static PHP_FUNCTION(ngx_dbd_query_destroy)
{
    ngx_dbd_query_t   *query;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &query)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_query_destroy(drv, query);
}


static PHP_FUNCTION(ngx_dbd_query_set_string)
{
    ngx_int_t          rc;
    ngx_str_t          sql;
    ngx_dbd_query_t   *query;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|s", &drv,
                              &query, &sql.data, &sql.len)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_query_set_string(drv, query, sql.data, sql.len);

    RETURN_LONG(rc);
}


static PHP_FUNCTION(ngx_dbd_query_result)
{
    ngx_int_t          rc;
    ngx_dbd_query_t   *query;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|l", &drv, &query,
                              &res)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_query_result(drv, query, res);

    RETURN_LONG(rc);
}


static PHP_FUNCTION(ngx_dbd_result_create)
{
    ngx_dbd_result_t   *res;
    ngx_dbd_driver_t   *drv;
    ngx_dbd_conn_v2_t  *conn;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &conn)
        == FAILURE)
    {
        return;
    }

    res = ngx_dbd_result_create(drv, conn);

    /* TODO: xxx */

    RETURN_LONG((long) res);
}


static PHP_FUNCTION(ngx_dbd_result_destroy)
{
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_result_destroy(drv, res);
}


static PHP_FUNCTION(ngx_dbd_result_column_count)
{
    ngx_uint_t         n;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    n = ngx_dbd_result_column_count(drv, res);

    RETURN_LONG(n);
}


static PHP_FUNCTION(ngx_dbd_result_row_count)
{
    ngx_uint_t         n;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    n = ngx_dbd_result_row_count(drv, res);

    RETURN_LONG(n);
}


static PHP_FUNCTION(ngx_dbd_result_affected_rows)
{
    ngx_uint_t         n;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    n = ngx_dbd_result_affected_rows(drv, res);

    RETURN_LONG(n);
}


static PHP_FUNCTION(ngx_dbd_result_insert_id)
{
    ngx_uint_t         n;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    n = ngx_dbd_result_insert_id(drv, res);

    RETURN_LONG(n);
}


static PHP_FUNCTION(ngx_dbd_column_create)
{
    ngx_dbd_column_t  *col;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    col = ngx_dbd_column_create(drv, res);

    /* TODO: xxx */

    RETURN_LONG((long) col);
}


static PHP_FUNCTION(ngx_dbd_column_destroy)
{
    ngx_dbd_column_t  *col;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &col)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_column_destroy(drv, col);
}


static PHP_FUNCTION(ngx_dbd_column_read)
{
    ngx_int_t          rc;
    ngx_dbd_column_t  *col;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &col)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_column_read(drv, col);

    RETURN_LONG(rc);
}


static PHP_FUNCTION(ngx_dbd_column_catalog)
{
}


static PHP_FUNCTION(ngx_dbd_column_db)
{
}


static PHP_FUNCTION(ngx_dbd_column_table)
{
}


static PHP_FUNCTION(ngx_dbd_column_orig_table)
{
}


static PHP_FUNCTION(ngx_dbd_column_name)
{
}


static PHP_FUNCTION(ngx_dbd_column_orig_name)
{
}


static PHP_FUNCTION(ngx_dbd_column_charset)
{
}


static PHP_FUNCTION(ngx_dbd_column_size)
{
}


static PHP_FUNCTION(ngx_dbd_column_max_size)
{
}


static PHP_FUNCTION(ngx_dbd_column_type)
{
}


static PHP_FUNCTION(ngx_dbd_column_flags)
{
}


static PHP_FUNCTION(ngx_dbd_row_create)
{
    ngx_dbd_row_v2_t  *row;
    ngx_dbd_result_t  *res;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &res)
        == FAILURE)
    {
        return;
    }

    row = ngx_dbd_row_create(drv, res);

    /* TODO: xxx */

    RETURN_LONG((long) row);
}


static PHP_FUNCTION(ngx_dbd_row_destroy)
{
    ngx_dbd_row_v2_t  *row;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &row)
        == FAILURE)
    {
        return;
    }

    /* TODO: xxx */

    ngx_dbd_row_destroy(drv, row);
}


static PHP_FUNCTION(ngx_dbd_row_read)
{
    ngx_int_t          rc;
    ngx_dbd_row_v2_t  *row;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &drv, &row)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_row_read(drv, row);

    RETURN_LONG(rc);
}


static PHP_FUNCTION(ngx_dbd_field_read)
{
    zval              *field;
    off_t              offset;
    size_t             size, total;
    u_char            *value;
    ngx_int_t          rc;
    ngx_dbd_row_v2_t  *row;
    ngx_dbd_driver_t  *drv;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l|a", &drv, &row,
                              &field)
        == FAILURE)
    {
        RETURN_LONG(NGX_ERROR);
        return;
    }

    /* TODO: xxx */

    rc = ngx_dbd_field_read(drv, row, &value, &offset, &size, &total);

    if (rc == NGX_OK) {
        add_assoc_stringl(field, "value", value, size, 1);
        add_assoc_long(field, "offset", (long) offset);
        add_assoc_long(field, "size", size);
        add_assoc_long(field, "total", total);
    }

    RETURN_LONG(rc);
}


static void
ngx_http_php_zend_dbd_conn_handler(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_php_handle_request(r);
}
