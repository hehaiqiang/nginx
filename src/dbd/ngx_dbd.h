
/*
 * Copyright (C) Seegle
 */


#ifndef _NGX_DBD_H_INCLUDED_
#define _NGX_DBD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_DBD_OPTION_NON_BLOCKING       0x01


typedef struct ngx_dbd_connection_s       ngx_dbd_connection_t;
typedef struct ngx_dbd_connection_pool_s  ngx_dbd_connection_pool_t;

typedef struct ngx_dbd_driver_s           ngx_dbd_driver_t;
typedef struct ngx_dbd_v2_s               ngx_dbd_v2_t;
typedef struct ngx_dbd_conn_v2_s          ngx_dbd_conn_v2_t;
typedef struct ngx_dbd_query_s            ngx_dbd_query_t;
typedef struct ngx_dbd_result_s           ngx_dbd_result_t;
typedef struct ngx_dbd_column_s           ngx_dbd_column_t;
typedef struct ngx_dbd_row_v2_s           ngx_dbd_row_v2_t;


struct ngx_dbd_connection_s {
    void                         *data;
    ngx_dbd_connection_pool_t    *conn_pool;

    ngx_pool_t                   *pool;
    ngx_dbd_driver_t             *drv;
    ngx_dbd_v2_t                 *dbd;
    ngx_dbd_conn_v2_t            *conn;

    ngx_str_t                    *sql;
};


struct ngx_dbd_connection_pool_s {
    ngx_dbd_connection_t         *connections;
    ngx_uint_t                    connection_n;

    ngx_dbd_connection_t         *free_connections;
    ngx_uint_t                    free_connection_n;
};


typedef void (*ngx_dbd_conn_handler_pt)(void *data);


struct ngx_dbd_driver_s {
    ngx_str_t            *name;
    ngx_int_t           (*init)(ngx_cycle_t *cycle);
    void                (*done)(ngx_cycle_t *cycle);

    ngx_dbd_v2_t       *(*create)(ngx_pool_t *pool, ngx_log_t *log);
    void                (*destroy)(ngx_dbd_v2_t *dbd);
    ngx_uint_t          (*get_options)(ngx_dbd_v2_t *dbd);
    ngx_int_t           (*set_options)(ngx_dbd_v2_t *dbd, ngx_uint_t opts);

    ngx_err_t           (*error_code)(ngx_dbd_v2_t *dbd);
    u_char             *(*error)(ngx_dbd_v2_t *dbd);

    ngx_dbd_conn_v2_t  *(*conn_create)(ngx_dbd_v2_t *dbd);
    void                (*conn_destroy)(ngx_dbd_conn_v2_t *conn);
    ngx_uint_t          (*conn_get_options)(ngx_dbd_conn_v2_t *conn);
    ngx_int_t           (*conn_set_options)(ngx_dbd_conn_v2_t *conn,
                                            ngx_uint_t opts);
    ngx_int_t           (*conn_set_tcp)(ngx_dbd_conn_v2_t *conn, u_char *host,
                                        ngx_uint_t port);
    ngx_int_t           (*conn_set_auth)(ngx_dbd_conn_v2_t *conn, u_char *user,
                                         u_char *passwd);
    ngx_int_t           (*conn_set_db)(ngx_dbd_conn_v2_t *conn, u_char *db);
    ngx_int_t           (*conn_set_handler)(ngx_dbd_conn_v2_t *conn,
                                            ngx_dbd_conn_handler_pt handler,
                                            void *data);
    ngx_int_t           (*conn_connect)(ngx_dbd_conn_v2_t *conn);
    ngx_int_t           (*conn_close)(ngx_dbd_conn_v2_t *conn);

    size_t              (*escape_string)(ngx_dbd_conn_v2_t *conn, u_char *dst,
                                         u_char *src, size_t src_size);

    ngx_dbd_query_t    *(*query_create)(ngx_dbd_conn_v2_t *conn);
    void                (*query_destroy)(ngx_dbd_query_t *query);
    ngx_int_t           (*query_set_string)(ngx_dbd_query_t *query,
                                            u_char *query_str, size_t size);
    ngx_int_t           (*query_result)(ngx_dbd_query_t *query,
                                        ngx_dbd_result_t *res);

    ngx_dbd_result_t   *(*result_create)(ngx_dbd_conn_v2_t *conn);
    void                (*result_destroy)(ngx_dbd_result_t *res);
    ngx_uint_t          (*result_column_count)(ngx_dbd_result_t *res);
    ngx_uint_t          (*result_row_count)(ngx_dbd_result_t *res);
    ngx_uint_t          (*result_affected_rows)(ngx_dbd_result_t *res);
    ngx_uint_t          (*result_insert_id)(ngx_dbd_result_t *res);

    ngx_dbd_column_t   *(*column_create)(ngx_dbd_result_t *res);
    void                (*column_destroy)(ngx_dbd_column_t *col);
    ngx_int_t           (*column_read)(ngx_dbd_column_t *col);
    u_char             *(*column_catalog)(ngx_dbd_column_t *col);
    u_char             *(*column_db)(ngx_dbd_column_t *col);
    u_char             *(*column_table)(ngx_dbd_column_t *col);
    u_char             *(*column_orig_table)(ngx_dbd_column_t *col);
    u_char             *(*column_name)(ngx_dbd_column_t *col);
    u_char             *(*column_orig_name)(ngx_dbd_column_t *col);
    ngx_uint_t          (*column_charset)(ngx_dbd_column_t *col);
    size_t              (*column_size)(ngx_dbd_column_t *col);
    size_t              (*column_max_size)(ngx_dbd_column_t *col);
    ngx_uint_t          (*column_type)(ngx_dbd_column_t *col);
    ngx_uint_t          (*column_flags)(ngx_dbd_column_t *col);

    ngx_dbd_row_v2_t   *(*row_create)(ngx_dbd_result_t *res);
    void                (*row_destroy)(ngx_dbd_row_v2_t *row);
    ngx_int_t           (*row_read)(ngx_dbd_row_v2_t *row);

    ngx_int_t           (*field_read)(ngx_dbd_row_v2_t *row, u_char **value,
                                      off_t *offset, size_t *size,
                                      size_t *total);
};


/* API of DBD V2 */

#define ngx_dbd_driver_name(drv)                (drv)->name

#define ngx_dbd_create(drv, pool, log)          (drv)->create(pool, log)
#define ngx_dbd_destroy(drv, dbd)               (drv)->destroy(dbd)
#define ngx_dbd_get_options(drv, dbd)           (drv)->get_options(dbd)
#define ngx_dbd_set_options(drv, dbd, opts)     (drv)->set_options(dbd, opts)

#define ngx_dbd_error_code(drv, dbd)            (drv)->error_code(dbd)
#define ngx_dbd_error(drv, dbd)                 (drv)->error(dbd)

#define ngx_dbd_conn_create(drv, dbd)           (drv)->conn_create(dbd)
#define ngx_dbd_conn_destroy(drv, conn)         (drv)->conn_destroy(conn)
#define ngx_dbd_conn_get_options(drv, conn)     (drv)->conn_get_options(conn)
#define ngx_dbd_conn_set_options(drv, conn, opts)                              \
    (drv)->conn_set_options(conn, opts)
#define ngx_dbd_conn_set_tcp(drv, conn, host, port)                            \
    (drv)->conn_set_tcp(conn, host, port)
#define ngx_dbd_conn_set_auth(drv, conn, user, passwd)                         \
    (drv)->conn_set_auth(conn, user, passwd)
#define ngx_dbd_conn_set_db(drv, conn, db)      (drv)->conn_set_db(conn, db)
#define ngx_dbd_conn_set_handler(drv, conn, handler, data)                     \
    (drv)->conn_set_handler(conn, handler, data)
/**
 * connecting to the database server.
 * @param drv database driver.
 * @param conn database connection.
 * @returns NGX_OK
 *          NGX_ERROR
 *          NGX_AGAIN
 */
#define ngx_dbd_conn_connect(drv, conn)         (drv)->conn_connect(conn)
#define ngx_dbd_conn_close(drv, conn)           (drv)->conn_close(conn)

#define ngx_dbd_escape_string(drv, conn, dst, src, src_size)                   \
    (drv)->escape_string(conn, dst, src, src_size)

#define ngx_dbd_query_create(drv, conn)         (drv)->query_create(conn)
#define ngx_dbd_query_destroy(drv, query)       (drv)->query_destroy(query)
#define ngx_dbd_query_set_string(drv, query, str, size)                        \
    (drv)->query_set_string(query, str, size)
/**
 * @returns NGX_OK
 *          NGX_ERROR
 *          NGX_AGAIN
 */
#define ngx_dbd_query_result(drv, query, res)   (drv)->query_result(query, res)

#define ngx_dbd_result_create(drv, conn)        (drv)->result_create(conn)
#define ngx_dbd_result_destroy(drv, res)        (drv)->result_destroy(res)
#define ngx_dbd_result_column_count(drv, res)   (drv)->result_column_count(res)
#define ngx_dbd_result_row_count(drv, res)      (drv)->result_row_count(res)
#define ngx_dbd_result_affected_rows(drv, res)  (drv)->result_affected_rows(res)
#define ngx_dbd_result_insert_id(drv, res)      (drv)->result_insert_id(res)

#define ngx_dbd_column_create(drv, res)         (drv)->column_create(res)
#define ngx_dbd_column_destroy(drv, col)        (drv)->column_destroy(col)
/**
 * @returns NGX_OK
 *          NGX_ERROR
 *          NGX_AGAIN
 *          NGX_DONE
 */
#define ngx_dbd_column_read(drv, col)           (drv)->column_read(col)
#define ngx_dbd_column_catalog(drv, col)        (drv)->column_catalog(col)
#define ngx_dbd_column_db(drv, col)             (drv)->column_db(col)
#define ngx_dbd_column_table(drv, col)          (drv)->column_table(col)
#define ngx_dbd_column_orig_table(drv, col)     (drv)->column_orig_table(col)
#define ngx_dbd_column_name(drv, col)           (drv)->column_name(col)
#define ngx_dbd_column_orig_name(drv, col)      (drv)->column_orig_name(col)
#define ngx_dbd_column_charset(drv, col)        (drv)->column_charset(col)
#define ngx_dbd_column_size(drv, col)           (drv)->column_size(col)
#define ngx_dbd_column_max_size(drv, col)       (drv)->column_max_size(col)
#define ngx_dbd_column_type(drv, col)           (drv)->column_type(col)
#define ngx_dbd_column_flags(drv, col)          (drv)->column_flags(col)

#define ngx_dbd_row_create(drv, res)            (drv)->row_create(res)
#define ngx_dbd_row_destroy(drv, row)           (drv)->row_destroy(row)
/**
 * @returns NGX_OK
 *          NGX_ERROR
 *          NGX_AGAIN
 *          NGX_DONE
 */
#define ngx_dbd_row_read(drv, row)              (drv)->row_read(row)

/**
 * @returns NGX_OK
 *          NGX_ERROR
 *          NGX_AGAIN
 *          NGX_DONE
 */
#define ngx_dbd_field_read(drv, row, value, offset, size, total)               \
    (drv)->field_read(row, value, offset, size, total)


ngx_dbd_driver_t *ngx_dbd_get_driver(ngx_str_t *name);


/**
 * Get one connection from dbd connection pool by upstream name.
 */
ngx_dbd_connection_t *ngx_dbd_get_connection_by_upstream(ngx_str_t *name);

/**
 * Get one connection from dbd connection pool by command name.
 */
ngx_dbd_connection_t *ngx_dbd_get_connection_by_command(ngx_str_t *name);

/**
 * free the connection and return it to dbd connection pool.
 */
void ngx_dbd_free_connection(ngx_dbd_connection_t *c);


ngx_str_t *ngx_dbd_get_command_sql(ngx_str_t *name);


#include <ngx_dbd_v1.h>


#endif /* _NGX_DBD_H_INCLUDED_ */
