
/*
 * Copyright (C) Seegle
 */


#ifndef _NGX_DBD_V1_H_INCLUDED_
#define _NGX_DBD_V1_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd.h>


#define NGX_DBD_TRANS_MODE_COMMIT         0x00
#define NGX_DBD_TRANS_MODE_ROLLBACK       0x01
#define NGX_DBD_TRANS_MODE_IGNORE_ERRORS  0x02

#define NGX_DBD_TRANS_IGNORE_ERRORS(t)                                         \
    ((t)->mode & NGX_DBD_TRANS_MODE_IGNORE_ERRORS)
#define NGX_DBD_TRANS_NOTICE_ERRORS(t)                                         \
    (!((t)->mode & NGX_DBD_TRANS_MODE_IGNORE_ERRORS))

#define NGX_DBD_TRANS_DO_COMMIT(t)                                             \
    (!((t)->mode & NGX_DBD_TRANS_MODE_ROLLBACK))
#define NGX_DBD_TRANS_DO_ROLLBACK(t)                                           \
    ((t)->mode & NGX_DBD_TRANS_MODE_ROLLBACK)

#define NGX_DBD_TRANS_MODE_BITS                                                \
    (NGX_DBD_TRANS_MODE_ROLLBACK|NGX_DBD_TRANS_MODE_IGNORE_ERRORS)


typedef enum {
    NGX_DBD_DATA_TYPE_TINY,
    NGX_DBD_DATA_TYPE_UTINY,
    NGX_DBD_DATA_TYPE_SHORT,
    NGX_DBD_DATA_TYPE_USHORT,
    NGX_DBD_DATA_TYPE_INT,
    NGX_DBD_DATA_TYPE_UINT,
    NGX_DBD_DATA_TYPE_LONG,
    NGX_DBD_DATA_TYPE_ULONG,
    NGX_DBD_DATA_TYPE_LONGLONG,
    NGX_DBD_DATA_TYPE_ULONGLONG,
    NGX_DBD_DATA_TYPE_FLOAT,
    NGX_DBD_DATA_TYPE_DOUBLE,
    NGX_DBD_DATA_TYPE_STRING,
    NGX_DBD_DATA_TYPE_TEXT,
    NGX_DBD_DATA_TYPE_TIME,
    NGX_DBD_DATA_TYPE_DATE,
    NGX_DBD_DATA_TYPE_DATETIME,
    NGX_DBD_DATA_TYPE_TIMESTAMP,
    NGX_DBD_DATA_TYPE_ZTIMESTAMP,
    NGX_DBD_DATA_TYPE_BLOB,
    NGX_DBD_DATA_TYPE_CLOB,
    NGX_DBD_DATA_TYPE_NULL
} ngx_dbd_data_type_e;


typedef struct ngx_dbd_s            ngx_dbd_t;
typedef struct ngx_dbd_tran_s       ngx_dbd_tran_t;
typedef struct ngx_dbd_prep_s       ngx_dbd_prep_t;
typedef struct ngx_dbd_res_s        ngx_dbd_res_t;
typedef struct ngx_dbd_row_s        ngx_dbd_row_t;
typedef struct ngx_dbd_conn_pool_s  ngx_dbd_conn_pool_t;
typedef struct ngx_dbd_param_s      ngx_dbd_param_t;
typedef struct ngx_dbd_conn_s       ngx_dbd_conn_t;


struct ngx_dbd_param_s {
    u_char                     *name;
    ngx_uint_t                  type;
    size_t                      size;
    void                       *value;
};


struct ngx_dbd_conn_s {
    void                       *data;

    ngx_dbd_conn_pool_t        *conn_pool;

    ngx_dbd_driver_t           *driver;
    ngx_pool_t                 *pool;
    ngx_dbd_t                  *dbd;

    ngx_hash_t                  preps_hash;
    ngx_hash_keys_arrays_t     *preps_keys;
};


struct ngx_dbd_conn_pool_s {
    ngx_uint_t                  connection_n;
    ngx_uint_t                  free_connection_n;

    ngx_dbd_conn_t             *connections;
    ngx_dbd_conn_t             *free_connections;
};


/* API of DBD V1 */

ngx_dbd_t *ngx_dbd_open(ngx_dbd_driver_t *drv, ngx_pool_t *pool,
    ngx_str_t *conn_str, ngx_log_t *log, u_char *errstr);
ngx_int_t ngx_dbd_close(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);

void *ngx_dbd_native_handle(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);
ngx_int_t ngx_dbd_check_conn(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);
ngx_int_t ngx_dbd_select_db(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd,
    u_char *dbname);

ngx_dbd_tran_t *ngx_dbd_start_tran(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);
ngx_int_t ngx_dbd_end_tran(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran);
ngx_uint_t ngx_dbd_get_tran_mode(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran);
ngx_uint_t ngx_dbd_set_tran_mode(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran,
    ngx_uint_t mode);

ngx_int_t ngx_dbd_exec(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *sql,
    int *affected);
ngx_dbd_res_t *ngx_dbd_query(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *sql,
    ngx_uint_t random);

ngx_dbd_prep_t *ngx_dbd_prepare(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd,
    u_char *sql);
ngx_int_t ngx_dbd_pexec(ngx_dbd_driver_t *drv, ngx_dbd_prep_t *prep, void *argv,
    ngx_uint_t argc, int *affected);
ngx_dbd_res_t *ngx_dbd_pquery(ngx_dbd_driver_t *drv, ngx_dbd_prep_t *prep,
    void *argv, ngx_uint_t argc, ngx_uint_t random);

ngx_int_t ngx_dbd_num_fields(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res);
ngx_int_t ngx_dbd_num_rows(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res);

ngx_str_t *ngx_dbd_field_name(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res,
    int col);
ngx_dbd_row_t *ngx_dbd_fetch_row(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res,
    int row);
ngx_str_t *ngx_dbd_fetch_field(ngx_dbd_driver_t *drv, ngx_dbd_row_t *row,
    int col);
ngx_int_t ngx_dbd_get_field(ngx_dbd_driver_t *drv, ngx_dbd_row_t *row, int col,
    ngx_dbd_data_type_e type, void *data);
u_char *ngx_dbd_escape(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *str,
    int strlen, int breal);

#if 0
int ngx_dbd_error(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);
u_char *ngx_dbd_strerror(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd);
#endif


ngx_dbd_conn_t *ngx_dbd_get_conn(ngx_str_t *cmd_id, ngx_log_t *log,
    u_char *errstr);
void ngx_dbd_free_conn(ngx_dbd_conn_t *c);
ngx_dbd_prep_t *ngx_dbd_conn_prepare(ngx_dbd_conn_t *c);


#endif /* _NGX_DBD_V1_H_INCLUDED_ */
