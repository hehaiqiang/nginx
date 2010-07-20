
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd_core_module_v1.h>

#include <ctype.h>


struct ngx_dbd_s {
    ngx_dbd_v2_t         *dbd;
    ngx_dbd_conn_v2_t    *conn;
    ngx_dbd_query_t      *query;
    ngx_dbd_result_t     *res;
    ngx_dbd_column_t     *col;
    ngx_dbd_row_v2_t     *row;

    ngx_pool_t           *pool;
    ngx_str_t             escape_buf;
};


struct ngx_dbd_tran_s {
    ngx_dbd_t            *dbd;
};


struct ngx_dbd_prep_s {
    ngx_dbd_t            *dbd;
};


struct ngx_dbd_row_s {
    ngx_dbd_res_t        *res;
    ngx_str_t             value;
};


struct ngx_dbd_res_s {
    ngx_dbd_t            *dbd;
    ngx_str_t             field_name;
    ngx_dbd_row_t         row;
};


static ngx_int_t ngx_dbd_v1_process_init(ngx_cycle_t *cycle);
static void ngx_dbd_v1_process_exit(ngx_cycle_t *cycle);

static char *ngx_dbd_v1_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_dbd_v1_commands[] = {

    { ngx_string("dbd"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_dbd_v1_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_dbd_v1_module_ctx = {
    ngx_string("dbd"),
    NULL,
    NULL
};


ngx_module_t  ngx_dbd_v1_module = {
    NGX_MODULE_V1,
    &ngx_dbd_v1_module_ctx,                /* module context */
    ngx_dbd_v1_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_dbd_v1_process_init,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_dbd_v1_process_exit,               /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_uint_t  ngx_dbd_v1_max_module;


ngx_dbd_t *
ngx_dbd_open(ngx_dbd_driver_t *drv, ngx_pool_t *pool, ngx_str_t *conn_str,
    ngx_log_t *log, u_char *errstr)
{
    u_char         host[64], user[64], passwd[64], db[64];
    u_char        *params, *last, *ptr, *key, *value;
    size_t         klen, vlen;
    ngx_int_t      rc;
    ngx_uint_t     i, port;
    ngx_dbd_t     *dbd;
    ngx_keyval_t   fields[] = {
        { ngx_string("host"), ngx_null_string },
        { ngx_string("user"), ngx_null_string },
        { ngx_string("passwd"), ngx_null_string },
        { ngx_string("db"), ngx_null_string },
        { ngx_string("port"), ngx_null_string },
        { ngx_null_string, ngx_null_string }
    };

    dbd = ngx_pcalloc(pool, sizeof(ngx_dbd_t));
    if (dbd == NULL) {
        return NULL;
    }

    dbd->pool = pool;

    dbd->dbd = ngx_dbd_create(drv, pool, log);
    if (dbd->dbd == NULL) {
        return NULL;
    }

    dbd->conn = ngx_dbd_conn_create(drv, dbd->dbd);
    if (dbd->conn == NULL) {
        return NULL;
    }

    /* parse the connection string */

    params = conn_str->data;
    last = params + conn_str->len;

    for (ptr = (u_char *) ngx_strchr(params, '='); ptr && ptr < last;
         ptr = (u_char *) ngx_strchr(params, '='))
    {
        /* don't dereference memory that may not belong to us */

        if (ptr == params) {
            ++ptr;
            continue;
        }

        /* key */

        for (key = ptr - 1; isspace((int)(*key)); key--);

        klen = 0;

        while (isspace((int)(*key)) == 0) {

            /* don't parse backwards off the start of the string */

            if (key == params) {
                ++klen;
                break;
            }

            --key;
            ++klen;
        }

        /* value */

        for (value = ptr + 1; isspace((int)(*value)); value++);

        vlen = strcspn((const char *) value, " \r\n\t;|,");

        for (i = 0; fields[i].key.data; i++) {
            if (fields[i].key.len == klen
                && ngx_strncmp(fields[i].key.data, key, klen) == 0)
            {
                fields[i].value.len = vlen;
                fields[i].value.data = value;
                break;
            }
        }

        params = value + vlen + 1;
    }

    if (fields[0].value.data) {
        ngx_cpystrn(host, fields[0].value.data, fields[0].value.len + 1);

    } else {
        ngx_cpystrn(host, (u_char *)"127.0.0.1", sizeof("127.0.0.1"));
    }

    if (fields[1].value.data) {
        ngx_cpystrn(user, fields[1].value.data, fields[1].value.len + 1);

    } else {
        user[0] = '\0';
    }

    if (fields[2].value.data) {
        ngx_cpystrn(passwd, fields[2].value.data, fields[2].value.len + 1);

    } else {
        passwd[0] = '\0';
    }

    if (fields[3].value.data) {
        ngx_cpystrn(db, fields[3].value.data, fields[3].value.len + 1);

    } else {
        db[0] = '\0';
    }

    if (fields[4].value.data) {
        port = ngx_atoi(fields[4].value.data, fields[4].value.len);

    } else {
        port = 3306;
    }

    ngx_dbd_conn_set_tcp(drv, dbd->conn, host, port);
    ngx_dbd_conn_set_auth(drv, dbd->conn, user, passwd);
    ngx_dbd_conn_set_db(drv, dbd->conn, db);

    rc = ngx_dbd_conn_connect(drv, dbd->conn);

    if (rc != NGX_OK) {
        ngx_dbd_conn_destroy(drv, dbd->conn);
        ngx_dbd_destroy(drv, dbd->dbd);
        return NULL;
    }

    return dbd;
}


ngx_int_t
ngx_dbd_close(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    if (dbd->row != NULL) {
        ngx_dbd_row_destroy(drv, dbd->row);
    }

    if (dbd->col != NULL) {
        ngx_dbd_column_destroy(drv, dbd->col);
    }

    if (dbd->res != NULL) {
        ngx_dbd_result_destroy(drv, dbd->res);
    }

    if (dbd->query != NULL) {
        ngx_dbd_query_destroy(drv, dbd->query);
    }

    if (dbd->col != NULL) {
        ngx_dbd_conn_close(drv, dbd->conn);
        ngx_dbd_conn_destroy(drv, dbd->conn);
    }

    if (dbd->dbd != NULL) {
        ngx_dbd_destroy(drv, dbd->dbd);
    }

    return NGX_OK;
}


void *
ngx_dbd_native_handle(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    return NULL;
}


ngx_int_t
ngx_dbd_check_conn(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    return NGX_DECLINED;
}


ngx_int_t
ngx_dbd_select_db(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *dbname)
{
    return NGX_DECLINED;
}


ngx_dbd_tran_t *
ngx_dbd_start_tran(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    return NULL;
}


ngx_int_t
ngx_dbd_end_tran(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran)
{
    return NGX_OK;
}


ngx_uint_t
ngx_dbd_get_tran_mode(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran)
{
    return 0;
}


ngx_uint_t
ngx_dbd_set_tran_mode(ngx_dbd_driver_t *drv, ngx_dbd_tran_t *tran,
    ngx_uint_t mode)
{
    return 0;
}


ngx_int_t
ngx_dbd_exec(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *sql, int *affected)
{
    if (dbd->query == NULL) {
        dbd->query = ngx_dbd_query_create(drv, dbd->conn);
        if (dbd->query == NULL) {
            return NGX_ERROR;
        }
    }

    if (dbd->res == NULL) {
        dbd->res = ngx_dbd_result_create(drv, dbd->conn);
        if (dbd->res == NULL) {
            return NGX_ERROR;
        }
    }

    ngx_dbd_query_set_string(drv, dbd->query, sql, ngx_strlen(sql));

    if (ngx_dbd_query_result(drv, dbd->query, dbd->res) != NGX_OK) {
        return NGX_ERROR;
    }

    if (affected != NULL) {
        *affected = (int) ngx_dbd_result_affected_rows(drv, dbd->res);
    }

    return NGX_OK;
}


ngx_dbd_res_t *
ngx_dbd_query(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *sql,
    ngx_uint_t random)
{
    ngx_dbd_res_t  *res;

    res = ngx_palloc(dbd->pool, sizeof(ngx_dbd_res_t));
    if (res == NULL) {
        return NULL;
    }

    if (dbd->query == NULL) {
        dbd->query = ngx_dbd_query_create(drv, dbd->conn);
        if (dbd->query == NULL) {
            return NULL;
        }
    }

    if (dbd->res == NULL) {
        dbd->res = ngx_dbd_result_create(drv, dbd->conn);
        if (dbd->res == NULL) {
            return NULL;
        }
    }

    ngx_dbd_query_set_string(drv, dbd->query, sql, ngx_strlen(sql));

    if (ngx_dbd_query_result(drv, dbd->query, dbd->res) != NGX_OK) {
        return NULL;
    }

    res->dbd = dbd;

    return res;
}


ngx_dbd_prep_t *
ngx_dbd_prepare(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *sql)
{
    return NULL;
}


ngx_int_t
ngx_dbd_pexec(ngx_dbd_driver_t *drv, ngx_dbd_prep_t *prep, void *argv,
    ngx_uint_t argc, int *affected)
{
    return NGX_DECLINED;
}


ngx_dbd_res_t *
ngx_dbd_pquery(ngx_dbd_driver_t *drv, ngx_dbd_prep_t *prep, void *argv,
    ngx_uint_t argc, ngx_uint_t random)
{
    return NULL;
}


ngx_int_t
ngx_dbd_num_fields(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res)
{
    return ngx_dbd_result_column_count(drv, res->dbd->res);
}


ngx_int_t
ngx_dbd_num_rows(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res)
{
    return ngx_dbd_result_row_count(drv, res->dbd->res);
}


ngx_str_t *
ngx_dbd_field_name(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res, int col)
{
    u_char     *name;
    ngx_int_t   rc;
    ngx_dbd_t  *dbd;

    dbd = res->dbd;

    if (dbd->col == NULL) {
        dbd->col = ngx_dbd_column_create(drv, dbd->res);
        if (dbd->col == NULL) {
            return NULL;
        }
    }

    rc = ngx_dbd_column_read(drv, dbd->col);

    if (rc == NGX_DONE) {
        return NULL;
    }

    if (rc != NGX_OK) {
        /* TODO: error handling */
        return NULL;
    }

    /* rc == NGX_OK */

    name = ngx_dbd_column_name(drv, dbd->col);

    res->field_name.len = ngx_strlen(name);
    res->field_name.data = name;

    return &res->field_name;
}


ngx_dbd_row_t *
ngx_dbd_fetch_row(ngx_dbd_driver_t *drv, ngx_dbd_res_t *res, int row)
{
    ngx_int_t       rc;
    ngx_dbd_t      *dbd;
    ngx_dbd_row_t  *dbd_row;

    dbd = res->dbd;

    if (dbd->row == NULL) {
        dbd->row = ngx_dbd_row_create(drv, dbd->res);
        if (dbd->row == NULL) {
            return NULL;
        }
    }

    rc = ngx_dbd_row_read(drv, dbd->row);

    if (rc == NGX_DONE) {
        return NULL;
    }

    if (rc != NGX_OK) {
        /* TODO: error handling */
        return NULL;
    }

    /* rc == NGX_OK */

    dbd_row = &res->row;
    dbd_row->res = res;

    return dbd_row;
}


ngx_str_t *
ngx_dbd_fetch_field(ngx_dbd_driver_t *drv, ngx_dbd_row_t *row, int col)
{
    off_t           offset;
    u_char         *value;
    size_t          size, total;
    ngx_int_t       rc;
    ngx_dbd_t      *dbd;
    ngx_dbd_res_t  *res;

    res = row->res;
    dbd = res->dbd;

    rc = ngx_dbd_field_read(drv, dbd->row, &value, &offset, &size, &total);

    if (rc == NGX_DONE) {
        return NULL;
    }

    if (rc != NGX_OK) {
        /* TODO: error handling */
        return NULL;
    }

    /* rc == NGX_OK */

    row->value.len = size;
    row->value.data = value;

    return &row->value;
}


ngx_int_t
ngx_dbd_get_field(ngx_dbd_driver_t *drv, ngx_dbd_row_t *row, int col,
    ngx_dbd_data_type_e type, void *data)
{
    off_t           offset;
    u_char         *value;
    size_t          size, total;
    ngx_int_t       rc;
    ngx_dbd_t      *dbd;
    ngx_dbd_res_t  *res;

    res = row->res;
    dbd = res->dbd;

    rc = ngx_dbd_field_read(drv, dbd->row, &value, &offset, &size, &total);

    if (rc == NGX_DONE) {
        return NGX_DONE;
    }

    if (rc != NGX_OK) {
        /* TODO: error handling */
        return NGX_ERROR;
    }

    /* rc == NGX_OK */

    /* TODO: copy value to the memory pointed by data */

    return NGX_OK;
}


u_char *
ngx_dbd_escape(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd, u_char *str, int strlen,
    int breal)
{
    size_t      size;
    ngx_str_t  *buf;

    buf = &dbd->escape_buf;
    size = strlen * 2;

    if (buf->len < size) {
        buf->data = ngx_palloc(dbd->pool, size);
        if (buf->data == NULL) {
            return NULL;
        }

        buf->len = size;
    }

    if (ngx_dbd_escape_string(drv, dbd->conn, buf->data, str, (size_t) strlen)
        < (size_t) strlen)
    {
        return NULL;
    }

    return buf->data;
}


#if 0

int
ngx_dbd_error(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    return 0;
}


u_char *
ngx_dbd_strerror(ngx_dbd_driver_t *drv, ngx_dbd_t *dbd)
{
    return (u_char *) "";
}

#endif


ngx_dbd_conn_t *
ngx_dbd_get_conn(ngx_str_t *cmd_id, ngx_log_t *log, u_char *errstr)
{
    ngx_str_t                    *conn_str;
    ngx_uint_t                    key;
    ngx_dbd_conn_t               *c;
    ngx_dbd_conn_pool_t          *conn_pool;
    ngx_dbd_v1_conf_ctx_t        *ctx;
    ngx_dbd_v1_core_cmd_conf_t   *cdcf;
    ngx_dbd_v1_core_main_conf_t  *cmcf;

    ctx = (ngx_dbd_v1_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                 ngx_dbd_v1_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "dbd configuration can't be found");
        return NULL;
    }

    cmcf = ngx_dbd_v1_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_dbd_v1_core_module);

    key = ngx_hash_key_lc(cmd_id->data, cmd_id->len);

    cdcf = ngx_hash_find(&cmcf->commands_hash, key, cmd_id->data, cmd_id->len);
    if (cdcf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "command id \"%V\" can't be found", cmd_id);
        return NULL;
    }

    conn_str = &cdcf->conn->conn_string;

    key = ngx_hash_key(conn_str->data, conn_str->len);

    conn_pool = ngx_hash_find(&cmcf->connections_hash, key,
                              conn_str->data, conn_str->len);
    if (conn_pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "connection pool can't be found "
                      "by connection string \"%V\"",
                      conn_str);
        return NULL;
    }

    /* ngx_mutex_lock */

    c = conn_pool->free_connections;

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "%ui conn_pool_size is not enough",
                      conn_pool->connection_n);

        /* ngx_mutex_unlock */

        return NULL;
    }

    conn_pool->free_connections = c->data;
    conn_pool->free_connection_n--;

    /* ngx_mutex_unlock */

    if (c->dbd == NULL) {
        c->dbd = ngx_dbd_open(c->driver, c->pool, conn_str, log, errstr);
        if (c->dbd == NULL) {
            ngx_dbd_free_conn(c);
            return NULL;
        }
    }

    c->data = cdcf;

    return c;
}


void
ngx_dbd_free_conn(ngx_dbd_conn_t *c)
{
    /* ngx_mutex_lock */

    c->data = c->conn_pool->free_connections;
    c->conn_pool->free_connections = c;
    c->conn_pool->free_connection_n++;

    /* ngx_mutex_unlock */
}


ngx_dbd_prep_t *
ngx_dbd_conn_prepare(ngx_dbd_conn_t *c)
{
    ngx_str_t                    *sql;
    ngx_uint_t                    key;
    ngx_dbd_prep_t              **prep;
    ngx_dbd_v1_core_cmd_conf_t   *cdcf;

    cdcf = c->data;
    sql = &cdcf->cmd_text;

    key = ngx_hash_key(sql->data, sql->len);

    prep = ngx_hash_find(&c->preps_hash, key, sql->data, sql->len);
    if (prep == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->pool->log, 0,
                      "command text \"%V\" can't be found", sql);
        return NULL;
    }

    if (*prep == NULL) {
        *prep = ngx_dbd_prepare(c->driver, c->dbd, sql->data);
        if (*prep == NULL) {
            return NULL;
        }
    }

    return *prep;
}


static ngx_int_t
ngx_dbd_v1_process_init(ngx_cycle_t *cycle)
{
    return NGX_OK;
}


static void
ngx_dbd_v1_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t                     i, c;
    ngx_dbd_conn_pool_t           *conn_pool;
    ngx_dbd_v1_conf_ctx_t         *conf;
    ngx_dbd_v1_core_conn_conf_t  **cccfp;
    ngx_dbd_v1_core_main_conf_t   *cmcf;

    conf = (ngx_dbd_v1_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                  ngx_dbd_v1_module);

    if (conf == NULL || conf->main_conf == NULL) {
        return;
    }

    /* close all db connections */

    cmcf = ngx_dbd_v1_cycle_get_module_main_conf(ngx_cycle,
                                                 ngx_dbd_v1_core_module);

    cccfp = cmcf->connections.elts;

    for (i = 0; i < cmcf->connections.nelts; i++) {
        conn_pool = cccfp[i]->conn_pool;

        for (c = 0; c < conn_pool->connection_n; c++) {
            ngx_dbd_close(conn_pool->connections[c].driver,
                          conn_pool->connections[c].dbd);

            ngx_destroy_pool(conn_pool->connections[c].pool);
        }
    }
}


static char *
ngx_dbd_v1_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                           *rv;
    ngx_int_t                       rc;
    ngx_uint_t                      mi, m, c, d, p, i;
    ngx_conf_t                      pcf;
    ngx_dbd_conn_t                 *conn, *next;
    ngx_dbd_prep_t                **preps;
    ngx_hash_init_t                 hash;
    ngx_dbd_conn_pool_t            *conn_pools;
    ngx_dbd_v1_module_t            *module;
    ngx_dbd_v1_conf_ctx_t          *ctx;
    ngx_dbd_v1_core_cmd_conf_t    **cdcfp;
    ngx_dbd_v1_core_conn_conf_t   **cccfp;
    ngx_dbd_v1_core_main_conf_t    *cmcf;
    ngx_dbd_v1_core_param_conf_t  **cpcfp;

    /* the main dbd context */

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_v1_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_dbd_v1_conf_ctx_t **) conf = ctx;


    /* count the number of the dbd modules and set up their indices */

    ngx_dbd_v1_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_dbd_v1_max_module++;
    }


    /* the dbd main_conf context, it is the same in the all dbd contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the dbd null conn_conf context,
     * it is used to merge the connection{}'s conn_conf's
     */

    ctx->conn_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->conn_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the dbd null cmd_conf context,
     * it is used to merge the command{}'s cmd_conf's
     */

    ctx->cmd_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->cmd_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the dbd null param_conf context,
     * it is used to merge the command{}' param_conf's
     */

    ctx->param_conf = ngx_pcalloc(cf->pool,
                                  sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->param_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null conn_conf's, the null cmd_conf's,
     * and the null param_conf's of the all dbd modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_conn_conf) {
            ctx->conn_conf[mi] = module->create_conn_conf(cf);
            if (ctx->conn_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_cmd_conf) {
            ctx->cmd_conf[mi] = module->create_cmd_conf(cf);
            if (ctx->cmd_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_param_conf) {
            ctx->param_conf[mi] = module->create_param_conf(cf);
            if (ctx->param_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the dbd{} block */

    pcf = *cf;

    cf->ctx = ctx;
    cf->module_type = NGX_DBD_V1_MODULE;
    cf->cmd_type = NGX_DBD_V1_MAIN_CONF;

    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK)
        goto failed;

    /*
     * init dbd{} main_conf's, merge the connection{}s' conn_conf's,
     * the command{}s' cmd_conf's and its parameter{}s' param_conf's
     */

    cmcf = ctx->main_conf[ngx_dbd_v1_core_module.ctx_index];
    cccfp = cmcf->connections.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;


        /* init dbd{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        for (c = 0; c < cmcf->connections.nelts; c++) {

            /* merge the connection{}'s conn_conf's */

            if (module->merge_conn_conf) {
                rv = module->merge_conn_conf(cf, ctx->conn_conf[mi],
                                             cccfp[c]->ctx->conn_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }

            if (module->merge_cmd_conf) {

                /* merge the command{}'s cmd_conf */

                rv = module->merge_cmd_conf(cf, ctx->cmd_conf[mi],
                                            cccfp[c]->ctx->cmd_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }

            if (module->merge_param_conf) {

                /* merge the parameter{}'s param_conf */

                rv = module->merge_param_conf(cf, ctx->param_conf[mi],
                                              cccfp[c]->ctx->param_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }


            cdcfp = cccfp[c]->commands.elts;

            for (d = 0; d < cccfp[c]->commands.nelts; d++) {

                /* merge the command{}'s cmd_conf's */

                if (module->merge_cmd_conf) {
                    rv = module->merge_cmd_conf(cf, cccfp[c]->ctx->cmd_conf[mi],
                                                cdcfp[d]->ctx->cmd_conf[mi]);
                    if (rv != NGX_CONF_OK) {
                        goto failed;
                    }
                }

                if (module->merge_param_conf) {

                    /* merge the parameter{}'s param_conf */

                    rv = module->merge_param_conf(cf,
                            cccfp[c]->ctx->param_conf[mi],
                            cdcfp[d]->ctx->param_conf[mi]);
                    if (rv != NGX_CONF_OK) {
                        goto failed;
                    }
                }

                cpcfp = cdcfp[d]->parameters.elts;

                for (p = 0; p < cdcfp[d]->parameters.nelts; p++) {

                    /* merge the parameter{}' param_conf's */

                    if (module->merge_param_conf) {
                        rv = module->merge_param_conf(cf,
                                cdcfp[d]->ctx->param_conf[mi],
                                cpcfp[p]->ctx->param_conf[mi]);
                        if (rv != NGX_CONF_OK) {
                            goto failed;
                        }
                    }
                }
            }
        }
    }

    *cf = pcf;


    cmcf->commands_keys = ngx_pcalloc(cf->temp_pool,
                                      sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->commands_keys == NULL) {
        return NGX_CONF_ERROR;
    }

    cmcf->commands_keys->pool = cf->pool;
    cmcf->commands_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->commands_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->connections_keys = ngx_pcalloc(cf->temp_pool,
                                         sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->connections_keys == NULL) {
        return NGX_CONF_ERROR;
    }

    cmcf->connections_keys->pool = cf->pool;
    cmcf->connections_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->connections_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    conn_pools = ngx_palloc(cf->pool,
                        sizeof(ngx_dbd_conn_pool_t) * cmcf->connections.nelts);
    if (conn_pools == NULL) {
        return NGX_CONF_ERROR;
    }

    for (c = 0; c < cmcf->connections.nelts; c++) {

        /* commands hash */

        cdcfp = cccfp[c]->commands.elts;

        for (d = 0; d < cccfp[c]->commands.nelts; d++) {
            rc = ngx_hash_add_key(cmcf->commands_keys,
                                  &cdcfp[d]->cmd_id, cdcfp[d], 0);

            if (rc == NGX_OK) {
                continue;
            }

            if (rc == NGX_BUSY) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "conflicting command id \"%V\"",
                                   &cdcfp[d]->cmd_id);
            }

            return NGX_CONF_ERROR;
        }

        /* connections hash */

        cccfp[c]->conn_pool = &conn_pools[c];

        conn_pools[c].connections = ngx_palloc(cf->pool,
                            sizeof(ngx_dbd_conn_t) * cccfp[c]->conn_pool_size);
        if (conn_pools[c].connections == NULL) {
            return NGX_CONF_ERROR;
        }

        conn_pools[c].connection_n = cccfp[c]->conn_pool_size;

        i = cccfp[c]->conn_pool_size;
        next = NULL;

        do {
            i--;

            conn = &conn_pools[c].connections[i];

            conn->data = next;
            conn->conn_pool = &conn_pools[c];
            conn->driver = cccfp[c]->driver;
            conn->dbd = NULL;

            conn->pool = ngx_create_pool(ngx_pagesize, cf->log);
            if (conn->pool == NULL) {
                return NGX_CONF_ERROR;
            }

            /* prepares hash */

            preps = ngx_pcalloc(cf->pool,
                          sizeof(ngx_dbd_prep_t *) * cccfp[c]->commands.nelts);
            if (preps == NULL) {
                return NGX_CONF_ERROR;
            }

            conn->preps_keys = ngx_pcalloc(cf->temp_pool,
                                           sizeof(ngx_hash_keys_arrays_t));
            if (conn->preps_keys == NULL) {
                return NGX_CONF_ERROR;
            }

            conn->preps_keys->pool = cf->pool;
            conn->preps_keys->temp_pool = cf->pool;

            if (ngx_hash_keys_array_init(conn->preps_keys, NGX_HASH_SMALL)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            for (d = 0; d < cccfp[c]->commands.nelts; d++) {
                rc = ngx_hash_add_key(conn->preps_keys,
                                      &cdcfp[d]->cmd_text, &preps[d],
                                      NGX_HASH_READONLY_KEY);

                if (rc == NGX_OK) {
                    continue;
                }

                if (rc == NGX_BUSY) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "conflicting command text \"%V\"",
                                       &cdcfp[d]->cmd_text);
                }

                return NGX_CONF_ERROR;
            }

            ngx_memzero(&conn->preps_hash, sizeof(ngx_hash_t));

            hash.hash = &conn->preps_hash;
            hash.key = ngx_hash_key;
            hash.max_size = cccfp[c]->preps_hash_max_size;
            hash.bucket_size = cccfp[c]->preps_hash_bucket_size;
            hash.name = "preps_hash";
            hash.pool = cf->pool;
            hash.temp_pool = NULL;

            if (ngx_hash_init(&hash, conn->preps_keys->keys.elts,
                              conn->preps_keys->keys.nelts)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            conn->preps_keys = NULL;

            next = conn;

        } while (i);

        conn_pools[c].free_connections = next;
        conn_pools[c].free_connection_n = cccfp[c]->conn_pool_size;

        rc = ngx_hash_add_key(cmcf->connections_keys,
                              &cccfp[c]->conn_string, &conn_pools[c],
                              NGX_HASH_READONLY_KEY);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting connection string \"%V\"",
                               &cccfp[c]->conn_string);
        }

        return NGX_CONF_ERROR;
    }


    hash.hash = &cmcf->commands_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->commands_hash_max_size;
    hash.bucket_size = cmcf->commands_hash_bucket_size;
    hash.name = "commands_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->commands_keys->keys.elts,
                      cmcf->commands_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->commands_keys = NULL;

    hash.hash = &cmcf->connections_hash;
    hash.max_size = cmcf->connections_hash_max_size;
    hash.bucket_size = cmcf->connections_hash_bucket_size;
    hash.name = "connections_hash";

    if (ngx_hash_init(&hash, cmcf->connections_keys->keys.elts,
                      cmcf->connections_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->connections_keys = NULL;

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}
