
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_dbd.h>
#include <nginx.h>


typedef struct {
    ngx_str_t              cmd_name;
} ngx_http_dbd_loc_conf_t;


typedef struct {
    ngx_dbd_connection_t  *conn;

    ngx_dbd_query_t       *query;
    ngx_dbd_result_t      *res;
    ngx_dbd_column_t      *col;
    ngx_dbd_row_v2_t      *row;

    ngx_buf_t             *buf;

    ngx_uint_t             state;
} ngx_http_dbd_ctx_t;


static void ngx_http_dbd_conn_handler(void *data);

static ngx_int_t ngx_http_dbd_init(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);
static ngx_int_t ngx_http_dbd_connect(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);
static ngx_int_t ngx_http_dbd_query_result(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);
static ngx_int_t ngx_http_dbd_read_column(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);
static ngx_int_t ngx_http_dbd_read_row(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);
static ngx_int_t ngx_http_dbd_read_field(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx);

static ngx_int_t ngx_http_dbd_output_string(ngx_http_request_t *r,
    ngx_http_dbd_ctx_t *ctx, ngx_str_t *str);
static void ngx_http_dbd_done(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx);

#if 0
static void ngx_http_dbd_test_old_api(ngx_http_request_t *r);
#endif

static void *ngx_http_dbd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dbd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_dbd(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_t  ngx_http_dbd_post = { ngx_http_dbd };


static ngx_command_t  ngx_http_dbd_commands[] = {

    { ngx_string("http_dbd"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dbd_loc_conf_t, cmd_name),
      &ngx_http_dbd_post },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dbd_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dbd_create_loc_conf,          /* create location configuration */
    ngx_http_dbd_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_dbd_module = {
    NGX_MODULE_V1,
    &ngx_http_dbd_module_ctx,              /* module context */
    ngx_http_dbd_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_dbd_handler(ngx_http_request_t *r)
{
    ngx_int_t            rc;
    ngx_http_dbd_ctx_t  *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dbd_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_dbd_module);

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_set_content_type(r);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if (nginx_version >= 8011)
    r->main->count++;
#endif

#if 0
    ngx_http_dbd_test_old_api(r);
#endif

    ngx_http_dbd_conn_handler(r);

    return NGX_DONE;
}


static void
ngx_http_dbd_conn_handler(void *data)
{
    ngx_http_request_t *r = data;

    ngx_int_t            rc;
    ngx_http_dbd_ctx_t  *ctx;
    enum {
        sw_init = 0,
        sw_connect,
        sw_query_result,
        sw_read_column,
        sw_read_row,
        sw_read_field,
        sw_error,
        sw_done
    } state;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dbd_module);

    state = ctx->state;

    for ( ;; ) {

        switch (state) {

        case sw_init:
            rc = ngx_http_dbd_init(r, ctx);
            if (rc == NGX_OK) {
                state = sw_connect;
            }

            break;

        case sw_connect:
            rc = ngx_http_dbd_connect(r, ctx);
            if (rc == NGX_OK) {
                state = sw_query_result;
            }

            break;

        case sw_query_result:
            rc = ngx_http_dbd_query_result(r, ctx);
            if (rc == NGX_OK) {
                state = sw_read_column;
            }

            if (rc == NGX_DONE) {
                state = sw_done;
            }

            break;

        case sw_read_column:
            rc = ngx_http_dbd_read_column(r, ctx);
            if (rc == NGX_DONE) {
                state = sw_read_row;
            }

            break;

        case sw_read_row:
            rc = ngx_http_dbd_read_row(r, ctx);
            if (rc == NGX_OK) {
                state = sw_read_field;
            }

            if (rc == NGX_DONE) {
                state = sw_done;
            }

            break;

        case sw_read_field:
            rc = ngx_http_dbd_read_field(r, ctx);
            if (rc == NGX_DONE) {
                state = sw_read_row;
            }

            break;

        case sw_error:
            /* TODO: error handling */
        case sw_done:
            ngx_http_dbd_done(r, ctx);
            return;

        default:
            /* TODO: error handling */
            return;
        }

        if (rc == NGX_AGAIN) {
            break;

        } else if (rc == NGX_ERROR) {
            state = sw_error;
        }
    }

    ctx->state = state;
}


static ngx_int_t
ngx_http_dbd_init(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    ngx_dbd_connection_t     *c;
    ngx_http_dbd_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dbd_module);

    c = ngx_dbd_get_connection_by_command(&dlcf->cmd_name);
    if (c == NULL) {
        return NGX_ERROR;
    }

    ctx->conn = c;

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_http_dbd_conn_handler, r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_connect(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    u_char                *p, buf[128];
    ngx_int_t              rc;
    ngx_str_t              str;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_conn_connect(c->drv, c->conn);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        p = ngx_snprintf(buf, sizeof(buf),
                         "<error_code>%d</error_code>\n"
                         "<error>%s</error>\n",
                         ngx_dbd_error_code(c->drv, c->dbd),
                         ngx_dbd_error(c->drv, c->dbd));
        str.len = p - buf;
        str.data = buf;
        ngx_http_dbd_output_string(r, ctx, &str);

        return NGX_ERROR;
    }

    /* rc == NGX_OK */

    ctx->res = ngx_dbd_result_create(c->drv, c->conn);
    if (ctx->res == NULL) {
        return NGX_ERROR;
    }

    ctx->query = ngx_dbd_query_create(c->drv, c->conn);
    if (ctx->query == NULL) {
        return NGX_ERROR;
    }

    ngx_dbd_query_set_string(c->drv, ctx->query, c->sql->data, c->sql->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_query_result(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    u_char                *p, buf[256];
    ngx_int_t              rc;
    ngx_str_t              str;
    ngx_uint_t             affected_rows, insert_id, row_count, col_count;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_query_result(c->drv, ctx->query, ctx->res);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        p = ngx_snprintf(buf, sizeof(buf),
                         "<error_code>%d</error_code>\n"
                         "<error>%s</error>\n",
                         ngx_dbd_error_code(c->drv, c->dbd),
                         ngx_dbd_error(c->drv, c->dbd));
        str.len = p - buf;
        str.data = buf;
        ngx_http_dbd_output_string(r, ctx, &str);

        return NGX_ERROR;
    }

    /* rc == NGX_OK */

    affected_rows = ngx_dbd_result_affected_rows(c->drv, ctx->res);
    insert_id = ngx_dbd_result_insert_id(c->drv, ctx->res);
    row_count = ngx_dbd_result_row_count(c->drv, ctx->res);
    col_count = ngx_dbd_result_column_count(c->drv, ctx->res);

    p = ngx_snprintf(buf, sizeof(buf),
                     "<row_count>%ui</row_count>\n"
                     "<column_count>%ui</column_count>\n"
                     "<affected_rows>%ui</affected_rows>\n"
                     "<insert_id>%ui</insert_id>\n\n",
                     row_count, col_count, affected_rows, insert_id);
    str.len = p - buf;
    str.data = buf;
    ngx_http_dbd_output_string(r, ctx, &str);

    if (col_count == 0) {
        return NGX_DONE;
    }

    ctx->col = ngx_dbd_column_create(c->drv, ctx->res);
    if (ctx->col == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_read_column(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_str_t              str;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_column_read(c->drv, ctx->col);

    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    if (rc == NGX_DONE) {
        ctx->row = ngx_dbd_row_create(c->drv, ctx->res);
        if (ctx->row == NULL) {
            return NGX_ERROR;
        }

        return NGX_DONE;
    }

    /* rc == NGX_OK */

    /* TODO: get column information */

    str.len = sizeof("<column>") - 1;
    str.data = (u_char *) "<column>";
    ngx_http_dbd_output_string(r, ctx, &str);

    str.data = ngx_dbd_column_name(c->drv, ctx->col);
    str.len = ngx_strlen(str.data);
    ngx_http_dbd_output_string(r, ctx, &str);

    str.len = sizeof("</column>\n") - 1;
    str.data = (u_char *) "</column>\n";
    ngx_http_dbd_output_string(r, ctx, &str);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_read_row(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_str_t              str;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_row_read(c->drv, ctx->row);

    if (rc != NGX_OK) {
        return rc;
    }

    /* rc == NGX_OK */

    str.len = sizeof("\n<row>") - 1;
    str.data = (u_char *) "\n<row>";
    ngx_http_dbd_output_string(r, ctx, &str);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_read_field(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    off_t                  offset;
    size_t                 size, total;
    u_char                *value;
    ngx_str_t              str;
    ngx_int_t              rc;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_field_read(c->drv, ctx->row, &value, &offset, &size, &total);

    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    if (rc == NGX_DONE) {
        str.len = sizeof("\n</row>\n") - 1;
        str.data = (u_char *) "\n</row>\n";
        ngx_http_dbd_output_string(r, ctx, &str);

        return NGX_DONE;
    }

    /* rc == NGX_OK */

    str.len = sizeof("  \n<field>") - 1;
    str.data = (u_char *) "  \n<field>";
    ngx_http_dbd_output_string(r, ctx, &str);

    /* TODO:
     *    value
     *    offset
     *    size
     *    total
     */

    str.len = size;
    str.data = value;
    ngx_http_dbd_output_string(r, ctx, &str);

    str.len = sizeof("</field>") - 1;
    str.data = (u_char *) "</field>";
    ngx_http_dbd_output_string(r, ctx, &str);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dbd_output_string(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx,
    ngx_str_t *str)
{
    ngx_buf_t  *b;

    if (ctx->buf == NULL) {
        ctx->buf = ngx_create_temp_buf(r->pool, ngx_pagesize * 32);
        if (ctx->buf == NULL) {
            return NGX_ERROR;
        }
    }

    b = ctx->buf;
    b->last = ngx_cpymem(b->last, str->data, str->len);

    return NGX_OK;
}


static void
ngx_http_dbd_done(ngx_http_request_t *r, ngx_http_dbd_ctx_t *ctx)
{
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_chain_t            out;
#if (NGX_STAT_STUB)
    ngx_atomic_int_t       ap, hn, ac, rq, rd, wr;
#endif
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    if (c != NULL) {
        if (ctx->row != NULL) {
            ngx_dbd_row_destroy(c->drv, ctx->row);

            ctx->row = NULL;
        }

        if (ctx->col != NULL) {
            ngx_dbd_column_destroy(c->drv, ctx->col);

            ctx->col = NULL;
        }

        if (ctx->res != NULL) {
            ngx_dbd_result_destroy(c->drv, ctx->res);

            ctx->res = NULL;
        }

        if (ctx->query != NULL) {
            ngx_dbd_query_destroy(c->drv, ctx->query);

            ctx->query = NULL;
        }

        ngx_dbd_free_connection(ctx->conn);

        ctx->conn = NULL;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    b = ctx->buf;

    out.buf = b;
    out.next = NULL;

#if (NGX_STAT_STUB)

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;

    b->last = ngx_sprintf(b->last, "\n\nActive connections: %uA \n", ac);

    b->last = ngx_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = ngx_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = ngx_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, ac - (rd + wr));

#endif

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_output_filter(r, &out);

    ngx_http_finalize_request(r, rc);
}


#if 0

static void
ngx_http_dbd_test_old_api(ngx_http_request_t *r)
{
#if 0
    int                affected;
#endif
    u_char            *str;
    ngx_str_t          name, conn_str, *field_name, *value;
    ngx_dbd_t         *dbd;
    ngx_dbd_res_t     *res;
    ngx_dbd_row_t     *row;
    ngx_dbd_driver_t  *drv;
    ngx_connection_t  *c;

    c = r->connection;

    name.len = sizeof("drizzle") - 1;
    name.data = (u_char *) "drizzle";

    drv = ngx_dbd_get_driver(&name);
    if (drv == NULL) {
        return;
    }

    str = (u_char *) "host=127.0.0.1;port=3306;user=root;passwd=123456";

    conn_str.len = ngx_strlen(str);
    conn_str.data = str;

    dbd = ngx_dbd_open(drv, r->pool, &conn_str, c->log, NULL);
    if (dbd == NULL) {
        return;
    }

#if 1
    str = (u_char *) "show databases";

    res = ngx_dbd_query(drv, dbd, str, 0);
    if (res == NULL) {
        ngx_dbd_close(drv, dbd);
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                  "num_fields:%d num_rows:%d",
                  ngx_dbd_num_fields(drv, res),
                  ngx_dbd_num_rows(drv, res));

    do {

        field_name = ngx_dbd_field_name(drv, res, -1);
        if (field_name == NULL) {
            break;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "field_name: %V", field_name);

    } while (1);

    for ( ;; ) {

        row = ngx_dbd_fetch_row(drv, res, -1);
        if (row == NULL) {
            break;
        }

        for ( ;; ) {

            value = ngx_dbd_fetch_field(drv, row, -1);
            if (value == NULL) {
                break;
            }

            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "value: %V", value);
        }

    };
#endif

#if 0
    str = "create database aiting";

    affected = 0;

    if (ngx_dbd_exec(drv, dbd, str, &affected) != NGX_OK) {
        ngx_dbd_close(drv, dbd);
        return;
    }
#endif

    ngx_dbd_close(drv, dbd);
}

#endif


static void *
ngx_http_dbd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dbd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dbd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_dbd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
#if 0
    ngx_http_dbd_loc_conf_t *prev = parent;
    ngx_http_dbd_loc_conf_t *conf = child;

    if (conf->cmd_name.len == 0) {
        return NGX_CONF_OK;
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_dbd(ngx_conf_t *cf, void *post, void *data)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dbd_handler;

    return NGX_CONF_OK;
}
