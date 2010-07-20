
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define NGX_HTTP_LUA_BUFFER_SIZE   4096


#define NGX_HTTP_LUA_REQUEST_LIB   "request"
#define NGX_HTTP_LUA_RESPONSE_LIB  "response"


typedef struct {
    ngx_str_t          handler;
} ngx_http_lua_loc_conf_t;


typedef struct {
    lua_State         *lua;
    ngx_str_t         *next;
    ngx_int_t          done;

    ngx_fd_t           fd;
    size_t             size;
    u_char            *buf;

    ngx_str_t          lsp_buf;
    ngx_str_t          lua_buf;

    ngx_chain_t       *out;
    ngx_chain_t       *last;
} ngx_http_lua_ctx_t;


static ngx_int_t ngx_http_lua_handler(ngx_http_request_t *r);
static void ngx_http_lua_handle_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_call_handler(ngx_http_request_t *r,
    lua_State *lua, ngx_str_t *handler);
static void ngx_http_lua_cleanup(void *data);
static void ngx_http_lua_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_lua_parse(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);

static lua_State *ngx_http_lua_create_interpreter(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_init_interpreter(ngx_http_request_t *r,
    lua_State *lua);
static void *ngx_http_lua_alloc(void *ud, void *ptr, size_t osize,
    size_t nsize);
static int ngx_http_lua_panic(lua_State *lua);
static const char *ngx_http_lua_reader(lua_State *lua, void *data,
    size_t *size);

static int ngx_http_lua_request_get_method(lua_State *lua);
static int ngx_http_lua_request_get_uri(lua_State *lua);
static int ngx_http_lua_request_get_args(lua_State *lua);
static int ngx_http_lua_request_get_user_agent(lua_State *lua);
static int ngx_http_lua_request_get_body(lua_State *lua);
static int ngx_http_lua_request_get_body_file(lua_State *lua);
static int ngx_http_lua_request_read_body(lua_State *lua);

static int ngx_http_lua_response_set_content_type(lua_State *lua);
static int ngx_http_lua_response_write(lua_State *lua);

static void *ngx_http_lua_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_lua_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_lua_commands[] = {

    { ngx_string("lua"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_lua,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_lua_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_lua_create_loc_conf,          /* create location configuration */
    ngx_http_lua_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_lua_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_module_ctx,              /* module context */
    ngx_http_lua_commands,                 /* module directives */
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


static luaL_Reg  ngx_http_lua_request_lib[] = {
    { "get_method", ngx_http_lua_request_get_method },
    { "get_uri", ngx_http_lua_request_get_uri },
    { "get_args", ngx_http_lua_request_get_args },
    { "get_user_agent", ngx_http_lua_request_get_user_agent },
    { "get_body", ngx_http_lua_request_get_body },
    { "get_body_file", ngx_http_lua_request_get_body_file },
    { "read_body", ngx_http_lua_request_read_body },
    { NULL, NULL }
};

static luaL_Reg  ngx_http_lua_response_lib[] = {
    { "set_content_type", ngx_http_lua_response_set_content_type },
    { "write", ngx_http_lua_response_write },
    { NULL, NULL }
};


static ngx_int_t
ngx_http_lua_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_cleanup_t       *cln;
    ngx_http_lua_ctx_t       *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_handler()");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lua_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_lua_module);
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_lua_cleanup;
    cln->data = r;

    ctx->lua = ngx_http_lua_create_interpreter(r);
    if (ctx->lua == NULL) {
        ngx_http_lua_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    rc = ngx_http_lua_init_interpreter(r, ctx->lua);
    if (rc != NGX_OK) {
        ngx_http_lua_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    ngx_http_lua_handle_request(r);

    return NGX_DONE;
}


static void
ngx_http_lua_handle_request(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_str_t                *handler;
    ngx_http_lua_ctx_t       *ctx;
    ngx_http_lua_loc_conf_t  *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_handle_request");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx->next == NULL) {
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);
        handler = &llcf->handler;

    } else {
        handler = ctx->next;
        ctx->next = NULL;
    }

    rc = ngx_http_lua_call_handler(r, ctx->lua, handler);

    if (rc == NGX_DONE) {
        return;
    }

    if (rc > 600) {
        rc = NGX_OK;
    }

    if (ctx->done || ctx->next) {
        return;
    }

    if (rc == NGX_OK || rc == NGX_HTTP_OK) {
        r->headers_out.status = rc;

        if (r->headers_out.content_type.data == NULL) {
            r->headers_out.content_type.len
                = sizeof("text/html; charset=utf-8") - 1;
            r->headers_out.content_type.data
                = (u_char *) "text/html; charset=utf-8";
        }

        rc = ngx_http_send_header(r);

        /* TODO: rc */

        if (ctx->out != NULL) {
            ngx_http_output_filter(r, ctx->out);
        }

        ngx_http_send_special(r, NGX_HTTP_LAST);
        ctx->done = 1;
    }

    ngx_http_lua_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_lua_call_handler(ngx_http_request_t *r, lua_State *lua,
    ngx_str_t *handler)
{
    ngx_int_t          rc;
    ngx_str_t          str;
    ngx_connection_t  *c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_call_handler() handler: %V", handler);

    lua_getfield(lua, LUA_GLOBALSINDEX, (const char *) handler->data);

    rc = (ngx_int_t) lua_pcall(lua, 0, 1, 0);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_pcall(\"%V\") rc:%i", handler, rc);

        if (lua_isnil(lua, -1) != 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        str.data = (u_char *) lua_tolstring(lua, -1, &str.len);
        if (str.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_pcall(\"%V\") %V", handler, &str);

        lua_pop(lua, 1);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    c = r->connection;

    if (c->destroyed) {
        return NGX_DONE;
    }

    if (lua_isnil(lua, -1) != 0) {
        return NGX_OK;
    }

    rc = lua_tointeger(lua, -1);
    lua_pop(lua, 1);

    return rc;
}


static void
ngx_http_lua_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_lua_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_cleanup()");

#if 0
    if (ctx->fd > 0) {
        ngx_close_file(ctx->fd);
    }

    if (ctx->lua != NULL) {
        lua_close(ctx->lua);
    }
#endif
}


static void
ngx_http_lua_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_lua_ctx_t  *ctx;

    /* TODO */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_finalize_request()");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx->fd > 0) {
        ngx_close_file(ctx->fd);
    }

    if (ctx->lua != NULL) {
        lua_close(ctx->lua);
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_lua_parse(ngx_http_request_t *r, ngx_http_lua_ctx_t *ctx)
{
    u_char      *p, *last, ch, *out;
    u_char      *html_start, *lua_start, *lua_end;
    ngx_uint_t   backslash, dquoted, squoted;
    enum {
        sw_start = 0,
        sw_html_block,
        sw_lua_start,
        sw_lua_block_start,
        sw_lua_block,
        sw_lua_block_end,
        sw_lua_exp_block_start,
        sw_lua_exp_block,
        sw_lua_exp_block_end,
        sw_error
    } state;

    state = sw_start;

    last = ctx->lsp_buf.data + ctx->lsp_buf.len;
    out = ctx->lua_buf.data;

    for (p = ctx->lsp_buf.data; p < last; p++) {

        ch = *p;

        switch (state) {

        case sw_start:
            if (ch == '<') {
                html_start = NULL;
                lua_start = p;

                state = sw_lua_start;
                break;
            }

            out = ngx_cpymem(out, "print([[", sizeof("print([[") - 1);
            *out++ = ch;

            html_start = p;
            lua_start = NULL;

            state = sw_html_block;
            break;

        case sw_html_block:
            if (ch == '<') {
                lua_start = p;

                state = sw_lua_start;
                break;
            }

            *out++ = ch;

            break;

        case sw_lua_start:
            if (ch == '%') {
                state = sw_lua_block_start;
                break;
            }

            if (html_start == NULL) {
                html_start = lua_start;
                lua_start = NULL;

                out = ngx_cpymem(out, "print([[", sizeof("print([[") - 1);
                *out++ = '<';
            }

            *out++ = ch;

            state = sw_html_block;
            break;

        case sw_lua_block_start:
            if (html_start != NULL) {
                html_start = NULL;

                out = ngx_cpymem(out, "]]);", sizeof("]]);") - 1);
            }

            backslash = 0;
            dquoted = 0;
            squoted = 0;

            if (ch == '=') {
                state = sw_lua_exp_block_start;
                break;
            }

            /* TODO: xxx */

            *out++ = ch;

            state = sw_lua_block;
            break;

        case sw_lua_block:
            switch (ch) {

            case '\'':
                if (backslash || dquoted || squoted) {
                    squoted = 0;
                    backslash = 0;

                } else {
                    squoted = 1;
                }
                break;

            case '\"':
                if (backslash || dquoted || squoted) {
                    dquoted = 0;
                    backslash = 0;

                } else {
                    dquoted = 1;
                }
                break;

            case '\\':
                if (backslash) {
                    backslash = 0;

                } else {
                    backslash = 1;
                }
                break;

            case '%':
                if (backslash || dquoted || squoted) {
                    break;
                }

                lua_end = p;

                state = sw_lua_block_end;
                break;

            default:
                backslash = 0;
                break;
            }

            if (state != sw_lua_block_end) {
                *out++ = ch;
            }

            break;

        case sw_lua_block_end:
            if (ch != '>') {
                /* syntax error */
                state = sw_error;
                break;
            }

            lua_start = NULL;

            state = sw_start;
            break;

        case sw_lua_exp_block_start:

            /* TODO: xxx */

            *out++ = ch;

            state = sw_lua_exp_block;
            break;

        case sw_lua_exp_block:
            switch (ch) {

            case '\'':
                if (backslash || dquoted || squoted) {
                    squoted = 0;
                    backslash = 0;

                } else {
                    squoted = 1;
                }
                break;

            case '\"':
                if (backslash || dquoted || squoted) {
                    dquoted = 0;
                    backslash = 0;

                } else {
                    dquoted = 1;
                }
                break;

            case '\\':
                if (backslash) {
                    backslash = 0;

                } else {
                    backslash = 1;
                }
                break;

            case '%':
                if (backslash || dquoted || squoted) {
                    break;
                }

                lua_end = p;

                state = sw_lua_exp_block_end;
                break;

            default:
                backslash = 0;
                break;
            }

            if (state != sw_lua_exp_block_end) {
                *out++ = ch;
            }

            break;

        case sw_lua_exp_block_end:
            if (ch != '>') {
                /* syntax error */
                state = sw_error;
                break;
            }

            /* TODO: xxx */

            lua_start = NULL;

            state = sw_start;
            break;

        case sw_error:
            /* TODO: error handling */
            break;
        }
    }

    if (lua_start != NULL) {
        /* TODO: error handling */
    }

    if (html_start != NULL) {
        out = ngx_cpymem(out, "]]);", sizeof("]]);") - 1);
    }

    ctx->size = out - ctx->lua_buf.data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "\n\n%*s\n\n", ctx->size, ctx->lua_buf.data);

    return NGX_OK;
}


static lua_State *
ngx_http_lua_create_interpreter(ngx_http_request_t *r)
{
    lua_State  *lua;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_create_interpreter()");

    lua = lua_newstate(ngx_http_lua_alloc, r);
    if (lua == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_newstate() failed");
        return NULL;
    }

    lua_atpanic(lua, &ngx_http_lua_panic);

    luaL_openlibs(lua);

    luaL_register(lua, NGX_HTTP_LUA_REQUEST_LIB, ngx_http_lua_request_lib);
    luaL_register(lua, NGX_HTTP_LUA_RESPONSE_LIB, ngx_http_lua_response_lib);

    return lua;
}


static ngx_int_t
ngx_http_lua_init_interpreter(ngx_http_request_t *r, lua_State *lua)
{
    int                  rc;
    size_t               root;
    ssize_t              n;
    u_char              *last;
    ngx_str_t            path, lsp_buf, lua_buf;
    ngx_err_t            err;
    ngx_file_info_t      sb;
    ngx_http_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_init_interpreter()");

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua script filename: \"%V\"", &path);

    /* TODO: parse lua script file */

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ctx->buf = ngx_palloc(r->pool, NGX_HTTP_LUA_BUFFER_SIZE);
    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    ctx->fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);
    if (ctx->fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                      ngx_open_file_n " \"%V\" failed", &path);

        switch (err) {
        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:
            return NGX_HTTP_NOT_FOUND;
        case NGX_EACCES:
            return NGX_HTTP_FORBIDDEN;
        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_fd_info(ctx->fd, &sb) == NGX_FILE_ERROR) {
        ngx_close_file(ctx->fd);
        return NGX_ERROR;
    }

    ctx->size = (size_t) ngx_file_size(&sb);

    lsp_buf.len = ctx->size;
    lsp_buf.data = ngx_palloc(r->pool, lsp_buf.len);
    if (lsp_buf.data == NULL) {
        return NGX_ERROR;
    }

    n = ngx_read_fd(ctx->fd, lsp_buf.data, lsp_buf.len);
    if (n == NGX_FILE_ERROR || n != lsp_buf.len) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_read_fd_n " failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "\n\n%V\n\n", &lsp_buf);

    ctx->lsp_buf = lsp_buf;

    lua_buf.len = ngx_max(lsp_buf.len * 2, ngx_pagesize);
    lua_buf.data = ngx_palloc(r->pool, lua_buf.len);
    if (lua_buf.data == NULL) {
        return NGX_ERROR;
    }

    ctx->lua_buf = lua_buf;

    /* TODO: xxx */

    ngx_http_lua_parse(r, ctx);

    rc = lua_load(lua, ngx_http_lua_reader, r, (const char *) path.data);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_load(\"%V\") rc:%d", &path, rc);
        return NGX_ERROR;
    }

    rc = lua_pcall(lua, 0, LUA_MULTRET, 0);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "lua_pcall() rc:%d", rc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_lua_alloc(void *data, void *ptr, size_t osize, size_t nsize)
{
    ngx_http_request_t *r = data;

    u_char  *new;

#if 0
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_alloc()");
#endif

    if (nsize == 0) {
#if 0
        ngx_pfree(r->pool, ptr);
#endif
        return NULL;
    }

    if (ptr != NULL && nsize <= osize) {
        return ptr;
    }

    new = ngx_palloc(r->pool, nsize);
    if (new == NULL) {
        return NULL;
    }

    if (ptr != NULL && osize > 0) {
        ngx_memcpy(new, ptr, osize);
    }

    return new;
}


static int
ngx_http_lua_panic(lua_State *lua)
{
#if 0
    ngx_str_t            str;
    ngx_http_request_t  *r;

    lua_getallocf(lua,  (void **) &r);

    str.data = (u_char *) lua_tolstring(lua, -1, &str.len);

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "ngx_http_lua_panic() %V", &str);
#endif
    return 0;
}


static const char *
ngx_http_lua_reader(lua_State *lua, void *data, size_t *size)
{
    ngx_http_request_t *r = data;

    ssize_t              n;
    ngx_http_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_lua_reader()");

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx->size == 0) {
        *size = 0;
        return NULL;
    }

#if 0
    n = ngx_read_fd(ctx->fd, ctx->buf, NGX_HTTP_LUA_BUFFER_SIZE);
    if (n == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_read_fd_n " failed");
        *size = 0;
        return NULL;
    }

    ctx->size -= n;
    *size = n;
#else
    n = ngx_min(ctx->size, NGX_HTTP_LUA_BUFFER_SIZE);

    /* TODO: xxx */

    ngx_memcpy(ctx->buf, ctx->lsp_buf.data, n);
    ctx->lsp_buf.data += n;

    ctx->size -= n;
    *size = n;
#endif

    return (const char *) ctx->buf;
}


static int
ngx_http_lua_request_get_method(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str = &r->method_name;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_get_uri(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str = &r->uri;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_get_args(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str = &r->args;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_get_user_agent(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str = &r->headers_in.user_agent->value;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_get_body(lua_State *lua)
{
    ngx_buf_t           *buf;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    if (r->request_body == NULL
        || r->request_body->temp_file != NULL
        || r->request_body->bufs == NULL)
    {
        lua_pushnil(lua);
        return 1;
    }

    buf = r->request_body->bufs->buf;
    lua_pushlstring(lua, (const char *) buf->pos, buf->last - buf->pos);

    return 1;
}


static int
ngx_http_lua_request_get_body_file(lua_State *lua)
{
    ngx_str_t           *str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        lua_pushnil(lua);
        return 1;
    }

    str = &r->request_body->temp_file->file.name;
    lua_pushlstring(lua, (const char *) str->data, str->len);

    return 1;
}


static int
ngx_http_lua_request_read_body(lua_State *lua)
{
    ngx_str_t            str;
    ngx_http_request_t  *r;
    ngx_http_lua_ctx_t  *ctx;

    str.data = (u_char *) lua_tolstring(lua, 1, &str.len);

    lua_getallocf(lua, (void **) &r);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ctx->next = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (ctx->next == NULL) {
        return 0;
    }

    ctx->next->len = str.len;
    ctx->next->data = ngx_pstrdup(r->pool, &str);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only > 0) {
        r->request_body_file_log_level = 0;
    }

    ngx_http_read_client_request_body(r, ngx_http_lua_handle_request);

    return 0;
}


static int
ngx_http_lua_response_set_content_type(lua_State *lua)
{
    ngx_str_t            str;
    ngx_http_request_t  *r;

    lua_getallocf(lua, (void **) &r);

    str.data = (u_char *) lua_tolstring(lua, 1, &str.len);

    r->headers_out.content_type.len = str.len;
    r->headers_out.content_type.data = ngx_pstrdup(r->pool, &str);

    return 0;
}


static int
ngx_http_lua_response_write(lua_State *lua)
{
    size_t               size;
    ngx_str_t            str;
    ngx_buf_t           *buf;
    ngx_chain_t         *last, *new;
    ngx_http_request_t  *r;
    ngx_http_lua_ctx_t  *ctx;

    str.data = (u_char *) lua_tolstring(lua, 1, &str.len);

    lua_getallocf(lua, (void **) &r);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx->out == NULL) {
        ctx->out = ngx_alloc_chain_link(r->pool);
        if (ctx->out == NULL) {
            return 0;
        }

        ctx->out->buf = ngx_create_temp_buf(r->pool, NGX_HTTP_LUA_BUFFER_SIZE);
        if (ctx->out->buf == NULL) {
            return 0;
        }

        ctx->out->next = NULL;
        ctx->last = ctx->out;
    }

    last = ctx->last;
    buf = last->buf;
    buf->last_buf = 0;

    if ((size_t) (buf->end - buf->last) < str.len) {
        new = ngx_alloc_chain_link(r->pool);
        if (new == NULL) {
            return 0;
        }

        size = str.len < NGX_HTTP_LUA_BUFFER_SIZE
               ? NGX_HTTP_LUA_BUFFER_SIZE : str.len;

        new->buf = ngx_create_temp_buf(r->pool, size);
        if (new->buf == NULL) {
            return 0;
        }

        new->next = NULL;
        last->next = new;

        buf = new->buf;
    }

    buf->last = ngx_cpymem(buf->last, str.data, str.len);
    buf->last_buf = 1;

    return 0;
}


static void *
ngx_http_lua_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_lua_loc_conf_t  *llcf;

    llcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_loc_conf_t));
    if (llcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     llcf->handler = { 0, NULL };
     */

    return llcf;
}


static char *
ngx_http_lua_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_lua_loc_conf_t *prev = parent;
    ngx_http_lua_loc_conf_t *conf = child;

    if (conf->handler.len == 0) {
        conf->handler = prev->handler;
    }

    if (conf->handler.len == 0) {
        conf->handler.len = sizeof("main") - 1;
        conf->handler.data = (u_char *) "main";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lua_loc_conf_t *llcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;

    if (cf->args->nelts == 2) {
        value = cf->args->elts;
        llcf->handler = value[1];
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_lua_handler;

    return NGX_CONF_OK;
}
