
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_php_module.h>


#if 0

typedef struct {
    PerlInterpreter   *perl;
    HV                *nginx;
    ngx_array_t       *modules;
    ngx_array_t       *requires;
} ngx_http_perl_main_conf_t;

#endif


typedef struct {
    ngx_str_t          handler;
} ngx_http_php_loc_conf_t;


#if 0

typedef struct {
    SV                *sub;
    ngx_str_t          handler;
} ngx_http_perl_variable_t;

#endif


#if 0
#if (NGX_HTTP_SSI)
static ngx_int_t ngx_http_perl_ssi(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ssi_ctx, ngx_str_t **params);
#endif
#endif

static ngx_int_t ngx_http_php_request_startup(TSRMLS_D);
static void ngx_http_php_request_shutdown(TSRMLS_D);
static ngx_int_t ngx_http_php_call_handler(u_char *file,
    u_char *handler TSRMLS_DC);
#if 0
static void ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv);

static ngx_int_t ngx_http_perl_preconfiguration(ngx_conf_t *cf);
static void *ngx_http_perl_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf);
#endif
static void *ngx_http_php_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_php_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_php(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#if 0
static char *ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#if (NGX_HAVE_PERL_MULTIPLICITY)
static void ngx_http_perl_cleanup_perl(void *data);
#endif
#endif

static ngx_int_t ngx_http_php_process_init(ngx_cycle_t *cycle);
static void ngx_http_php_process_exit(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_php_commands[] = {

#if 0
    { ngx_string("perl_modules"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, modules),
      NULL },

    { ngx_string("perl_require"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, requires),
      NULL },

    { ngx_string("perl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_perl_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
#endif

    { ngx_string("php"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
      ngx_http_php,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


#if 0

static ngx_http_module_t  ngx_http_perl_module_ctx = {
    ngx_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_perl_create_main_conf,        /* create main configuration */
    ngx_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_perl_create_loc_conf,         /* create location configuration */
    ngx_http_perl_merge_loc_conf           /* merge location configuration */
};

#else

static ngx_http_module_t  ngx_http_php_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_php_create_loc_conf,          /* create location configuration */
    ngx_http_php_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_php_module = {
    NGX_MODULE_V1,
    &ngx_http_php_module_ctx,              /* module context */
    ngx_http_php_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_php_process_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_php_process_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif


#if 0

#if (NGX_HTTP_SSI)

#define NGX_HTTP_PERL_SSI_SUB  0
#define NGX_HTTP_PERL_SSI_ARG  1


static ngx_http_ssi_param_t  ngx_http_perl_ssi_params[] = {
    { ngx_string("sub"), NGX_HTTP_PERL_SSI_SUB, 1, 0 },
    { ngx_string("arg"), NGX_HTTP_PERL_SSI_ARG, 0, 1 },
    { ngx_null_string, 0, 0, 0 }
};

static ngx_http_ssi_command_t  ngx_http_perl_ssi_command = {
    ngx_string("perl"), ngx_http_perl_ssi, ngx_http_perl_ssi_params, 0, 0, 1
};

#endif


static ngx_str_t         ngx_null_name = ngx_null_string;
static HV               *nginx_stash;

#if (NGX_HAVE_PERL_MULTIPLICITY)
static ngx_uint_t        ngx_perl_term;
#else
static PerlInterpreter  *perl;
#endif


static void
ngx_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    nginx_stash = gv_stashpv("nginx", TRUE);
}

#endif


static ngx_int_t
ngx_http_php_handler(ngx_http_request_t *r)
{
    u_char              *last;
    size_t               root;
    ngx_int_t            rc;
    ngx_err_t            err;
    ngx_str_t            path;
    ngx_log_t           *log;
    ngx_file_info_t      fi;
    ngx_http_php_ctx_t  *ctx;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_http_php_handler()");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_php_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_php_module);

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0, "root:%uz path:%V", root, &path);

    rc = (ngx_int_t) ngx_file_info(path.data, &fi);

    err = ngx_errno;

    if (rc == NGX_FILE_ERROR && (err == NGX_ENOENT || err == NGX_ENOPATH)) {
        return NGX_HTTP_NOT_FOUND;
    }

    ctx->filename = path;

    rc = ngx_http_read_client_request_body(r, ngx_http_php_handle_request);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


void
ngx_http_php_handle_request(ngx_http_request_t *r)
{
    u_char                    *p, file[NGX_MAX_PATH];
    ngx_int_t                  rc;
    ngx_err_t                  err;
#if 0
    ngx_str_t                  uri, args, *handler;
#endif
    ngx_chain_t               *cl;
    ngx_file_info_t            fi;
    ngx_http_php_ctx_t        *ctx;
#if 0
    ngx_http_php_loc_conf_t   *plcf;
    ngx_http_php_main_conf_t  *pmcf;
#endif
    enum {
        sw_initialize = 0,
        sw_process_cycle,
        sw_output,
        sw_finalize,
        sw_error,
        sw_done
    } state;

    TSRMLS_FETCH();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_php_handle_request()");

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->tsrm_ls == NULL) {
        ctx->tsrm_ls = tsrm_new_interpreter_context();
        if (ctx->tsrm_ls == NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "tsrm_new_interpreter_context() failed");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    ctx->thr_tsrm_ls = tsrm_set_interpreter_context(ctx->tsrm_ls);

    TSRMLS_C = ctx->tsrm_ls;

    SG(server_context) = r;

    state = ctx->state;

    while (1) {

        switch (state) {

        case sw_initialize:
            ctx->in_buf = r->request_body->bufs;

            if (ngx_http_php_request_startup(TSRMLS_C) != NGX_OK) {
                state = sw_error;
                break;
            }

            p = ngx_cpymem(file, ctx->filename.data, ctx->filename.len);
            p = ngx_cpymem(p, ".php", sizeof(".php") - 1);
            *p = '\0';

            rc = (ngx_int_t) ngx_file_info(file, &fi);

            err = ngx_errno;

            if (rc == NGX_FILE_ERROR
                && (err == NGX_ENOENT || err == NGX_ENOPATH))
            {
                state = sw_output;
                break;
            }

            rc = ngx_http_php_call_handler(file, NULL TSRMLS_CC);
            if (rc == NGX_ERROR) {
                state = sw_error;
                break;
            }

            rc = ngx_http_php_call_handler(NULL, "initialize()" TSRMLS_CC);
            if (rc == NGX_ERROR) {
                state = sw_error;
                break;
            }

            ctx->inited = 1;

            state = sw_process_cycle;
            break;

        case sw_process_cycle:
            rc = ngx_http_php_call_handler(NULL, "process_cycle()" TSRMLS_CC);
            if (rc == NGX_ERROR) {
                state = sw_error;
                break;
            }

            if (rc == NGX_AGAIN) {
                goto again;
            }

            state = sw_output;
            break;

        case sw_output:
            rc = ngx_http_php_call_handler(ctx->filename.data, NULL TSRMLS_CC);
            if (rc == NGX_ERROR) {
                state = sw_error;
                break;
            }

            if (!ctx->inited) {
                state = sw_done;
                break;
            }

            state = sw_finalize;
            break;

        case sw_finalize:
            rc = ngx_http_php_call_handler(NULL, "finalize()" TSRMLS_CC);
            if (rc == NGX_ERROR) {
                state = sw_error;
                break;
            }

            state = sw_done;
            break;

        case sw_error:
            state = sw_done;
            break;

        case sw_done:
            ngx_http_php_request_shutdown(TSRMLS_C);

            ngx_str_set(&r->headers_out.content_type, "text/html");

            if (r->method == NGX_HTTP_HEAD) {
                r->headers_out.status = NGX_HTTP_OK;

                rc = ngx_http_send_header(r);

                if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
                    ngx_http_finalize_request(r, rc);
                    return;
                }
            }

            r->headers_out.status = NGX_HTTP_OK;

            if (ctx->size > 0) {
                r->headers_out.content_length_n = ctx->size;
            }

            rc = ngx_http_send_header(r);

            if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
                ngx_http_finalize_request(r, rc);
                return;
            }

            cl = ctx->last;

            if (cl != NULL) {
                cl->buf->last_buf = 1;

                ngx_http_output_filter(r, ctx->out);
            }

            ngx_http_finalize_request(r, rc);
            return;

        default:
            break;
        }

    }

again:

    ctx->state = state;

    if (ctx->thr_tsrm_ls != NULL) {
        tsrm_set_interpreter_context(ctx->thr_tsrm_ls);

        ctx->thr_tsrm_ls = NULL;
    }

#if 0
    if (ctx->next == NULL) {
        plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);
        sub = plcf->sub;
        handler = &plcf->handler;

    } else {
        sub = ctx->next;
        handler = &ngx_null_name;
        ctx->next = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, pmcf->nginx, sub, NULL, handler,
                                    NULL);

    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc == NGX_DONE) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc > 600) {
        rc = NGX_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;
        args = ctx->redirect_args;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (ctx->done || ctx->next) {
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (uri.len) {
        ngx_http_internal_redirect(r, &uri, &args);
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc == NGX_OK || rc == NGX_HTTP_OK) {
        ngx_http_send_special(r, NGX_HTTP_LAST);
        ctx->done = 1;
    }

    ngx_http_finalize_request(r, rc);
#endif
}


void
ngx_http_php_sleep_handler(ngx_http_request_t *r)
{
#if 0
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->timedout) {
        wev->timedout = 0;
        ngx_http_perl_handle_request(r);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
#endif
}


#if 0

#if (NGX_HTTP_SSI)

static ngx_int_t
ngx_http_perl_ssi(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ssi_ctx,
    ngx_str_t **params)
{
    SV                         *sv, **asv;
    ngx_int_t                   rc;
    ngx_str_t                  *handler, **args;
    ngx_uint_t                  i;
    ngx_http_perl_ctx_t        *ctx;
    ngx_http_perl_main_conf_t  *pmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
    }

    pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);

    ctx->ssi = ssi_ctx;

    handler = params[NGX_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    ngx_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return NGX_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[NGX_HTTP_PERL_SSI_ARG];

    if (args) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = ngx_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return NGX_ERROR;
        }

        asv[0] = (SV *) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, pmcf->nginx, sv, asv, handler,
                                    NULL);

    SvREFCNT_dec(sv);

    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif

#endif


static ngx_int_t
ngx_http_php_request_startup(TSRMLS_D)
{
    u_char              *p;
    ngx_http_request_t  *r;

    r = SG(server_context);

    p = ngx_pstrdup_ex(r->pool, &r->method_name);
    SG(request_info).request_method = p;

    p = ngx_pstrdup_ex(r->pool, &r->args);
    SG(request_info).query_string = p;

    if (r->headers_in.content_type != NULL) {
        p = ngx_pstrdup_ex(r->pool, &r->headers_in.content_type->value);
        SG(request_info).content_type = p;
    }

    SG(request_info).content_length = (long) r->headers_in.content_length_n;

    SG(sapi_headers).http_response_code = NGX_HTTP_OK;

    if (php_request_startup(TSRMLS_C) != SUCCESS) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_php_request_shutdown(TSRMLS_D)
{
    ngx_http_request_t  *r;
    ngx_http_php_ctx_t  *ctx;

    php_request_shutdown(NULL);

    r = SG(server_context);

    ctx = ngx_http_get_module_ctx(r, ngx_http_php_module);

    if (ctx->thr_tsrm_ls != NULL) {
        tsrm_set_interpreter_context(ctx->thr_tsrm_ls);
    }

    if (ctx->tsrm_ls != NULL) {
        tsrm_free_interpreter_context(ctx->tsrm_ls);
    }
}


static ngx_int_t
ngx_http_php_call_handler(u_char *file, u_char *handler TSRMLS_DC)
{
    zval                 rv;
    ngx_int_t            rc;
    zend_file_handle     zfh;
    ngx_http_request_t  *r;

    r = SG(server_context);

    rc = NGX_OK;

    zend_first_try {

        if (file != NULL) {

            zfh.type = ZEND_HANDLE_FILENAME;
            zfh.filename = file;
            zfh.free_filename = 0;
            zfh.opened_path = NULL;

            if (php_execute_script(&zfh TSRMLS_CC) == FAILURE) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "php_execute_script() failed");
                rc = NGX_ERROR;
            }

        } else {

            if (zend_eval_string(handler, &rv, handler TSRMLS_CC) == FAILURE) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "zend_eval_string() failed");
                rc = NGX_ERROR;

            } else {

                rc = rv.value.lval;

                zval_dtor(&rv);
            }
        }

    } zend_catch {

        zend_try {
        } zend_end_try();

    } zend_end_try();

    return rc;
}


#if 0

static void *
ngx_http_perl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules = NGX_CONF_UNSET_PTR;
    pmcf->requires = NGX_CONF_UNSET_PTR;

    return pmcf;
}


static char *
ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_perl_main_conf_t *pmcf = conf;

    if (pmcf->perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


#if (NGX_HAVE_PERL_MULTIPLICITY)

static void
ngx_http_perl_cleanup_perl(void *data)
{
    PerlInterpreter  *perl = data;

    PERL_SET_CONTEXT(perl);

    (void) perl_destruct(perl);

    perl_free(perl);

    if (ngx_perl_term) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "perl term");

        PERL_SYS_TERM();
    }
}

#endif


static ngx_int_t
ngx_http_perl_preconfiguration(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSI)
    ngx_int_t                  rc;
    ngx_http_ssi_main_conf_t  *smcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);

    rc = ngx_hash_add_key(&smcf->commands, &ngx_http_perl_ssi_command.name,
                          &ngx_http_perl_ssi_command, NGX_HASH_READONLY_KEY);

    if (rc != NGX_OK) {
        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &ngx_http_perl_ssi_command.name);
        }

        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}

#endif


static void *
ngx_http_php_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_php_loc_conf_t *plcf;

    plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_php_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

    return plcf;
}


static char *
ngx_http_php_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_php_loc_conf_t *prev = parent;
    ngx_http_php_loc_conf_t *conf = child;

#if 0
    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_php(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_php_handler;

    return NGX_CONF_OK;
}


#if 0

static char *
ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   index;
    ngx_str_t                  *value;
    ngx_http_variable_t        *v;
    ngx_http_perl_variable_t   *pv;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    pv = ngx_palloc(cf->pool, sizeof(ngx_http_perl_variable_t));
    if (pv == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (pmcf->perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);

    ngx_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = ngx_http_perl_variable;
    v->data = (uintptr_t) pv;

    return NGX_CONF_OK;
}

#endif


static ngx_int_t
ngx_http_php_process_init(ngx_cycle_t *cycle)
{
    u_char  *conf_path, *p;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "ngx_http_php_process_init()");

    conf_path = ngx_palloc(cycle->pool, cycle->prefix.len + 1);
    if (conf_path == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(conf_path, cycle->prefix.data, cycle->prefix.len);
    *p = '\0';

    ngx_http_php_sapi.php_ini_path_override = conf_path;

    tsrm_startup(1, 1, 0, NULL);
    sapi_startup(&ngx_http_php_sapi);

    if (ngx_http_php_sapi.startup(&ngx_http_php_sapi) != SUCCESS) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "ngx_http_php_sapi.startup() failed");
        sapi_shutdown();
        tsrm_shutdown();
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_php_process_exit(ngx_cycle_t *cycle)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "ngx_http_php_process_exit()");

    ngx_http_php_sapi.shutdown(&ngx_http_php_sapi);

    sapi_shutdown();
    tsrm_shutdown();
}
