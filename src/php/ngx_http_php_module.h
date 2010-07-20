
/*
 * Copyright (C) Seegle
 */


#ifndef _NGX_HTTP_PHP_MODULE_H_INCLUDED_
#define _NGX_HTTP_PHP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


#if 1

#undef _WIN32_WINNT

#undef _USE_32BIT_TIME_T
#undef S_IWRITE

#define HAVE_SOCKLEN_T

#endif


#pragma warning(push)

#include <php.h>
#include <php_main.h>
#include <php_variables.h>
#include <sapi.h>
#include <ext/standard/info.h>


typedef struct {
    void                     *tsrm_ls;    /* php interpreter context */
    void                     *thr_tsrm_ls;

    ngx_str_t                 filename;
    ngx_uint_t                inited;

    ngx_chain_t              *in_buf;

    u_char                   *cookies;

    ngx_chain_t              *out;
    ngx_chain_t              *last;
    size_t                    size;

    ngx_uint_t                state;

    ngx_str_t                 redirect_uri;
    ngx_str_t                 redirect_args;

    ngx_uint_t                done;       /* unsigned  done:1; */

    ngx_array_t              *variables;  /* array of ngx_http_perl_var_t */

#if (NGX_HTTP_SSI)
    ngx_http_ssi_ctx_t       *ssi;
#endif
} ngx_http_php_ctx_t;


void ngx_http_php_handle_request(ngx_http_request_t *r);
void ngx_http_php_sleep_handler(ngx_http_request_t *r);


static ngx_inline u_char *
ngx_pstrdup_ex(ngx_pool_t *pool, ngx_str_t *src)
{
    u_char  *dst, *p;

    dst = ngx_pnalloc(pool, src->len + 1);
    if (dst == NULL) {
        return NULL;
    }

    p = ngx_cpymem(dst, src->data, src->len);
    *p = '\0';

    return dst;
}


extern ngx_module_t        ngx_http_php_module;

extern sapi_module_struct  ngx_http_php_sapi;
extern zend_module_entry   ngx_http_php_zend_dbd;


#endif /* _NGX_HTTP_PHP_MODULE_H_INCLUDED_ */
