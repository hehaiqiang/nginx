
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_udp.h>


static void *ngx_udp_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_udp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_udp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_udp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_udp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_udp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_udp_core_pool_size(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_handler_pt  ngx_udp_core_pool_size_p =
    ngx_udp_core_pool_size;


static ngx_command_t  ngx_udp_core_commands[] = {

    { ngx_string("server"),
      NGX_UDP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_udp_core_server,
      0,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_UDP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_udp_core_listen,
      NGX_UDP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("protocol"),
      NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_udp_core_protocol,
      NGX_UDP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_core_srv_conf_t, connection_pool_size),
      &ngx_udp_core_pool_size_p },

    { ngx_string("client_buffer_size"),
      NGX_UDP_MAIN_CONF|NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_core_srv_conf_t, client_buffer_size),
      NULL },

      ngx_null_command
};


static ngx_udp_module_t  ngx_udp_core_module_ctx = {
    NULL,                                  /* protocol */

    ngx_udp_core_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_udp_core_create_srv_conf,          /* create server configuration */
    ngx_udp_core_merge_srv_conf            /* merge server configuration */
};


ngx_module_t  ngx_udp_core_module = {
    NGX_MODULE_V1,
    &ngx_udp_core_module_ctx,              /* module context */
    ngx_udp_core_commands,                 /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_udp_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_udp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_udp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_udp_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_udp_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
ngx_udp_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_udp_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_udp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     */

    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->client_buffer_size = NGX_CONF_UNSET_SIZE;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
ngx_udp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_udp_core_srv_conf_t *prev = parent;
    ngx_udp_core_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, ngx_pagesize);
    ngx_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size, 1024);

    if (conf->protocol == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown udp protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_udp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                      *rv;
    void                      *mconf;
    ngx_uint_t                 m;
    ngx_conf_t                 pcf;
    ngx_udp_module_t          *module;
    ngx_udp_conf_ctx_t        *ctx, *udp_ctx;
    ngx_udp_core_srv_conf_t   *cscf, **cscfp;
    ngx_udp_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_udp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    udp_ctx = cf->ctx;
    ctx->main_conf = udp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_udp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_UDP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_udp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_udp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_UDP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_udp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                     len, off;
    in_port_t                  port;
    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_uint_t                 i;
    struct sockaddr           *sa;
    ngx_udp_listen_t          *ls;
    struct sockaddr_in        *sin;
    ngx_udp_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_udp_conf_get_module_main_conf(cf, ngx_udp_core_module);

    ls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = (struct sockaddr_in6 *) sa;
            port = sin6->sin6_port;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = (struct sockaddr_in *) sa;
            port = sin->sin_port;
            break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);

        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_udp_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 2;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");

            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_udp_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_udp_core_srv_conf_t  *cscf = conf;

    ngx_str_t         *value;
    ngx_uint_t         m;
    ngx_udp_module_t  *module;

    value = cf->args->elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_UDP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->protocol
            && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_udp_core_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);
        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
