
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd_core_module.h>


static void *ngx_dbd_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_dbd_core_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_dbd_core_create_ups_conf(ngx_conf_t *cf);
static char *ngx_dbd_core_merge_ups_conf(ngx_conf_t *cf,
    void *parent, void *child);

static void *ngx_dbd_core_create_cmd_conf(ngx_conf_t *cf);
static char *ngx_dbd_core_merge_cmd_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_dbd_core_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_dbd_core_command(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);

static char *ngx_dbd_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_dbd_core_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_dbd_core_commands[] = {

    { ngx_string("upstream"),
      NGX_DBD_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_dbd_core_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_DBD_UPS_CONF|NGX_CONF_1MORE,
      ngx_dbd_core_server,
      NGX_DBD_UPS_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("command"),
      NGX_DBD_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_dbd_core_command,
      0,
      0,
      NULL },

    { ngx_string("sql"),
      NGX_DBD_CMD_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_DBD_CMD_CONF_OFFSET,
      offsetof(ngx_dbd_core_cmd_conf_t, sql),
      NULL },

    { ngx_string("pass"),
      NGX_DBD_CMD_CONF|NGX_CONF_TAKE1,
      ngx_dbd_core_pass,
      NGX_DBD_CMD_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_dbd_module_t  ngx_dbd_core_module_ctx = {
    ngx_dbd_core_create_main_conf,         /* create main configuration */
    ngx_dbd_core_init_main_conf,           /* init main configuration */

    ngx_dbd_core_create_ups_conf,          /* create upstream configuration */
    ngx_dbd_core_merge_ups_conf,           /* merge upstream configuration */

    ngx_dbd_core_create_cmd_conf,          /* create command configuration */
    ngx_dbd_core_merge_cmd_conf            /* merge command configuration */
};


ngx_module_t  ngx_dbd_core_module = {
    NGX_MODULE_V1,
    &ngx_dbd_core_module_ctx,              /* module context */
    ngx_dbd_core_commands,                 /* module directives */
    NGX_DBD_MODULE,                        /* module type */
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
ngx_dbd_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_dbd_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_core_main_conf_t));
    if (cmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cmcf->commands_hash = { 0 };
     *     cmcf->commands_keys = NULL;
     */

    if (ngx_array_init(&cmcf->upstreams, cf->pool, 8,
                       sizeof(ngx_dbd_core_ups_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cmcf->commands, cf->pool, 32,
                       sizeof(ngx_dbd_core_cmd_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->commands_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->commands_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_dbd_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_dbd_core_main_conf_t *cmcf = conf;

    if (cmcf->commands_hash_max_size == NGX_CONF_UNSET_UINT) {
        cmcf->commands_hash_max_size = 512;
    }

    if (cmcf->commands_hash_bucket_size == NGX_CONF_UNSET_UINT) {
        cmcf->commands_hash_bucket_size = 64;
    }

    cmcf->commands_hash_bucket_size =
        ngx_align(cmcf->commands_hash_bucket_size, ngx_cacheline_size);

    return NGX_CONF_OK;
}


static void *
ngx_dbd_core_create_ups_conf(ngx_conf_t *cf)
{
    ngx_dbd_core_ups_conf_t  *cucf;

    cucf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_core_ups_conf_t));
    if (cucf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cucf->name = { 0 };
     *     cucf->ctx = NULL;
     */

    if (ngx_array_init(&cucf->servers, cf->pool, 4,
                       sizeof(ngx_dbd_core_server_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return cucf;
}


static char *
ngx_dbd_core_merge_ups_conf(ngx_conf_t *cf, void *parent, void *child)
{
#if 0
    ngx_dbd_core_ups_conf_t *prev = parent;
    ngx_dbd_core_ups_conf_t *conf = child;
#endif

    /* TODO: xxx */

    return NGX_CONF_OK;
}


static void *
ngx_dbd_core_create_cmd_conf(ngx_conf_t *cf)
{
    ngx_dbd_core_cmd_conf_t  *cccf;

    cccf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_core_cmd_conf_t));
    if (cccf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cccf->name = { 0 };
     *     cccf->upstream = NULL;
     *     cccf->sql = { 0 };
     *     cccf->ctx = NULL;
     */

    return cccf;
}


static char *
ngx_dbd_core_merge_cmd_conf(ngx_conf_t *cf, void *parent, void *child)
{
#if 0
    ngx_dbd_core_cmd_conf_t *prev = parent;
    ngx_dbd_core_cmd_conf_t *conf = child;
#endif

    /* TODO: xxx */

    return NGX_CONF_OK;
}


static char *
ngx_dbd_core_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    ngx_str_t                 *value;
    ngx_uint_t                 m, mi;
    ngx_conf_t                 pcf;
    ngx_dbd_module_t          *module;
    ngx_dbd_conf_ctx_t        *ctx, *dbd_ctx;
    ngx_dbd_core_ups_conf_t   *cucf, **cucfp;
    ngx_dbd_core_main_conf_t  *cmcf;

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    dbd_ctx = cf->ctx;

    ctx->main_conf = dbd_ctx->main_conf;

    /* the upstream{}'s ups_conf */

    ctx->ups_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_dbd_max_module);
    if (ctx->ups_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_ups_conf) {
            ctx->ups_conf[mi] = module->create_ups_conf(cf);
            if (ctx->ups_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* the upstream configuration context */

    value = cf->args->elts;

    cucf = ctx->ups_conf[ngx_dbd_core_module.ctx_index];
    cucf->ctx = ctx;
    cucf->name = value[1];

    cmcf = ctx->main_conf[ngx_dbd_core_module.ctx_index];

    /* TODO: duplicated name ??? */

    cucfp = ngx_array_push(&cmcf->upstreams);
    if (cucfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cucfp = cucf;


    /* parse inside upstream{} */

    pcf = *cf;

    cf->ctx = ctx;
    cf->cmd_type = NGX_DBD_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_dbd_core_command(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    ngx_str_t                 *value;
    ngx_uint_t                 m, mi;
    ngx_conf_t                 pcf;
    ngx_dbd_module_t          *module;
    ngx_dbd_conf_ctx_t        *ctx, *dbd_ctx;
    ngx_dbd_core_cmd_conf_t   *cccf, **cccfp;
    ngx_dbd_core_main_conf_t  *cmcf;

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    dbd_ctx = cf->ctx;

    ctx->main_conf = dbd_ctx->main_conf;

    /* the command{}'s cmd_conf */

    ctx->cmd_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_dbd_max_module);
    if (ctx->cmd_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_cmd_conf) {
            ctx->cmd_conf[mi] = module->create_cmd_conf(cf);
            if (ctx->cmd_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* the command configuration context */

    value = cf->args->elts;

    cccf = ctx->cmd_conf[ngx_dbd_core_module.ctx_index];
    cccf->ctx = ctx;
    cccf->name = value[1];

    cmcf = ctx->main_conf[ngx_dbd_core_module.ctx_index];

    /* TODO: duplicated name ??? */

    cccfp = ngx_array_push(&cmcf->commands);
    if (cccfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cccfp = cccf;


    /* parse inside command{} */

    pcf = *cf;

    cf->ctx = ctx;
    cf->cmd_type = NGX_DBD_CMD_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_dbd_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_dbd_core_ups_conf_t *cucf = conf;

    ngx_str_t              *value;
    ngx_uint_t              i;
    ngx_dbd_core_server_t  *cs, **csp;

    cs = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_core_server_t));
    if (cs == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memcpy(cs->host, value[1].data, value[1].len);

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {

            cs->port = ngx_atoi(&value[i].data[5], value[i].len - 5);

            if (cs->port == (ngx_uint_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "user=", 5) == 0) {

            ngx_memcpy(cs->user, &value[i].data[5], value[i].len - 5);

            continue;
        }

        if (ngx_strncmp(value[i].data, "passwd=", 7) == 0) {

            ngx_memcpy(cs->passwd, &value[i].data[7], value[i].len - 7);

            continue;
        }

        if (ngx_strncmp(value[i].data, "db=", 3) == 0) {

            ngx_memcpy(cs->db, &value[i].data[3], value[i].len - 3);

            continue;
        }

        if (ngx_strncmp(value[i].data, "driver=", 7) == 0) {
            cs->driver.len = value[i].len - 7;
            cs->driver.data = &value[i].data[7];
            continue;
        }

        if (ngx_strncmp(value[i].data, "max_conn=", 9) == 0) {

            cs->max_conn = ngx_atoi(&value[i].data[9], value[i].len - 9);

            if (cs->max_conn == (ngx_uint_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        goto invalid;
    }

    /* TODO: xxx */

    csp = ngx_array_push(&cucf->servers);
    if (csp == NULL) {
        return NGX_CONF_ERROR;
    }

    *csp = cs;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_dbd_core_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_dbd_core_cmd_conf_t *cccf = conf;

    ngx_str_t                  *value, *name;
    ngx_uint_t                  i;
    ngx_dbd_core_ups_conf_t   **cucfp;
    ngx_dbd_core_main_conf_t   *cmcf;

    if (cccf->upstream != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cmcf = ngx_dbd_conf_get_module_main_conf(cf, ngx_dbd_core_module);

    cucfp = cmcf->upstreams.elts;

    for (i = 0; i < cmcf->upstreams.nelts; i++) {
        name = &cucfp[i]->name;

        if (name->len == value[1].len
            && ngx_strncmp(name->data, value[1].data, value[1].len) == 0)
        {
            cccf->upstream = cucfp[i];
            break;
        }
    }

    if (cccf->upstream == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "invalid upstream \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
