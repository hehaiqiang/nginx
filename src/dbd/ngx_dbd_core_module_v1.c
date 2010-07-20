
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd_core_module_v1.h>


static void *ngx_dbd_v1_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_dbd_v1_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_dbd_v1_core_create_conn_conf(ngx_conf_t *cf);
static char *ngx_dbd_v1_core_merge_conn_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void *ngx_dbd_v1_core_create_cmd_conf(ngx_conf_t *cf);
static char *ngx_dbd_v1_core_merge_cmd_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void *ngx_dbd_v1_core_create_param_conf(ngx_conf_t *cf);
static char *ngx_dbd_v1_core_merge_param_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_dbd_v1_core_connection(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_dbd_v1_core_command(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_dbd_v1_core_parameter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);

static char *ngx_dbd_v1_core_driver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_dbd_v1_core_cmd_type[] = {
    { ngx_string("execute"), NGX_DBD_V1_CMD_TYPE_EXEC },
    { ngx_string("query"), NGX_DBD_V1_CMD_TYPE_QUERY },
    { ngx_null_string, 0, }
};


/* TODO: ngx_dbd_core_param_type */

static ngx_conf_enum_t  ngx_dbd_v1_core_param_type[] = {
    { ngx_string("tiny"), NGX_DBD_DATA_TYPE_TINY },
    { ngx_string("utiny"), NGX_DBD_DATA_TYPE_UTINY },
    { ngx_string("short"), NGX_DBD_DATA_TYPE_SHORT },
    { ngx_string("ushort"), NGX_DBD_DATA_TYPE_USHORT },
    { ngx_string("int"), NGX_DBD_DATA_TYPE_INT },
    { ngx_string("uint"), NGX_DBD_DATA_TYPE_UINT },
    { ngx_string("long"), NGX_DBD_DATA_TYPE_LONG },
    { ngx_string("ulong"), NGX_DBD_DATA_TYPE_ULONG },
    { ngx_string("longlong"), NGX_DBD_DATA_TYPE_LONGLONG },
    { ngx_string("ulonglong"), NGX_DBD_DATA_TYPE_ULONGLONG },
    { ngx_string("float"), NGX_DBD_DATA_TYPE_FLOAT },
    { ngx_string("double"), NGX_DBD_DATA_TYPE_DOUBLE },
    { ngx_string("string"), NGX_DBD_DATA_TYPE_STRING },
    { ngx_string("text"), NGX_DBD_DATA_TYPE_TEXT },
    { ngx_string("time"), NGX_DBD_DATA_TYPE_TIME },
    { ngx_string("date"), NGX_DBD_DATA_TYPE_DATE },
    { ngx_string("datetime"), NGX_DBD_DATA_TYPE_DATETIME },
    { ngx_string("timestamp"), NGX_DBD_DATA_TYPE_TIMESTAMP },
    { ngx_string("ztimestamp"), NGX_DBD_DATA_TYPE_ZTIMESTAMP },
    { ngx_string("blob"), NGX_DBD_DATA_TYPE_BLOB },
    { ngx_string("clob"), NGX_DBD_DATA_TYPE_CLOB },
    { ngx_string("null"), NGX_DBD_DATA_TYPE_NULL },
    { ngx_null_string, 0, }
};


static ngx_conf_enum_t  ngx_dbd_v1_core_param_direction[] = {
    { ngx_string("in"), NGX_DBD_V1_PARAM_DIRECTION_IN },
    { ngx_string("out"), NGX_DBD_V1_PARAM_DIRECTION_OUT },
    { ngx_string("inout"), NGX_DBD_V1_PARAM_DIRECTION_IN_OUT },
    { ngx_string("return"), NGX_DBD_V1_PARAM_DIRECTION_RETURN },
    { ngx_null_string, 0, }
};


static ngx_command_t  ngx_dbd_v1_core_commands[] = {

    { ngx_string("commands_hash_max_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_MAIN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_main_conf_t, commands_hash_max_size),
      NULL },

    { ngx_string("commands_hash_bucket_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_MAIN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_main_conf_t, commands_hash_bucket_size),
      NULL },

    { ngx_string("connections_hash_max_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_MAIN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_main_conf_t, connections_hash_max_size),
      NULL },

    { ngx_string("connections_hash_bucket_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_MAIN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_main_conf_t, connections_hash_bucket_size),
      NULL },

    { ngx_string("connection"),
      NGX_DBD_V1_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS,
      ngx_dbd_v1_core_connection,
      0,
      0,
      NULL },

    { ngx_string("driver"),
      NGX_DBD_V1_MAIN_CONF|NGX_DBD_V1_CONN_CONF|NGX_CONF_TAKE1,
      ngx_dbd_v1_core_driver,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("conn_string"),
      NGX_DBD_V1_CONN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_conn_conf_t, conn_string),
      NULL },

    { ngx_string("conn_pool_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_DBD_V1_CONN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_conn_conf_t, conn_pool_size),
      NULL },

    { ngx_string("preps_hash_max_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_DBD_V1_CONN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_conn_conf_t, preps_hash_max_size),
      NULL },

    { ngx_string("preps_hash_bucket_size"),
      NGX_DBD_V1_MAIN_CONF|NGX_DBD_V1_CONN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_conn_conf_t, preps_hash_bucket_size),
      NULL },

    { ngx_string("command"),
      NGX_DBD_V1_CONN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_dbd_v1_core_command,
      NGX_DBD_V1_CONN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cmd_id"),
      NGX_DBD_V1_CMD_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_DBD_V1_CMD_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_cmd_conf_t, cmd_id),
      NULL },

    { ngx_string("cmd_type"),
      NGX_DBD_V1_CONN_CONF|NGX_DBD_V1_CMD_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_DBD_V1_CMD_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_cmd_conf_t, cmd_type),
      ngx_dbd_v1_core_cmd_type },

    { ngx_string("cmd_text"),
      NGX_DBD_V1_CMD_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_DBD_V1_CMD_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_cmd_conf_t, cmd_text),
      NULL },

    { ngx_string("parameter"),
      NGX_DBD_V1_CMD_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_dbd_v1_core_parameter,
      NGX_DBD_V1_CMD_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("param_name"),
      NGX_DBD_V1_PARAM_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_DBD_V1_PARAM_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_param_conf_t, name),
      NULL },

    { ngx_string("param_type"),
      NGX_DBD_V1_CMD_CONF|NGX_DBD_V1_PARAM_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_DBD_V1_PARAM_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_param_conf_t, type),
      ngx_dbd_v1_core_param_type },

    { ngx_string("param_size"),
      NGX_DBD_V1_PARAM_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_DBD_V1_PARAM_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_param_conf_t, size),
      NULL },

    { ngx_string("param_direction"),
      NGX_DBD_V1_CMD_CONF|NGX_DBD_V1_PARAM_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_DBD_V1_PARAM_CONF_OFFSET,
      offsetof(ngx_dbd_v1_core_param_conf_t, direction),
      ngx_dbd_v1_core_param_direction },

      ngx_null_command
};


static ngx_dbd_v1_module_t  ngx_dbd_v1_core_module_ctx = {
    ngx_dbd_v1_core_create_main_conf,      /* create main configuration */
    ngx_dbd_v1_core_init_main_conf,        /* init main configuration */

    ngx_dbd_v1_core_create_conn_conf,      /* create connection configuration */
    ngx_dbd_v1_core_merge_conn_conf,       /* merge connection configuration */

    ngx_dbd_v1_core_create_cmd_conf,       /* create command configuration */
    ngx_dbd_v1_core_merge_cmd_conf,        /* merge command configuration */

    ngx_dbd_v1_core_create_param_conf,     /* create parameter configuration */
    ngx_dbd_v1_core_merge_param_conf,      /* merge parameter configuration */
};


ngx_module_t  ngx_dbd_v1_core_module = {
    NGX_MODULE_V1,
    &ngx_dbd_v1_core_module_ctx,           /* module context */
    ngx_dbd_v1_core_commands,              /* module directives */
    NGX_DBD_V1_MODULE,                     /* module type */
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
ngx_dbd_v1_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_dbd_v1_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_v1_core_main_conf_t));
    if (cmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cmcf->commands_hash = { 0 };
     *     cmcf->commands_keys = NULL;
     *     cmcf->connections_hash = { 0 };
     *     cmcf->connections_keys = NULL;
     */

    if (ngx_array_init(&cmcf->connections, cf->pool, 4,
                       sizeof(ngx_dbd_v1_core_conn_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->commands_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->commands_hash_bucket_size = NGX_CONF_UNSET_UINT;
    cmcf->connections_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->connections_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_dbd_v1_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_dbd_v1_core_main_conf_t *cmcf = conf;

    if (cmcf->commands_hash_max_size == NGX_CONF_UNSET_UINT) {
        cmcf->commands_hash_max_size = 512;
    }

    if (cmcf->commands_hash_bucket_size == NGX_CONF_UNSET_UINT) {
        cmcf->commands_hash_bucket_size = 64;
    }

    cmcf->commands_hash_bucket_size =
        ngx_align(cmcf->commands_hash_bucket_size, ngx_cacheline_size);

    if (cmcf->connections_hash_max_size == NGX_CONF_UNSET_UINT) {
        cmcf->connections_hash_max_size = 512;
    }

    if (cmcf->connections_hash_bucket_size == NGX_CONF_UNSET_UINT) {
        cmcf->connections_hash_bucket_size = 64;
    }

    cmcf->connections_hash_bucket_size =
        ngx_align(cmcf->connections_hash_bucket_size, ngx_cacheline_size);

    return NGX_CONF_OK;
}


static void *
ngx_dbd_v1_core_create_conn_conf(ngx_conf_t *cf)
{
    ngx_dbd_v1_core_conn_conf_t  *cccf;

    cccf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_v1_core_conn_conf_t));
    if (cccf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cccf->conn_string = { 0 };
     *     cccf->ctx = NULL;
     */

    if (ngx_array_init(&cccf->commands, cf->pool, 4,
                       sizeof(ngx_dbd_v1_core_cmd_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cccf->driver = NGX_CONF_UNSET_PTR;
    cccf->conn_pool_size = NGX_CONF_UNSET_SIZE;
    cccf->preps_hash_max_size = NGX_CONF_UNSET_UINT;
    cccf->preps_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cccf;
}


static char *
ngx_dbd_v1_core_merge_conn_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_dbd_v1_core_conn_conf_t *prev = parent;
    ngx_dbd_v1_core_conn_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->driver, prev->driver, NULL);

    if (conf->driver == NULL) {
        /* TODO */
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->conn_pool_size,
                              prev->conn_pool_size, 64);
    ngx_conf_merge_uint_value(conf->preps_hash_max_size,
                              prev->preps_hash_max_size, 512);
    ngx_conf_merge_uint_value(conf->preps_hash_bucket_size,
                              prev->preps_hash_bucket_size, 64);

    conf->preps_hash_bucket_size =
        ngx_align(conf->preps_hash_bucket_size, ngx_cacheline_size);

    /* TODO: conf->conn_string */

    return NGX_CONF_OK;
}


static void *
ngx_dbd_v1_core_create_cmd_conf(ngx_conf_t *cf)
{
    ngx_dbd_v1_core_cmd_conf_t  *cccf;

    cccf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_v1_core_cmd_conf_t));
    if (cccf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cccf->conn = NULL;
     *     cccf->cmd_id = { 0 };
     *     cccf->cmd_text = { 0 };
     *     cccf->ctx = NULL;
     */

    if (ngx_array_init(&cccf->parameters, cf->pool, 4,
                       sizeof(ngx_dbd_v1_core_param_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cccf->cmd_type = NGX_CONF_UNSET_UINT;

    return cccf;
}


static char *
ngx_dbd_v1_core_merge_cmd_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_dbd_v1_core_cmd_conf_t *prev = parent;
    ngx_dbd_v1_core_cmd_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->cmd_type, prev->cmd_type,
                              NGX_DBD_V1_CMD_TYPE_QUERY);

    /* TODO: conf->cmd_id */
    /* TODO: conf->cmd_text */

    return NGX_CONF_OK;
}


static void *
ngx_dbd_v1_core_create_param_conf(ngx_conf_t *cf)
{
    ngx_dbd_v1_core_param_conf_t  *cpcf;

    cpcf = ngx_pcalloc(cf->pool, sizeof(ngx_dbd_v1_core_param_conf_t));
    if (cpcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cpcf->name = { 0 };
     *     cpcf->ctx = NULL;
     */

    cpcf->type = NGX_CONF_UNSET_UINT;
    cpcf->direction = NGX_CONF_UNSET_UINT;
    cpcf->size = NGX_CONF_UNSET_SIZE;

    return cpcf;
}


static char *
ngx_dbd_v1_core_merge_param_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_dbd_v1_core_param_conf_t *prev = parent;
    ngx_dbd_v1_core_param_conf_t *conf = child;

    /* TODO: conf->name */

    ngx_conf_merge_uint_value(conf->type, prev->type,
                              NGX_DBD_DATA_TYPE_INT);
    ngx_conf_merge_uint_value(conf->direction, prev->direction,
                              NGX_DBD_V1_PARAM_DIRECTION_IN);
    ngx_conf_merge_size_value(conf->size, prev->size, 4);

    return NGX_CONF_OK;
}


static char *
ngx_dbd_v1_core_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                         *rv;
    ngx_uint_t                    m, mi;
    ngx_conf_t                    pcf;
    ngx_dbd_v1_module_t          *module;
    ngx_dbd_v1_conf_ctx_t        *ctx, *dbd_ctx;
    ngx_dbd_v1_core_conn_conf_t  *cccf, **cccfp;
    ngx_dbd_v1_core_main_conf_t  *cmcf;

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_v1_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    dbd_ctx = cf->ctx;

    ctx->main_conf = dbd_ctx->main_conf;

    /* the connection{}'s conn_conf */

    ctx->conn_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->conn_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the connection{}'s cmd_conf */

    ctx->cmd_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->cmd_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the connection{}'s param_conf */

    ctx->param_conf = ngx_pcalloc(cf->pool,
                                  sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->param_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

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


    /* the connection configuration context */

    cccf = ctx->conn_conf[ngx_dbd_v1_core_module.ctx_index];
    cccf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_dbd_v1_core_module.ctx_index];

    cccfp = ngx_array_push(&cmcf->connections);
    if (cccfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cccfp = cccf;


    /* parse inside connection{} */

    pcf = *cf;

    cf->ctx = ctx;
    cf->cmd_type = NGX_DBD_V1_CONN_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_dbd_v1_core_command(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                         *rv;
    ngx_uint_t                    m, mi;
    ngx_conf_t                    pcf;
    ngx_dbd_v1_module_t          *module;
    ngx_dbd_v1_conf_ctx_t        *ctx, *dbd_ctx;
    ngx_dbd_v1_core_cmd_conf_t   *cdcf, **cdcfp;
    ngx_dbd_v1_core_conn_conf_t  *cccf;

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_v1_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    dbd_ctx = cf->ctx;

    ctx->main_conf = dbd_ctx->main_conf;
    ctx->conn_conf = dbd_ctx->conn_conf;

    /* the command{}'s cmd_conf */

    ctx->cmd_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->cmd_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the command{}'s param_conf */

    ctx->param_conf = ngx_pcalloc(cf->pool,
                                  sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->param_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
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

        if (module->create_param_conf) {
            ctx->param_conf[mi] = module->create_param_conf(cf);
            if (ctx->param_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* the command configuration context */

    cccf = ctx->conn_conf[ngx_dbd_v1_core_module.ctx_index];

    cdcf = ctx->cmd_conf[ngx_dbd_v1_core_module.ctx_index];
    cdcf->ctx = ctx;
    cdcf->conn = cccf;

    cdcfp = ngx_array_push(&cccf->commands);
    if (cdcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cdcfp = cdcf;


    /* parse inside command{} */

    pcf = *cf;

    cf->ctx = ctx;
    cf->cmd_type = NGX_DBD_V1_CMD_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_dbd_v1_core_parameter(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                          *rv;
    ngx_uint_t                     m, mi;
    ngx_conf_t                     pcf;
    ngx_dbd_v1_module_t           *module;
    ngx_dbd_v1_conf_ctx_t         *ctx, *dbd_ctx;
    ngx_dbd_v1_core_cmd_conf_t    *cdcf;
    ngx_dbd_v1_core_param_conf_t  *cpcf, **cpcfp;

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_v1_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    dbd_ctx = cf->ctx;

    ctx->main_conf = dbd_ctx->main_conf;
    ctx->conn_conf = dbd_ctx->conn_conf;
    ctx->cmd_conf = dbd_ctx->cmd_conf;

    /* the parameter{}'s param_conf */

    ctx->param_conf = ngx_pcalloc(cf->pool,
                                  sizeof(void *) * ngx_dbd_v1_max_module);
    if (ctx->param_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_V1_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_param_conf) {
            ctx->param_conf[mi] = module->create_param_conf(cf);
            if (ctx->param_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* the parameter configuration context */

    cpcf = ctx->param_conf[ngx_dbd_v1_core_module.ctx_index];
    cpcf->ctx = ctx;

    cdcf = ctx->cmd_conf[ngx_dbd_v1_core_module.ctx_index];

    cpcfp = ngx_array_push(&cdcf->parameters);
    if (cpcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cpcfp = cpcf;


    /* parse inside parameter{} */

    pcf = *cf;

    cf->ctx = ctx;
    cf->cmd_type = NGX_DBD_V1_PARAM_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_dbd_v1_core_driver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_dbd_v1_core_conn_conf_t *cccf = conf;

    ngx_str_t  *value;

    if (cccf->driver != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cccf->driver = ngx_dbd_get_driver(&value[1]);

    if (cccf->driver == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "invalid driver \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
