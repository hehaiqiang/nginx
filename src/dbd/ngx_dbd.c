
/*
 * Copyright (C) Seegle
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd_core_module.h>


static ngx_int_t ngx_dbd_process_init(ngx_cycle_t *cycle);
static void ngx_dbd_process_exit(ngx_cycle_t *cycle);

static char *ngx_dbd_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_dbd_commands[] = {

    { ngx_string("dbd_v2"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_dbd_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_dbd_module_ctx = {
    ngx_string("dbd_v2"),
    NULL,
    NULL
};


ngx_module_t  ngx_dbd_module = {
    NGX_MODULE_V1,
    &ngx_dbd_module_ctx,                   /* module context */
    ngx_dbd_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_dbd_process_init,                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_dbd_process_exit,                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_uint_t  ngx_dbd_max_module;


#if (NGX_DBD_DRIZZLE)
extern ngx_dbd_driver_t   ngx_dbd_drizzle_driver;
#endif


static ngx_dbd_driver_t  *ngx_dbd_drivers[] = {
#if (NGX_DBD_DRIZZLE)
    &ngx_dbd_drizzle_driver,
#endif
    NULL
};


ngx_dbd_driver_t *
ngx_dbd_get_driver(ngx_str_t *name)
{
    ngx_str_t         *drv_name;
    ngx_uint_t         i;
    ngx_dbd_driver_t  *drv;

    for (i = 0; ngx_dbd_drivers[i] != NULL; i++) {
        drv = ngx_dbd_drivers[i];
        drv_name = ngx_dbd_driver_name(drv);

        if (name->len == drv_name->len
            && ngx_strncmp(name->data, drv_name->data, drv_name->len) == 0)
        {
            return drv;
        }
    }

    return NULL;
}


static ngx_dbd_core_cmd_conf_t *
ngx_dbd_get_core_cmd_conf(ngx_str_t *name)
{
    ngx_uint_t                 key;
    ngx_dbd_conf_ctx_t        *ctx;
    ngx_dbd_core_cmd_conf_t   *cccf;
    ngx_dbd_core_main_conf_t  *cmcf;

    ctx = (ngx_dbd_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                              ngx_dbd_module);

    if (ctx == NULL || ctx->main_conf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "dbd_v2 configuration can't be found");
        return NULL;
    }

    cmcf = ngx_dbd_cycle_get_module_main_conf(ngx_cycle, ngx_dbd_core_module);


    key = ngx_hash_key_lc(name->data, name->len);

    cccf = ngx_hash_find(&cmcf->commands_hash, key, name->data, name->len);
    if (cccf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "dbd_v2 command \"%V\" can't be found", name);
        return NULL;
    }

    return cccf;
}


static ngx_dbd_connection_t *
ngx_dbd_get_connection(ngx_dbd_core_ups_conf_t *cucf)
{
    ngx_uint_t                  i, n, nn;
    ngx_dbd_connection_t       *c;
    ngx_dbd_core_server_t      *cs, **csp;
    ngx_dbd_connection_pool_t  *conn_pool;

    csp = cucf->servers.elts;

    cs = csp[0];
    conn_pool = &cs->conn_pool;
    n = conn_pool->connection_n - conn_pool->free_connection_n;

    for (i = 1; i < cucf->servers.nelts; i++) {
        nn = csp[i]->conn_pool.connection_n
             - csp[i]->conn_pool.free_connection_n;

        if (n <= nn) {
            continue;
        }

        cs = csp[i];
        conn_pool = &cs->conn_pool;
        n = nn;
    }


    c = conn_pool->free_connections;

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "dbd connection pool is full");
        return NULL;
    }

    conn_pool->free_connections = c->data;
    conn_pool->free_connection_n--;

    if (c->pool == NULL) {
        c->pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    if (c->drv == NULL) {
        c->drv = ngx_dbd_get_driver(&cs->driver);
    }

    if (c->dbd == NULL) {
        c->dbd = ngx_dbd_create(c->drv, c->pool, ngx_cycle->log);
        if (c->dbd == NULL) {
            goto failed;
        }

        ngx_dbd_set_options(c->drv, c->dbd, NGX_DBD_OPTION_NON_BLOCKING);
    }

    if (c->conn == NULL) {
        c->conn = ngx_dbd_conn_create(c->drv, c->dbd);
        if (c->conn == NULL) {
            goto failed;
        }

        ngx_dbd_conn_set_tcp(c->drv, c->conn, cs->host, cs->port);
        ngx_dbd_conn_set_auth(c->drv, c->conn, cs->user, cs->passwd);
        ngx_dbd_conn_set_db(c->drv, c->conn, cs->db);
    }

    c->data = NULL;

    return c;

failed:

    ngx_dbd_free_connection(c);

    return NULL;
}


ngx_dbd_connection_t *
ngx_dbd_get_connection_by_upstream(ngx_str_t *name)
{
    ngx_uint_t                 i;
    ngx_dbd_conf_ctx_t        *ctx;
    ngx_dbd_connection_t      *c;
    ngx_dbd_core_ups_conf_t   *cucf, **cucfp;
    ngx_dbd_core_main_conf_t  *cmcf;

    ctx = (ngx_dbd_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                              ngx_dbd_module);

    if (ctx == NULL || ctx->main_conf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "dbd_v2 configuration can't be found");
        return NULL;
    }

    cmcf = ngx_dbd_cycle_get_module_main_conf(ngx_cycle, ngx_dbd_core_module);


    cucfp = cmcf->upstreams.elts;
    cucf = NULL;

    for (i = 0; i < cmcf->upstreams.nelts; i++) {

        if (cucfp[i]->name.len == name->len
            && ngx_strncmp(cucfp[i]->name.data, name->data, name->len) == 0)
        {
            cucf = cucfp[i];
            break;
        }
    }

    if (cucf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "upstream \"%V\" can't be found", name);
        return NULL;
    }

    c = ngx_dbd_get_connection(cucf);
    if (c == NULL) {
        return NULL;
    }

    c->sql = NULL;

    return c;
}


ngx_dbd_connection_t *
ngx_dbd_get_connection_by_command(ngx_str_t *name)
{
    ngx_dbd_connection_t     *c;
    ngx_dbd_core_cmd_conf_t  *cccf;

    cccf = ngx_dbd_get_core_cmd_conf(name);
    if (cccf == NULL) {
        return NULL;
    }

    c = ngx_dbd_get_connection(cccf->upstream);
    if (c == NULL) {
        return NULL;
    }

    c->sql = &cccf->sql;

    return c;
}


void
ngx_dbd_free_connection(ngx_dbd_connection_t *c)
{
    ngx_dbd_connection_pool_t  *conn_pool;

    c->sql = NULL;

    /* TODO: xxx */

    ngx_dbd_conn_set_handler(c->drv, c->conn, NULL, NULL);

    conn_pool = c->conn_pool;

    c->data = conn_pool->free_connections;
    conn_pool->free_connections = c;
    conn_pool->free_connection_n++;
}


ngx_str_t *
ngx_dbd_get_command_sql(ngx_str_t *name)
{
    ngx_dbd_core_cmd_conf_t  *cccf;

    cccf = ngx_dbd_get_core_cmd_conf(name);
    if (cccf == NULL) {
        return NULL;
    }

    return &cccf->sql;
}


static ngx_int_t
ngx_dbd_process_init(ngx_cycle_t *cycle)
{
    ngx_int_t          rc;
    ngx_uint_t         i;
    ngx_dbd_driver_t  *drv;

    for (i = 0; ngx_dbd_drivers[i] != NULL; i++) {
        drv = ngx_dbd_drivers[i];

        if (drv->init) {
            rc = drv->init(cycle);
            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

    return NGX_OK;
}


static void
ngx_dbd_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i, s, c;
    ngx_dbd_driver_t            *drv;
    ngx_dbd_conf_ctx_t          *ctx;
    ngx_dbd_connection_t        *conn;
    ngx_dbd_core_server_t      **csp;
    ngx_dbd_core_ups_conf_t    **cucfp;
    ngx_dbd_core_main_conf_t    *cmcf;
    ngx_dbd_connection_pool_t   *conn_pool;

    ctx = (ngx_dbd_conf_ctx_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                              ngx_dbd_module);

    if (ctx == NULL || ctx->main_conf == NULL) {
        return;
    }

    /* close all database connections */

    cmcf = ngx_dbd_cycle_get_module_main_conf(ngx_cycle, ngx_dbd_core_module);

    cucfp = cmcf->upstreams.elts;

    for (i = 0; i < cmcf->upstreams.nelts; i++) {

        csp = cucfp[i]->servers.elts;

        for (s = 0; s < cucfp[i]->servers.nelts; s++) {

            conn_pool = &csp[s]->conn_pool;

            for (c = 0; c < conn_pool->connection_n; c++) {
                conn = &conn_pool->connections[c];

                if (conn->conn != NULL) {
                    ngx_dbd_conn_close(conn->drv, conn->conn);
                    ngx_dbd_conn_destroy(conn->drv, conn->conn);
                }

                if (conn->dbd != NULL) {
                    ngx_dbd_destroy(conn->drv, conn->dbd);
                }

                if (conn->pool != NULL) {
                    ngx_destroy_pool(conn->pool);
                }
            }
        }
    }

    /* clean up all database driver */

    for (i = 0; ngx_dbd_drivers[i] != NULL; i++) {
        drv = ngx_dbd_drivers[i];

        if (drv->done) {
            drv->done(cycle);
        }
    }
}


static char *
ngx_dbd_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_int_t                    rc;
    ngx_uint_t                   mi, m, i, s, c;
    ngx_conf_t                   pcf;
    ngx_hash_init_t              hash;
    ngx_dbd_module_t            *module;
    ngx_dbd_conf_ctx_t          *ctx;
    ngx_dbd_connection_t        *conn, *next;
    ngx_dbd_core_server_t      **csp;
    ngx_dbd_core_cmd_conf_t    **cccfp;
    ngx_dbd_core_ups_conf_t    **cucfp;
    ngx_dbd_core_main_conf_t    *cmcf;
    ngx_dbd_connection_pool_t   *conn_pool;

    /* the main dbd_v2 context */

    ctx = ngx_palloc(cf->pool, sizeof(ngx_dbd_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_dbd_conf_ctx_t **) conf = ctx;


    /* count the number of the dbd_v2 modules and set up their indices */

    ngx_dbd_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_dbd_max_module++;
    }


    /*
     * the dbd_v2 main_conf context,
     * it is the same in the all dbd_v2 contexts.
     */

    ctx->main_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_dbd_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * the dbd_v2 null ups_conf context,
     * it is used to merge the upstream{}'s ups_conf's.
     */

    ctx->ups_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_dbd_max_module);
    if (ctx->ups_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * the dbd_v2 null cmd_conf context,
     * it is used to merge the command{}'s cmd_conf's.
     */

    ctx->cmd_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_dbd_max_module);
    if (ctx->cmd_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null ups_conf's,
     * and the null cmd_conf's of the all dbd_v2 modules.
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_MODULE) {
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

        if (module->create_ups_conf) {
            ctx->ups_conf[mi] = module->create_ups_conf(cf);
            if (ctx->ups_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_cmd_conf) {
            ctx->cmd_conf[mi] = module->create_cmd_conf(cf);
            if (ctx->cmd_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the dbd_v2{} block */

    pcf = *cf;

    cf->ctx = ctx;
    cf->module_type = NGX_DBD_MODULE;
    cf->cmd_type = NGX_DBD_MAIN_CONF;

    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        goto failed;
    }


    /*
     * init dbd_v2{} main_conf's, merge the upstream{}s' ups_conf's
     * and the command{}s' cmd_conf's.
     */

    cmcf = ctx->main_conf[ngx_dbd_core_module.ctx_index];
    cucfp = cmcf->upstreams.elts;
    cccfp = cmcf->commands.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_DBD_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;


        /* init dbd_v2{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        /* merge the upstream{}'s ups_conf's */

        for (i = 0; i < cmcf->upstreams.nelts; i++) {

            if (module->merge_ups_conf) {
                rv = module->merge_ups_conf(cf, ctx->ups_conf[mi],
                                            cucfp[i]->ctx->ups_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }
        }

        /* merge the command{}'s cmd_conf */

        for (i = 0; i < cmcf->commands.nelts; i++) {

            if (module->merge_cmd_conf) {
                rv = module->merge_cmd_conf(cf, ctx->cmd_conf[mi],
                                            cccfp[i]->ctx->cmd_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }
        }
    }

    *cf = pcf;


    /* create dbd connection pool for all database server */

    for (i = 0; i < cmcf->upstreams.nelts; i++) {

        csp = cucfp[i]->servers.elts;

        for (s = 0; s < cucfp[i]->servers.nelts; s++) {

            conn_pool = &csp[s]->conn_pool;

            conn_pool->connections = ngx_pcalloc(cf->pool,
                               sizeof(ngx_dbd_connection_t) * csp[s]->max_conn);
            if (conn_pool->connections == NULL) {
                return NGX_CONF_ERROR;
            }

            conn_pool->connection_n = csp[s]->max_conn;


            c = csp[s]->max_conn;;
            next = NULL;

            do {
                c--;

                conn = &conn_pool->connections[c];
                conn->data = next;
                conn->conn_pool = conn_pool;

                next = conn;

            } while (c > 0);

            conn_pool->free_connections = next;
            conn_pool->free_connection_n = csp[s]->max_conn;
        }
    }


    /* init commands hash */

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

    for (i = 0; i < cmcf->commands.nelts; i++) {

        rc = ngx_hash_add_key(cmcf->commands_keys,
                              &cccfp[i]->name, cccfp[i], 0);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting command \"%V\"", &cccfp[i]->name);
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


    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}
