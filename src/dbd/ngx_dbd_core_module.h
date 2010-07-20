
/*
 * Copyright (C) Seegle
 */


#ifndef _NGX_DBD_CORE_MODULE_H_INCLUDED_
#define _NGX_DBD_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd.h>


typedef struct {
    void                        **main_conf;
    void                        **ups_conf;
    void                        **cmd_conf;
} ngx_dbd_conf_ctx_t;


typedef struct {
    ngx_array_t                   upstreams;  /* ngx_dbd_core_ups_conf_t */

    ngx_array_t                   commands;   /* ngx_dbd_core_cmd_conf_t */

    ngx_hash_t                    commands_hash;
    ngx_hash_keys_arrays_t       *commands_keys;

    ngx_uint_t                    commands_hash_max_size;
    ngx_uint_t                    commands_hash_bucket_size;
} ngx_dbd_core_main_conf_t;


typedef struct {
    ngx_str_t                     driver;
    ngx_uint_t                    max_conn;
    u_char                        host[32];
    ngx_uint_t                    port;
    u_char                        user[32];
    u_char                        passwd[32];
    u_char                        db[32];

    ngx_dbd_connection_pool_t     conn_pool;
} ngx_dbd_core_server_t;


typedef struct {
    ngx_str_t                     name;

    ngx_array_t                   servers;  /* ngx_dbd_core_server_t */

    /* upstream ctx */
    ngx_dbd_conf_ctx_t           *ctx;
} ngx_dbd_core_ups_conf_t;


typedef struct {
    ngx_str_t                     name;

    ngx_dbd_core_ups_conf_t      *upstream;

    ngx_str_t                     sql;

    /* command ctx */
    ngx_dbd_conf_ctx_t           *ctx;
} ngx_dbd_core_cmd_conf_t;


typedef struct {
    void    *(*create_main_conf)(ngx_conf_t *cf);
    char    *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void    *(*create_ups_conf)(ngx_conf_t *cf);
    char    *(*merge_ups_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void    *(*create_cmd_conf)(ngx_conf_t *cf);
    char    *(*merge_cmd_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_dbd_module_t;


#define NGX_DBD_MODULE              0x00444244  /* "DBD" */

#define NGX_DBD_MAIN_CONF           0x02000000
#define NGX_DBD_UPS_CONF            0x04000000
#define NGX_DBD_CMD_CONF            0x08000000


#define NGX_DBD_MAIN_CONF_OFFSET    offsetof(ngx_dbd_conf_ctx_t, main_conf)
#define NGX_DBD_UPS_CONF_OFFSET     offsetof(ngx_dbd_conf_ctx_t, ups_conf)
#define NGX_DBD_CMD_CONF_OFFSET     offsetof(ngx_dbd_conf_ctx_t, cmd_conf)


#define ngx_dbd_conf_get_module_main_conf(cf, module)                          \
    ((ngx_dbd_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_dbd_conf_get_module_ups_conf(cf, module)                           \
    ((ngx_dbd_conf_ctx_t *) cf->ctx)->ups_conf[module.ctx_index]
#define ngx_dbd_conf_get_module_cmd_conf(cf, module)                           \
    ((ngx_dbd_conf_ctx_t *) cf->ctx)->cmd_conf[module.ctx_index]

#define ngx_dbd_cycle_get_module_main_conf(cycle, module)                      \
    ((ngx_dbd_conf_ctx_t *)                                                    \
     cycle->conf_ctx[ngx_dbd_module.index])->main_conf[module.ctx_index]


extern ngx_uint_t    ngx_dbd_max_module;
extern ngx_module_t  ngx_dbd_module;
extern ngx_module_t  ngx_dbd_core_module;


#endif /* _NGX_DBD_CORE_MODULE_H_INCLUDED_ */
