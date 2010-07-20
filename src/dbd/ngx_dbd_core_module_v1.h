
/*
 * Copyright (C) Seegle
 */


#ifndef _NGX_DBD_CORE_MODULE_H_INCLUDED_
#define _NGX_DBD_CORE_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dbd_v1.h>


#define NGX_DBD_V1_CMD_TYPE_EXEC             0
#define NGX_DBD_V1_CMD_TYPE_QUERY            1

#define NGX_DBD_V1_PARAM_DIRECTION_IN        0
#define NGX_DBD_V1_PARAM_DIRECTION_OUT       1
#define NGX_DBD_V1_PARAM_DIRECTION_IN_OUT    2
#define NGX_DBD_V1_PARAM_DIRECTION_RETURN    3


typedef struct {
    void                        **main_conf;
    void                        **conn_conf;
    void                        **cmd_conf;
    void                        **param_conf;
} ngx_dbd_v1_conf_ctx_t;


typedef struct {
    ngx_array_t                   connections;  /* ngx_dbd_core_conn_conf_t */

    ngx_hash_t                    commands_hash;
    ngx_hash_keys_arrays_t       *commands_keys;

    ngx_uint_t                    commands_hash_max_size;
    ngx_uint_t                    commands_hash_bucket_size;

    ngx_hash_t                    connections_hash;
    ngx_hash_keys_arrays_t       *connections_keys;

    ngx_uint_t                    connections_hash_max_size;
    ngx_uint_t                    connections_hash_bucket_size;
} ngx_dbd_v1_core_main_conf_t;


typedef struct {
    ngx_dbd_driver_t             *driver;

    ngx_str_t                     conn_string;
    size_t                        conn_pool_size;

    ngx_uint_t                    preps_hash_max_size;
    ngx_uint_t                    preps_hash_bucket_size;

    ngx_array_t                   commands;  /* ngx_dbd_core_cmd_conf_t */

    ngx_dbd_conn_pool_t          *conn_pool;

    /* connection ctx */
    ngx_dbd_v1_conf_ctx_t        *ctx;
} ngx_dbd_v1_core_conn_conf_t;


typedef struct {
    ngx_dbd_v1_core_conn_conf_t  *conn;

    ngx_str_t                     cmd_id;
    ngx_uint_t                    cmd_type;
    ngx_str_t                     cmd_text;

    ngx_array_t                   parameters;  /* ngx_dbd_core_param_conf_t */

    /* command ctx */
    ngx_dbd_v1_conf_ctx_t        *ctx;
} ngx_dbd_v1_core_cmd_conf_t;


typedef struct {
    ngx_str_t                     name;
    ngx_uint_t                    type;
    ngx_uint_t                    direction;
    size_t                        size;

    /* parameter ctx */
    ngx_dbd_v1_conf_ctx_t        *ctx;
} ngx_dbd_v1_core_param_conf_t;


typedef struct {
    void    *(*create_main_conf)(ngx_conf_t *cf);
    char    *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void    *(*create_conn_conf)(ngx_conf_t *cf);
    char    *(*merge_conn_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void    *(*create_cmd_conf)(ngx_conf_t *cf);
    char    *(*merge_cmd_conf)(ngx_conf_t *cf, void *prev, void *conf);

    void    *(*create_param_conf)(ngx_conf_t *cf);
    char    *(*merge_param_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_dbd_v1_module_t;


#define NGX_DBD_V1_MODULE               0x01444244  /* "DBD" */

#define NGX_DBD_V1_MAIN_CONF            0x02000000
#define NGX_DBD_V1_CONN_CONF            0x04000000
#define NGX_DBD_V1_CMD_CONF             0x08000000
#define NGX_DBD_V1_PARAM_CONF           0x10000000


#define NGX_DBD_V1_MAIN_CONF_OFFSET                                            \
    offsetof(ngx_dbd_v1_conf_ctx_t, main_conf)
#define NGX_DBD_V1_CONN_CONF_OFFSET                                            \
    offsetof(ngx_dbd_v1_conf_ctx_t, conn_conf)
#define NGX_DBD_V1_CMD_CONF_OFFSET                                             \
    offsetof(ngx_dbd_v1_conf_ctx_t, cmd_conf)
#define NGX_DBD_V1_PARAM_CONF_OFFSET                                           \
    offsetof(ngx_dbd_v1_conf_ctx_t, param_conf)


#define ngx_dbd_v1_conf_get_module_main_conf(cf, module)                       \
    ((ngx_dbd_v1_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_dbd_v1_conf_get_module_conn_conf(cf, module)                       \
    ((ngx_dbd_v1_conf_ctx_t *) cf->ctx)->conn_conf[module.ctx_index]
#define ngx_dbd_v1_conf_get_module_cmd_conf(cf, module)                        \
    ((ngx_dbd_v1_conf_ctx_t *) cf->ctx)->cmd_conf[module.ctx_index]
#define ngx_dbd_v1_conf_get_module_param_conf(cf, module)                      \
    ((ngx_dbd_v1_conf_ctx_t *) cf->ctx)->param_conf[module.ctx_index]

#define ngx_dbd_v1_cycle_get_module_main_conf(cycle, module)                   \
    ((ngx_dbd_v1_conf_ctx_t *)                                                 \
     cycle->conf_ctx[ngx_dbd_v1_module.index])->main_conf[module.ctx_index]


extern ngx_uint_t    ngx_dbd_v1_max_module;
extern ngx_module_t  ngx_dbd_v1_module;
extern ngx_module_t  ngx_dbd_v1_core_module;


#endif /* _NGX_DBD_CORE_MODULE_H_INCLUDED_ */
