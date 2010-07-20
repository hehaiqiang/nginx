
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_IOCP_MODULE_H_INCLUDED_
#define _NGX_IOCP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_uint_t    concurrent_threads;
    ngx_uint_t    events;

    ngx_uint_t    post_acceptex;
    ngx_flag_t    acceptex_read;

    ngx_uint_t    post_udp_recv;
} ngx_iocp_conf_t;


ngx_int_t ngx_iocp_add_file(ngx_file_t *file);


extern ngx_module_t  ngx_iocp_module;
extern ngx_addr_t    ngx_iocp_local_addr;


#endif /* _NGX_IOCP_MODULE_H_INCLUDED_ */
