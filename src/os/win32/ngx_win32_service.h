
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_SERVICE_H_INCLUDED_
#define _NGX_WIN32_SERVICE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void (ngx_stdcall *ngx_service_main_pt)(int argc, char **argv);


ngx_int_t ngx_service(ngx_service_main_pt func);
ngx_int_t ngx_set_service_handler(void);

ngx_int_t ngx_set_service_running_status(void);
ngx_int_t ngx_set_service_stopped_status(void);

ngx_int_t ngx_install_service(void);
ngx_int_t ngx_uninstall_service(void);

ngx_int_t ngx_start_service(void);
ngx_int_t ngx_stop_service(void);


extern ngx_uint_t  ngx_run_as_service;


#endif /* _NGX_WIN32_SERVICE_H_INCLUDED_ */
