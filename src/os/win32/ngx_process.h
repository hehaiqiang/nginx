
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


typedef void (ngx_stdcall *ngx_service_main_pt)(int argc, char **argv);


typedef DWORD            ngx_pid_t;

#define NGX_INVALID_PID  ((ngx_pid_t) -1)


typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;
    int                 status;
    ngx_socket_t        channel[2];

    ngx_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   GetCurrentProcessId

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#define ngx_sched_yield()  Sleep(1 / 1000)  /* usleep(1) */


ngx_int_t ngx_service(ngx_service_main_pt func);
ngx_int_t ngx_set_service_handler(void);
ngx_int_t ngx_set_service_running_status(void);
ngx_int_t ngx_set_service_stopped_status(void);
ngx_int_t ngx_install_service(void);
ngx_int_t ngx_uninstall_service(void);
ngx_int_t ngx_start_service(void);
ngx_int_t ngx_stop_service(void);


extern int              ngx_argc;
extern char           **ngx_argv;
extern char           **ngx_os_argv;

extern ngx_pid_t        ngx_pid;
extern ngx_socket_t     ngx_channel;
extern ngx_int_t        ngx_process_slot;
extern ngx_int_t        ngx_last_process;
extern ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

extern ngx_uint_t       ngx_run_as_service;


#endif /* _NGX_PROCESS_H_INCLUDED_ */
