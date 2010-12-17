
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SERVICE_NAME  "NGINX"


typedef struct {
     int     signo;
     char   *signame;
     char   *name;
     void  (*handler)(int signo);
} ngx_signal_t;


static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);

static ngx_uint_t ngx_stdcall ngx_service_handler(ngx_uint_t ctl,
    ngx_uint_t type, void *data, void *ctx);

extern int main(int argc, char *const *argv);

static void ngx_stdcall ngx_service_main(int argc, char **argv);


int                             ngx_argc;
char                          **ngx_argv;
char                          **ngx_os_argv;

ngx_int_t                       ngx_process_slot;
ngx_socket_t                    ngx_channel;
ngx_int_t                       ngx_last_process;
ngx_process_t                   ngx_processes[NGX_MAX_PROCESSES];

ngx_uint_t                      ngx_run_as_service;


static SERVICE_STATUS           ngx_ss;
static SERVICE_STATUS_HANDLE    ngx_sshandle;


#if 0

ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};


ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
    ngx_int_t  s;

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }

        if (s == NGX_MAX_PROCESSES) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }


    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);

        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        on = 1;
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        ngx_channel = ngx_processes[s].channel[1];

    } else {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }

    ngx_process_slot = s;


    pid = fork();

    switch (pid) {

    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;

    case 0:
        ngx_pid = ngx_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    switch (respawn) {

    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }

    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}

#endif


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
#if 0
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
#endif
    return NGX_INVALID_PID;
}


#if 0

static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_signal_handler(int signo)
{
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    ngx_time_update(0, 0);

    action = "";

    switch (ngx_process) {

    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            ngx_noaccept = 1;
            action = ", stop accepting connections";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (getppid() > 1 || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            ngx_sigalrm = 1;
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;

        case SIGCHLD:
            ngx_reap = 1;
            break;
        }

        break;

    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            ngx_debug_quit = 1;
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "signal %d (%s) received%s", signo, sig->signame, action);

    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}


static void
ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

#if (NGX_SOLARIS || NGX_FREEBSD)

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                              "waitpid() failed (%d: %s)",
                              err, ngx_sigsafe_strerror(err));
                return;
            }

#endif

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "waitpid() failed (%d: %s)",
                          err, ngx_sigsafe_strerror(err));
            return;
        }


        if (ngx_accept_mutex_ptr) {

            /*
             * unlock the accept mutex if the abnormally exited process
             * held it
             */

            ngx_atomic_cmp_set(ngx_accept_mutex_ptr, pid, 0);
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and can not be respawn",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }
    }
}
#endif


void
ngx_debug_point(void)
{
#if 0
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
#endif
}


ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_int_t pid)
{
    return 0;
}


ngx_int_t
ngx_service(ngx_service_main_pt func)
{
    SERVICE_TABLE_ENTRY  stes[] = {
        { "", (LPSERVICE_MAIN_FUNCTION) func },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(stes) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "StartServiceCtrlDispatcher() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_set_service_handler(void)
{
    ngx_sshandle = RegisterServiceCtrlHandlerEx(NGX_SERVICE_NAME,
                            (LPHANDLER_FUNCTION_EX) ngx_service_handler, NULL);

    if (ngx_sshandle == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "RegisterServiceCtrlHandlerEx() failed");
        return NGX_ERROR;
    }

    ngx_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS
                           |SERVICE_INTERACTIVE_PROCESS;
    ngx_ss.dwCurrentState = SERVICE_START_PENDING;
    ngx_ss.dwControlsAccepted = 0;
    ngx_ss.dwWin32ExitCode = NO_ERROR;
    ngx_ss.dwServiceSpecificExitCode = 0;
    ngx_ss.dwCheckPoint = 0;
    ngx_ss.dwWaitHint = 0;

    if (SetServiceStatus(ngx_sshandle, &ngx_ss) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_START_PENDING) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_set_service_running_status(void)
{
    ngx_ss.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
    ngx_ss.dwCurrentState = SERVICE_RUNNING;

    if (SetServiceStatus(ngx_sshandle, &ngx_ss) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_RUNNING) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_set_service_stopped_status(void)
{
    ngx_ss.dwControlsAccepted = 0;
    ngx_ss.dwCurrentState = SERVICE_STOPPED;

    if (SetServiceStatus(ngx_sshandle, &ngx_ss) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_STOPPED) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_install_service(void)
{
    u_char     exec_path[NGX_MAX_PATH], *p;
    ngx_err_t  err;
    SC_HANDLE  manager;
    SC_HANDLE  service;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, SERVICE_ALL_ACCESS);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {

        p = exec_path;
        p += GetModuleFileName(NULL, p, NGX_MAX_PATH);
        p = ngx_cpymem(p, " -s", sizeof(" -s") - 1);
        *p = '\0';

        service = CreateService(manager, NGX_SERVICE_NAME, NGX_SERVICE_NAME,
                                SERVICE_ALL_ACCESS,
                                SERVICE_WIN32_OWN_PROCESS
                                |SERVICE_INTERACTIVE_PROCESS,
                                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                exec_path, NULL, NULL, NULL, NULL, NULL);
        if (service == NULL) {
            ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                            "CreateService() failed");
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

    } else if (service == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno, "OpenService() failed");
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    return NGX_OK;
}


ngx_int_t
ngx_uninstall_service(void)
{
    ngx_err_t  err;
    ngx_int_t  rc;
    SC_HANDLE  manager;
    SC_HANDLE  service;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, DELETE);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {
        CloseServiceHandle(manager);
        return NGX_OK;

    } else if (service == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, err, "OpenService() failed");
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    if (DeleteService(service) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "DeleteService() failed");
        rc = NGX_ERROR;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    return rc;
}


ngx_int_t
ngx_start_service(void)
{
    int                     err;
    DWORD                   bytes_needed;
    DWORD                   old_check_point;
    DWORD                   start_tick_count;
    DWORD                   wait_time;
    SC_HANDLE               manager;
    SC_HANDLE               service;
    SERVICE_STATUS_PROCESS  ssp;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno, "OpenService() failed");
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    if (StartService(service, 0, NULL) == 0) {
        err = ngx_errno;

        CloseServiceHandle(service);
        CloseServiceHandle(manager);

        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            return NGX_OK;
        }

        ngx_message_box(NGX_SERVICE_NAME, 0, err, "StartService() failed");
        return NGX_ERROR;
    }

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssp,
                             sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)
        == 0)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);

        return NGX_ERROR;
    }

    start_tick_count = GetTickCount();
    old_check_point = ssp.dwCheckPoint;

    while (ssp.dwCurrentState == SERVICE_START_PENDING) {

        wait_time = ssp.dwWaitHint / 10;

        if (wait_time < 1000) {
            wait_time = 1000;

        } else if (wait_time > 10000) {
            wait_time = 10000;
        }

        Sleep(wait_time);

        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssp,
                                 sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)
            == 0)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);

            return NGX_ERROR;
        }

        if (ssp.dwCheckPoint > old_check_point) {
            start_tick_count = GetTickCount();
            old_check_point = ssp.dwCheckPoint;

        } else if (GetTickCount() - start_tick_count > ssp.dwWaitHint) {
            break;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        return NGX_OK;

    } else {
        return NGX_ERROR;
    }
}


ngx_int_t
ngx_stop_service(void)
{
    DWORD                   bytes_needed;
    DWORD                   start_tick_count;
    DWORD                   wait_time;
    SC_HANDLE               manager;
    SC_HANDLE               service;
    SERVICE_STATUS_PROCESS  ssp;

    start_tick_count = GetTickCount();

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL) {
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME,
                          SERVICE_STOP|SERVICE_QUERY_STATUS);
    if (service == NULL) {
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    do {

        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssp,
                                 sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)
            == 0)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NGX_OK;
        }

        if (GetTickCount() - start_tick_count > 30000) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

        wait_time = ssp.dwWaitHint / 10;

        if (wait_time < 1000) {
            wait_time = 1000;

        } else if (wait_time > 10000) {
            wait_time = 10000;
        }

        Sleep(wait_time);

    } while (ssp.dwCurrentState == SERVICE_STOP_PENDING);

    if (ControlService(service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &ssp)
        == 0)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    while (ssp.dwCurrentState != SERVICE_STOPPED) {

        wait_time = ssp.dwWaitHint / 10;

        if (wait_time < 1000) {
            wait_time = 1000;

        } else if (wait_time > 10000) {
            wait_time = 10000;
        }

        Sleep(wait_time);

        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE) &ssp,
                                 sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)
            == 0)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            break;
        }

        if (GetTickCount() - start_tick_count > 60000) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    return NGX_OK;
}


static ngx_uint_t ngx_stdcall
ngx_service_handler(ngx_uint_t ctl, ngx_uint_t type, void *data, void *ctx)
{
    switch (ctl) {

    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:

        ngx_atomic_cmp_set(&ngx_quit, 0, 1);

        ngx_ss.dwCurrentState = SERVICE_STOP_PENDING;
        ngx_ss.dwWin32ExitCode = NO_ERROR;
        ngx_ss.dwServiceSpecificExitCode = 0;
        ngx_ss.dwCheckPoint = 0;
        ngx_ss.dwWaitHint = 0;

        break;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    if (SetServiceStatus(ngx_sshandle, &ngx_ss) == 0) {
        ngx_message_box(NGX_SERVICE_NAME, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_STOP_PENDING) failed");
    }

    return NO_ERROR;
}


static LONG WINAPI
ngx_unhandled_exception_filter(EXCEPTION_POINTERS *ex)
{
    u_char                          file[NGX_MAX_PATH], *p;
    ngx_fd_t                        fd;
    MINIDUMP_EXCEPTION_INFORMATION  ei;

    if (ex == NULL || ngx_cycle == NULL) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    p = ngx_snprintf(file, NGX_MAX_PATH, "%Vlogs/nginx.dmp",
                     &ngx_cycle->prefix);
    *p = '\0';

    fd = ngx_open_file(file, NGX_FILE_TRUNCATE, NGX_FILE_CREATE_OR_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    ei.ThreadId = GetCurrentThreadId();
    ei.ExceptionPointers = ex;
    ei.ClientPointers = FALSE;

    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), fd,
                      MiniDumpNormal, &ei, NULL, NULL);

    ngx_close_file(fd);

    return EXCEPTION_EXECUTE_HANDLER;
}


int WINAPI
WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_line, int cmd_show)
{
    SetUnhandledExceptionFilter(ngx_unhandled_exception_filter);

    /*
     * command line arguments:
     *
     *   -i, install service.
     *   -u, uninstall service.
     *   -r, start service.
     *   -e, stop service.
     *   -s, run as service.
     */

#if 0
    ngx_message_box("command line", 0, 0, "%s", cmd_line);
#endif

    if ((ngx_strlen(cmd_line) == 2) && cmd_line[0] == '-') {

        switch (cmd_line[1]) {

        case 'i':
            ngx_install_service();
            return 0;

        case 'u':
            ngx_uninstall_service();
            return 0;

        case 'r':
            ngx_start_service();
            return 0;

        case 'e':
            ngx_stop_service();
            return 0;

        case 's':
            ngx_run_as_service = 1;

            if (ngx_service(ngx_service_main) != NGX_OK) {
                return 1;
            }

            return 0;

        default:
            break;
        }
    }

    ngx_service_main(0, NULL);

    return 0;
}


static void ngx_stdcall
ngx_service_main(int argc, char **argv)
{
    int      n;
    u_char  *arguments[4], prefix[NGX_MAX_PATH], *p;

    if (ngx_run_as_service) {
        if (ngx_set_service_handler() != NGX_OK) {
            return;
        }

        if (ngx_set_service_running_status() != NGX_OK) {
            ngx_set_service_stopped_status();
            return;
        }
    }

    n = GetModuleFileName(NULL, prefix, NGX_MAX_PATH);
    if (n == 0) {
        ngx_message_box("ngx_service_main", 0, ngx_errno,
                        "GetModuleFileName() failed");

        if (ngx_run_as_service) {
            ngx_set_service_stopped_status();
        }

        return;
    }

    p = prefix + n;
    while (p > prefix) {
        if (*p == '\\') {
            *p = '\0';
            break;
        }

        p--;
    }

#if 0
    ngx_message_box("ngx_service_main", 0, 0,
                    "prefix: \"%s\"", prefix);
#endif

    argc = sizeof(arguments) / sizeof(u_char *) - 1;

    arguments[0] = "ngwsx.exe";
    arguments[1] = "-p";
    arguments[2] = prefix;
    arguments[3] = "";

    main(argc, arguments);

    if (ngx_run_as_service) {
        ngx_set_service_stopped_status();
    }
}


ngx_int_t
ngx_message_box(u_char *caption, ngx_uint_t type, ngx_err_t err,
    const char *fmt, ...)
{
    u_char   errstr[NGX_MAX_ERROR_STR], *p, *last;
    va_list  args;

    p = errstr;
    last = errstr + NGX_MAX_ERROR_STR;

    va_start(args, fmt);
    p = ngx_vsnprintf(p, last - p, fmt, args);
    va_end(args);

    if (err) {

        if ((unsigned) err >= 0x80000000) {
            p = ngx_snprintf(p, last - p, " (%Xd: ", err);

        } else {
            p = ngx_snprintf(p, last - p, " (%d: ", err);
        }

        p = ngx_strerror(err, p, last - p);

        if (p < last) {
            *p++ = ')';
        }
    }

    *p = '\0';

    return MessageBox(NULL, errstr, caption, (UINT) type);
}
