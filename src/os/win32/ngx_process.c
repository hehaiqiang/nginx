
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SERVICE_NAME  "NGINX"


extern int ngx_main(int argc, char *const *argv);

static ngx_uint_t ngx_stdcall ngx_service_handler(ngx_uint_t ctl,
    ngx_uint_t type, void *data, void *ctx);
static void WINAPI ngx_service_main(DWORD argc, LPTSTR *argv);


int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

ngx_int_t        ngx_last_process;
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

ngx_uint_t       ngx_run_as_service;

static SERVICE_STATUS         ngx_ss;
static SERVICE_STATUS_HANDLE  ngx_sshandle;


ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, char *name, ngx_int_t respawn)
{
    u_long          rc, n, code;
    ngx_int_t       s;
    ngx_pid_t       pid;
    ngx_exec_ctx_t  ctx;
    HANDLE          events[2];
    char            file[MAX_PATH + 1];

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].handle == NULL) {
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

    n = GetModuleFileName(NULL, file, MAX_PATH);

    if (n == 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "GetModuleFileName() failed");
        return NGX_INVALID_PID;
    }

    file[n] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "GetModuleFileName: \"%s\"", file);

    ctx.path = file;
    ctx.name = name;
    ctx.args = GetCommandLine();
    ctx.argv = NULL;
    ctx.envp = NULL;

    pid = ngx_execute(cycle, &ctx);

    if (pid == NGX_INVALID_PID) {
        return pid;
    }

    ngx_memzero(&ngx_processes[s], sizeof(ngx_process_t));

    ngx_processes[s].handle = ctx.child;
    ngx_processes[s].pid = pid;
    ngx_processes[s].name = name;

    ngx_sprintf(ngx_processes[s].term_event, "ngx_%s_term_%ul%Z", name, pid);
    ngx_sprintf(ngx_processes[s].quit_event, "ngx_%s_quit_%ul%Z", name, pid);
    ngx_sprintf(ngx_processes[s].reopen_event, "ngx_%s_reopen_%ul%Z",
                name, pid);

    events[0] = ngx_master_process_event;
    events[1] = ctx.child;

    rc = WaitForMultipleObjects(2, events, 0, 5000);

    ngx_time_update();

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "WaitForMultipleObjects: %ul", rc);

    switch (rc) {

    case WAIT_OBJECT_0:

        ngx_processes[s].term = OpenEvent(EVENT_MODIFY_STATE, 0,
                                          (char *) ngx_processes[s].term_event);
        if (ngx_processes[s].term == NULL) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "OpenEvent(\"%s\") failed",
                          ngx_processes[s].term_event);
            goto failed;
        }

        ngx_processes[s].quit = OpenEvent(EVENT_MODIFY_STATE, 0,
                                          (char *) ngx_processes[s].quit_event);
        if (ngx_processes[s].quit == NULL) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "OpenEvent(\"%s\") failed",
                          ngx_processes[s].quit_event);
            goto failed;
        }

        ngx_processes[s].reopen = OpenEvent(EVENT_MODIFY_STATE, 0,
                                       (char *) ngx_processes[s].reopen_event);
        if (ngx_processes[s].reopen == NULL) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "OpenEvent(\"%s\") failed",
                          ngx_processes[s].reopen_event);
            goto failed;
        }

        if (ResetEvent(ngx_master_process_event) == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "ResetEvent(\"%s\") failed",
                          ngx_master_process_event_name);
            goto failed;
        }

        break;

    case WAIT_OBJECT_0 + 1:
        if (GetExitCodeProcess(ctx.child, &code) == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "GetExitCodeProcess(%P) failed", pid);
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "%s process %P exited with code %Xul",
                      name, pid, code);

        goto failed;

    case WAIT_TIMEOUT:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "the event \"%s\" was not signaled for 5s",
                      ngx_master_process_event_name);
        goto failed;

    case WAIT_FAILED:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "WaitForSingleObject(\"%s\") failed",
                      ngx_master_process_event_name);

        goto failed;
    }

    if (respawn >= 0) {
        return pid;
    }

    switch (respawn) {

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].just_spawn = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].just_spawn = 1;
        break;
    }

    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;

failed:

    if (ngx_processes[s].reopen) {
        ngx_close_handle(ngx_processes[s].reopen);
    }

    if (ngx_processes[s].quit) {
        ngx_close_handle(ngx_processes[s].quit);
    }

    if (ngx_processes[s].term) {
        ngx_close_handle(ngx_processes[s].term);
    }

    TerminateProcess(ngx_processes[s].handle, 2);

    if (ngx_processes[s].handle) {
        ngx_close_handle(ngx_processes[s].handle);
    }

    return NGX_INVALID_PID;
}


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    STARTUPINFO          si;
    PROCESS_INFORMATION  pi;

    ngx_memzero(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ngx_memzero(&pi, sizeof(PROCESS_INFORMATION));

    if (CreateProcess(ctx->path, ctx->args,
                      NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
        == 0)
    {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
                      "CreateProcess(\"%s\") \"%s\" failed",
                      ctx->path != NULL ? ctx->path : "",
                      ctx->args != NULL ? ctx->args : "");

        return 0;
    }

    ctx->child = pi.hProcess;

    if (CloseHandle(pi.hThread) == 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "CloseHandle(pi.hThread) failed");
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "start %s process %P", ctx->name, pi.dwProcessId);

    return pi.dwProcessId;
}


static BOOL CALLBACK
ngx_enum_windows_proc(HWND hwnd, LPARAM param)
{
    ngx_pid_t  pid;

    pid = NGX_INVALID_PID;

    GetWindowThreadProcessId(hwnd, &pid);

    if (pid != (ngx_pid_t) param && pid != ngx_pid) {
        return TRUE;
    }

    PostMessage(hwnd, WM_KEYDOWN, VK_RETURN, 1);
    PostMessage(hwnd, WM_KEYUP, VK_RETURN, 1);

    return FALSE;
}


void
ngx_process_get_status(void)
{
    ngx_int_t       i, rc;
    ngx_process_t  *process;

    for (i = 0; i < ngx_last_process; i++) {
        process = &ngx_processes[i];

        if (process->pid == -1 || process->handle == NULL) {
            continue;
        }

        if (EnumWindows(ngx_enum_windows_proc, (LPARAM) process->pid) == FALSE)
        {
#if 0
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "EnumWindows() ph:%d failed", process->ph);
#endif
        }

        rc = WaitForSingleObject(process->handle, 0);

        if (rc == WAIT_TIMEOUT) {
            continue;
        }

        if (rc == WAIT_FAILED) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "WaitForSingleObject() handle:%d failed",
                          process->handle);
            continue;
        }

        /* rc == WAIT_OBJECT_0 */

        /* TODO: process->status */

        CloseHandle(process->handle);

        process->handle = NULL;
        process->pid = (ngx_pid_t) -1;
    }
}


ngx_int_t
ngx_service(LPSERVICE_MAIN_FUNCTION func)
{
    SERVICE_TABLE_ENTRY  stes[] = {
        { (LPTSTR) "", func },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(stes) == 0) {
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, SERVICE_ALL_ACCESS);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {

        p = exec_path;
        p += GetModuleFileName(NULL, (LPTSTR) p, NGX_MAX_PATH);
        p = ngx_cpymem(p, " -s", sizeof(" -s") - 1);
        *p = '\0';

        service = CreateService(manager, NGX_SERVICE_NAME, NGX_SERVICE_NAME,
                                SERVICE_ALL_ACCESS,
                                SERVICE_WIN32_OWN_PROCESS
                                |SERVICE_INTERACTIVE_PROCESS,
                                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                (LPCTSTR) exec_path, NULL, NULL, NULL, NULL,
                                NULL);
        if (service == NULL) {
            ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                            "CreateService() failed");
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

    } else if (service == NULL) {
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenService() failed");
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, DELETE);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {
        CloseServiceHandle(manager);
        return NGX_OK;

    } else if (service == NULL) {
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, err,
                        "OpenService() failed");
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    if (DeleteService(service) == 0) {
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGX_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "OpenService() failed");
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

        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, err,
                        "StartService() failed");
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
        ngx_message_box((u_char *) NGX_SERVICE_NAME, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_STOP_PENDING) failed");
    }

    return NO_ERROR;
}


static LONG WINAPI
ngx_unhandled_exception_filter(EXCEPTION_POINTERS *ex)
{
    u_char                          file[NGX_MAX_PATH];
    ngx_tm_t                        tm;
    ngx_fd_t                        fd;
    MINIDUMP_EXCEPTION_INFORMATION  ei;

    if (ex == NULL || ngx_cycle == NULL) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    ngx_gmtime(ngx_time() + ngx_gettimezone() * 60, &tm);

    ngx_snprintf(file, NGX_MAX_PATH,
                 "%Vlogs/nginx-%4d%02d%02d%02d%02d%02d.dmp%Z",
                 &ngx_cycle->prefix, tm.ngx_tm_year, tm.ngx_tm_mon,
                 tm.ngx_tm_mday, tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);

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


int ngx_cdecl
main(int argc, char *const *argv)
{
    u_char     *p;
    ngx_int_t   i;

    SetUnhandledExceptionFilter(ngx_unhandled_exception_filter);

    /*
     * command line arguments:
     *
     *   -i, install service.
     *   -u, uninstall service.
     *   -r, start service.
     *   -e, stop service.
     *   -z, run as service.
     */

#if 0
    ngx_message_box("command line", 0, 0, "%s", cmd_line);
#endif

    for (i = 1; i < argc; i++) {

        p = (u_char *) argv[i];

        if (*p++ != '-') {
            ngx_log_stderr(0, "invalid option: \"%s\"", argv[i]);
            return 1;
        }

        while (*p) {

            switch (*p++) {

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

            case 'z':
                ngx_run_as_service = 1;

                if (ngx_service(ngx_service_main) != NGX_OK) {
                    return 1;
                }

                return 0;

            case 'p':
            case 'c':
            case 'g':
            case 's':
                i++;

            default:
                break;
            }
        }
    }

    ngx_service_main((DWORD) argc, (LPTSTR *) argv);

    return 0;
}


static void WINAPI
ngx_service_main(DWORD argc, LPTSTR *argv)
{
    int       n, i;
    u_char  **argvs, *prefix, *p;

    if (ngx_run_as_service) {
        if (ngx_set_service_handler() != NGX_OK) {
            return;
        }

        if (ngx_set_service_running_status() != NGX_OK) {
            ngx_set_service_stopped_status();
            return;
        }
    }

    prefix = malloc(NGX_MAX_PATH);
    if (prefix == NULL) {
        goto failed;
    }

    n = GetModuleFileName(NULL, (LPTSTR) prefix, NGX_MAX_PATH);
    if (n == 0) {
        ngx_message_box((u_char *) "ngx_service_main", 0, ngx_errno,
                        "GetModuleFileName() failed");
        free(prefix);
        goto failed;
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
    ngx_message_box("ngx_service_main", 0, 0, "prefix: \"%s\"", prefix);
#endif

    SetCurrentDirectory((LPCTSTR) prefix);

    argvs = (u_char **) malloc(sizeof(u_char *) * (argc + 3));
    if (argvs == NULL) {
        free(prefix);
        goto failed;
    }

    for (i = 0; i < (int) argc; i++) {
        argvs[i] = (u_char *) argv[i];
    }

    argvs[argc++] = (u_char *) "-p";
    argvs[argc++] = prefix;
    argvs[argc] = NULL;

    ngx_main((int) argc, (char *const *) argvs);

    free(prefix);
    free(argvs);

failed:

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

    return MessageBox(NULL, (LPCSTR) errstr, (LPCSTR) caption, (UINT) type);
}
