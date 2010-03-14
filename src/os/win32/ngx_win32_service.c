
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define NGWSX  "Ngwsx"


static ngx_uint_t ngx_stdcall ngx_service_handler(ngx_uint_t ctl,
    ngx_uint_t type, void *data, void *ctx);


ngx_uint_t  ngx_run_as_service;


static SERVICE_STATUS         ngx_ss;
static SERVICE_STATUS_HANDLE  ngx_sshandle;


ngx_int_t
ngx_service(ngx_service_main_pt func)
{
    SERVICE_TABLE_ENTRY  stes[] = {
        { "", (LPSERVICE_MAIN_FUNCTION) func },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(stes) == 0) {
        ngx_message_box(NGWSX, 0, ngx_errno,
                        "StartServiceCtrlDispatcher() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_set_service_handler(void)
{
    ngx_sshandle = RegisterServiceCtrlHandlerEx(NGWSX,
                            (LPHANDLER_FUNCTION_EX) ngx_service_handler, NULL);

    if (ngx_sshandle == 0) {
        ngx_message_box(NGWSX, 0, ngx_errno,
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
        ngx_message_box(NGWSX, 0, ngx_errno,
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
        ngx_message_box(NGWSX, 0, ngx_errno,
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
        ngx_message_box(NGWSX, 0, ngx_errno,
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
        ngx_message_box(NGWSX, 0, ngx_errno, "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGWSX, SERVICE_ALL_ACCESS);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {

        p = exec_path;
        p += GetModuleFileName(NULL, p, NGX_MAX_PATH);
        p = ngx_cpymem(p, " -s", sizeof(" -s") - 1);
        *p = '\0';

        service = CreateService(manager, NGWSX, NGWSX,
                                SERVICE_ALL_ACCESS,
                                SERVICE_WIN32_OWN_PROCESS
                                |SERVICE_INTERACTIVE_PROCESS,
                                SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                exec_path, NULL, NULL, NULL, NULL, NULL);
        if (service == NULL) {
            ngx_message_box(NGWSX, 0, ngx_errno,
                            "CreateService() failed");
            CloseServiceHandle(manager);
            return NGX_ERROR;
        }

    } else if (service == NULL) {
        ngx_message_box(NGWSX, 0, ngx_errno, "OpenService() failed");
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
        ngx_message_box(NGWSX, 0, ngx_errno, "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGWSX, DELETE);

    err = ngx_errno;

    if (service == NULL && err == ERROR_SERVICE_DOES_NOT_EXIST) {
        CloseServiceHandle(manager);
        return NGX_OK;

    } else if (service == NULL) {
        ngx_message_box(NGWSX, 0, err, "OpenService() failed");
        CloseServiceHandle(manager);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    if (DeleteService(service) == 0) {
        ngx_message_box(NGWSX, 0, ngx_errno, "DeleteService() failed");
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
        ngx_message_box(NGWSX, 0, ngx_errno, "OpenSCManager() failed");
        return NGX_ERROR;
    }

    service = OpenService(manager, NGWSX, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        ngx_message_box(NGWSX, 0, ngx_errno, "OpenService() failed");
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

        ngx_message_box(NGWSX, 0, err, "StartService() failed");
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

    service = OpenService(manager, NGWSX,
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
        ngx_message_box(NGWSX, 0, ngx_errno,
                        "SetServiceStatus(SERVICE_STOP_PENDING) failed");
    }

    return NO_ERROR;
}
