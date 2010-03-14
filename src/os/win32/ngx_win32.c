
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


extern int main(int argc, char *const *argv);

static void ngx_stdcall ngx_service_main(int argc, char **argv);


#if (NGX_WINCE)
char  **environ;
int     timezone;
#endif


#if (NGX_WINCE)

int WINAPI
WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPWSTR cmd_line, int cmd_show)

#else

int WINAPI
WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_line, int cmd_show)

#endif
{
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
