
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_os_io_t  ngx_os_io = {
    ngx_win32_recv,
    ngx_readv_chain,
    ngx_udp_win32_recv,
    ngx_win32_send,
#if (NGX_HAVE_SENDFILE)
    ngx_transmitfile_chain,
    NGX_IO_SENDFILE
#else
    ngx_writev_chain,
    0
#endif
};


ngx_int_t                         ngx_ncpu;
ngx_int_t                         ngx_max_sockets;
ngx_uint_t                        ngx_inherited_nonblocking;
ngx_uint_t                        ngx_tcp_nodelay_and_tcp_nopush;

ngx_uint_t                        ngx_win32_ver;

LPFN_ACCEPTEX                     ngx_acceptex;
LPFN_CONNECTEX                    ngx_connectex;
LPFN_DISCONNECTEX                 ngx_disconnectex;
LPFN_TRANSMITFILE                 ngx_transmit_file;
LPFN_TRANSMITPACKETS              ngx_transmit_packets;
LPFN_GETACCEPTEXSOCKADDRS         ngx_get_acceptex_sockaddrs;
LPFN_GETQUEUEDCOMPLETIONSTATUSEX  ngx_get_queued_completion_status_ex;


static struct {
    GUID          guid;
    u_long        glen;
    void        **func;
    u_long        flen;
    ngx_uint_t    win_ver;
    char         *func_name;
}  ngx_wefs[] = {

    { WSAID_GETACCEPTEXSOCKADDRS,
      sizeof(GUID),
      (void **) &ngx_get_acceptex_sockaddrs,
      sizeof(ngx_get_acceptex_sockaddrs),
      NGX_WIN32_VER_400,
      "GetAcceptExSockaddrs" },

    { WSAID_ACCEPTEX,
      sizeof(GUID),
      (void **) &ngx_acceptex,
      sizeof(ngx_acceptex),
      NGX_WIN32_VER_500,
      "AcceptEx" },

    { WSAID_TRANSMITFILE,
      sizeof(GUID),
      (void **) &ngx_transmit_file,
      sizeof(ngx_transmit_file),
      NGX_WIN32_VER_500,
      "TransmitFile" },

    { WSAID_CONNECTEX,
      sizeof(GUID),
      (void **) &ngx_connectex,
      sizeof(ngx_connectex),
      NGX_WIN32_VER_501,
      "ConnectEx" },

    { WSAID_DISCONNECTEX,
      sizeof(GUID),
      (void **) &ngx_disconnectex,
      sizeof(ngx_disconnectex),
      NGX_WIN32_VER_501,
      "DisconnectEx" },

    { WSAID_TRANSMITPACKETS,
      sizeof(GUID),
      (void **) &ngx_transmit_packets,
      sizeof(ngx_transmit_packets),
      NGX_WIN32_VER_501,
      "TransmitPackets" },

    { {0,0,0,{0,0,0,0,0,0,0,0}}, 0, NULL, 0, 0, NULL }
};


ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    void           *handle;
    HKEY            hkey;
    long            rc;
    u_long          num_conn, len;
    u_long          bytes;
    SOCKET          s;
    WSADATA         wsadata;
    u_short         port;
    ngx_err_t       err;
    ngx_uint_t      n;
    SOCKADDR_IN     sa;
    SYSTEM_INFO     si;
    OSVERSIONINFO   osvi;

    /* current windows version */

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (!GetVersionEx(&osvi)) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "GetVersionEx() failed");
        return NGX_ERROR;
    }

    ngx_win32_ver = osvi.dwMajorVersion * 100 + osvi.dwMinorVersion;


    if (ngx_win32_ver >= NGX_WIN32_VER_600) {
        handle = GetModuleHandle("kernel32.dll");
        if (handle == NULL) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "GetModuleHandle(\"kernel32.dll\") failed");
            return NGX_ERROR;
        }

        ngx_get_queued_completion_status_ex = (void *) GetProcAddress(handle,
                                                 "GetQueuedCompletionStatusEx");
        if (ngx_get_queued_completion_status_ex == NULL) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "GetProcAddress(\"GetQueuedCompletionStatusEx\") failed");
            return NGX_ERROR;
        }
    }


    rc = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, rc, "WSAStartup() failed");
        return NGX_ERROR;

    } else if (LOBYTE(wsadata.wVersion) != 2
               || HIBYTE(wsadata.wVersion) != 2)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "WinSock DLL doesn't supports V2.2");
        WSACleanup();
        return NGX_ERROR;
    }

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
                      "socket() failed");
        WSACleanup();
        return NGX_ERROR;
    }

    port = 0;

retry_bind:

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);

    if (bind(s, (SOCKADDR *) &sa, sizeof(SOCKADDR_IN)) == SOCKET_ERROR) {
        err = ngx_socket_errno;

        if (err == WSAEADDRINUSE) {
            ngx_log_error(NGX_LOG_ALERT, log, err, "bind() failed: %s:%u",
                          inet_ntoa(sa.sin_addr), port);

            port++;
            goto retry_bind;
        }

        ngx_log_error(NGX_LOG_EMERG, log, err, "bind() failed");

        closesocket(s);
        WSACleanup();

        return NGX_ERROR;
    }

    if (listen(s, NGX_LISTEN_BACKLOG) == SOCKET_ERROR) {
        err = ngx_socket_errno;

        if (err == WSAEADDRINUSE) {
            ngx_log_error(NGX_LOG_ALERT, log, err, "listen() failed: %s:%u",
                          inet_ntoa(sa.sin_addr), port);
            port++;
            goto retry_bind;
        }

        ngx_log_error(NGX_LOG_EMERG, log, err, "listen() failed");
        closesocket(s);
        WSACleanup();
        return NGX_ERROR;
    }

    for (n = 0; ngx_wefs[n].func; n++) {

        if (ngx_win32_ver >= ngx_wefs[n].win_ver) {
            bytes = 0;

            if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &ngx_wefs[n].guid, ngx_wefs[n].glen,
                    ngx_wefs[n].func, ngx_wefs[n].flen, &bytes, NULL, NULL)
                == SOCKET_ERROR)
            {
                err = ngx_socket_errno;

                if (err != WSAEINVAL && err != WSAEOPNOTSUPP) {
                    ngx_log_error(NGX_LOG_EMERG, log, err,
                                  "WSAIoctl(%s) failed", ngx_wefs[n].func_name);
                    closesocket(s);
                    WSACleanup();
                    return NGX_ERROR;
                }

                ngx_log_error(NGX_LOG_ALERT, log, err,
                              "WSAIoctl: %s", ngx_wefs[n].func_name);

                continue;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                           "WSAIoctl(%s) successfully", ngx_wefs[n].func_name);
        }
    }

    closesocket(s);


    ngx_memzero(&si, sizeof(SYSTEM_INFO));

    GetSystemInfo(&si);

    ngx_pagesize = si.dwPageSize;
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

    ngx_ncpu = si.dwNumberOfProcessors;

    /*
     * TODO:
     *
     * si.wProcessorArchitecture
     * si.dwAllocationGranularity
     */

    /* TODO: xxx */
#if 0
    ngx_cpuinfo();
#endif


    rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
             "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Winsock",
             0, KEY_READ, &hkey);
    if (rc != ERROR_SUCCESS) {
        ngx_log_error(NGX_LOG_ALERT, log, rc,
                   "RegOpenKeyEx(HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet"
                   "\\Services\\Tcpip\\Parameters\\Winsock) failed");

    } else {
        num_conn = 0;
        len = sizeof(num_conn);

        rc = RegQueryValueEx(hkey, "TcpNumConnections", NULL, NULL,
                             (u_char *) &num_conn, &len);
        if (rc != ERROR_SUCCESS) {
#if 0
            ngx_log_error(NGX_LOG_ALERT, log, rc,
                          "RegQueryValueEx(TcpNumConnections) failed");
#endif
        }

        RegCloseKey(hkey);
    }

    if (rc == ERROR_SUCCESS) {
        ngx_max_sockets = num_conn;

    } else {
        /* TODO */
    }


#if (NGX_HAVE_INHERITED_NONBLOCK)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

#if (NGX_HAVE_SENDFILE)
    if (ngx_win32_ver >= NGX_WIN32_VER_501) {
        ngx_os_io.send_chain = ngx_transmitpackets_chain;
    }
#endif

    srand((unsigned int) ngx_time());

    return NGX_OK;
}


void
ngx_os_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER);

#ifdef NGX_COMPILER
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
#endif
}
