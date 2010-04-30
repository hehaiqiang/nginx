
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#include <ngx_auto_config.h>


#if (0)
#define _WIN32_WINNT         0x0500  /* Windows 2000 */
#elif (1)
#define _WIN32_WINNT         0x0501  /* Windows XP */
#elif (0)
#define _WIN32_WINNT         0x0502  /* Windows Server 2003 */
#else
#define _WIN32_WINNT         0x0600  /* Windows Vista, Windows Server 2008 */
#endif


#define WIN32_LEAN_AND_MEAN


#undef FD_SETSIZE
#define FD_SETSIZE           1024


#define _USE_32BIT_TIME_T


#define _OFF_T_DEFINED
#define _SIZE_T_DEFINED
#define _TIME_T_DEFINED


#include <windows.h>
#include <windowsx.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <commdlg.h>

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utime.h>

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>


#define NGX_LISTEN_BACKLOG  SOMAXCONN

#define NGX_CPU_CACHE_LINE  32


#define ngx_inline      __inline

#define ngx_stdcall     __stdcall
#define ngx_cdecl       __cdecl
#define ngx_libc_cdecl


#define S_IRUSR        0
#define S_IWUSR        0
#define S_IXUSR        0
#define F_SETFD        0
#define FD_CLOEXEC     0
#define RLIMIT_NOFILE  0
#define SIGALRM        0
#define ITIMER_REAL    0

#define IOV_MAX        64

#define SHUT_WR        SD_SEND


#undef EAGAIN
#define EAGAIN        WSAEWOULDBLOCK

#undef EEXIST
#define EEXIST        ERROR_ALREADY_EXISTS

#define EINPROGRESS   WSAEINPROGRESS

#define EADDRINUSE    WSAEADDRINUSE
#define ECONNABORTED  WSAECONNABORTED
#define ECONNRESET    WSAECONNRESET
#define ENOTCONN      WSAENOTCONN
#define ETIMEDOUT     WSAETIMEDOUT
#define ECONNREFUSED  WSAECONNREFUSED

#if 0
#define ENAMETOOLONG
#endif

#define ENETDOWN      WSAENETDOWN
#define ENETUNREACH   WSAENETUNREACH
#define EHOSTDOWN     WSAEHOSTDOWN
#define EHOSTUNREACH  WSAEHOSTUNREACH


#define ngx_random    rand

#define vsnprintf     _vsnprintf


typedef int           ngx_aiocb_t;


typedef int           rlim_t;
typedef int           sig_atomic_t;
typedef uint32_t      in_addr_t;
typedef unsigned short  in_port_t;
typedef int           socklen_t;


struct iovec {
    u_long     iov_len;
    char FAR  *iov_base;
};


#if (_MSC_VER < 1500)

extern char  **environ;

#endif


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
