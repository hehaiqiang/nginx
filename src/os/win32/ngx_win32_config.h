
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


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

#define FD_SETSIZE           64


#include <windows.h>
#include <windowsx.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <commdlg.h>

#include <winsock2.h>
#if !(NGX_WINCE)
#include <mswsock.h>
#endif
#include <ws2tcpip.h>

#if !(NGX_WINCE)
#include <sys/types.h>
#include <sys/utime.h>
#include <sys/stat.h>
#endif

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#if !(NGX_WINCE)
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#endif
#include <limits.h>
#include <time.h>


#include <ngx_auto_config.h>


#if (NGX_WINCE)
#include <ngx_wince.h>
#include <ngx_wince_time.h>
#endif


#define NGX_LISTEN_BACKLOG  SOMAXCONN

#define NGX_CPU_CACHE_LINE  32


#define ngx_inline      __inline

#define ngx_stdcall     __stdcall
#define ngx_cdecl       __cdecl
#define ngx_libc_cdecl


#define S_IRUSR        0
#define S_IWUSR        0
#define S_IXUSR        0
#if (NGX_WINCE)
#define S_IWRITE       0000200
#endif
#define F_SETFD        0
#define FD_CLOEXEC     0
#define RLIMIT_NOFILE  0
#define SIGALRM        0
#define ITIMER_REAL    0
#define IOV_MAX        64
#define SHUT_WR        SD_SEND


#if (NGX_WINCE)
#define EACCES        ERROR_ACCESS_DENIED
#define EPERM         ERROR_ACCESS_DENIED
#define EXDEV         0
#define ENOTDIR       ERROR_DIRECTORY
#define ENAMETOOLONG  ERROR_FILENAME_EXCED_RANGE
#define ENOSPC        ERROR_DISK_FULL
#define EISDIR        0
#endif

#undef EAGAIN
#define EAGAIN        WSAEWOULDBLOCK

#undef EEXIST
#define EEXIST        ERROR_ALREADY_EXISTS
#if (NGX_WINCE)
#define ENOENT        ERROR_FILE_NOT_FOUND
#define EINTR         WSAEINTR
#endif
#define EINPROGRESS   WSAEINPROGRESS
#define EADDRINUSE    WSAEADDRINUSE
#define ECONNABORTED  WSAECONNABORTED
#define ECONNRESET    WSAECONNRESET
#define ENOTCONN      WSAENOTCONN
#define ETIMEDOUT     WSAETIMEDOUT
#define ECONNREFUSED  WSAECONNREFUSED
/* #define ENAMETOOLONG */
#define ENETDOWN      WSAENETDOWN
#define ENETUNREACH   WSAENETUNREACH
#define EHOSTDOWN     WSAEHOSTDOWN
#define EHOSTUNREACH  WSAEHOSTUNREACH


#define ngx_random    rand

#define ioctl         ioctlsocket
#define getpid        GetCurrentProcessId

#define vsnprintf     _vsnprintf
#if (NGX_WINCE)
#define getenv(name)  NULL
#endif

#if 1
#if (NGX_WINCE)
typedef int           off_t;
#endif
typedef int           intptr_t;
typedef unsigned int  uintptr_t;
#endif

typedef SSIZE_T       ssize_t;
typedef INT32         int32_t;
typedef UINT32        uint32_t;
typedef INT64         int64_t;
typedef UINT64        uint64_t;

typedef PSID          uid_t;
typedef PSID          gid_t;
typedef DWORD         pid_t;
typedef int           rlim_t;
typedef int           sig_atomic_t;
typedef u_long        in_addr_t;
typedef u_short       in_port_t;
typedef int           socklen_t;


struct iovec {
    u_long     iov_len;
    char FAR  *iov_base;
};


extern char  **environ;


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
