
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
#define _NGX_WIN32_CONFIG_H_INCLUDED_


#define NGX_HAVE_SENDFILE     1

#define NGX_HAVE_FILE_AIO     1

#define NGX_HAVE_AIO_SENDFILE 0

#define NGX_LISTEN_BACKLOG    SOMAXCONN

#define NGX_PTR_SIZE          4


#if (NGX_PTR_SIZE == 4)

#define NGX_MAX_SIZE_T_VALUE  2147483647L

#define NGX_MAX_OFF_T_VALUE   2147483647L

#define NGX_SIZE_T_LEN        (sizeof("-2147483648") - 1)

#define NGX_OFF_T_LEN         (sizeof("-2147483648") - 1)

#define NGX_TIME_T_LEN        (sizeof("-2147483648") - 1)

#else

#define NGX_MAX_SIZE_T        9223372036854775807LL

#define NGX_MAX_OFF_T_VALUE   9223372036854775807LL

#define NGX_SIZE_T_LEN        (sizeof("-9223372036854775808") - 1)

#define NGX_OFF_T_LEN         (sizeof("-9223372036854775808") - 1)

#define NGX_TIME_T_LEN        (sizeof("-9223372036854775808") - 1)

#endif


#define NGX_THREADS           1


typedef unsigned char     u_char;

typedef char              int8_t;
typedef unsigned char     uint8_t;

typedef short             int16_t;
typedef unsigned short    uint16_t;

typedef int               int32_t;
typedef unsigned int      uint32_t;

typedef __int64           int64_t;
typedef unsigned __int64  uint64_t;


#if (NGX_PTR_SIZE == 4)

typedef uint32_t          size_t;
typedef int32_t           ssize_t;

#if 0
typedef int32_t           off_t;
typedef int32_t           _off_t;
#else
typedef int64_t           off_t;
typedef int64_t           _off_t;
#endif

typedef long              time_t;

typedef int32_t           intptr_t;
typedef uint32_t          uintptr_t;

#else

typedef uint64_t          size_t;
typedef int64_t           ssize_t;

typedef int64_t           off_t;
typedef int64_t           _off_t;

typedef int64_t           time_t;

typedef int64_t           intptr_t;
typedef uint64_t          uintptr_t;

#endif


#if (NGX_PTR_SIZE == 4)
#define _USE_32BIT_TIME_T
#endif

#define _SIZE_T_DEFINED
#define _OFF_T_DEFINED
#define _TIME_T_DEFINED
#define _INTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED


#if (0)
#define _WIN32_WINNT      0x0500  /* Windows 2000 */
#elif (1)
#define _WIN32_WINNT      0x0501  /* Windows XP */
#elif (0)
#define _WIN32_WINNT      0x0502  /* Windows Server 2003 */
#else
#define _WIN32_WINNT      0x0600  /* Windows Vista, Windows Server 2008 */
#endif


#define WIN32_LEAN_AND_MEAN


#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <dbghelp.h>

#include <stddef.h>
#include <stdlib.h>
#include <time.h>


#ifdef _MSC_VER

#pragma warning(default:4201)

/* disable some "-W4" level warnings */

#pragma warning(disable:4204)

/* 'type cast': from function pointer to data pointer */
#pragma warning(disable:4054)

/* 'type cast': from data pointer to function pointer */
#pragma warning(disable:4055)

/* unreferenced formal parameter */
#pragma warning(disable:4100)

/* FD_SET() and FD_CLR(): conditional expression is constant */
#pragma warning(disable:4127)

#pragma warning(disable:4152)

#endif


#include <ngx_auto_config.h>


#if 0

#define NGX_HAVE_GMTOFF              0

#if (defined SO_ACCEPTFILTER && !defined NGX_HAVE_DEFERRED_ACCEPT)
#define NGX_HAVE_DEFERRED_ACCEPT     1
#elif (defined TCP_DEFER_ACCEPT && !defined NGX_HAVE_DEFERRED_ACCEPT)
#define NGX_HAVE_DEFERRED_ACCEPT     1
#elif (!defined NGX_HAVE_DEFERRED_ACCEPT)
#define NGX_HAVE_DEFERRED_ACCEPT     0
#endif

/* setsockopt(SO_SNDLOWAT) returns ENOPROTOOPT */
#define NGX_HAVE_SO_SNDLOWAT         0

#define NGX_HAVE_INHERITED_NONBLOCK  0

#endif


#define ngx_inline        __inline

#define ngx_stdcall       __stdcall
#define ngx_cdecl         __cdecl
#define ngx_libc_cdecl


#define ngx_random        rand

#define vsnprintf         _vsnprintf


#define S_IWRITE          0x01

#define S_IRUSR           0x10
#define S_IWUSR           0x20
#define S_IXUSR           0x40


#define F_SETFD           0
#define FD_CLOEXEC        0
#define RLIMIT_NOFILE     0
#define SIGALRM           0
#define ITIMER_REAL       0


#define IOV_MAX           64

#define SHUT_WR           SD_SEND


typedef int               ngx_aiocb_t;

typedef int               rlim_t;
typedef int               sig_atomic_t;

typedef uint32_t          in_addr_t;
typedef unsigned short    in_port_t;
typedef int               socklen_t;


struct iovec {
    unsigned long   iov_len;
    char           *iov_base;
};


#if (_MSC_VER < 1500)
extern char  **environ;
#endif


#endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
