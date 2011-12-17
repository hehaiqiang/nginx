
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SOCKET_H_INCLUDED_
#define _NGX_SOCKET_H_INCLUDED_


#include <ngx_config.h>


#define NGX_WRITE_SHUTDOWN SHUT_WR

#if (NGX_UDT)
#define SOCK_UDT  (SOCK_STREAM - 1)
#endif

typedef int  ngx_socket_t;

#if (NGX_UDT)
typedef struct {
    ngx_socket_t  fd;
    ngx_uint_t    type;
} ngx_os_socket_t;
#endif

#if !(NGX_UDT)
#define ngx_socket          socket
#define ngx_socket_n        "socket()"
#else
int ngx_socket(int af, int type, int proto);
#define ngx_socket_n        "ngx_socket()"

int ngx_bind(int s, const struct sockaddr *addr, socklen_t addr_len);
int ngx_listen(int s, int backlog);
int ngx_accept(int s, struct sockaddr *addr, socklen_t *addr_len);
int ngx_connect(int s, const struct sockaddr *addr, socklen_t addr_len);

#if 0
int ngx_socket_errno(int s);
#endif

int ngx_getpeername(int s, struct sockaddr *addr, socklen_t *addr_len);
int ngx_getsockname(int s, struct sockaddr *addr, socklen_t *addr_len);

int ngx_getsockopt(int s, int level, int opt_name, void *opt_val,
    socklen_t *opt_len);
int ngx_setsockopt(int s, int level, int opt_name, const void *opt_val,
    socklen_t opt_len);

ssize_t ngx_sendto(int s, const void *buf, size_t len, int flags,
    const struct sockaddr *addr, socklen_t addr_len);
ssize_t ngx_recvfrom(int s, void *buf, size_t len, int flags,
    struct sockaddr *addr, socklen_t *addr_len);
#endif


#if !(NGX_UDT)
#if (NGX_HAVE_FIONBIO)

int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ioctl(FIONBIO)"
#define ngx_blocking_n      "ioctl(!FIONBIO)"

#else

#define ngx_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define ngx_nonblocking_n   "fcntl(O_NONBLOCK)"

#define ngx_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define ngx_blocking_n      "fcntl(!O_NONBLOCK)"

#endif
#else
int ngx_nonblocking(ngx_socket_t s);
int ngx_blocking(ngx_socket_t s);

#define ngx_nonblocking_n   "ngx_nonblocking()"
#define ngx_blocking_n      "ngx_blocking()"
#endif

int ngx_tcp_nopush(ngx_socket_t s);
int ngx_tcp_push(ngx_socket_t s);

#if !(NGX_UDT)
#if (NGX_LINUX)

#define ngx_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define ngx_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define ngx_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define ngx_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif
#else
#define ngx_tcp_nopush_n   "ngx_tcp_nopush()"
#define ngx_tcp_push_n     "ngx_tcp_push()"
#endif


#if !(NGX_UDT)
#define ngx_shutdown_socket    shutdown
#define ngx_shutdown_socket_n  "shutdown()"
#else
int ngx_shutdown_socket(int s, int how);
#define ngx_shutdown_socket_n  "ngx_shutdown_socket()"
#endif

#if !(NGX_UDT)
#define ngx_close_socket    close
#define ngx_close_socket_n  "close() socket"
#else
int ngx_close_socket(int s);
#define ngx_close_socket_n  "ngx_close_socket()"
#endif


#endif /* _NGX_SOCKET_H_INCLUDED_ */
