
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if !(NGX_UDT)
int
ngx_nonblocking(ngx_socket_t s)
{
    u_long  nb;

    nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_blocking(ngx_socket_t s)
{
    u_long  nb;

    nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}
#endif


int
ngx_tcp_push(ngx_socket_t s)
{
    return 0;
}
