
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_FIONBIO)

int
ngx_nonblocking(ngx_socket_t s)
{
    int  nb;

    nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_blocking(ngx_socket_t s)
{
    int  nb;

    nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}

#endif


int
ngx_tcp_nopush(ngx_socket_t s)
{
    return 0;
}


int
ngx_tcp_push(ngx_socket_t s)
{
    return 0;
}
