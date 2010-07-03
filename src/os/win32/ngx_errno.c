
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


u_char *
ngx_strerror_r(int err, u_char *errstr, size_t size)
{
    if (size == 0) {
        return errstr;
    }

    errstr[0] = '\0';

    if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      errstr, (DWORD) size, NULL)
        == 0)
    {
        return errstr;
    }

    while (*errstr && size) {
        errstr++;
        size--;
    }

    /* TODO: remove the last CRLF */

    errstr -= 2;
    *errstr = '\0';

    return errstr;
}