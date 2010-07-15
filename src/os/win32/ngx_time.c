
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


void
ngx_timezone_update(void)
{
}


void
ngx_localtime(time_t s, ngx_tm_t *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
    (void) localtime_r(&s, tm);

#else
    ngx_tm_t  *t;

    t = localtime(&s);
    *tm = *t;

#endif

    tm->ngx_tm_mon++;
    tm->ngx_tm_year += 1900;
}


void
ngx_libc_localtime(time_t s, struct tm *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
    (void) localtime_r(&s, tm);

#else
    struct tm  *t;

    t = localtime(&s);
    *tm = *t;

#endif
}


void
ngx_libc_gmtime(time_t s, struct tm *tm)
{
#if (NGX_HAVE_LOCALTIME_R)
    (void) gmtime_r(&s, tm);

#else
    struct tm  *t;

    t = gmtime(&s);
    *tm = *t;

#endif
}


void
ngx_gettimeofday(struct timeval *tp)
{
    FILETIME    ft;
    ULONGLONG   usec;
    SYSTEMTIME  st;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);

    usec = ft.dwHighDateTime;
    usec <<= 32;
    usec |= ft.dwLowDateTime;
    usec /= 10;
    usec -= 11644473600000000LL;

    tp->tv_sec = (long) (usec / 1000000);
    tp->tv_usec = (long) (usec % 1000000);
}
