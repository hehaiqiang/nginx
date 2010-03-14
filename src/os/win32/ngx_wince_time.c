
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>


static struct tm  ngx_tm;


static void
ngx_time_to_filetime(time_t time, FILETIME *ft)
{
    LONGLONG  usec;

    usec = Int32x32To64(time, 10000000);
    usec += 116444736000000000;

    ft->dwLowDateTime = (DWORD) usec;
    ft->dwHighDateTime = (DWORD) (usec >> 32);
}


static int
ngx_day_of_year(int year, int month, int day)
{
    int  leap, yday;

    leap = (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0));

    yday = day - 1;

    if (month > 0) {
        yday += 31;
    }

    if (month > 1) {
        yday += 28 + (leap == 1 ? 1 : 0);
    }

    if (month > 2) {
        yday += 31;
    }

    if (month > 3) {
        yday += 30;
    }

    if (month > 4) {
        yday += 31;
    }

    if (month > 5) {
        yday += 30;
    }

    if (month > 6) {
        yday += 31;
    }

    if (month > 7) {
        yday += 31;
    }

    if (month > 8) {
        yday += 30;
    }

    if (month > 9) {
        yday += 31;
    }

    if (month > 10) {
        yday += 30;
    }

    return yday;
}


struct tm *
localtime(const time_t *timer)
{
    DWORD                  id;
    FILETIME               utc_ft, local_ft;
    SYSTEMTIME             st;
    TIME_ZONE_INFORMATION  tzi;

    if (timer == NULL) {
        return NULL;
    }

    ngx_time_to_filetime(*timer, &utc_ft);

    if (FileTimeToLocalFileTime(&utc_ft, &local_ft) == 0) {
        return NULL;
    }

    if (FileTimeToSystemTime(&local_ft, &st) == 0) {
        return NULL;
    }

    ngx_tm.tm_sec = st.wSecond;
    ngx_tm.tm_min = st.wMinute;
    ngx_tm.tm_hour = st.wHour;
    ngx_tm.tm_mday = st.wDay;
    ngx_tm.tm_mon = st.wMonth - 1;
    ngx_tm.tm_year = st.wYear - 1900;
    ngx_tm.tm_wday = st.wDayOfWeek;
    ngx_tm.tm_yday = ngx_day_of_year(st.wYear, st.wMonth - 1, st.wDay);

    id = GetTimeZoneInformation(&tzi);

    if (id == TIME_ZONE_ID_UNKNOWN) {
        ngx_tm.tm_isdst = -1;
    } else if (id == TIME_ZONE_ID_STANDARD) {
        ngx_tm.tm_isdst = 0;
    } else if (id == TIME_ZONE_ID_DAYLIGHT) {
        ngx_tm.tm_isdst = 1;
    }

    return &ngx_tm;
}


struct tm *
gmtime(const time_t *timer)
{
    return NULL;
}


time_t
mktime(struct tm *timeptr)
{
    return 0;
}


size_t
strftime(char *strDest, size_t maxsize, const char *format,
    const struct tm *timeptr)
{
    return 0;
}
