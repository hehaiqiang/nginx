
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WINCE_TIME_H_INCLUDED_
#define _NGX_WINCE_TIME_H_INCLUDED_


#undef localtime
#undef gmtime
#undef mktime
#undef strftime


struct tm *localtime(const time_t *timer);

struct tm *gmtime(const time_t *timer);

time_t mktime(struct tm *timeptr);

size_t strftime(char *strDest, size_t maxsize, const char *format,
    const struct tm *timeptr);


#endif /* _NGX_WINCE_TIME_H_INCLUDED_ */
