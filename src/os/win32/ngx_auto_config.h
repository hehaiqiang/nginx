
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_AUTO_CONFIG_H_INCLUDED_
#define _NGX_AUTO_CONFIG_H_INCLUDED_


/* libraries */

#define NGX_SSL                      0
#define NGX_PCRE                     1
#define NGX_OPENSSL                  0
#define NGX_OPENSSL_MD5              0
#define NGX_CRYPT                    0


/* event modules */

#define NGX_HAVE_AIO                 1
#define NGX_HAVE_ASYNCSELECT         0
#define NGX_HAVE_EVENTSELECT         0
#define NGX_HAVE_IOCP                1
#define NGX_HAVE_OVLPIO              0
#define NGX_HAVE_SELECT              1
#define NGX_HAVE_WSAPOLL             0

#define NGX_TEST_BUILD_WSAPOLL       0
#define NGX_TEST_BUILD_TRANSMITPACKETS  0


/* http modules */

#define NGX_HTTP                     1
#define NGX_HTTP_GZIP                1
#define NGX_HTTP_CHARSET             1
#define NGX_HTTP_SSI                 1
#define NGX_HTTP_DAV                 1
#define NGX_HTTP_AUTOINDEX           1
#define NGX_HTTP_AUTH_BASIC          0
#define NGX_HTTP_ACCESS              1
#define NGX_HTTP_REALIP              1
#define NGX_HTTP_GEO                 1
#define NGX_HTTP_MAP                 1
#define NGX_HTTP_REWRITE             1
#define NGX_HTTP_SSL                 0
#define NGX_HTTP_PROXY               1
#define NGX_HTTP_PERL                0
#define NGX_STAT_STUB                1
#define NGX_HTTP_CACHE               0


/* mail modules */

#define NGX_MAIL                     1
#define NGX_MAIL_SSL                 0


/* features */

#define NGX_THREADS                  0

#define NGX_HAVE_FILE_AIO            0

#define NGX_HAVE_AIO_SENDFILE        0

#define NGX_HAVE_FIONBIO             1

#define NGX_HAVE_SENDFILE            0

#define NGX_HAVE_GMTOFF              0

#define NGX_HAVE_OS_SPECIFIC_INIT    0

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

#define NGX_HAVE_LOCALTIME_R         0

#define NGX_HAVE_STRERROR_R          0

#define NGX_HAVE_GNU_CRYPT_R         0

#define NGX_HAVE_PERL_MULTIPLICITY   0

#define NGX_PTR_SIZE                 4

#define NGX_MAX_SIZE_T_VALUE         2147483647L
#define NGX_MAX_OFF_T_VALUE          9223372036854775807LL

#define NGX_SIZE_T_LEN               (sizeof("-2147483648") - 1)
#define NGX_OFF_T_LEN                (sizeof("-9223372036854775808") - 1)
#define NGX_TIME_T_LEN               (sizeof("-2147483648") - 1)


#define NGX_CONFIGURE                ""
#define NGX_COMPILER                 "VC8 (Windows XP SP3)"

#define NGX_USER                     ""
#define NGX_GROUP                    ""


#define NGX_CONF_PREFIX              "conf"
#define NGX_CONF_PATH                "conf\\nginx.conf"
#define NGX_LOG_PREFIX               "logs\\"
#define NGX_ERROR_LOG_PATH           "logs\\error.log"
#define NGX_PID_PATH                 "logs\\nginx.pid"
#define NGX_HTTP_LOG_PATH            "logs\\access.log"
#define NGX_HTTP_CLIENT_TEMP_PATH    "temp\\client_temp"
#define NGX_HTTP_PROXY_TEMP_PATH     "temp\\proxy_temp"
#define NGX_HTTP_FASTCGI_TEMP_PATH   "temp\\fastcgi_temp"


#endif /* _NGX_AUTO_CONFIG_H_INCLUDED_ */
