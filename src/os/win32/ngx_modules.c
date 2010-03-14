
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;

extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_select_module;
extern ngx_module_t  ngx_iocp_module;

extern ngx_module_t  ngx_openssl_module;

extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_dav_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_zone_module;
extern ngx_module_t  ngx_http_realip_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_ssl_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_perl_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_flv_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_stub_status_module;
extern ngx_module_t  ngx_http_gzip_static_module;

extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_sub_filter_module;
extern ngx_module_t  ngx_http_addition_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

extern ngx_module_t  ngx_mail_module;
extern ngx_module_t  ngx_mail_core_module;
extern ngx_module_t  ngx_mail_ssl_module;
extern ngx_module_t  ngx_mail_pop3_module;
extern ngx_module_t  ngx_mail_imap_module;
extern ngx_module_t  ngx_mail_smtp_module;
extern ngx_module_t  ngx_mail_auth_http_module;
extern ngx_module_t  ngx_mail_proxy_module;


ngx_module_t  *ngx_modules[] = {
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,

    &ngx_events_module,
    &ngx_event_core_module,
#if (NGX_HAVE_SELECT)
    &ngx_select_module,
#endif
#if (NGX_HAVE_IOCP)
    &ngx_iocp_module,
#endif

#if (NGX_OPENSSL)
    &ngx_openssl_module,
#endif

#if (NGX_HTTP)
    &ngx_http_module,
    &ngx_http_core_module,
    &ngx_http_log_module,
    &ngx_http_upstream_module,
    &ngx_http_static_module,
    &ngx_http_dav_module,
    &ngx_http_autoindex_module,
    &ngx_http_index_module,
#if (NGX_HTTP_AUTH_BASIC)
    &ngx_http_auth_basic_module,
#endif
    &ngx_http_access_module,
    &ngx_http_limit_zone_module,
    &ngx_http_realip_module,
    &ngx_http_geo_module,
    &ngx_http_map_module,
    &ngx_http_referer_module,
#if (NGX_HTTP_REWRITE)
    &ngx_http_rewrite_module,
#endif
#if (NGX_HTTP_SSL)
    &ngx_http_ssl_module,
#endif
    &ngx_http_proxy_module,
    &ngx_http_fastcgi_module,
#if (NGX_HTTP_PERL)
    &ngx_http_perl_module,
#endif
    &ngx_http_memcached_module,
    &ngx_http_empty_gif_module,
    &ngx_http_browser_module,
    &ngx_http_flv_module,
    &ngx_http_upstream_ip_hash_module,
#if (NGX_STAT_STUB)
    &ngx_http_stub_status_module,
#endif
#if (NGX_HTTP_GZIP)
    &ngx_http_gzip_static_module,
#endif

    &ngx_http_write_filter_module,
    &ngx_http_header_filter_module,
    &ngx_http_chunked_filter_module,
    &ngx_http_range_header_filter_module,
#if (NGX_HTTP_GZIP)
    &ngx_http_gzip_filter_module,
#endif
    &ngx_http_postpone_filter_module,
    &ngx_http_charset_filter_module,
    &ngx_http_ssi_filter_module,
    &ngx_http_sub_filter_module,
    &ngx_http_addition_filter_module,
    &ngx_http_userid_filter_module,
    &ngx_http_headers_filter_module,
    &ngx_http_copy_filter_module,
    &ngx_http_range_body_filter_module,
    &ngx_http_not_modified_filter_module,
#endif

#if (NGX_MAIL)
    &ngx_mail_module,
    &ngx_mail_core_module,
#if (NGX_MAIL_SSL)
    &ngx_mail_ssl_module,
#endif
    &ngx_mail_pop3_module,
    &ngx_mail_imap_module,
    &ngx_mail_smtp_module,
    &ngx_mail_auth_http_module,
    &ngx_mail_proxy_module,
#endif

    NULL
};
