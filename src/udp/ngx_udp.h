
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_UDP_H_INCLUDED_
#define _NGX_UDP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#if (NGX_UDP_SSL)
#include <ngx_udp_ssl_module.h>
#endif


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_udp_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_udp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_UDP_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_udp_listen_t;


typedef struct {
    ngx_udp_conf_ctx_t     *ctx;
    ngx_str_t               addr_text;
#if (NGX_UDP_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ngx_udp_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_udp_addr_conf_t     conf;
} ngx_udp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_udp_addr_conf_t     conf;
} ngx_udp_in6_addr_t;

#endif


typedef struct {
    /* ngx_udp_in_addr_t or ngx_udp_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_udp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_udp_conf_addr_t */
} ngx_udp_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_udp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_UDP_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_udp_conf_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_udp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_udp_listen_t */
} ngx_udp_core_main_conf_t;


typedef struct ngx_udp_protocol_s  ngx_udp_protocol_t;


typedef struct {
    ngx_udp_protocol_t     *protocol;

    size_t                  connection_pool_size;
    size_t                  client_buffer_size;

    u_char                 *file_name;
    ngx_int_t               line;

    /* server ctx */
    ngx_udp_conf_ctx_t     *ctx;
} ngx_udp_core_srv_conf_t;


typedef struct {
    ngx_udp_connection_t    uc;
    ngx_buf_t              *buffer;
} ngx_udp_proxy_t;


typedef struct {
    ngx_connection_t       *connection;

    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_udp_proxy_t        *proxy;

    ngx_str_t              *addr_text;
    ngx_str_t               host;
} ngx_udp_session_t;


typedef struct {
    ngx_str_t              *client;
    ngx_udp_session_t      *session;
} ngx_udp_log_ctx_t;


typedef ngx_int_t (*ngx_udp_init_session_pt)(ngx_udp_session_t *s);
typedef void (*ngx_udp_close_session_pt)(ngx_udp_session_t *s);
typedef void (*ngx_udp_process_session_pt)(ngx_udp_session_t *s);
typedef void (*ngx_udp_process_proxy_response_pt)(ngx_udp_session_t *s,
    u_char *buf, size_t size);
typedef void (*ngx_udp_internal_server_error_pt)(ngx_udp_session_t *s);


struct ngx_udp_protocol_s {
    ngx_str_t                          name;
    ngx_udp_init_session_pt            init_session;
    ngx_udp_close_session_pt           close_session;
    ngx_udp_process_session_pt         process_session;
    ngx_udp_process_proxy_response_pt  process_proxy_response;
    ngx_udp_internal_server_error_pt   internal_server_error;
};


typedef struct {
    ngx_udp_protocol_t         *protocol;

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                                  void *conf);
} ngx_udp_module_t;


#define NGX_UDP_MODULE         0x00504455     /* "UDP" */

#define NGX_UDP_MAIN_CONF      0x02000000
#define NGX_UDP_SRV_CONF       0x04000000


#define NGX_UDP_MAIN_CONF_OFFSET  offsetof(ngx_udp_conf_ctx_t, main_conf)
#define NGX_UDP_SRV_CONF_OFFSET   offsetof(ngx_udp_conf_ctx_t, srv_conf)


#define ngx_udp_get_module_ctx(s, module)  (s)->ctx[module.ctx_index]
#define ngx_udp_set_ctx(s, c, module)      (s)->ctx[module.ctx_index] = c
#define ngx_udp_delete_ctx(s, module)      (s)->ctx[module.ctx_index] = NULL


#define ngx_udp_get_module_main_conf(s, module)                                \
    (s)->main_conf[module.ctx_index]
#define ngx_udp_get_module_srv_conf(s, module)   (s)->srv_conf[module.ctx_index]

#define ngx_udp_conf_get_module_main_conf(cf, module)                          \
    ((ngx_udp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_udp_conf_get_module_srv_conf(cf, module)                           \
    ((ngx_udp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (NGX_UDP_SSL)
void ngx_udp_starttls_handler(ngx_event_t *rev);
ngx_int_t ngx_udp_starttls_only(ngx_udp_session_t *s, ngx_connection_t *c);
#endif


void ngx_udp_init_connection(ngx_connection_t *c);
ssize_t ngx_udp_send(ngx_connection_t *c, u_char *buf, size_t size);
void ngx_udp_close_connection(ngx_connection_t *c);
void ngx_udp_internal_server_error(ngx_udp_session_t *s);

void ngx_udp_proxy_init(ngx_udp_session_t *s, ngx_addr_t *peer);


extern ngx_uint_t    ngx_udp_max_module;
extern ngx_module_t  ngx_udp_core_module;


#endif /* _NGX_UDP_H_INCLUDED_ */
