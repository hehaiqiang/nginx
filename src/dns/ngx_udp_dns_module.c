
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_udp.h>
#include <ngx_dbd.h>


#define NGX_DNS_QR_QUERY               0
#define NGX_DNS_QR_RESPONSE            1

#define NGX_DNS_OPCODE_QUERY           0
#define NGX_DNS_OPCODE_IQUERY          1
#define NGX_DNS_OPCODE_STATUS          2

#define NGX_DNS_RA_NOT_AVAIL           0
#define NGX_DNS_RA_AVAIL               1

#define NGX_DNS_RCODE_NO_ERROR         0
#define NGX_DNS_RCODE_FORMAT_ERROR     1
#define NGX_DNS_RCODE_SERVER_FAILURE   2
#define NGX_DNS_RCODE_NAME_ERROR       3
#define NGX_DNS_RCODE_NOT_IMPLEMENTED  4
#define NGX_DNS_RCODE_REFUSED          5


#define NGX_DNS_QTYPE_A                1
#define NGX_DNS_QTYPE_NS               2
#define NGX_DNS_QTYPE_MD               3
#define NGX_DNS_QTYPE_MF               4
#define NGX_DNS_QTYPE_CNAME            5
#define NGX_DNS_QTYPE_SOA              6
#define NGX_DNS_QTYPE_MB               7
#define NGX_DNS_QTYPE_MG               8
#define NGX_DNS_QTYPE_MR               9
#define NGX_DNS_QTYPE_NULL             10
#define NGX_DNS_QTYPE_WKS              11
#define NGX_DNS_QTYPE_PTR              12
#define NGX_DNS_QTYPE_HINFO            13
#define NGX_DNS_QTYPE_MINFO            14
#define NGX_DNS_QTYPE_MX               15
#define NGX_DNS_QTYPE_TXT              16
#define NGX_DNS_QTYPE_AXFR             252
#define NGX_DNS_QTYPE_MAILB            253
#define NGX_DNS_QTYPE_MAILA            254
#define NGX_DNS_QTYPE_ALL              255

#define NGX_DNS_QCLASS_IN              1
#define NGX_DNS_QCLASS_CS              2
#define NGX_DNS_QCLASS_CH              3
#define NGX_DNS_QCLASS_HS              4
#define NGX_DNS_QCLASS_ANY             255


#define NGX_DNS_RR_TYPE_A              1
#define NGX_DNS_RR_TYPE_NS             2
#define NGX_DNS_RR_TYPE_MD             3
#define NGX_DNS_RR_TYPE_MF             4
#define NGX_DNS_RR_TYPE_CNAME          5
#define NGX_DNS_RR_TYPE_SOA            6
#define NGX_DNS_RR_TYPE_MB             7
#define NGX_DNS_RR_TYPE_MG             8
#define NGX_DNS_RR_TYPE_MR             9
#define NGX_DNS_RR_TYPE_NULL           10
#define NGX_DNS_RR_TYPE_WKS            11
#define NGX_DNS_RR_TYPE_PTR            12
#define NGX_DNS_RR_TYPE_HINFO          13
#define NGX_DNS_RR_TYPE_MINFO          14
#define NGX_DNS_RR_TYPE_MX             15
#define NGX_DNS_RR_TYPE_TXT            16

#define NGX_DNS_RR_CLASS_IN            1
#define NGX_DNS_RR_CLASS_CS            2
#define NGX_DNS_RR_CLASS_CH            3
#define NGX_DNS_RR_CLASS_HS            4


#define NGX_DNS_RR_ANSWER              1
#define NGX_DNS_RR_AUTHORITY           2
#define NGX_DNS_RR_ADDITIONAL          3


typedef struct {
    uint16_t               id;

    uint8_t                rd:1;
    uint8_t                tc:1;
    uint8_t                aa:1;
    uint8_t                opcode:4;
    uint8_t                qr:1;

    uint8_t                rcode:4;
    uint8_t                z:3;
    uint8_t                ra:1;

    uint16_t               qdcount;
    uint16_t               ancount;
    uint16_t               nscount;
    uint16_t               arcount;
} ngx_dns_header_t;


typedef struct {
    u_char                 qname[256];
    uint16_t               qtype;
    uint16_t               qclass;
} ngx_dns_question_t;


typedef struct {
    ngx_uint_t             rr_type;

    u_char                 name[256];
    uint16_t               type;
    uint16_t               class;
    uint32_t               ttl;
    uint16_t               rdlength;
    u_char                 rdata[256];
} ngx_dns_rr_t;


typedef struct {
    unsigned               stub;
} ngx_dns_cache_node_t;


typedef struct {
    unsigned               stub;
} ngx_dns_cache_t;


typedef struct {
    ngx_udp_session_t     *session;

    ngx_dns_header_t       header;
    ngx_dns_question_t     question;
    ngx_array_t            rrs;
    ngx_dns_rr_t          *cur_rr;

    ngx_dbd_connection_t  *conn;
    ngx_dbd_query_t       *query;
    ngx_dbd_result_t      *res;
    ngx_dbd_column_t      *col;
    ngx_dbd_row_v2_t      *row;
    ngx_uint_t             cur_row;
    ngx_uint_t             cur_col;
} ngx_udp_dns_ctx_t;


typedef struct {
    ngx_str_t              sql_cmd;
    ngx_str_t              upstream;
} ngx_udp_dns_srv_conf_t;


static ngx_int_t ngx_udp_dns_init_session(ngx_udp_session_t *s);
static void ngx_udp_dns_close_session(ngx_udp_session_t *s);
static void ngx_udp_dns_process_session(ngx_udp_session_t *s);
static void ngx_udp_dns_process_proxy_response(ngx_udp_session_t *s,
    u_char *buf, size_t size);
static void ngx_udp_dns_internal_server_error(ngx_udp_session_t *s);

static ngx_int_t ngx_udp_dns_parse(ngx_udp_session_t *s,
    ngx_udp_dns_ctx_t *ctx, u_char *buf, size_t size);
static u_char *ngx_udp_dns_parse_rr(ngx_array_t *rrs, u_char *p, u_char *last,
    ngx_uint_t type, uint16_t count);
static void ngx_udp_dns_send_response(ngx_udp_session_t *s,
    ngx_udp_dns_ctx_t *ctx);

static ngx_int_t ngx_udp_dns_dbd_init(ngx_udp_session_t *s,
    ngx_udp_dns_ctx_t *ctx);
static void ngx_udp_dns_dbd_conn(void *data);
static void ngx_udp_dns_dbd_query(void *data);
static void ngx_udp_dns_dbd_read_col(void *data);
static void ngx_udp_dns_dbd_read_row(void *data);
static void ngx_udp_dns_dbd_read_field(void *data);

static void *ngx_udp_dns_create_srv_conf(ngx_conf_t *cf);
static char *ngx_udp_dns_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_udp_protocol_t  ngx_udp_dns_protocol = {
    ngx_string("dns"),
    ngx_udp_dns_init_session,
    ngx_udp_dns_close_session,
    ngx_udp_dns_process_session,
    ngx_udp_dns_process_proxy_response,
    ngx_udp_dns_internal_server_error
};


static ngx_command_t  ngx_udp_dns_commands[] = {

    { ngx_string("dns_sql_cmd"),
      NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_dns_srv_conf_t, sql_cmd),
      NULL },

    { ngx_string("dns_upstream"),
      NGX_UDP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_UDP_SRV_CONF_OFFSET,
      offsetof(ngx_udp_dns_srv_conf_t, upstream),
      NULL },

      ngx_null_command
};


static ngx_udp_module_t  ngx_udp_dns_module_ctx = {
    &ngx_udp_dns_protocol,                 /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_udp_dns_create_srv_conf,           /* create server configuration */
    ngx_udp_dns_merge_srv_conf             /* merge server configuration */
};


ngx_module_t  ngx_udp_dns_module = {
    NGX_MODULE_V1,
    &ngx_udp_dns_module_ctx,               /* module context */
    ngx_udp_dns_commands,                  /* module directives */
    NGX_UDP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_udp_dns_init_session(ngx_udp_session_t *s)
{
    ngx_udp_dns_ctx_t  *ctx;

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_udp_dns_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_udp_set_ctx(s, ctx, ngx_udp_dns_module);

    if (ngx_array_init(&ctx->rrs, s->connection->pool, 16, sizeof(ngx_dns_rr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->session = s;

    return NGX_OK;
}


static void
ngx_udp_dns_close_session(ngx_udp_session_t *s)
{
    ngx_udp_dns_ctx_t  *ctx;

    ctx = ngx_udp_get_module_ctx(s, ngx_udp_dns_module);

    if (ctx->conn != NULL) {

        if (ctx->row != NULL) {
            ngx_dbd_row_destroy(ctx->conn->drv, ctx->row);
        }

        if (ctx->col != NULL) {
            ngx_dbd_column_destroy(ctx->conn->drv, ctx->col);
        }

        if (ctx->res != NULL) {
            ngx_dbd_result_destroy(ctx->conn->drv, ctx->res);
        }

        if (ctx->query != NULL) {
            ngx_dbd_query_destroy(ctx->conn->drv, ctx->query);
        }

        ngx_dbd_free_connection(ctx->conn);
    }
}


static void
ngx_udp_dns_process_session(ngx_udp_session_t *s)
{
    ngx_int_t           rc;
    ngx_udp_dns_ctx_t  *ctx;

    ctx = ngx_udp_get_module_ctx(s, ngx_udp_dns_module);

    rc = ngx_udp_dns_parse(s, ctx, s->buffer->pos,
                           s->buffer->last - s->buffer->pos);
    if (rc != NGX_OK) {
        ngx_udp_close_connection(s->connection);
        return;
    }

    /* TODO: ctx->header.qdcount */

    if (ctx->header.qdcount < 1) {
        ngx_udp_close_connection(s->connection);
        return;
    }

    /* TODO: query dns cache */

#if 0
    switch (ctx->question.qtype) {

    case NGX_DNS_QTYPE_A:
        rc = ngx_udp_dns_dbd_init(s, ctx);
        if (rc != NGX_OK) {
            ngx_udp_internal_server_error(s);
            return;
        }
        break;

    case NGX_DNS_QTYPE_NS:
    case NGX_DNS_QTYPE_MD:
    case NGX_DNS_QTYPE_MF:
    case NGX_DNS_QTYPE_CNAME:
    case NGX_DNS_QTYPE_SOA:
    case NGX_DNS_QTYPE_MB:
    case NGX_DNS_QTYPE_MG:
    case NGX_DNS_QTYPE_MR:
    case NGX_DNS_QTYPE_NULL:
    case NGX_DNS_QTYPE_WKS:

    case NGX_DNS_QTYPE_PTR:
        ctx->answer.rdlength = sizeof("ns2.51ddns.com") - 1;
        ngx_memcpy(ctx->answer.rdata, "ns2.51ddns.com", ctx->answer.rdlength);
        ngx_udp_dns_send_response(s, ctx);
        return;

    case NGX_DNS_QTYPE_HINFO:
    case NGX_DNS_QTYPE_MINFO:
    case NGX_DNS_QTYPE_MX:
    case NGX_DNS_QTYPE_TXT:
    case NGX_DNS_QTYPE_AXFR:
    case NGX_DNS_QTYPE_MAILB:
    case NGX_DNS_QTYPE_MAILA:
    case NGX_DNS_QTYPE_ALL:
    default:
        ngx_udp_close_connection(s->connection);
        return;
    }
#endif

    rc = ngx_udp_dns_dbd_init(s, ctx);
    if (rc != NGX_OK) {
        ngx_udp_internal_server_error(s);
        return;
    }
}


static void
ngx_udp_dns_process_proxy_response(ngx_udp_session_t *s, u_char *buf,
    size_t size)
{
    ngx_int_t           rc;
    ngx_udp_dns_ctx_t  *ctx;

    ctx = ngx_udp_get_module_ctx(s, ngx_udp_dns_module);

    rc = ngx_udp_dns_parse(s, ctx, buf, size);
    if (rc != NGX_OK) {
        ngx_udp_internal_server_error(s);
        return;
    }

    /* TODO: adding record to dns cache */

    ngx_udp_send(s->connection, buf, size);

    ngx_udp_close_connection(s->connection);
}


static void
ngx_udp_dns_internal_server_error(ngx_udp_session_t *s)
{
    /* TODO: send failed response */
}


static ngx_int_t
ngx_udp_dns_parse(ngx_udp_session_t *s, ngx_udp_dns_ctx_t *ctx, u_char *buf,
    size_t size)
{
    u_char              *p, *last, *name, len;
    ngx_dns_header_t    *header;
    ngx_dns_question_t  *question;
    enum {
        sw_header = 0,
        sw_question,
        sw_answer,
        sw_authority,
        sw_additional,
        sw_error,
        sw_done
    } state;

    header = &ctx->header;
    question = &ctx->question;

    ctx->rrs.nelts = 0;

    p = buf;
    last = p + size;

    state = sw_header;

    for ( ;; ) {

        switch (state) {

        case sw_header:
            if (last - p < sizeof(ngx_dns_header_t)) {
                state = sw_error;
            }

            ngx_memcpy(header, p, sizeof(ngx_dns_header_t));
            p += sizeof(ngx_dns_header_t);

            header->id = ntohs(header->id);
            header->qdcount = ntohs(header->qdcount);
            header->ancount = ntohs(header->ancount);
            header->nscount = ntohs(header->nscount);
            header->arcount = ntohs(header->arcount);

            state = sw_question;
            break;

        case sw_question:
            if (header->qdcount < 1) {
                state = sw_answer;
                break;
            }

            if (last - p < 1) {
                state = sw_error;
                break;
            }

            name = question->qname;

            for ( ;; ) {
                len = *p++;

                if (len > 0) {
                    if (last - p <= len) {
                        state = sw_error;
                        break;
                    }

                    name = ngx_cpymem(name, p, len);
                    *name++ = '.';

                    p += len;

                } else {
                    break;
                }
            }

            if (state == sw_error) {
                break;
            }

            if (name-- != question->qname) {
                *name = '\0';
            }

            if (last - p < 4) {
                state = sw_error;
                break;
            }

            question->qtype = ntohs(*(uint16_t *) p);
            p += 2;

            question->qclass = ntohs(*(uint16_t *) p);
            p += 2;

            state = sw_answer;
            break;

        case sw_answer:
            if (header->ancount < 1) {
                state = sw_authority;
                break;
            }

            p = ngx_udp_dns_parse_rr(&ctx->rrs, p, last, NGX_DNS_RR_ANSWER,
                                     header->ancount);
            if (p == NULL) {
                state = sw_error;
                break;
            }

            state = sw_authority;
            break;

        case sw_authority:
            if (header->nscount < 1) {
                state = sw_additional;
                break;
            }

            p = ngx_udp_dns_parse_rr(&ctx->rrs, p, last, NGX_DNS_RR_AUTHORITY,
                                     header->nscount);
            if (p == NULL) {
                state = sw_error;
                break;
            }

            state = sw_additional;
            break;

        case sw_additional:
            if (header->arcount < 1) {
                state = sw_done;
                break;
            }

            p = ngx_udp_dns_parse_rr(&ctx->rrs, p, last, NGX_DNS_RR_ADDITIONAL,
                                     header->arcount);
            if (p == NULL) {
                state = sw_error;
                break;
            }

            state = sw_done;
            break;

        case sw_error:
            return NGX_ERROR;

        case sw_done:
            if (p != last) {
                state = sw_error;
                break;
            }

            return NGX_OK;
        }
    }
}


static u_char *
ngx_udp_dns_parse_rr(ngx_array_t *rrs, u_char *p, u_char *last, ngx_uint_t type,
    uint16_t count)
{
    size_t         len;
    ngx_uint_t     i;
    ngx_dns_rr_t  *rr;

    /* the size of name, type, class, ttl and rdlength */

    len = 2 + 2 + 2 + 4 + 2;

    if (last - p < (ssize_t) (len * count)) {
        return NULL;
    }

    rr = ngx_array_push_n(rrs, count);
    if (rr == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {

        if (last - p < (ssize_t) len) {
            return NULL;
        }

        rr[i].rr_type = type;

        rr[i].name[0] = *p++;
        rr[i].name[1] = *p++;
        rr[i].name[2] = '\0';

        rr[i].type = ntohs(*(uint16_t *) p);
        p += 2;

        rr[i].class = ntohs(*(uint16_t *) p);
        p += 2;

        rr[i].ttl = ntohl(*(uint32_t *) p);
        p += 4;

        rr[i].rdlength = ntohs(*(uint16_t *) p);
        p += 2;

        /* TODO: xxx */

        if (last - p < rr[i].rdlength) {
            return NULL;
        }

        ngx_memcpy(rr[i].rdata, p, rr[i].rdlength);
        p += rr[i].rdlength;
    }

    return p;
}


static void
ngx_udp_dns_send_response(ngx_udp_session_t *s, ngx_udp_dns_ctx_t *ctx)
{
    u_char              *p, *start, len;
    size_t               size;
    uint16_t             rdlength;
    ngx_uint_t           i;
    ngx_buf_t           *b;
    ngx_dns_rr_t        *rrs;
    ngx_dns_header_t    *header;
    ngx_dns_question_t  *question;

    /* creating response */

    b = ngx_create_temp_buf(s->connection->pool, ngx_pagesize);
    if (b == NULL) {
        ngx_udp_close_connection(s->connection);
        return;
    }

    header = &ctx->header;
    question = &ctx->question;

    switch (question->qtype) {

    case NGX_DNS_QTYPE_A:

        /* header */

        header->id = htons(header->id);

        header->rd = 0;
        header->aa = 1;
        header->qr = NGX_DNS_QR_RESPONSE;
        header->rcode = NGX_DNS_RCODE_NO_ERROR;
        header->ra = NGX_DNS_RA_AVAIL;

        header->qdcount = htons(header->qdcount);
        header->ancount = htons(1);
        header->nscount = htons(0);
        header->arcount = htons(0);

        b->last = ngx_cpymem(b->last, header, sizeof(ngx_dns_header_t));

        /* question */

        p = question->qname;
        start = p;
        len = 0;

        for ( ;; ) {

            if (*p == '.') {
                *b->last++ = len;
                b->last = ngx_cpymem(b->last, start, len);

                start = p + 1;
                len = 0;

            } else if (*p == '\0') {
                if (len == 0) {
                    break;
                }

                *b->last++ = len;
                b->last = ngx_cpymem(b->last, start, len);

                break;

            } else {
                len++;
            }

            p++;
        }

        *b->last++ = '\0';

        question->qtype = htons(question->qtype);
        question->qclass = htons(question->qclass);

        b->last = ngx_cpymem(b->last, &question->qtype, sizeof(uint16_t));
        b->last = ngx_cpymem(b->last, &question->qclass, sizeof(uint16_t));

        /* answer, authority, additional */

        rrs = ctx->rrs.elts;

        for (i = 0; i < ctx->rrs.nelts; i++) {

            rrs[i].ttl = htonl(rrs[i].ttl);

            rdlength = rrs[i].rdlength;
            rrs[i].rdlength = htons(rdlength);

            b->last = ngx_cpymem(b->last, rrs[i].name, 2);
            b->last = ngx_cpymem(b->last, &rrs[i].type, sizeof(uint16_t));
            b->last = ngx_cpymem(b->last, &rrs[i].class, sizeof(uint16_t));
            b->last = ngx_cpymem(b->last, &rrs[i].ttl, sizeof(uint32_t));
            b->last = ngx_cpymem(b->last, &rrs[i].rdlength, sizeof(uint16_t));
            b->last = ngx_cpymem(b->last, rrs[i].rdata, rdlength);
        }

        break;

    case NGX_DNS_QTYPE_NS:
    case NGX_DNS_QTYPE_MD:
    case NGX_DNS_QTYPE_MF:
    case NGX_DNS_QTYPE_CNAME:
    case NGX_DNS_QTYPE_SOA:
    case NGX_DNS_QTYPE_MB:
    case NGX_DNS_QTYPE_MG:
    case NGX_DNS_QTYPE_MR:
    case NGX_DNS_QTYPE_NULL:
    case NGX_DNS_QTYPE_WKS:
    case NGX_DNS_QTYPE_PTR:
    case NGX_DNS_QTYPE_HINFO:
    case NGX_DNS_QTYPE_MINFO:
    case NGX_DNS_QTYPE_MX:
    case NGX_DNS_QTYPE_TXT:
    case NGX_DNS_QTYPE_AXFR:
    case NGX_DNS_QTYPE_MAILB:
    case NGX_DNS_QTYPE_MAILA:
    case NGX_DNS_QTYPE_ALL:
    default:
        break;
    }

    /* sending response */

    size = b->last - b->pos;

    if (size > 0) {
        ngx_udp_send(s->connection, b->pos, size);
    }

    ngx_udp_close_connection(s->connection);
}


static ngx_int_t
ngx_udp_dns_dbd_init(ngx_udp_session_t *s, ngx_udp_dns_ctx_t *ctx)
{
    ngx_dbd_connection_t    *c;
    ngx_udp_dns_srv_conf_t  *dscf;

    dscf = ngx_udp_get_module_srv_conf(s, ngx_udp_dns_module);

    c = ngx_dbd_get_connection_by_command(&dscf->sql_cmd);
    if (c == NULL) {
        return NGX_ERROR;
    }

    ctx->conn = c;

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_conn, ctx);

    ngx_udp_dns_dbd_conn(ctx);

    return NGX_OK;
}


static void
ngx_udp_dns_dbd_conn(void *data)
{
    ngx_udp_dns_ctx_t *ctx = data;

    u_char                *buf, *last;
    ngx_int_t              rc;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_conn_connect(c->drv, c->conn);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    /* rc == NGX_OK */

    ctx->query = ngx_dbd_query_create(c->drv, c->conn);
    if (ctx->query == NULL) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    buf = ngx_palloc(ctx->session->connection->pool, ngx_pagesize);
    if (buf == NULL) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    last = ngx_snprintf(buf, ngx_pagesize, c->sql->data,
                        ctx->question.qname, 1);

    ngx_dbd_query_set_string(c->drv, ctx->query, buf, last - buf);

    ctx->res = ngx_dbd_result_create(c->drv, c->conn);
    if (ctx->res == NULL) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_query, ctx);

    ngx_udp_dns_dbd_query(ctx);
}


static void
ngx_udp_dns_dbd_query(void *data)
{
    ngx_udp_dns_ctx_t *ctx = data;

    ngx_int_t              rc;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    rc = ngx_dbd_query_result(c->drv, ctx->query, ctx->res);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    /* rc == NGX_OK */

    ctx->col = ngx_dbd_column_create(c->drv, ctx->res);
    if (ctx->col == NULL) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    ctx->row = ngx_dbd_row_create(c->drv, ctx->res);
    if (ctx->row == NULL) {
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_read_col, ctx);

    ngx_udp_dns_dbd_read_col(ctx);
}


static void
ngx_udp_dns_dbd_read_col(void *data)
{
    ngx_udp_dns_ctx_t *ctx = data;

    ngx_int_t              rc;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    for ( ;; ) {

        rc = ngx_dbd_column_read(c->drv, ctx->col);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_udp_internal_server_error(ctx->session);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */
    }

    /* rc == NGX_DONE */

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_read_row, ctx);

    ngx_udp_dns_dbd_read_row(ctx);
}


static void
ngx_udp_dns_dbd_read_row(void *data)
{
    ngx_udp_dns_ctx_t *ctx = data;

    ngx_int_t                rc;
    ngx_url_t                u;
    ngx_dbd_connection_t    *c;
    ngx_udp_dns_srv_conf_t  *dscf;

    c = ctx->conn;

    for ( ;; ) {

        rc = ngx_dbd_row_read(c->drv, ctx->row);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_udp_internal_server_error(ctx->session);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        ctx->cur_rr = ngx_array_push(&ctx->rrs);
        if (ctx->cur_rr == NULL) {
            ngx_udp_internal_server_error(ctx->session);
            return;
        }

        ctx->cur_rr->name[0] = 0xC0;
        ctx->cur_rr->name[1] = 0x0C;
        ctx->cur_rr->name[2] = '\0';
        ctx->cur_rr->type = ctx->question.qtype;
        ctx->cur_rr->class = ctx->question.qclass;

        ctx->cur_row++;
        ctx->cur_col = 0;

        ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_read_field,
                                 ctx);

        ngx_udp_dns_dbd_read_field(ctx);

        return;
    }

    /* rc == NGX_DONE */

    if (ctx->cur_row > 0) {

        /* TODO: adding record to dns cache */

        ngx_udp_dns_send_response(ctx->session, ctx);
        return;
    }

    /* query from upstream */

    dscf = ngx_udp_get_module_srv_conf(ctx->session, ngx_udp_dns_module);

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = dscf->upstream;
    u.port = 53;

    if (ngx_inet_resolve_host(ctx->session->connection->pool, &u) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, ctx->session->connection->log, 0,
                      "%V: %s", &u.host, u.err);
        ngx_udp_internal_server_error(ctx->session);
        return;
    }

    ngx_udp_proxy_init(ctx->session, &u.addrs[0]);
}


static void
ngx_udp_dns_dbd_read_field(void *data)
{
    ngx_udp_dns_ctx_t *ctx = data;

    off_t                  offset;
    u_char                *value;
    size_t                 size, total;
    uint32_t               ttl;
    in_addr_t              addr;
    ngx_int_t              rc;
    ngx_dbd_connection_t  *c;

    c = ctx->conn;

    for ( ;; ) {

        rc = ngx_dbd_field_read(c->drv, ctx->row, &value, &offset, &size,
                                &total);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_udp_internal_server_error(ctx->session);
            return;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* rc == NGX_OK */

        switch (ctx->cur_col) {

        case 0:
            addr = ngx_inet_addr(value, size);
            ngx_memcpy(ctx->cur_rr->rdata, &addr, sizeof(in_addr_t));
            ctx->cur_rr->rdlength = sizeof(in_addr_t);
            break;
        case 1:
            break;
        case 2:
            ttl = ngx_atoi(value, size);
            if (ttl == NGX_ERROR) {
                ttl = 3600;
            }
            ctx->cur_rr->ttl = ttl;
            break;
        }

        ctx->cur_col++;
    }

    /* rc == NGX_DONE */

    ngx_dbd_conn_set_handler(c->drv, c->conn, ngx_udp_dns_dbd_read_row, ctx);

    ngx_udp_dns_dbd_read_row(ctx);
}


static void *
ngx_udp_dns_create_srv_conf(ngx_conf_t *cf)
{
    ngx_udp_dns_srv_conf_t  *dscf;

    dscf = ngx_pcalloc(cf->pool, sizeof(ngx_udp_dns_srv_conf_t));
    if (dscf == NULL) {
        return NULL;
    }

    return dscf;
}


static char *
ngx_udp_dns_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_udp_dns_srv_conf_t *prev = parent;
    ngx_udp_dns_srv_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->sql_cmd, prev->sql_cmd, "dns_sql_cmd");
    ngx_conf_merge_str_value(conf->upstream, prev->upstream, "202.96.128.86");

    return NGX_CONF_OK;
}
