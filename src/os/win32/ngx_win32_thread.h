
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_THREAD_H_INCLUDED_
#define _NGX_WIN32_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    DWORD   tid;
    HANDLE  handle;
} ngx_tid_t;

#define ngx_thread_self()  GetCurrentThreadId()
#define ngx_log_tid        ngx_thread_self()

#define NGX_TID_T_FMT      "%d"


typedef DWORD  ngx_tls_key_t;

static ngx_inline int
ngx_thread_key_create(ngx_tls_key_t *key)
{
    DWORD  index;

    index = TlsAlloc();
    if (index == TLS_OUT_OF_INDEXES) {
        return ngx_errno;
    }

    *key = index;

    return 0;
}

#define ngx_thread_key_create_n      "TlsAlloc()"
#define ngx_thread_set_tls(key, value)                                        \
    (TlsSetValue(key, value) ? 0 : ngx_errno)
#define ngx_thread_set_tls_n         "TlsSetValue()"
#define ngx_thread_get_tls(key)      TlsGetValue(key)


#define NGX_MUTEX_LIGHT  0

typedef struct {
    CRITICAL_SECTION   cs;
    ngx_log_t         *log;
} ngx_mutex_t;

typedef struct {
    CRITICAL_SECTION   cs;
    HANDLE             sem;
    ngx_uint_t         waits;
    ngx_uint_t         wakes;
    ngx_uint_t         gens;
    ngx_log_t         *log;
} ngx_cond_t;

#define ngx_thread_sigmask
#define ngx_thread_sigmask_n

#define ngx_thread_join(t, p)                                                 \
    (WaitForSingleObject((t).handle, INFINITE) == WAIT_OBJECT_0 ? 0 : ngx_errno)

#define ngx_setthrtitle(n)


ngx_int_t ngx_mutex_trylock(ngx_mutex_t *m);
void ngx_mutex_lock(ngx_mutex_t *m);
void ngx_mutex_unlock(ngx_mutex_t *m);


typedef DWORD  ngx_thread_value_t;
typedef ngx_thread_value_t (WINAPI *ngx_thread_func_pt)(void *arg);


#endif /* _NGX_WIN32_THREAD_H_INCLUDED_ */
