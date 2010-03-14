
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_THREADS)


static ngx_uint_t  nthreads;
static ngx_uint_t  max_threads;
static size_t       stack_size;


ngx_err_t
ngx_create_thread(ngx_tid_t *tid, ngx_thread_func_pt func, void *arg,
    ngx_log_t *log)
{
    ngx_err_t  err;

    if (nthreads >= max_threads) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "no more than %ui threads can be created",
                      max_threads);

        return NGX_ERROR;
    }

    tid->handle = CreateThread(NULL, stack_size, func, arg, 0, &tid->tid);
    if (tid->handle == NULL) {
        err = ngx_errno;

        ngx_log_error(NGX_LOG_ALERT, log, err, "CreateThread() failed");

        return err;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0,
                   "CreateThread() h: %p, tid: " NGX_TID_T_FMT,
                   tid->handle, tid->tid);

    nthreads++;

    return NGX_OK;
}


ngx_int_t
ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle)
{
    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "ngx_init_threads(%d, %uz)", n, size);

    max_threads = n;
    stack_size = size;

    ngx_threaded = 1;

    return NGX_OK;
}


ngx_mutex_t *
ngx_mutex_init(ngx_log_t *log, ngx_uint_t flags)
{
    ngx_mutex_t  *m;

    m = ngx_alloc(sizeof(ngx_mutex_t), log);
    if (m == NULL) {
        return NULL;
    }

    __try {

        InitializeCriticalSection(&m->cs);

    } __except (EXCEPTION_EXECUTE_HANDLER) {

        /* raise a STATUS_NO_MEMORY exception */

        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "InitializeCriticalSection() raise a exception");

        ngx_free(m);

        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, log, 0, "init mutex %p", m);

    m->log = log;

    return m;
}


void
ngx_mutex_destroy(ngx_mutex_t *m)
{
    DeleteCriticalSection(&m->cs);

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "destroy mutex %p", m);

    ngx_free(m);
}


void
ngx_mutex_lock(ngx_mutex_t *m)
{
    if (!ngx_threaded) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "lock mutex %p", m);

    EnterCriticalSection(&m->cs);

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);
}


ngx_int_t
ngx_mutex_trylock(ngx_mutex_t *m)
{
    if (!ngx_threaded) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "try lock mutex %p", m);

    if (TryEnterCriticalSection(&m->cs) == 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);

    return NGX_OK;
}


void
ngx_mutex_unlock(ngx_mutex_t *m)
{
    if (!ngx_threaded) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "unlock mutex %p", m);

    LeaveCriticalSection(&m->cs);

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is unlocked", m);

    return;
}


ngx_cond_t *
ngx_cond_init(ngx_log_t *log)
{
    ngx_cond_t  *cv;

    cv = ngx_calloc(sizeof(ngx_cond_t), log);
    if (cv == NULL) {
        return NULL;
    }

    cv->log = log;

    cv->sem = CreateSemaphore(NULL, 0, LONG_MAX, NULL);
    if (cv->sem == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, ngx_errno,
                      "CreateSemaphore() failed");

        ngx_free(cv);

        return NULL;
    }

    __try {
        InitializeCriticalSection(&cv->cs);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ngx_log_error(NGX_LOG_ALERT, cv->log, 0,
                      "InitializeCriticalSection() raise a exception");

        CloseHandle(cv->sem);
        ngx_free(cv);

        return NULL;
    }

    return cv;
}


void
ngx_cond_destroy(ngx_cond_t *cv)
{
    CloseHandle(cv->sem);

    DeleteCriticalSection(&cv->cs);

    ngx_free(cv);
}


ngx_int_t
ngx_cond_wait(ngx_cond_t *cv, ngx_mutex_t *m)
{
    DWORD       res;
    ngx_int_t   rc;
    ngx_uint_t  gens, wake;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p wait", cv);

    wake = 0;

    EnterCriticalSection(&cv->cs);

    cv->waits++;
    gens = cv->gens;

    LeaveCriticalSection(&cv->cs);

    ngx_mutex_unlock(m);

    do {
        res = WaitForSingleObject(cv->sem, INFINITE);

        EnterCriticalSection(&cv->cs);

        if (cv->wakes) {
            if (cv->gens != gens) {
                cv->wakes--;
                cv->waits--;
                rc = NGX_OK;
                break;

            } else {
                wake = 1;
            }

        } else if (res != WAIT_OBJECT_0) {
            ngx_log_error(NGX_LOG_ALERT, cv->log, ngx_errno,
                          "WaitForSingleObject() failed");

            cv->waits--;
            rc = NGX_ERROR;
            break;
        }

        LeaveCriticalSection(&cv->cs);

        if (wake) {
            wake = 0;
            ReleaseSemaphore(cv->sem, 1, NULL);
        }

    } while (TRUE);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is waked up", cv);

    LeaveCriticalSection(&cv->cs);

    ngx_mutex_lock(m);

    ngx_log_debug1(NGX_LOG_DEBUG_MUTEX, m->log, 0, "mutex %p is locked", m);

    return rc;
}


ngx_int_t
ngx_cond_signal(ngx_cond_t *cv)
{
    u_int  wake;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p to signal", cv);

    wake = 0;

    EnterCriticalSection(&cv->cs);

    if (cv->waits > cv->wakes) {
        wake = 1;
        cv->wakes++;
        cv->gens++;
    }

    LeaveCriticalSection(&cv->cs);

    if (wake) {
        ReleaseSemaphore(cv->sem, 1, NULL);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cv->log, 0, "cv %p is signaled", cv);
    }

    return NGX_OK;
}


#endif
