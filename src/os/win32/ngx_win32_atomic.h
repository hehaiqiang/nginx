
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_ATOMIC_H_INCLUDED_
#define _NGX_WIN32_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HAVE_ATOMIC_OPS  1


#if (NGX_PTR_SIZE == 8)

typedef LONGLONG                          ngx_atomic_int_t;
typedef ULONGLONG                         ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN                  sizeof("-9223372036854775808") - 1


#define ngx_atomic_cmp_set(lock, old, new)                                     \
    (InterlockedCompareExchange64(lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd64(value, add)

#else

typedef LONG                              ngx_atomic_int_t;
typedef ULONG                             ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN                  sizeof("-2147483648") - 1


#define ngx_atomic_cmp_set(lock, old, new)                                     \
    (InterlockedCompareExchange((volatile LONG *) lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd(value, add)

#endif


#define ngx_memory_barrier()

#define ngx_cpu_pause()

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


#endif /* _NGX_WIN32_ATOMIC_H_INCLUDED_ */
