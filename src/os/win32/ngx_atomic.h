
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_HAVE_ATOMIC_OPS  1


#if (NGX_PTR_SIZE == 8)

typedef int64_t                           ngx_atomic_int_t;
typedef uint64_t                          ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN                  sizeof("-9223372036854775808") - 1


#define ngx_atomic_cmp_set(lock, old, new)                                     \
    (InterlockedCompareExchange64(lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd64(value, add)

#else

typedef int32_t                           ngx_atomic_int_t;
typedef uint32_t                          ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN                  sizeof("-2147483648") - 1


#define ngx_atomic_cmp_set(lock, old, new)                                     \
    (InterlockedCompareExchange((volatile LONG *) lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd(value, add)

#endif


#define ngx_memory_barrier()

#define ngx_cpu_pause()


typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)   *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
