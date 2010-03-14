
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


#define ngx_atomic_cmp_set(lock, old, new)                                    \
    (InterlockedCompareExchange64(lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd64(value, add)

/*
 * TODO:
 * replace InterlockedCompareExchange64 with InterlockedCompareExchangePointer
 */
#if 0
#define ngx_atomic_cmp_set_ptr(value, old, new)                               \
    (InterlockedCompareExchange64((volatile LONGLONG *) (value),              \
                                  (LONGLONG) *((LONGLONG *) &(new)),          \
                                  (LONGLONG) *((LONGLONG *) &(old)))          \
     == (LONGLONG) *((LONGLONG *) &(old)))

#define ngx_atomic_set(value, new)        InterlockedExchange64(value, new)

/* TODO: replace InterlockedExchange64 with InterlockedExchangePointer */

#define ngx_atomic_set_ptr(value, new)                                        \
    InterlockedExchange64((volatile LONGLONG *) (value),                      \
                          (LONGLONG) *((LONGLONG *) &(new)))
#endif

#else

typedef LONG                              ngx_atomic_int_t;
typedef ULONG                             ngx_atomic_uint_t;
#define NGX_ATOMIC_T_LEN                  sizeof("-2147483648") - 1


#if !(NGX_WINCE)

#define ngx_atomic_cmp_set(lock, old, new)                                    \
    (InterlockedCompareExchange((volatile LONG *) lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)  InterlockedExchangeAdd(value, add)

#else

#define ngx_atomic_cmp_set(lock, old, new)                                    \
    (InterlockedCompareExchange((LONG *) lock, new, old) == (old))

#define ngx_atomic_fetch_add(value, add)                                      \
    InterlockedExchangeAdd((LONG *) value, add)

#endif


/*
 * TODO:
 * replace InterlockedCompareExchange with InterlockedCompareExchangePointer
 */
#if 0
#define ngx_atomic_cmp_set_ptr(value, old, new)                               \
    (InterlockedCompareExchange((volatile LONG *) (value),                    \
                                (LONG) *((LONG *) &(new)),                    \
                                (LONG) *((LONG *) &(old)))                    \
     == (LONG) *((LONG *) &(old)))

#define ngx_atomic_set(value, new)        InterlockedExchange(value, new)

/* TODO: replace InterlockedExchange with InterlockedExchangePointer */

#define ngx_atomic_set_ptr(value, new)                                        \
    InterlockedExchange((volatile LONG *) (value), (LONG) *((LONG *) &(new)))
#endif

#endif


#define ngx_memory_barrier()

#define ngx_cpu_pause()

typedef volatile ngx_atomic_uint_t  ngx_atomic_t;


#endif /* _NGX_WIN32_ATOMIC_H_INCLUDED_ */
