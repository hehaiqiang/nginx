
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_ATOMIC_H_INCLUDED_
#define _NGX_ATOMIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_win32_atomic.h>


void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);

#define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
#define ngx_unlock(lock)    *(lock) = 0


#endif /* _NGX_ATOMIC_H_INCLUDED_ */
