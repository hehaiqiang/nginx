
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_ERRNO_H_INCLUDED_
#define _NGX_ERRNO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef int               ngx_err_t;

#define NGX_EPERM         EPERM
#define NGX_ENOENT        ENOENT
#define NGX_ENOPATH       ENOENT
#define NGX_ESRCH         ESRCH
#define NGX_EINTR         EINTR
#define NGX_ECHILD        ECHILD
#define NGX_ENOMEM        ENOMEM
#define NGX_EACCES        EACCES
#define NGX_EBUSY         EBUSY
#define NGX_EEXIST        EEXIST
#define NGX_EXDEV         EXDEV
#define NGX_ENOTDIR       ENOTDIR
#define NGX_EISDIR        EISDIR
#define NGX_EINVAL        EINVAL
#define NGX_ENOSPC        ENOSPC
#define NGX_EPIPE         EPIPE
#define NGX_EAGAIN        EAGAIN
#define NGX_EINPROGRESS   EINPROGRESS
#define NGX_EADDRINUSE    EADDRINUSE
#define NGX_ECONNABORTED  ECONNABORTED
#define NGX_ECONNRESET    ECONNRESET
#define NGX_ENOTCONN      ENOTCONN
#define NGX_ETIMEDOUT     ETIMEDOUT
#define NGX_ECONNREFUSED  ECONNREFUSED
#define NGX_ENAMETOOLONG  ENAMETOOLONG
#define NGX_ENETDOWN      ENETDOWN
#define NGX_ENETUNREACH   ENETUNREACH
#define NGX_EHOSTDOWN     EHOSTDOWN
#define NGX_EHOSTUNREACH  EHOSTUNREACH
#define NGX_ENOSYS        ENOSYS
#define NGX_ECANCELED     ECANCELED
#define NGX_EILSEQ        EILSEQ
#define NGX_ENOMOREFILES  ERROR_NO_MORE_FILES



#define ngx_errno                  (int) GetLastError()
#define ngx_socket_errno           WSAGetLastError()
#define ngx_set_errno(err)         SetLastError((DWORD) err)
#define ngx_set_socket_errno(err)  WSASetLastError(err)


u_char *ngx_strerror_r(int err, u_char *errstr, size_t size);


#if 0
#define NGX_IS_EPERM(err)    (err == ERROR_CANNOT_MAKE                        \
                              || err == ERROR_NOT_OWNER)
#define NGX_IS_ENOENT(err)   (err == ERROR_FILE_NOT_FOUND                     \
                              || err == ERROR_PATH_NOT_FOUND                  \
                              || err == ERROR_INVALID_NAME                    \
                              || err == ERROR_BAD_PATHNAME                    \
                              || err == ERROR_MOD_NOT_FOUND)
#define NGX_IS_ESRCH(err)    (err == ERROR_PROC_NOT_FOUND)
#define NGX_IS_EINTR(err)    (err == WSAEINTR                                 \
                              || err == ERROR_INVALID_AT_INTERRUPT_TIME)
#define NGX_IS_ECHILD(err)   (err == ERROR_WAIT_NO_CHILDREN)
#define NGX_IS_ENOMEM(err)   (err == ERROR_NOT_ENOUGH_MEMORY                  \
                              || err == ERROR_OUTOFMEMORY)
#define NGX_IS_EACCES(err)   (err == ERROR_ACCESS_DENIED                      \
                              || err == ERROR_LOCK_VIOLATION)
#define NGX_IS_EBUSY(err)    (err == ERROR_BUSY                               \
                              || err == ERROR_CHILD_NOT_COMPLETE              \
                              || err == ERROR_PIPE_BUSY                       \
                              || err == ERROR_PIPE_CONNECTED                  \
                              || err == ERROR_SHARING_VIOLATION               \
                              || err == ERROR_SIGNAL_PENDING)
#define NGX_IS_EEXIST(err)   (err == ERROR_ALREADY_EXISTS                     \
                              || err == ERROR_FILE_EXISTS)
#define NGX_IS_ENOTDIR(err)  (err == ERROR_DIRECTORY)
#define NGX_EISDIR           0 /* TODO: EISDIR */
#define NGX_IS_EINVAL(err)   (err == ERROR_INVALID_PARAMETER                  \
                              || err == WSAEINVAL                             \
                              || err == ERROR_INVALID_DATA                    \
                              || err == ERROR_INVALID_ADDRESS                 \
                              || err == ERROR_SEEK                            \
                              || err == ERROR_NEGATIVE_SEEK                   \
                              || err == ERROR_INVALID_SIGNAL_NUMBER           \
                              || err == ERROR_BAD_PIPE                        \
                              || err == ERROR_BAD_USERNAME                    \
                              || err == ERROR_META_EXPANSION_TOO_LONG         \
                              || err == ERROR_NO_TOKEN                        \
                              || err == ERROR_THREAD_1_INACTIVE               \
                              || err == ERROR_SECTOR_NOT_FOUND)
#define NGX_IS_ENOSPC(err)   (err == ERROR_DISK_FULL                          \
                              || err == ERROR_HANDLE_DISK_FULL                \
                              || err == ERROR_END_OF_MEDIA)
#define NGX_IS_EPIPE(err)    (err == ERROR_BROKEN_PIPE                        \
                              || err == ERROR_NO_DATA)
#define NGX_IS_EAGAIN(err)   (err == WSAEWOULDBLOCK                           \
                              || err == ERROR_IO_PENDING                      \
                              || err == ERROR_OPEN_FILES                      \
                              || err == ERROR_DEVICE_IN_USE                   \
                              || err == ERROR_NO_SYSTEM_RESOURCES             \
                              || err == ERROR_COMMITMENT_LIMIT                \
                              || err == ERROR_MAX_THRDS_REACHED               \
                              || err == ERROR_NONPAGED_SYSTEM_RESOURCES       \
                              || err == ERROR_PAGED_SYSTEM_RESOURCES          \
                              || err == ERROR_PAGEFILE_QUOTA                  \
                              || err == ERROR_WORKING_SET_QUOTA               \
                              || err == ERROR_NO_PROC_SLOTS                   \
                              || err == ERROR_ACTIVE_CONNECTIONS)
#define NGX_EINPROGRESS      WSAEINPROGRESS
#define NGX_EADDRINUSE       WSAEADDRINUSE
#define NGX_ECONNABORTED     WSAECONNABORTED
#define NGX_ECONNRESET       WSAECONNRESET
#define NGX_ENOTCONN         WSAENOTCONN
#define NGX_ETIMEDOUT        WSAETIMEDOUT
#define NGX_ECONNREFUSED     WSAECONNREFUSED
#define NGX_IS_ENAMETOOLONG(err)                                              \
                             (err == WSAENAMETOOLONG                          \
                              || err == ERROR_FILENAME_EXCED_RANGE)
#define NGX_ENETDOWN         WSAENETDOWN
#define NGX_ENETUNREACH      WSAENETUNREACH
#define NGX_EHOSTDOWN        WSAEHOSTDOWN
#define NGX_EHOSTUNREACH     WSAEHOSTUNREACH
#define NGX_IS_ENOSYS(err)   (err == ERROR_CALL_NOT_IMPLEMENTED               \
                              || err == ERROR_NOT_SUPPORTED)
#define NGX_IS_ECANCELED     ECANCELED
#define NGX_IS_ENOMOREFILES(err)                                              \
    (err == ERROR_NO_MORE_FILES || err == ERROR_NO_MORE_ITEMS)
#endif


#endif /* _NGX_ERRNO_H_INCLUDED_ */
