
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WIN32_H_INCLUDED_
#define _NGX_WIN32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_dlfcn.h>
#include <ngx_win32_service.h>


/*
 * Windows 7                 6.1  (601)
 * Windows Server 2008 R2    6.1  (601)
 * Windows Server 2008       6.0  (600)
 * Windows Vista             6.0  (600)
 * Windows Server 2003 R2    5.2  (502)
 * Windows Server 2003       5.2  (502)
 * Windows XP                5.1  (501)
 * Windows 2000              5.0  (500)
 * Windows Me                4.90 (490)
 * Windows 98                4.10 (410)
 * Windows NT 4.0            4.0  (400)
 * Windows 95                4.0  (400)
 * Windows CE
 */

#define NGX_WIN32_VER_601  601
#define NGX_WIN32_VER_600  600
#define NGX_WIN32_VER_502  502
#define NGX_WIN32_VER_501  501
#define NGX_WIN32_VER_500  500
#define NGX_WIN32_VER_400  400


void ngx_event_log(ngx_err_t err, const char *fmt, ...);

ngx_int_t ngx_file_append_mode(ngx_fd_t fd);
#define ngx_file_append_mode_n  "SetFilePointer"

#if 1
#define ngx_win32_rename_file(src, to, log)  NGX_OK
#else
ngx_int_t ngx_win32_rename_file(ngx_str_t *src, ngx_str_t *to, ngx_log_t *log);
#endif

ngx_int_t ngx_message_box(u_char *caption, ngx_uint_t type, ngx_err_t err,
    const char *fmt, ...);


/* win32 sendfile */

ngx_chain_t *ngx_transmitfile_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
ngx_chain_t *ngx_transmitpackets_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);


/*
 * AcceptEx,TransmitFile:
 *     NT,2000,XP,2003,Vista,2008
 * ConnectEx,DisconnectEx,TransmitPackets:
 *     XP,Vista,2003,2008
 * GetAcceptExSockaddrs:
 *     95,98,Me,NT,2000,XP,2003,Vista,2008
 * GetQueuedCompletionStatusEx:
 *     Vista,2008
 */


#if (_MSC_VER < 1500)

typedef struct _OVERLAPPED_ENTRY {
    ULONG_PTR       lpCompletionKey;
    LPOVERLAPPED    lpOverlapped;
    ULONG_PTR       Internal;
    DWORD           dwNumberOfBytesTransferred;
} OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;

#endif


typedef BOOL (WINAPI *LPFN_GETQUEUEDCOMPLETIONSTATUSEX)(HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries, ULONG ulCount,
    PULONG ulNumEntriesRemoved, DWORD dwMilliseconds, BOOL fAlertable);


extern LPFN_ACCEPTEX                     ngx_acceptex;
extern LPFN_CONNECTEX                    ngx_connectex;
extern LPFN_DISCONNECTEX                 ngx_disconnectex;
extern LPFN_TRANSMITFILE                 ngx_transmit_file;
extern LPFN_TRANSMITPACKETS              ngx_transmit_packets;
extern LPFN_GETACCEPTEXSOCKADDRS         ngx_get_acceptex_sockaddrs;
extern LPFN_GETQUEUEDCOMPLETIONSTATUSEX  ngx_get_queued_completion_status_ex;


extern ngx_fd_t                          ngx_stderr_fileno;
extern ngx_uint_t                        ngx_win32_ver;

extern HINSTANCE                         ngx_inst;


#endif /* _NGX_WIN32_H_INCLUDED_ */
