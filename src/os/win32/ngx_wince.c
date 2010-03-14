
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (_WIN32_WCE <= 0x420)
int __security_cookie;
int __security_check_cookie;
#endif


int
MessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
    return 0;
}


DWORD
FormatMessage(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
    DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list *Arguments)
{
    size_t    size, n;
    wchar_t  *buf;

    n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
                       |FORMAT_MESSAGE_FROM_SYSTEM
                       |FORMAT_MESSAGE_IGNORE_INSERTS,
                       lpSource, dwMessageId, dwLanguageId,
                       (LPWSTR) &buf, 0, Arguments);
    if (n == 0) {
        return 0;
    }

    size = WideCharToMultiByte(CP_ACP, 0, buf, n, lpBuffer, nSize, NULL, NULL);

    LocalFree(buf);

    return size;
}


LONG
RegOpenKeyEx(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired,
    PHKEY phkResult)
{
    return 0;
}


LONG
RegQueryValueEx(HKEY hkey, LPCTSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    return 0;
}


DWORD
GetCurrentDirectory(DWORD nBufferLength, LPTSTR lpBuffer)
{
    size_t    size, n;
    u_char   *last;
    wchar_t   buf[NGX_MAX_PATH];

    n = GetModuleFileNameW(NULL, buf, NGX_MAX_PATH);
    if (n == 0) {
        return 0;
    }

    size = WideCharToMultiByte(CP_ACP, 0, buf, n, lpBuffer, nBufferLength,
                               NULL, NULL);
    if (size == 0) {
        return 0;
    }

    last = lpBuffer + size;

    while (last >= lpBuffer) {
        if (*last-- == '\\') {
            last++;
            size = last - lpBuffer;
            ngx_memzero(last + 1, nBufferLength - size);
            break;
        }
    }

    return size;
}


BOOL
CreateDirectory(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    int      rv;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpPathName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = CreateDirectoryW(buf, lpSecurityAttributes);

    return rv;
}


BOOL
RemoveDirectory(LPCTSTR lpPathName)
{
    int      rv;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpPathName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = RemoveDirectoryW(buf);

    return rv;
}


HANDLE
CreateFileMapping(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
    LPCTSTR lpName)
{
    size_t   n;
    HANDLE   hmap;
    wchar_t  buf[NGX_MAX_PATH], *p;

    if (lpName != NULL) {

        n = MultiByteToWideChar(CP_ACP, 0, lpName, -1, buf, NGX_MAX_PATH);
        if (n == 0) {
            return NULL;
        }

        p = buf;

    } else {
        p = NULL;
    }

    hmap = CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect,
                              dwMaximumSizeHigh, dwMaximumSizeLow, p);

    return hmap;
}


HANDLE
CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    size_t   n;
    HANDLE   fd;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return INVALID_HANDLE_VALUE;
    }

    fd = CreateFileW(buf, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                     dwCreationDisposition, dwFlagsAndAttributes,
                     hTemplateFile);

    return fd;
}


BOOL
DeleteFile(LPCTSTR lpFileName)
{
    int      rv;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = DeleteFileW(buf);

    return rv;
}


BOOL
MoveFile(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName)
{
    int      rv;
    size_t   n;
    wchar_t  old_name_buf[NGX_MAX_PATH], new_name_buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpExistingFileName, -1,
                        old_name_buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    n = MultiByteToWideChar(CP_ACP, 0, lpNewFileName, -1,
                        new_name_buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = MoveFileW(old_name_buf, new_name_buf);

    return rv;
}


DWORD
GetFileAttributes(LPCTSTR lpFileName)
{
    int      attr;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return INVALID_FILE_ATTRIBUTES;
    }

    attr = GetFileAttributesW(buf);

    return attr;
}


BOOL
SetFileAttributes(LPCTSTR lpFileName, DWORD dwFileAttributes)
{
    int      rv;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = SetFileAttributesW(buf, dwFileAttributes);

    return rv;
}


BOOL
GetFileAttributesEx(LPCTSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation)
{
    int      rv;
    size_t   n;
    wchar_t  buf[NGX_MAX_PATH];

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return FALSE;
    }

    rv = GetFileAttributesExW(buf, fInfoLevelId, lpFileInformation);

    return rv;
}


HANDLE
FindFirstFile(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
{
    size_t            n;
    HANDLE            fd;
    wchar_t           buf[NGX_MAX_PATH];
    WIN32_FIND_DATAW  wfd;

    n = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, buf, NGX_MAX_PATH);
    if (n == 0) {
        return INVALID_HANDLE_VALUE;
    }

    fd = FindFirstFileW(buf, &wfd);
    if (fd == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }

    lpFindFileData->dwFileAttributes = wfd.dwFileAttributes;
    lpFindFileData->ftCreationTime = wfd.ftCreationTime;
    lpFindFileData->ftLastAccessTime = wfd.ftLastAccessTime;
    lpFindFileData->ftLastWriteTime = wfd.ftLastWriteTime;
    lpFindFileData->nFileSizeHigh = wfd.nFileSizeHigh;
    lpFindFileData->nFileSizeLow = wfd.nFileSizeLow;
#if 0
    lpFindFileData->dwOID = wfd.dwOID;
#endif

    WideCharToMultiByte(CP_ACP, 0, wfd.cFileName, -1, lpFindFileData->cFileName,
                        NGX_MAX_PATH, NULL, NULL);

    return fd;
}


BOOL
FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData)
{
    int               rv;
    WIN32_FIND_DATAW  wfd;

    rv = FindNextFileW(hFindFile, &wfd);
    if (rv == 0) {
        return 0;
    }

    lpFindFileData->dwFileAttributes = wfd.dwFileAttributes;
    lpFindFileData->ftCreationTime = wfd.ftCreationTime;
    lpFindFileData->ftLastAccessTime = wfd.ftLastAccessTime;
    lpFindFileData->ftLastWriteTime = wfd.ftLastWriteTime;
    lpFindFileData->nFileSizeHigh = wfd.nFileSizeHigh;
    lpFindFileData->nFileSizeLow = wfd.nFileSizeLow;
#if 0
    lpFindFileData->dwOID = wfd.dwOID;
#endif

    WideCharToMultiByte(CP_ACP, 0, wfd.cFileName, -1, lpFindFileData->cFileName,
                        NGX_MAX_PATH, NULL, NULL);

    return rv;
}


#if (_WIN32_WCE <= 0x420)

BOOL
LockFileEx(HANDLE hFile, DWORD dwFlags, DWORD dwReserved,
    DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh,
    LPOVERLAPPED lpOverlapped)
{
    /* TODO: */

    return TRUE;
}


BOOL
UnlockFileEx(HANDLE hFile, DWORD dwReserved, DWORD nNumberOfBytesToLockLow,
    DWORD nNumberOfBytesToLockHigh, LPOVERLAPPED lpOverlapped)
{
    /* TODO: */

    return TRUE;
}

#endif
