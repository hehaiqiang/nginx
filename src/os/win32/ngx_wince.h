
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_WINCE_H_INCLUDED_
#define _NGX_WINCE_H_INCLUDED_


#if (_WIN32_WCE <= 0x420)

#define INVALID_FILE_ATTRIBUTES    0xFFFFFFFF

#define LOCKFILE_EXCLUSIVE_LOCK    0

#define LOCKFILE_FAIL_IMMEDIATELY  0

#endif


#undef GetVersionEx
#undef MessageBox
#undef FormatMessage
#undef RegOpenKeyEx
#undef RegQueryValueEx
#undef GetCurrentDirectory
#undef CreateDirectory
#undef RemoveDirectory
#undef CreateFileMapping
#undef CreateFile
#undef DeleteFile
#undef MoveFile
#undef GetFileAttributes
#undef SetFileAttributes
#undef GetFileAttributesEx
#undef FindFirstFile
#undef FindNextFile


BOOL GetVersionEx(LPOSVERSIONINFO lpVersionInformation);

int MessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

DWORD FormatMessage(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId,
    DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list *Arguments);

LONG RegOpenKeyEx(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions,
    REGSAM samDesired, PHKEY phkResult);

LONG RegQueryValueEx(HKEY hkey, LPCTSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

DWORD GetCurrentDirectory(DWORD nBufferLength, LPTSTR lpBuffer);

BOOL CreateDirectory(LPCTSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes);

BOOL RemoveDirectory(LPCTSTR lpPathName);

HANDLE CreateFileMapping(HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);

HANDLE CreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL DeleteFile(LPCTSTR lpFileName);

BOOL MoveFile(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName);

DWORD GetFileAttributes(LPCTSTR lpFileName);

BOOL SetFileAttributes(LPCTSTR lpFileName, DWORD dwFileAttributes);

BOOL GetFileAttributesEx(LPCTSTR lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);

HANDLE FindFirstFile(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData);

BOOL FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData);


#if (_WIN32_WCE <= 0x420)

BOOL LockFileEx(HANDLE hFile, DWORD dwFlags, DWORD dwReserved,
    DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh,
    LPOVERLAPPED lpOverlapped);

BOOL UnlockFileEx(HANDLE hFile, DWORD dwReserved, DWORD nNumberOfBytesToLockLow,
    DWORD nNumberOfBytesToLockHigh, LPOVERLAPPED lpOverlapped);

#endif


#endif /* _NGX_WINCE_H_INCLUDED_ */
