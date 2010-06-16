
/*
 * Copyright (C) Ngwsx
 */


#ifndef _NGX_FILES_H_INCLUDED_
#define _NGX_FILES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef HANDLE                   ngx_fd_t;

typedef struct {
    u_char                      *name;

    WIN32_FILE_ATTRIBUTE_DATA    attr;
    BY_HANDLE_FILE_INFORMATION   info;

    unsigned                     valid_attr:1;
    unsigned                     valid_info:1;
} ngx_file_info_t;

typedef uint64_t                 ngx_file_uniq_t;


typedef struct {
    HANDLE                       dir;
    WIN32_FIND_DATA              de;

    u_char                       path[MAX_PATH];
    size_t                       len;

    unsigned                     type:8;
    unsigned                     valid_info:1;
    unsigned                     valid_de:1;
} ngx_dir_t;


typedef struct {
    ngx_dir_t                    dir;
    u_char                      *pattern;
    ngx_log_t                   *log;
    ngx_uint_t                   test;
} ngx_glob_t;


#define NGX_INVALID_FILE         ((ngx_fd_t) -1)
#define NGX_FILE_ERROR           -1


ngx_fd_t ngx_open_file(const char *path, int mode, int create, int access);
#define ngx_open_file_n          "CreateFile()"

#define NGX_FILE_RDONLY          GENERIC_READ
#define NGX_FILE_WRONLY          GENERIC_WRITE
#define NGX_FILE_RDWR            GENERIC_READ|GENERIC_WRITE
#define NGX_FILE_CREATE_OR_OPEN  0x01
#define NGX_FILE_OPEN            0x02
#define NGX_FILE_TRUNCATE        0x04
#define NGX_FILE_APPEND          0x08
#define NGX_FILE_NONBLOCK        0x10
#define NGX_FILE_OVERLAPPED      0x20

#define NGX_FILE_DEFAULT_ACCESS  0
#define NGX_FILE_OWNER_ACCESS    0


#define ngx_close_file(fd)       (CloseHandle(fd) == 0 ? NGX_FILE_ERROR : 0)
#define ngx_close_file_n         "CloseHandle()"


#define ngx_delete_file(name)    (DeleteFile(name) == 0 ? NGX_FILE_ERROR : 0)
#define ngx_delete_file_n        "DeleteFile()"


ngx_fd_t ngx_open_tempfile(u_char *name, ngx_uint_t persistent,
    ngx_uint_t access);
#define ngx_open_tempfile_n      "CreateFile()"


ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset);
#define ngx_read_file_n          "ReadFile()"

ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
    off_t offset, ngx_pool_t *pool);


static ngx_inline ssize_t
ngx_read_fd(ngx_fd_t fd, void *buf, size_t n)
{
    ssize_t  size;

    if (ReadFile(fd, buf, (DWORD) n, (LPDWORD) &size, NULL) == 0) {
        return NGX_FILE_ERROR;
    }

    return size;
}
#define ngx_read_fd_n            "ReadFile()"


static ngx_inline ssize_t
ngx_write_fd(ngx_fd_t fd, void *buf, size_t n)
{
    ssize_t  size;

    if (WriteFile(fd, buf, (DWORD) n, (LPDWORD) &size, NULL) == 0) {
        return NGX_FILE_ERROR;
    }

    return size;
}
#define ngx_write_fd_n           "WriteFile()"


#define ngx_write_console        ngx_write_fd


#define ngx_linefeed(p)          do { *p++ = CR; *p++ = LF; } while (0);
#define NGX_LINEFEED_SIZE        2


#define ngx_rename_file(o, n)                                                  \
    (MoveFile((LPCSTR) o, (LPCSTR) n) == 0 ? NGX_FILE_ERROR : 0)
#define ngx_rename_file_n        "MoveFile()"


ngx_err_t ngx_win32_rename_file(ngx_str_t *src, ngx_str_t *to, ngx_log_t *log);


int ngx_change_file_access(const char *n, int a);
#define ngx_change_file_access_n "SetFileAttributes()"


ngx_int_t ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s);
#define ngx_set_file_time_n      "SetFileTime()"


static ngx_inline int
ngx_file_info(u_char *file, ngx_file_info_t *sb)
{
    if (GetFileAttributesEx((LPCSTR) file, GetFileExInfoStandard, &sb->attr)
        == 0)
    {
        return NGX_FILE_ERROR;
    }

    sb->name = file;
    sb->valid_attr = 1;

    return 0;
}
#define ngx_file_info_n          "GetFileAttributesEx()"


static ngx_inline int
ngx_fd_info(ngx_fd_t fd, ngx_file_info_t *sb)
{
    if (GetFileInformationByHandle(fd, &sb->info) == 0) {
        return NGX_FILE_ERROR;
    }

    sb->name = NULL;
    sb->valid_info = 1;

    return 0;
}
#define ngx_fd_info_n            "GetFileInformationByHandle()"


static ngx_inline int
ngx_link_info(u_char *file, ngx_file_info_t *sb)
{
    if (GetFileAttributesEx((LPCSTR) file, GetFileExInfoStandard, &sb->attr)
        == 0)
    {
        return NGX_FILE_ERROR;
    }

    sb->name = file;
    sb->valid_attr = 1;

    return 0;
}
#define ngx_link_info_n          "GetFileAttributesEx()"


static ngx_inline int
ngx_is_dir(ngx_file_info_t *sb)
{
    int  attr;

    if (sb->valid_attr) {
        attr = sb->attr.dwFileAttributes;
    } else {
        attr = sb->info.dwFileAttributes;
    }

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        return 1;
    } else {
        return 0;
    }
}


static ngx_inline int
ngx_is_file(ngx_file_info_t *sb)
{
    int  attr;

    if (sb->valid_attr) {
        attr = sb->attr.dwFileAttributes;
    } else {
        attr = sb->info.dwFileAttributes;
    }

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        return 0;
    } else {
        return 1;
    }
}


#define ngx_is_link(sb)          0
#define ngx_is_exec(sb)          0
#define ngx_file_access(sb)      ((sb)->st_mode & 0777)
off_t ngx_file_size(ngx_file_info_t *sb);
time_t ngx_file_mtime(ngx_file_info_t *sb);
ngx_file_uniq_t ngx_file_uniq(ngx_file_info_t *sb);


#if (NGX_HAVE_CASELESS_FILESYSTEM)

#define ngx_filename_cmp(s1, s2, n)                                            \
    ngx_strncasecmp((char *) s1, (char *) s2, n)

#else

#define ngx_filename_cmp         ngx_memcmp

#endif


#define ngx_realpath(p, r)       strcpy(r, p)
#define ngx_realpath_n           "ngx_realpath()"
#define ngx_getcwd(buf, size)    GetCurrentDirectory(size, (LPSTR) buf)
#define ngx_getcwd_n             "GetCurrentDirectory()"
#define ngx_path_separator(c)    ((c) == '/')

#define NGX_MAX_PATH             MAX_PATH

#define NGX_DIR_MASK_LEN         0


ngx_int_t ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir);
#define ngx_open_dir_n           "FindFirstFile()"


#define ngx_close_dir(d)                                                       \
    (FindClose((d)->dir) == 0 ? NGX_ERROR : 0)
#define ngx_close_dir_n          "FindClose()"


ngx_int_t ngx_read_dir(ngx_dir_t *dir);
#define ngx_read_dir_n           "FindNextFile()"


#define ngx_create_dir(name, access)                                           \
    (CreateDirectory(name, NULL) == 0 ? NGX_FILE_ERROR : 0)
#define ngx_create_dir_n         "CreateDirectory()"


#define ngx_delete_dir(name)                                                   \
    (RemoveDirectory(name) == 0 ? NGX_FILE_ERROR : 0)
#define ngx_delete_dir_n         "RemoveDirectory()"


#define ngx_dir_access(a)        (a | (a & 0444) >> 2)


#define ngx_de_name(dir)         ((u_char *) (dir)->de.cFileName)
#define ngx_de_namelen(dir)      ngx_strlen((dir)->de.cFileName)
#define ngx_de_info(name, dir)   NGX_FILE_ERROR /* stat((const char *) name, &(dir)->info) */
#define ngx_de_info_n            "TODO: ngx_de_info()" /* "stat()" */
#define ngx_de_link_info(name, dir)  NGX_FILE_ERROR /* lstat((const char *) name, &(dir)->info) */
#define ngx_de_link_info_n       "TODO: ngx_de_link_info()" /* "lstat()" */
#define ngx_de_is_dir(dir)                                                     \
    ((dir)->de.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_de_is_file(dir)                                                    \
    !((dir)->de.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
#define ngx_de_is_link(dir)      0 /* (S_ISLNK((dir)->info.st_mode)) */
#define ngx_de_access(dir)       0 /* (((dir)->info.st_mode) & 0777) */
off_t ngx_de_size(ngx_dir_t *dir);
time_t ngx_de_mtime(ngx_dir_t *dir);


static ngx_inline ngx_int_t
ngx_open_glob(ngx_glob_t *gl)
{
    ngx_str_t  name;

    name.len = ngx_strlen(gl->pattern);
    name.data = gl->pattern;

    if (ngx_open_dir(&name, &gl->dir) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
#define ngx_open_glob_n          ngx_open_dir_n

static ngx_inline ngx_int_t
ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
{
    u_char  *p;
    size_t   len;

    if (ngx_read_dir(&gl->dir) != NGX_OK) {
        return NGX_ERROR;
    }

    len = ngx_strlen(gl->dir.de.cFileName);

    p = gl->dir.path + gl->dir.len;
    p = ngx_cpymem(p, gl->dir.de.cFileName, len);
    *p = '\0';

    name->len = gl->dir.len + len;
    name->data = gl->dir.path;

    return NGX_OK;
}

#define ngx_close_glob(gl)       ngx_close_dir(&(gl)->dir)


ngx_err_t ngx_trylock_fd(ngx_fd_t fd);
ngx_err_t ngx_lock_fd(ngx_fd_t fd);
ngx_err_t ngx_unlock_fd(ngx_fd_t fd);

#define ngx_trylock_fd_n         "LockFileEx(LOCKFILE_FAIL_IMMEDIATELY)"
#define ngx_lock_fd_n            "LockFileEx()"
#define ngx_unlock_fd_n          "UnlockFileEx()"


#define ngx_read_ahead(fd, n)    0
#define ngx_read_ahead_n         "ngx_read_ahead_n"


#define ngx_directio_on(fd)      0
#define ngx_directio_on_n        "ngx_directio_on_n"


size_t ngx_fs_bsize(u_char *name);


#define ngx_stderr               GetStdHandle(STD_ERROR_HANDLE)
#define ngx_set_stderr(fd)       (SetStdHandle(STD_ERROR_HANDLE, fd) ? 0 : -1)
#define ngx_set_stderr_n         "SetStdHandle(STD_ERROR_HANDLE)"


#if (NGX_HAVE_FILE_AIO)

ssize_t ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset, ngx_pool_t *pool);

ssize_t ngx_file_aio_write(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset, ngx_pool_t *pool);

extern ngx_uint_t  ngx_file_aio;

#endif


#endif /* _NGX_FILES_H_INCLUDED_ */
