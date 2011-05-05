
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_FILE_AIO)

ngx_uint_t  ngx_file_aio = 1;

#endif


ngx_fd_t
ngx_open_file(u_char *path, int mode, int create, int access)
{
    int       da, sm, cd, fa;
    ngx_fd_t  fd;

    /* Desired Access */

    if (mode & NGX_FILE_TRUNCATE) {
        da = NGX_FILE_WRONLY;
    } else if (mode & NGX_FILE_APPEND) {
        da = NGX_FILE_WRONLY;
    } else {
        da = mode;
    }

    /* TODO: Share Mode */

    sm = FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;

    /* Creation Disposition */

    if (create & NGX_FILE_OPEN) {
        cd = OPEN_EXISTING;

    } else {
        cd = OPEN_ALWAYS;
    }

    /* TODO: Flags And Attributes */

    fa = FILE_ATTRIBUTE_NORMAL|FILE_FLAG_BACKUP_SEMANTICS;

    if (mode & NGX_FILE_OVERLAPPED) {
        fa |= FILE_FLAG_OVERLAPPED;
    }

    fd = CreateFile((LPCTSTR) path, da, sm, NULL, cd, fa, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        return NGX_INVALID_FILE;
    }

    if (mode & NGX_FILE_TRUNCATE) {
        if (SetEndOfFile(fd) == 0) {
            CloseHandle(fd);
            return NGX_INVALID_FILE;
        }

    } else if (mode & NGX_FILE_APPEND) {
        if (SetFilePointer(fd, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
            CloseHandle(fd);
            return NGX_INVALID_FILE;
        }
    }

    return fd;
}


ssize_t
ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t        n;
    LARGE_INTEGER  li, lirv;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "ReadFile: %p, %p, %uz, %O", file->fd, buf, size, offset);

    if (file->sys_offset != offset) {
        li.QuadPart = offset;
        lirv.QuadPart = 0;

        if (SetFilePointerEx(file->fd, li, &lirv, FILE_BEGIN) == 0) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "SetFilePointerEx() failed");
            return NGX_ERROR;
        }

        file->sys_offset = (off_t) lirv.QuadPart;
    }

    if (ReadFile(file->fd, buf, (DWORD) size, (LPDWORD) &n, NULL) == 0) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "ReadFile() failed");
        return NGX_ERROR;
    }

    file->sys_offset += (off_t) n;
    file->offset += (off_t) n;

    return n;
}


ssize_t
ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t        n;
    LARGE_INTEGER  li, lirv;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "WriteFile: %P, %p, %uz, %O", file->fd, buf, size, offset);

    if (file->sys_offset != offset) {
        li.QuadPart = offset;
        lirv.QuadPart = 0;

        if (SetFilePointerEx(file->fd, li, &lirv, FILE_BEGIN) == 0) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "SetFilePointerEx() failed");
            return NGX_ERROR;
        }

        file->sys_offset = (off_t) lirv.QuadPart;
    }

    if (WriteFile(file->fd, buf, (DWORD) size, (LPDWORD) &n, NULL) == 0) {
        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "WriteFile() failed");
        return NGX_ERROR;
    }

    if (n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                      "WriteFile() has written only %z of %uz", n, size);
        return NGX_ERROR;
    }

    file->sys_offset += (off_t) n;
    file->offset += (off_t) n;

    return n;
}


ngx_fd_t
ngx_open_tempfile(u_char *name, ngx_uint_t persistent, ngx_uint_t access)
{
    int       sm;
    u_char    buf[NGX_MAX_PATH], c, *p, *last;
    ngx_fd_t  fd;

    p = buf;
    last = ngx_cpymem(p, name, ngx_strlen(name));

    while (p < last) {
        if (*p == '\\' || *p == '/') {
            c = *p;
            *p = '\0';

            ngx_create_dir(buf, 0);

            *p = c;
        }

        p++;
    }

    /* TODO: Share Mode */

    sm = FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;

    fd = CreateFile((LPCTSTR) name, NGX_FILE_RDWR, sm, NULL, CREATE_NEW,
                    persistent ? FILE_ATTRIBUTE_NORMAL
                    : FILE_FLAG_DELETE_ON_CLOSE, NULL);

    return fd;
}


#define NGX_IOVS  8


ssize_t
ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
    ngx_pool_t *pool)
{
#if (NGX_WINCE)
    off_t           new_offset;
#endif
    WSABUF         *iov, iovs[NGX_IOVS];
    u_char         *prev;
    size_t          size;
    ssize_t         n, written;
#if (NGX_WINCE)
    ngx_err_t       err;
#endif
    ngx_uint_t      i;
    ngx_array_t     vec;
#if !(NGX_WINCE)
    LARGE_INTEGER   li, lirv;
#endif

    if (file->sys_offset != offset) {
#if !(NGX_WINCE)
        li.QuadPart = offset;
        lirv.QuadPart = 0;

        if (SetFilePointerEx(file->fd, li, &lirv, FILE_BEGIN) == 0) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                          "SetFilePointerEx() failed");
            return NGX_ERROR;
        }

        file->sys_offset = (off_t) lirv.QuadPart;
#else

        new_offset = SetFilePointer(file->fd, offset, NULL, FILE_BEGIN);
        err = ngx_errno;
        if (new_offset == 0xFFFFFFFF && err != NO_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, file->log, err,
                          "SetFilePointer() failed");
            return NGX_ERROR;
        }

        file->sys_offset = new_offset;
#endif
    }

    vec.elts = iovs;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NGX_IOVS;
    vec.pool = pool;

    written = 0;

    do {
        prev = NULL;
        iov = NULL;
        size = 0;

        vec.nelts = 0;

        /* create the iovec and coalesce the neighbouring bufs */

        while (cl && vec.nelts < IOV_MAX) {
            if (prev == cl->buf->pos) {
                iov->len += (u_long) (cl->buf->last - cl->buf->pos);

            } else {
                iov = ngx_array_push(&vec);
                if (iov == NULL) {
                    return NGX_ERROR;
                }

                iov->buf = (void *) cl->buf->pos;
                iov->len = (u_long) (cl->buf->last - cl->buf->pos);
            }

            size += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
            cl = cl->next;
        }

        iov = vec.elts;

        for (i = 0; i < vec.nelts; i++) {

            if (WriteFile(file->fd, iov[i].buf, iov[i].len, (LPDWORD) &n, NULL)
                == 0)
            {
                ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                              "WriteFile() failed");
                return NGX_ERROR;
            }

            if (n != (ssize_t) iov[i].len) {
                ngx_log_error(NGX_LOG_CRIT, file->log, 0,
                              "WriteFile() has written only %z of %uz",
                              n, iov[i].len);
                return NGX_ERROR;
            }

            written += n;
        }

    } while (cl);

    file->sys_offset += (off_t) written;
    file->offset += (off_t) written;

    return written;
}


ngx_err_t
ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_log_t *log)
{
    u_char             *name;
    ngx_err_t           err;
    ngx_uint_t          collision;
    ngx_atomic_uint_t   num;

    name = ngx_alloc(to->len + 1 + 10 + 1 + sizeof("DELETE"), log);
    if (name == NULL) {
        return NGX_ENOMEM;
    }

    ngx_memcpy(name, to->data, to->len);

    collision = 0;

    /* mutex_lock() (per cache or single ?) */

    for ( ;; ) {
        num = ngx_next_temp_number(collision);

        ngx_sprintf(name + to->len, ".%0muA.DELETE%Z", num);

        if (MoveFile((const char *) to->data, (const char *) name) != 0) {
            break;
        }

        collision = 1;

        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "MoveFile() \"%s\" to \"%s\" failed", to->data, name);
    }

    if (MoveFile((const char *) from->data, (const char *) to->data) == 0) {
        err = ngx_errno;

    } else {
        err = 0;
    }

    if (DeleteFile((const char *) name) == 0) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "DeleteFile() \"%s\" failed", name);
    }

    /* mutex_unlock() */

    ngx_free(name);

    return err;
}


int
ngx_change_file_access(const char *n, int a)
{
    DWORD  attr;

    attr = GetFileAttributes(n);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return NGX_FILE_ERROR;
    }

    if (a & S_IWRITE) {
        attr &= ~FILE_ATTRIBUTE_READONLY;

    } else {
        attr |= FILE_ATTRIBUTE_READONLY;
    }

    if (!SetFileAttributes(n, attr)) {
        return NGX_FILE_ERROR;
    }

    return 0;
}


ngx_int_t
ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
{
    FILETIME   atime, mtime;
    ULONGLONG  usec;

    usec = s;
    usec += 11644473600000000LL;
    usec *= 10;

    atime.dwLowDateTime = (DWORD) usec;
    atime.dwHighDateTime = (DWORD) (usec >> 32);

    mtime.dwLowDateTime = (DWORD) usec;
    mtime.dwHighDateTime = (DWORD) (usec >> 32);

    if (SetFileTime(fd, NULL, &atime, &mtime) == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


off_t
ngx_file_size(ngx_file_info_t *sb)
{
    off_t  size;

    if (sb->valid_info) {
        size = sb->info.nFileSizeHigh;
        size <<= 32;
        size |= sb->info.nFileSizeLow;

    } else if (sb->valid_attr) {
        size = sb->attr.nFileSizeHigh;
        size <<= 32;
        size |= sb->attr.nFileSizeLow;

    } else {
        return -1;
    }

    return size;
}


time_t
ngx_file_mtime(ngx_file_info_t *sb)
{
    ULONGLONG  usec;

    if (sb->valid_info) {
        usec = sb->info.ftLastWriteTime.dwHighDateTime;
        usec <<= 32;
        usec |= sb->info.ftLastWriteTime.dwLowDateTime;

    } else if (sb->valid_attr) {
        usec = sb->attr.ftLastWriteTime.dwHighDateTime;
        usec <<= 32;
        usec |= sb->attr.ftLastWriteTime.dwLowDateTime;

    } else {
        return -1;
    }

    usec /= 10;
    usec -= 11644473600000000LL;

    return (time_t) usec;
}


ngx_file_uniq_t
ngx_file_uniq(ngx_file_info_t *sb)
{
    ngx_fd_t         fd;
    ngx_file_uniq_t  uniq;

    if (sb->valid_info == 0) {
        fd = ngx_open_file(sb->name, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                           NGX_FILE_DEFAULT_ACCESS);
        if (fd == NGX_INVALID_FILE) {
            return 0;
        }

        if (GetFileInformationByHandle(fd, &sb->info) == 0) {
            ngx_close_file(fd);
            return 0;
        }

        ngx_close_file(fd);
    }

    uniq = sb->info.nFileIndexHigh;
    uniq <<= 32;
    uniq |= sb->info.nFileIndexLow;

    return uniq;
}


ngx_int_t
ngx_create_file_mapping(ngx_file_mapping_t *fm)
{
#if 0
    fm->fd = ngx_open_file(fm->name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
                           NGX_FILE_DEFAULT_ACCESS);
    if (fm->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", fm->name);
        return NGX_ERROR;
    }

    if (ftruncate(fm->fd, fm->size) == -1) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      "ftruncate() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    fm->fd, 0);
    if (fm->addr != MAP_FAILED) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                  "mmap(%uz) \"%s\" failed", fm->size, fm->name);

failed:

    if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", fm->name);
    }
#endif

    return NGX_ERROR;
}


void
ngx_close_file_mapping(ngx_file_mapping_t *fm)
{
#if 0
    if (munmap(fm->addr, fm->size) == -1) {
        ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
                      "munmap(%uz) \"%s\" failed", fm->size, fm->name);
    }

    if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", fm->name);
    }
#endif
}


off_t
ngx_de_size(ngx_dir_t *dir)
{
    off_t  size;

    size = dir->de.nFileSizeHigh;
    size <<= 32;
    size |= dir->de.nFileSizeLow;

    return size;
}


time_t
ngx_de_mtime(ngx_dir_t *dir)
{
    ULONGLONG  usec;

    usec = dir->de.ftLastWriteTime.dwHighDateTime;
    usec <<= 32;
    usec |= dir->de.ftLastWriteTime.dwLowDateTime;
    usec -= 116444736000000000LL;
    usec /= 10000000;

    return (time_t) usec;
}


ngx_int_t
ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
{
    u_char  *p, *last;

    last = ngx_cpymem(dir->path, name->data, name->len);
    *last = '\0';

    if (ngx_strlchr(dir->path, last, '*') == NULL) {
        p = last - 1;

        if (*p != '\\' || *p != '/') {
            *last++ = '/';
        }

        dir->len = last - dir->path;

        *last++ = '*';
        *last = '\0';

    } else {

        while (last > dir->path) {

            if (*last == '\\' || *last == '/') {
                dir->len = last - dir->path + 1;
                break;
            }

            last--;
        }
    }

    dir->dir = FindFirstFile((LPCTSTR) dir->path, &dir->de);

    if (dir->dir == INVALID_HANDLE_VALUE) {
        return NGX_ERROR;
    }

    dir->valid_de = 1;
    dir->valid_info = 1;

    return NGX_OK;
}


ngx_int_t
ngx_read_dir(ngx_dir_t *d)
{
    if (d->valid_de) {
        d->valid_de = 0;
        return NGX_OK;
    }

    if (FindNextFile(d->dir, &d->de) == 0) {
        return NGX_ERROR;
    }

    d->valid_info = 1;

    return NGX_OK;
}


ngx_err_t
ngx_trylock_fd(ngx_fd_t fd)
{
    OVERLAPPED  ovlp = { 0 };

    if (LockFileEx(fd, LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY, 0,
                   0xffffffff, 0xffffffff, &ovlp)
        == 0)
    {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_lock_fd(ngx_fd_t fd)
{
    OVERLAPPED  ovlp = { 0 };

    if (LockFileEx(fd, LOCKFILE_EXCLUSIVE_LOCK, 0, 0xffffffff, 0xffffffff,
                   &ovlp)
        == 0)
    {
        return ngx_errno;
    }

    return 0;
}


ngx_err_t
ngx_unlock_fd(ngx_fd_t fd)
{
    OVERLAPPED  ovlp = { 0 };

    if (UnlockFileEx(fd, 0, 0xffffffff, 0xffffffff, &ovlp) == 0) {
        return ngx_errno;
    }

    return 0;
}


#if (NGX_HAVE_STATFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_bsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_bsize;
}

#elif (NGX_HAVE_STATVFS)

size_t
ngx_fs_bsize(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_frsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_frsize;
}

#else

size_t
ngx_fs_bsize(u_char *name)
{
    return 512;
}

#endif
