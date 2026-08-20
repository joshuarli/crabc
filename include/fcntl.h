#ifndef _FCNTL_H
#define _FCNTL_H

#include <features.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int open(const char *, int, ...);
int openat(int, const char *, int, ...);
int creat(const char *, unsigned int);
int fcntl(int, int, ...);

#define O_RDONLY   0
#define O_WRONLY   1
#define O_RDWR     2
#define O_CREAT    64
#define O_EXCL     128
#define O_NOCTTY   256
#define O_TRUNC    512
#define O_APPEND   1024
#define O_NONBLOCK 2048
#define O_NOFOLLOW 0x8000
#define O_CLOEXEC  0x80000

#define F_DUPFD  0
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4
#define F_GETLK  5
#define F_SETLK  6
#define F_SETLKW 7
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETOWN_EX 15
#define F_GETOWN_EX 16
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#define F_DUPFD_CLOEXEC 1030

#define FD_CLOEXEC 1

#define O_ACCMODE 3
#define O_DIRECTORY 0x4000
#define O_DSYNC 0x1000
#define O_RSYNC 0x101000
#define O_SYNC 0x101000
#define O_EXEC 0x400000
#define O_SEARCH 0x400000
#define O_TTY_INIT 0

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define AT_EACCESS 0x200
#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_SYMLINK_FOLLOW 0x400
#define AT_REMOVEDIR 0x200
#ifdef _GNU_SOURCE
#define AT_EMPTY_PATH 0x1000
#endif

#define POSIX_FADV_NORMAL 0
#define POSIX_FADV_RANDOM 1
#define POSIX_FADV_SEQUENTIAL 2
#define POSIX_FADV_WILLNEED 3
#define POSIX_FADV_DONTNEED 4
#define POSIX_FADV_NOREUSE 5

/* File mode bits are part of the fcntl.h interface as well as sys/stat.h. */
#ifndef S_IRUSR
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRWXU 0700
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IRWXG 0070
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#define S_IRWXO 0007
#endif

struct flock {
    short l_type;
    short l_whence;
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
};

int posix_fadvise(int, off_t, off_t, int);
int posix_fallocate(int, off_t, off_t);

#ifdef _GNU_SOURCE
#define F_OWNER_TID 0
#define F_OWNER_PID 1
#define F_OWNER_PGRP 2
#define F_OWNER_GID 2

struct f_owner_ex {
    int type;
    pid_t pid;
};

struct file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[];
};

#define MAX_HANDLE_SZ 128
int name_to_handle_at(int, const char *, struct file_handle *, int *, int);
int open_by_handle_at(int, struct file_handle *, int);
#endif

#ifdef __cplusplus
}
#endif

#endif
