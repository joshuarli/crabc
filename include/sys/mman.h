#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define PROT_NONE   0x0

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANON      0x20
#define MAP_ANONYMOUS MAP_ANON
#define MAP_FAILED    ((void *)-1)

void *mmap(void *, size_t, int, int, int, off_t);
int munmap(void *, size_t);
int mprotect(void *, size_t, int);
int mlock(const void *, size_t);
int munlock(const void *, size_t);
int mlockall(int);
int munlockall(void);
int msync(void *, size_t, int);
int posix_madvise(void *, size_t, int);

#ifdef _GNU_SOURCE
int mlock2(const void *, size_t, unsigned);
int remap_file_pages(void *, size_t, int, size_t, int);
#define MLOCK_ONFAULT 0x01U
#endif

#define MS_ASYNC 1
#define MS_INVALIDATE 2
#define MS_SYNC 4
#define MCL_CURRENT 1
#define MCL_FUTURE 2
#define POSIX_MADV_NORMAL 0
#define POSIX_MADV_RANDOM 1
#define POSIX_MADV_SEQUENTIAL 2
#define POSIX_MADV_WILLNEED 3
#define POSIX_MADV_DONTNEED 4

int shm_open(const char *, int, mode_t);
int shm_unlink(const char *);

#ifdef __cplusplus
}
#endif

#endif
