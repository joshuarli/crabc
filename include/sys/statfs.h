#ifndef _CRABC_SYS_STATFS_H
#define _CRABC_SYS_STATFS_H

#include <sys/types.h>
#include <sys/statvfs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __fsid_t { int __val[2]; } fsid_t;
struct statfs {
    unsigned long f_type;
    unsigned long f_bsize;
    fsblkcnt_t f_blocks, f_bfree, f_bavail;
    fsfilcnt_t f_files, f_ffree;
    fsid_t f_fsid;
    unsigned long f_namelen, f_frsize, f_flags;
    unsigned long f_spare[4];
};
int statfs(const char *, struct statfs *);
int fstatfs(int, struct statfs *);

#if defined(_LARGEFILE64_SOURCE)
#define statfs64 statfs
#define fstatfs64 fstatfs
#define fsblkcnt64_t fsblkcnt_t
#define fsfilcnt64_t fsfilcnt_t
#endif

#ifdef __cplusplus
}
#endif

#endif
