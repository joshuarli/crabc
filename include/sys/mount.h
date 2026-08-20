#ifndef _SYS_MOUNT_H
#define _SYS_MOUNT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define MS_RDONLY      1UL
#define MS_NOSUID      2UL
#define MS_NODEV       4UL
#define MS_NOEXEC      8UL
#define MS_SYNCHRONOUS 16UL
#define MS_REMOUNT     32UL
#define MS_MANDLOCK    64UL
#define MS_DIRSYNC     128UL
#define MS_NOSYMFOLLOW 256UL
#define MS_NOATIME     1024UL
#define MS_NODIRATIME  2048UL
#define MS_BIND        4096UL
#define MS_MOVE        8192UL
#define MS_REC         16384UL
#define MS_SILENT      32768UL
#define MS_POSIXACL    (1UL << 16)
#define MS_UNBINDABLE  (1UL << 17)
#define MS_PRIVATE     (1UL << 18)
#define MS_SLAVE       (1UL << 19)
#define MS_SHARED      (1UL << 20)
#define MS_RELATIME    (1UL << 21)
#define MS_KERNMOUNT   (1UL << 22)
#define MS_I_VERSION   (1UL << 23)
#define MS_STRICTATIME (1UL << 24)
#define MS_LAZYTIME    (1UL << 25)
#define MS_NOREMOTELOCK (1UL << 27)
#define MS_NOSEC       (1UL << 28)
#define MS_BORN        (1UL << 29)
#define MS_ACTIVE      (1UL << 30)
#define MS_NOUSER      (1UL << 31)
#define MS_RMT_MASK    (MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | \
                       MS_I_VERSION | MS_LAZYTIME)
#define MS_MGC_VAL     0xc0ed0000UL
#define MS_MGC_MSK     0xffff0000UL

#define MNT_FORCE       1
#define MNT_DETACH      2
#define MNT_EXPIRE      4
#define UMOUNT_NOFOLLOW 8

int mount(const char *, const char *, const char *, unsigned long, const void *);
int umount(const char *);
int umount2(const char *, int);
int pivot_root(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif
