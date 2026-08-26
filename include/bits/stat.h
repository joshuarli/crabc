#ifndef _BITS_STAT_H
#define _BITS_STAT_H

/* Linux/x86-64 struct stat, copied from the kernel-shaped musl ABI. */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "crabc x86-64 bits/stat.h requires LP64 x86-64"
#endif

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;
    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    unsigned int __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

#endif
