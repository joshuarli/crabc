/* Pinned-musl/raw Linux/x86-64 pathname lifecycle and metadata reference. */

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 struct stat layout");
_Static_assert(offsetof(struct stat, st_dev) == 0 &&
                   offsetof(struct stat, st_ino) == 8 &&
                   offsetof(struct stat, st_nlink) == 16 &&
                   offsetof(struct stat, st_mode) == 24 &&
                   offsetof(struct stat, st_uid) == 28 &&
                   offsetof(struct stat, st_gid) == 32 &&
                   offsetof(struct stat, st_size) == 48 &&
                   offsetof(struct stat, st_blksize) == 56 &&
                   offsetof(struct stat, st_blocks) == 64 &&
                   offsetof(struct stat, st_atim) == 72 &&
                   offsetof(struct stat, st_mtim) == 88 &&
                   offsetof(struct stat, st_ctim) == 104,
               "x86 struct stat offsets");
_Static_assert(SYS_openat == 257 && SYS_mkdirat == 258 && SYS_mknodat == 259 &&
                   SYS_fchownat == 260 && SYS_newfstatat == 262 &&
                   SYS_unlinkat == 263 && SYS_fchmodat == 268 &&
                   SYS_fchmod == 91 && SYS_fchown == 93 && SYS_truncate == 76 &&
                   AT_FDCWD == -100 && AT_SYMLINK_NOFOLLOW == 0x100,
               "x86 pathname lifecycle syscall constants");

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode) {
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
static int raw_statat(int dirfd, const char *path, struct stat *st, int flags) {
    return (int)syscall(SYS_newfstatat, dirfd, path, st, flags);
}
static int raw_mkdirat(int dirfd, const char *path, mode_t mode) {
    return (int)syscall(SYS_mkdirat, dirfd, path, mode);
}
static int raw_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev) {
    return (int)syscall(SYS_mknodat, dirfd, path, mode, dev);
}
static int raw_unlinkat(int dirfd, const char *path, int flags) {
    return (int)syscall(SYS_unlinkat, dirfd, path, flags);
}
static int raw_fchmod(int fd, mode_t mode) {
    return (int)syscall(SYS_fchmod, fd, mode);
}
static int raw_fchmodat(int dirfd, const char *path, mode_t mode, int flags) {
    return (int)syscall(SYS_fchmodat, dirfd, path, mode, flags);
}
static int raw_fchown(int fd, uid_t uid, gid_t gid) {
    return (int)syscall(SYS_fchown, fd, uid, gid);
}
static int raw_fchownat(int dirfd, const char *path, uid_t uid, gid_t gid,
                        int flags) {
    return (int)syscall(SYS_fchownat, dirfd, path, uid, gid, flags);
}
static int raw_truncate(const char *path, off_t length) {
    return (int)syscall(SYS_truncate, path, length);
}

static int same_record(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_nlink == b->st_nlink && a->st_mode == b->st_mode &&
           a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
           a->st_size == b->st_size && a->st_blocks == b->st_blocks;
}

int main(void) {
    char template[] = "/tmp/crabc-x86-path-lifecycle-XXXXXX";
    char absolute[sizeof(template) + sizeof("/record")];
    char *root = mkdtemp(template);
    struct stat musl_st, raw_st;
    int dirfd = -1, fd = -1, rawfd = -1, status = 0;
    uid_t uid = geteuid();
    gid_t gid = getegid();

    if (root == NULL) return 2;
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) { status = 3; goto cleanup; }

    fd = openat(dirfd, "record", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0640);
    if (fd < 0 || write(fd, "record", 6) != 6) { status = 4; goto cleanup; }
    if (fstatat(dirfd, "record", &musl_st, 0) != 0 ||
        raw_statat(dirfd, "record", &raw_st, 0) != 0 ||
        !same_record(&musl_st, &raw_st) || !S_ISREG(musl_st.st_mode) ||
        musl_st.st_size != 6 || (musl_st.st_mode & 0777) != 0640) {
        status = 5; goto cleanup;
    }
    if (snprintf(absolute, sizeof(absolute), "%s/record", root) < 0 ||
        truncate(absolute, 3) != 0 || raw_truncate(absolute, 1) != 0 ||
        fstat(fd, &musl_st) != 0 || musl_st.st_size != 1) {
        status = 6; goto cleanup;
    }

    if (symlinkat("record", dirfd, "link") != 0 ||
        fstatat(dirfd, "link", &musl_st, 0) != 0 ||
        raw_statat(dirfd, "link", &raw_st, 0) != 0 ||
        !S_ISREG(musl_st.st_mode) || !same_record(&musl_st, &raw_st) ||
        fstatat(dirfd, "link", &musl_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        raw_statat(dirfd, "link", &raw_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(musl_st.st_mode) || !same_record(&musl_st, &raw_st)) {
        status = 7; goto cleanup;
    }

    if (fchmod(fd, 0600) != 0 || raw_fchmod(fd, 0640) != 0 ||
        fchmodat(dirfd, "record", 0600, 0) != 0 ||
        raw_fchmodat(dirfd, "record", 0640, 0) != 0 ||
        fstat(fd, &musl_st) != 0 || (musl_st.st_mode & 0777) != 0640) {
        status = 8; goto cleanup;
    }
    /* Same-owner/group no-op changes avoid privilege-dependent ownership. */
    if (fchown(fd, uid, gid) != 0 || raw_fchown(fd, uid, gid) != 0 ||
        fchownat(dirfd, "record", uid, gid, 0) != 0 ||
        raw_fchownat(dirfd, "record", uid, gid, 0) != 0) {
        status = 9; goto cleanup;
    }

    if (mkdirat(dirfd, "subdir", 0700) != 0 ||
        raw_mkdirat(dirfd, "rawdir", 0700) != 0 ||
        raw_mknodat(dirfd, "fifo", S_IFIFO | 0600, 0) != 0 ||
        fstatat(dirfd, "subdir", &musl_st, 0) != 0 ||
        !S_ISDIR(musl_st.st_mode) || fstatat(dirfd, "fifo", &musl_st, 0) != 0 ||
        !S_ISFIFO(musl_st.st_mode)) {
        status = 10; goto cleanup;
    }
    errno = 0;
    if (unlinkat(dirfd, "subdir", AT_REMOVEDIR) != 0 ||
        raw_unlinkat(dirfd, "rawdir", AT_REMOVEDIR) != 0 ||
        unlinkat(dirfd, "fifo", 0) != 0 || unlinkat(dirfd, "record", 0) != 0 ||
        unlinkat(dirfd, "link", 0) != 0) {
        status = 11; goto cleanup;
    }
    errno = 0;
    if (fstatat(dirfd, "record", &musl_st, 0) != -1 || errno != ENOENT) {
        status = 12; goto cleanup;
    }
    errno = 0;
    if (raw_statat(dirfd, "record", &raw_st, 0) != -1 || errno != ENOENT) {
        status = 13; goto cleanup;
    }
    rawfd = raw_openat(dirfd, "missing", O_RDONLY | O_CLOEXEC, 0);
    if (rawfd != -1 || errno != ENOENT) { status = 14; goto cleanup; }
    puts("stat=144/offsets=proved openat=257 newfstatat=262 truncate=76 mkdirat=258 mknodat=259 unlinkat=263 chmod=fchmod91/fchmodat268 chown=fchown93/fchownat260 lifecycle=regular/symlink/fifo/dirs errors=ENOENT");

cleanup:
    if (rawfd >= 0) close(rawfd);
    if (fd >= 0) close(fd);
    if (dirfd >= 0) {
        unlinkat(dirfd, "fifo", 0);
        unlinkat(dirfd, "link", 0);
        unlinkat(dirfd, "record", 0);
        unlinkat(dirfd, "subdir", AT_REMOVEDIR);
        unlinkat(dirfd, "rawdir", AT_REMOVEDIR);
        close(dirfd);
    }
    rmdir(root);
    return status;
}
