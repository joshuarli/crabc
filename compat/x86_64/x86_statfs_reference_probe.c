/* Pinned-musl/raw Linux/x86-64 statfs/statvfs capacity reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(struct statfs) == 120 && _Alignof(struct statfs) == 8,
               "x86 struct statfs layout");
_Static_assert(offsetof(struct statfs, f_type) == 0 &&
                   offsetof(struct statfs, f_bsize) == 8 &&
                   offsetof(struct statfs, f_blocks) == 16 &&
                   offsetof(struct statfs, f_bfree) == 24 &&
                   offsetof(struct statfs, f_bavail) == 32 &&
                   offsetof(struct statfs, f_files) == 40 &&
                   offsetof(struct statfs, f_ffree) == 48 &&
                   offsetof(struct statfs, f_fsid) == 56 &&
                   offsetof(struct statfs, f_namelen) == 64 &&
                   offsetof(struct statfs, f_frsize) == 72 &&
                   offsetof(struct statfs, f_flags) == 80 &&
                   offsetof(struct statfs, f_spare) == 88,
               "x86 struct statfs offsets");
_Static_assert(SYS_statfs == 137 && SYS_fstatfs == 138,
               "x86 statfs syscall numbers");
_Static_assert(sizeof(long) == 8 && sizeof(unsigned long) == 8,
               "x86 LP64 word width");
_Static_assert(ST_RDONLY == 1 && ST_NOSUID == 2 && ST_NODEV == 4 &&
                   ST_NOEXEC == 8 && ST_SYNCHRONOUS == 16 && ST_MANDLOCK == 64 &&
                   ST_WRITE == 128 && ST_APPEND == 256 && ST_IMMUTABLE == 512 &&
                   ST_NOATIME == 1024 && ST_NODIRATIME == 2048 &&
                   ST_RELATIME == 4096,
               "Linux statfs f_flags constants");

struct call_result {
    int value;
    int error;
};

static struct call_result libc_statfs(const char *path, struct statfs *value)
{
    struct call_result result;
    errno = 0;
    result.value = statfs(path, value);
    result.error = errno;
    return result;
}

static struct call_result raw_statfs(const char *path, struct statfs *value)
{
    struct call_result result;
    errno = 0;
    result.value = (int)syscall(SYS_statfs, path, value);
    result.error = errno;
    return result;
}

static struct call_result libc_fstatfs(int fd, struct statfs *value)
{
    struct call_result result;
    errno = 0;
    result.value = fstatfs(fd, value);
    result.error = errno;
    return result;
}

static struct call_result raw_fstatfs(int fd, struct statfs *value)
{
    struct call_result result;
    errno = 0;
    result.value = (int)syscall(SYS_fstatfs, fd, value);
    result.error = errno;
    return result;
}

static int same_statfs(const struct statfs *left, const struct statfs *right)
{
    return left->f_type == right->f_type && left->f_bsize == right->f_bsize &&
           left->f_blocks == right->f_blocks && left->f_bfree == right->f_bfree &&
           left->f_bavail == right->f_bavail && left->f_files == right->f_files &&
           left->f_ffree == right->f_ffree &&
           memcmp(&left->f_fsid, &right->f_fsid, sizeof(left->f_fsid)) == 0 &&
           left->f_namelen == right->f_namelen &&
           left->f_frsize == right->f_frsize && left->f_flags == right->f_flags &&
           memcmp(left->f_spare, right->f_spare, sizeof(left->f_spare)) == 0;
}

static int statvfs_matches_statfs(const struct statvfs *value,
                                  const struct statfs *source)
{
    int fsid0;
    unsigned long frsize = source->f_frsize != 0 ? source->f_frsize : source->f_bsize;
    memcpy(&fsid0, &source->f_fsid, sizeof(fsid0));
    return value->f_bsize == source->f_bsize && value->f_frsize == frsize &&
           value->f_blocks == source->f_blocks && value->f_bfree == source->f_bfree &&
           value->f_bavail == source->f_bavail && value->f_files == source->f_files &&
           value->f_ffree == source->f_ffree && value->f_favail == source->f_ffree &&
           value->f_fsid == (unsigned long)fsid0 &&
           value->f_flag == source->f_flags && value->f_namemax == source->f_namelen &&
           value->f_type == (unsigned int)source->f_type;
}

static int same_statvfs(const struct statvfs *left, const struct statvfs *right)
{
    return left->f_bsize == right->f_bsize && left->f_frsize == right->f_frsize &&
           left->f_blocks == right->f_blocks && left->f_bfree == right->f_bfree &&
           left->f_bavail == right->f_bavail && left->f_files == right->f_files &&
           left->f_ffree == right->f_ffree && left->f_favail == right->f_favail &&
           left->f_fsid == right->f_fsid && left->f_flag == right->f_flag &&
           left->f_namemax == right->f_namemax && left->f_type == right->f_type;
}

static int expected_error(struct call_result result, int error)
{
    return result.value == -1 && result.error == error;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-statfs-XXXXXX";
    char missing[sizeof(template) + sizeof("-missing")];
    struct statfs libc_path;
    struct statfs raw_path;
    struct statfs libc_fd;
    struct statfs raw_fd;
    struct statvfs path_vfs;
    struct statvfs fd_vfs;
    struct call_result result;
    int fd = -1;
    int closed_fd = -1;
    int status = 0;

    fd = mkstemp(template);
    if (fd < 0)
        return 2;
    if (snprintf(missing, sizeof(missing), "%s-missing", template) < 0) {
        status = 3;
        goto cleanup;
    }

    result = libc_statfs(template, &libc_path);
    if (result.value != 0 || libc_fstatfs(fd, &libc_fd).value != 0) {
        status = 4;
        goto cleanup;
    }
    result = raw_statfs(template, &raw_path);
    if (result.value != 0 || raw_fstatfs(fd, &raw_fd).value != 0 ||
        !same_statfs(&libc_path, &raw_path) || !same_statfs(&libc_fd, &raw_fd) ||
        !same_statfs(&libc_path, &libc_fd)) {
        status = 5;
        goto cleanup;
    }
    if (statvfs(template, &path_vfs) != 0 || fstatvfs(fd, &fd_vfs) != 0 ||
        !statvfs_matches_statfs(&path_vfs, &libc_path) ||
        !statvfs_matches_statfs(&fd_vfs, &libc_fd) ||
        !same_statvfs(&path_vfs, &fd_vfs)) {
        status = 6;
        goto cleanup;
    }

    errno = 0;
    if (!expected_error(libc_statfs(missing, &libc_path), ENOENT)) {
        status = 7;
        goto cleanup;
    }
    errno = 0;
    if (!expected_error(raw_statfs(missing, &raw_path), ENOENT)) {
        status = 8;
        goto cleanup;
    }
    closed_fd = dup(fd);
    if (closed_fd < 0 || close(closed_fd) != 0) {
        status = 9;
        goto cleanup;
    }
    result = libc_fstatfs(closed_fd, &libc_fd);
    if (!expected_error(result, EBADF)) {
        status = 10;
        goto cleanup;
    }
    result = raw_fstatfs(closed_fd, &raw_fd);
    if (!expected_error(result, EBADF)) {
        status = 11;
        goto cleanup;
    }

cleanup:
    (void)unlink(template);
    if (fd >= 0 && close(fd) != 0 && status == 0)
        status = 12;
    if (status != 0)
        return status;

    puts("statfs=137 fstatfs=138 struct-size=120 struct-align=8 offsets=proved "
         "path=regular-file fd=matches raw=matches-musl statvfs=invariants "
         "flags=NOATIME:1024,NODIRATIME:2048,RELATIME:4096 "
         "missing=ENOENT closed-fd=EBADF");
    return 0;
}
