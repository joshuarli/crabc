/* Pinned-musl Linux/x86-64 fstatat/newfstatat behavior reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 struct stat layout");
_Static_assert(offsetof(struct stat, st_dev) == 0 &&
                   offsetof(struct stat, st_ino) == 8 &&
                   offsetof(struct stat, st_nlink) == 16 &&
                   offsetof(struct stat, st_mode) == 24 &&
                   offsetof(struct stat, st_uid) == 28 &&
                   offsetof(struct stat, st_gid) == 32 &&
                   offsetof(struct stat, st_rdev) == 40 &&
                   offsetof(struct stat, st_size) == 48 &&
                   offsetof(struct stat, st_blksize) == 56 &&
                   offsetof(struct stat, st_blocks) == 64 &&
                   offsetof(struct stat, st_atim) == 72 &&
                   offsetof(struct stat, st_mtim) == 88 &&
                   offsetof(struct stat, st_ctim) == 104,
               "x86 struct stat offsets");
_Static_assert(SYS_newfstatat == 262 && AT_FDCWD == -100 &&
                   AT_SYMLINK_NOFOLLOW == 0x100,
               "x86 newfstatat constants");

static int direct_statat(int dirfd, const char *path, struct stat *value,
                         int flags) {
    return (int)syscall(SYS_newfstatat, dirfd, path, value, flags);
}

static int is_regular_record(const struct stat *value) {
    return S_ISREG(value->st_mode) && value->st_size == 6 &&
           (value->st_mode & 0777) == 0640;
}

static int is_same_file(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_size == right->st_size;
}

int main(void) {
    char template[] = "/tmp/crabc-x86-statat-XXXXXX";
    char absolute[sizeof(template) + sizeof("/record")];
    char *root = mkdtemp(template);
    struct stat musl_value;
    struct stat direct_value;
    int cwd_fd = -1;
    int dirfd = -1;
    int filefd = -1;
    int status = 0;

    if (root == NULL) return 2;
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        status = 3;
        goto cleanup;
    }
    filefd = openat(dirfd, "record", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
                    0640);
    if (filefd < 0 || write(filefd, "record", 6) != 6 ||
        fchmod(filefd, 0640) != 0) {
        status = 4;
        goto cleanup;
    }
    if (close(filefd) != 0) {
        filefd = -1;
        status = 5;
        goto cleanup;
    }
    filefd = -1;
    if (symlinkat("record", dirfd, "link") != 0) {
        status = 6;
        goto cleanup;
    }
    cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cwd_fd < 0 || fchdir(dirfd) != 0) {
        status = 7;
        goto cleanup;
    }
    if (fstatat(AT_FDCWD, "record", &musl_value, 0) != 0 ||
        direct_statat(AT_FDCWD, "record", &direct_value, 0) != 0 ||
        !is_regular_record(&musl_value) || !is_regular_record(&direct_value) ||
        !is_same_file(&musl_value, &direct_value)) {
        status = 8;
        goto cleanup;
    }
    if (fchdir(cwd_fd) != 0) {
        status = 9;
        goto cleanup;
    }
    if (close(cwd_fd) != 0) {
        cwd_fd = -1;
        status = 10;
        goto cleanup;
    }
    cwd_fd = -1;
    if (snprintf(absolute, sizeof(absolute), "%s/record", root) < 0) {
        status = 11;
        goto cleanup;
    }

    if (fstatat(dirfd, "record", &musl_value, 0) != 0 ||
        direct_statat(dirfd, "record", &direct_value, 0) != 0 ||
        !is_regular_record(&musl_value) || !is_regular_record(&direct_value) ||
        !is_same_file(&musl_value, &direct_value)) {
        status = 12;
        goto cleanup;
    }
    if (fstatat(AT_FDCWD, absolute, &musl_value, 0) != 0 ||
        direct_statat(AT_FDCWD, absolute, &direct_value, 0) != 0 ||
        !is_same_file(&musl_value, &direct_value) ||
        !is_regular_record(&musl_value)) {
        status = 13;
        goto cleanup;
    }
    if (fstatat(dirfd, "link", &musl_value, 0) != 0 ||
        direct_statat(dirfd, "link", &direct_value, 0) != 0 ||
        !is_regular_record(&musl_value) || !is_regular_record(&direct_value) ||
        !is_same_file(&musl_value, &direct_value)) {
        status = 14;
        goto cleanup;
    }
    if (fstatat(dirfd, "link", &musl_value, AT_SYMLINK_NOFOLLOW) != 0 ||
        direct_statat(dirfd, "link", &direct_value, AT_SYMLINK_NOFOLLOW) !=
            0 ||
        !S_ISLNK(musl_value.st_mode) || !S_ISLNK(direct_value.st_mode) ||
        musl_value.st_size != 6 || direct_value.st_size != 6 ||
        !is_same_file(&musl_value, &direct_value)) {
        status = 15;
        goto cleanup;
    }
    errno = 0;
    if (fstatat(dirfd, "missing", &musl_value, 0) != -1 || errno != ENOENT) {
        status = 16;
        goto cleanup;
    }
    errno = 0;
    if (direct_statat(dirfd, "missing", &direct_value, 0) != -1 ||
        errno != ENOENT) {
        status = 17;
        goto cleanup;
    }
    errno = 0;
    if (fstatat(dirfd, "record", &musl_value, 0x40000000) != -1 ||
        errno != EINVAL) {
        status = 18;
        goto cleanup;
    }
    errno = 0;
    if (direct_statat(dirfd, "record", &direct_value, 0x40000000) != -1 ||
        errno != EINVAL) {
        status = 19;
        goto cleanup;
    }

cleanup:
    if (filefd >= 0 && close(filefd) != 0 && status == 0) status = 20;
    if (cwd_fd >= 0) {
        if (fchdir(cwd_fd) != 0 && status == 0) status = 21;
        if (close(cwd_fd) != 0 && status == 0) status = 22;
    }
    if (dirfd >= 0) {
        if (unlinkat(dirfd, "link", 0) != 0 && errno != ENOENT && status == 0)
            status = 23;
        if (unlinkat(dirfd, "record", 0) != 0 && errno != ENOENT && status == 0)
            status = 24;
        if (close(dirfd) != 0 && status == 0) status = 25;
    }
    if (rmdir(root) != 0 && status == 0) status = 26;
    if (status != 0) return status;
    puts("regular=size6=follow=regular=nofollow=symlink=missing=ENOENT=invalid=EINVAL");
    return 0;
}
