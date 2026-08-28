/* Pinned-musl/raw Linux/x86-64 namespace-link ABI and behavior reference. */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_RENAME_NOREPLACE
#define AT_RENAME_NOREPLACE 1
#endif
#ifndef AT_RENAME_EXCHANGE
#define AT_RENAME_EXCHANGE 2
#endif
#ifndef AT_RENAME_WHITEOUT
#define AT_RENAME_WHITEOUT 4
#endif

_Static_assert(SYS_linkat == 265, "x86 linkat syscall number");
_Static_assert(SYS_symlinkat == 266, "x86 symlinkat syscall number");
_Static_assert(SYS_readlinkat == 267, "x86 readlinkat syscall number");
_Static_assert(SYS_renameat2 == 316, "x86 renameat2 syscall number");
_Static_assert(AT_RENAME_NOREPLACE == 1, "renameat2 NOREPLACE");
_Static_assert(AT_RENAME_EXCHANGE == 2, "renameat2 EXCHANGE");
_Static_assert(AT_RENAME_WHITEOUT == 4, "renameat2 WHITEOUT");
_Static_assert(AT_EMPTY_PATH == 0x1000, "AT_EMPTY_PATH");
_Static_assert(AT_SYMLINK_NOFOLLOW == 0x100, "AT_SYMLINK_NOFOLLOW");
_Static_assert(AT_SYMLINK_FOLLOW == 0x400, "AT_SYMLINK_FOLLOW");

struct result { long value; int error; };

static struct result call_link(int oldfd, const char *oldname, int newfd,
                               const char *newname, int raw)
{
    struct result r; errno = 0;
    r.value = raw ? syscall(SYS_linkat, oldfd, oldname, newfd, newname, 0)
                  : linkat(oldfd, oldname, newfd, newname, 0);
    r.error = errno; return r;
}

static struct result call_symlink(const char *target, int dirfd,
                                  const char *name, int raw)
{
    struct result r; errno = 0;
    r.value = raw ? syscall(SYS_symlinkat, target, dirfd, name)
                  : symlinkat(target, dirfd, name);
    r.error = errno; return r;
}

static struct result call_readlink(int dirfd, const char *name, char *buf,
                                   size_t len, int raw)
{
    struct result r; errno = 0;
    r.value = raw ? syscall(SYS_readlinkat, dirfd, name, buf, len)
                  : readlinkat(dirfd, name, buf, len);
    r.error = errno; return r;
}

static struct result call_rename(int oldfd, const char *oldname, int newfd,
                                 const char *newname, unsigned flags, int raw)
{
    struct result r; errno = 0;
    /* musl exposes ordinary renameat(2); renameat2 flags are kernel-only. */
    r.value = raw || flags != 0
                  ? syscall(SYS_renameat2, oldfd, oldname, newfd, newname, flags)
                  : renameat(oldfd, oldname, newfd, newname);
    r.error = errno; return r;
}

static int write_file(int dirfd, const char *name, const char *data)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd); return n == (ssize_t)strlen(data) ? 0 : -1;
}

static int contents(int dirfd, const char *name, const char *expected)
{
    char buf[32]; int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf)); close(fd);
    return n == (ssize_t)strlen(expected) && memcmp(buf, expected, (size_t)n) == 0;
}

int main(void)
{
    char template[] = "/tmp/crabc-x86-namespace-XXXXXX";
    int root = mkdtemp(template) ? open(template, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    int result = 0;
    struct stat a, b;
    char exact[32], shortbuf[5];
    struct result mr, rr;
    if (root < 0) return 10;
    if (write_file(root, "source", "source") != 0 || write_file(root, "replace", "old") != 0 ||
        mkdirat(root, "left", 0700) != 0 || mkdirat(root, "right", 0700) != 0) { result = 11; goto cleanup; }
    int left = openat(root, "left", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    int right = openat(root, "right", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (left < 0 || right < 0) { result = 12; goto cleanup; }

    /* Musl and raw linkat agree, and the resulting names share an inode. */
    mr = call_link(root, "source", left, "hard-musl", 0);
    rr = call_link(root, "source", right, "hard-raw", 1);
    if (mr.value != 0 || rr.value != 0 ||
        fstatat(left, "hard-musl", &a, 0) != 0 || fstatat(right, "hard-raw", &b, 0) != 0 ||
        a.st_dev != b.st_dev || a.st_ino != b.st_ino) { result = 13; goto cleanup_dirs; }

    /* Exact target, truncation, and absence of a kernel-added NUL. */
    if (call_symlink("target/nonutf8", left, "sym-musl", 0).value != 0 ||
        call_symlink("target/nonutf8", right, "sym-raw", 1).value != 0) { result = 14; goto cleanup_dirs; }
    memset(exact, 'X', sizeof(exact)); mr = call_readlink(left, "sym-musl", exact, sizeof(exact), 0);
    rr = call_readlink(right, "sym-raw", exact + 16, sizeof(exact) - 16, 1);
    if (mr.value != 14 || rr.value != 14 || memcmp(exact, "target/nonutf8", 14) != 0 ||
        exact[14] != 'X' || exact[15] != 'X') { result = 15; goto cleanup_dirs; }
    memset(shortbuf, 'X', sizeof(shortbuf));
    if (call_readlink(left, "sym-musl", shortbuf, 5, 0).value != 5 ||
        memcmp(shortbuf, "targe", 5) != 0 || call_readlink(left, "sym-musl", shortbuf, 0, 1).error != EINVAL) { result = 16; goto cleanup_dirs; }

    /* Ordinary replacement and the two atomic renameat2 policies. */
    mr = call_rename(root, "source", left, "moved", 0, 0);
    if (mr.value != 0 || !contents(left, "moved", "source")) {
        fprintf(stderr, "ordinary first rename: value=%ld errno=%d\n", mr.value, mr.error);
        result = 17; goto cleanup_dirs;
    }
    if (write_file(right, "new", "new") != 0) {
        fprintf(stderr, "ordinary replacement setup failed\n");
        result = 17; goto cleanup_dirs;
    }
    mr = call_rename(right, "new", left, "moved", 0, 0);
    if (mr.value != 0 || !contents(left, "moved", "new")) {
        fprintf(stderr, "ordinary replacement: value=%ld errno=%d\n", mr.value, mr.error);
        result = 17; goto cleanup_dirs;
    }
    if (write_file(left, "one", "one") != 0 || write_file(right, "two", "two") != 0) {
        fprintf(stderr, "renameat2 setup failed\n");
        result = 17; goto cleanup_dirs;
    }
    rr = call_rename(left, "one", right, "two", AT_RENAME_NOREPLACE, 1);
    if (rr.error != EEXIST) {
        fprintf(stderr, "renameat2 noreplace: value=%ld errno=%d\n", rr.value, rr.error);
        result = 17; goto cleanup_dirs;
    }
    mr = call_rename(left, "one", right, "two", AT_RENAME_EXCHANGE, 0);
    if (mr.value != 0 || !contents(left, "one", "two") || !contents(right, "two", "one")) {
        fprintf(stderr, "renameat2 exchange: value=%ld errno=%d\n", mr.value, mr.error);
        result = 17; goto cleanup_dirs;
    }
    rr = call_rename(left, "one", right, "two", AT_RENAME_EXCHANGE | AT_RENAME_WHITEOUT, 1);
    if (rr.error != EINVAL) {
        fprintf(stderr, "renameat2 invalid flags: value=%ld errno=%d\n", rr.value, rr.error);
        result = 17; goto cleanup_dirs;
    }
    rr = call_rename(left, "missing", right, "missing", 0, 0);
    if (rr.error != ENOENT) {
        fprintf(stderr, "renameat missing source: value=%ld errno=%d\n", rr.value, rr.error);
        result = 17; goto cleanup_dirs;
    }
    close(left); left = -1;
    close(right); right = -1;
cleanup_dirs:
    if (left >= 0) close(left);
    if (right >= 0) close(right);
    unlinkat(root, "source", 0); unlinkat(root, "replace", 0);
    unlinkat(root, "left/hard-musl", 0); unlinkat(root, "right/hard-raw", 0);
    unlinkat(root, "left/sym-musl", 0); unlinkat(root, "right/sym-raw", 0);
    unlinkat(root, "left/moved", 0); unlinkat(root, "right/moved", 0);
    unlinkat(root, "left/one", 0); unlinkat(root, "right/one", 0);
    unlinkat(root, "left/two", 0); unlinkat(root, "right/two", 0);
    unlinkat(root, "left", AT_REMOVEDIR); unlinkat(root, "right", AT_REMOVEDIR);
cleanup:
    close(root); rmdir(template);
    if (result != 0) return result;
    puts("symlinkat=266 readlinkat=267 linkat=265 renameat2=316 flags=NOREPLACE:1,EXCHANGE:2,WHITEOUT:4,EMPTY_PATH:4096,NOFOLLOW:256,FOLLOW:1024 raw=matches-musl descriptor-relative=proved hardlink=inode-equal symlink=exact-short-no-nul replacement=proved errors=EEXIST,EINVAL,ENOENT cleanup=deterministic");
    return 0;
}
