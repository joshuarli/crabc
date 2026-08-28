/*
 * Pinned-musl/raw Linux/x86-64 temporary-object reference.
 *
 * `openat`, `unlinkat`, `mkdirat`, and the ordinary C descriptor operations
 * appear here only as the pinned-musl oracle for the private Rust
 * temporary-object boundary. This fixture selects no crabc C temporary API,
 * installed header, C errno/TLS contract, or public x86 ABI.
 */
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
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(sizeof(off_t) == 8, "x86 off_t width");
_Static_assert(SYS_read == 0, "x86 read syscall number");
_Static_assert(SYS_write == 1, "x86 write syscall number");
_Static_assert(SYS_close == 3, "x86 close syscall number");
_Static_assert(SYS_fstat == 5, "x86 fstat syscall number");
_Static_assert(SYS_lseek == 8, "x86 lseek syscall number");
_Static_assert(SYS_fcntl == 72, "x86 fcntl syscall number");
_Static_assert(SYS_openat == 257, "x86 openat syscall number");
_Static_assert(SYS_mkdirat == 258, "x86 mkdirat syscall number");
_Static_assert(SYS_newfstatat == 262, "x86 newfstatat syscall number");
_Static_assert(SYS_unlinkat == 263, "x86 unlinkat syscall number");
_Static_assert(AT_FDCWD == -100, "x86 current-directory token");
_Static_assert(AT_REMOVEDIR == 0x200, "x86 AT_REMOVEDIR value");
_Static_assert(O_RDWR == 0x00000002, "x86 O_RDWR value");
_Static_assert(O_CREAT == 0x00000040, "x86 O_CREAT value");
_Static_assert(O_EXCL == 0x00000080, "x86 O_EXCL value");
_Static_assert(O_DIRECTORY == 0x00010000, "x86 O_DIRECTORY value");
_Static_assert(O_CLOEXEC == 0x00080000, "x86 O_CLOEXEC value");
_Static_assert(O_TMPFILE == 0x00410000, "x86 O_TMPFILE value");
_Static_assert(FD_CLOEXEC == 1, "x86 FD_CLOEXEC value");

enum {
    NAMED_MODE = 0600,
    DIRECTORY_MODE = 0700,
    NAMED_FLAGS = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
    ANONYMOUS_FLAGS = O_RDWR | O_TMPFILE | O_CLOEXEC,
};

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

static int raw_mkdirat(int dirfd, const char *path, mode_t mode)
{
    return (int)syscall(SYS_mkdirat, dirfd, path, mode);
}

static int raw_newfstatat(int dirfd, const char *path, struct stat *value,
                          int flags)
{
    return (int)syscall(SYS_newfstatat, dirfd, path, value, flags);
}

static int raw_unlinkat(int dirfd, const char *path, int flags)
{
    return (int)syscall(SYS_unlinkat, dirfd, path, flags);
}

static int expect_error(long value, int error)
{
    return value == -1 && errno == error;
}

static int is_private_regular(const struct stat *value)
{
    return S_ISREG(value->st_mode) && value->st_nlink == 1 &&
           (value->st_mode & 0777) == NAMED_MODE;
}

static int is_private_directory(const struct stat *value)
{
    return S_ISDIR(value->st_mode) && (value->st_mode & 0777) == DIRECTORY_MODE;
}

static int has_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

static int raw_has_cloexec(int fd)
{
    long flags = syscall(SYS_fcntl, fd, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

/*
 * Opens one C-oracle and one raw-syscall anonymous inode beneath the same
 * parent. A filesystem that does not implement Linux O_TMPFILE must reject
 * both with EOPNOTSUPP; no named fallback is admitted by this evidence.
 */
static int check_anonymous_pair(int parent_fd, int *available)
{
    static const char payload[] = "anonymous";
    char musl_received[sizeof(payload) - 1];
    char raw_received[sizeof(payload) - 1];
    struct stat musl_stat;
    struct stat raw_stat;
    int musl_fd = -1;
    int raw_fd = -1;
    int musl_error;
    int raw_error;
    int status = 0;

    errno = 0;
    musl_fd = openat(parent_fd, ".", ANONYMOUS_FLAGS, NAMED_MODE);
    musl_error = errno;
    errno = 0;
    raw_fd = raw_openat(parent_fd, ".", ANONYMOUS_FLAGS, NAMED_MODE);
    raw_error = errno;

    if (musl_fd < 0 || raw_fd < 0) {
        if (musl_fd == -1 && raw_fd == -1 && musl_error == EOPNOTSUPP &&
            raw_error == EOPNOTSUPP) {
            *available = 0;
            return 0;
        }
        status = 1;
        goto cleanup;
    }
    *available = 1;

    if (!has_cloexec(musl_fd) || fstat(musl_fd, &musl_stat) != 0 ||
        !S_ISREG(musl_stat.st_mode) || musl_stat.st_nlink != 0 ||
        (musl_stat.st_mode & 0777) != NAMED_MODE ||
        write(musl_fd, payload, sizeof(payload) - 1) !=
            (ssize_t)(sizeof(payload) - 1) ||
        lseek(musl_fd, 0, SEEK_SET) != 0 ||
        read(musl_fd, musl_received, sizeof(musl_received)) !=
            (ssize_t)sizeof(musl_received) ||
        memcmp(musl_received, payload, sizeof(musl_received)) != 0) {
        status = 2;
        goto cleanup;
    }

    if (!raw_has_cloexec(raw_fd) ||
        syscall(SYS_fstat, raw_fd, &raw_stat) != 0 ||
        !S_ISREG(raw_stat.st_mode) || raw_stat.st_nlink != 0 ||
        (raw_stat.st_mode & 0777) != NAMED_MODE ||
        syscall(SYS_write, raw_fd, payload, sizeof(payload) - 1) !=
            (long)(sizeof(payload) - 1) ||
        syscall(SYS_lseek, raw_fd, (off_t)0, SEEK_SET) != 0 ||
        syscall(SYS_read, raw_fd, raw_received, sizeof(raw_received)) !=
            (long)sizeof(raw_received) ||
        memcmp(raw_received, payload, sizeof(raw_received)) != 0) {
        status = 3;
        goto cleanup;
    }

cleanup:
    if (raw_fd >= 0 && close(raw_fd) != 0 && status == 0)
        status = 4;
    if (musl_fd >= 0 && close(musl_fd) != 0 && status == 0)
        status = 5;
    return status;
}

int main(void)
{
    static const char musl_name[] = "named-musl";
    static const char raw_name[] = "named-raw";
    static const char musl_directory[] = "directory-musl";
    static const char raw_directory[] = "directory-raw";
    char template[] = "/tmp/crabc-x86-temporary-object-XXXXXX";
    struct stat musl_stat;
    struct stat raw_stat;
    mode_t saved_umask;
    int parent_fd = -1;
    int saved_cwd = -1;
    int musl_fd = -1;
    int raw_fd = -1;
    int collision_fd = -1;
    int cwd_changed = 0;
    int anonymous_available = 0;
    int status = 0;

    if (mkdtemp(template) == NULL)
        return 10;
    saved_umask = umask(0);
    parent_fd = open(template, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) {
        status = 11;
        goto cleanup;
    }

    /* Pinned-musl named creation: private mode, CLOEXEC, and EEXIST. */
    musl_fd = openat(parent_fd, musl_name, NAMED_FLAGS, NAMED_MODE);
    if (musl_fd < 0 || !has_cloexec(musl_fd) || fstat(musl_fd, &musl_stat) != 0 ||
        !is_private_regular(&musl_stat)) {
        status = 12;
        goto cleanup;
    }
    errno = 0;
    collision_fd = openat(parent_fd, musl_name, NAMED_FLAGS, NAMED_MODE);
    if (!expect_error(collision_fd, EEXIST)) {
        status = 13;
        goto cleanup;
    }
    if (close(musl_fd) != 0) {
        musl_fd = -1;
        status = 14;
        goto cleanup;
    }
    musl_fd = -1;

    /* Raw x86 openat/newfstatat/fcntl observes the same named-file contract. */
    raw_fd = raw_openat(parent_fd, raw_name, NAMED_FLAGS, NAMED_MODE);
    if (raw_fd < 0 || !raw_has_cloexec(raw_fd) ||
        raw_newfstatat(parent_fd, raw_name, &raw_stat, 0) != 0 ||
        !is_private_regular(&raw_stat)) {
        status = 15;
        goto cleanup;
    }
    errno = 0;
    collision_fd = raw_openat(parent_fd, raw_name, NAMED_FLAGS, NAMED_MODE);
    if (!expect_error(collision_fd, EEXIST)) {
        status = 16;
        goto cleanup;
    }
    if (close(raw_fd) != 0) {
        raw_fd = -1;
        status = 17;
        goto cleanup;
    }
    raw_fd = -1;

    /* The parent descriptor, not ambient CWD, is the named-entry authority. */
    saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved_cwd < 0 || chdir("/") != 0) {
        status = 18;
        goto cleanup;
    }
    cwd_changed = 1;
    if (unlinkat(parent_fd, musl_name, 0) != 0 ||
        raw_unlinkat(parent_fd, raw_name, 0) != 0) {
        status = 19;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(fstatat(parent_fd, musl_name, &musl_stat, 0), ENOENT)) {
        status = 20;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(raw_newfstatat(parent_fd, raw_name, &raw_stat, 0), ENOENT)) {
        status = 21;
        goto cleanup;
    }
    if (fchdir(saved_cwd) != 0) {
        status = 22;
        goto cleanup;
    }
    cwd_changed = 0;
    if (close(saved_cwd) != 0) {
        saved_cwd = -1;
        status = 23;
        goto cleanup;
    }
    saved_cwd = -1;

    status = check_anonymous_pair(parent_fd, &anonymous_available);
    if (status != 0) {
        status += 30;
        goto cleanup;
    }

    /* mkdirat's descriptor-relative names and mode are checked on both paths. */
    if (mkdirat(parent_fd, musl_directory, DIRECTORY_MODE) != 0 ||
        raw_mkdirat(parent_fd, raw_directory, DIRECTORY_MODE) != 0 ||
        fstatat(parent_fd, musl_directory, &musl_stat, 0) != 0 ||
        !is_private_directory(&musl_stat) ||
        raw_newfstatat(parent_fd, raw_directory, &raw_stat, 0) != 0 ||
        !is_private_directory(&raw_stat)) {
        status = 40;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(mkdirat(parent_fd, musl_directory, DIRECTORY_MODE), EEXIST)) {
        status = 41;
        goto cleanup;
    }
    errno = 0;
    if (!expect_error(raw_mkdirat(parent_fd, raw_directory, DIRECTORY_MODE),
                      EEXIST)) {
        status = 42;
        goto cleanup;
    }
    if (unlinkat(parent_fd, musl_directory, AT_REMOVEDIR) != 0 ||
        raw_unlinkat(parent_fd, raw_directory, AT_REMOVEDIR) != 0) {
        status = 43;
        goto cleanup;
    }

    if (anonymous_available) {
        puts("syscalls=read:0,write:1,close:3,fstat:5,lseek:8,fcntl:72,openat:257,mkdirat:258,newfstatat:262,unlinkat:263 flags=creat:0x40,excl:0x80,cloexec:0x80000,tmpfile:0x410000,removedir:0x200 named=exclusive:cloexec:mode0600:stable-parent-unlink anonymous=cloexec:regular:nlink0:read-write tempdir=mkdirat:mode0700:name-flow c-api-selection=excluded");
    } else {
        puts("syscalls=read:0,write:1,close:3,fstat:5,lseek:8,fcntl:72,openat:257,mkdirat:258,newfstatat:262,unlinkat:263 flags=creat:0x40,excl:0x80,cloexec:0x80000,tmpfile:0x410000,removedir:0x200 named=exclusive:cloexec:mode0600:stable-parent-unlink anonymous=unavailable:EOPNOTSUPP tempdir=mkdirat:mode0700:name-flow c-api-selection=excluded");
    }

cleanup:
    if (cwd_changed && saved_cwd >= 0 && fchdir(saved_cwd) != 0 && status == 0)
        status = 50;
    if (saved_cwd >= 0 && close(saved_cwd) != 0 && status == 0)
        status = 51;
    if (raw_fd >= 0 && close(raw_fd) != 0 && status == 0)
        status = 52;
    if (musl_fd >= 0 && close(musl_fd) != 0 && status == 0)
        status = 53;
    if (collision_fd >= 0 && close(collision_fd) != 0 && status == 0)
        status = 54;
    if (parent_fd >= 0) {
        (void)unlinkat(parent_fd, musl_name, 0);
        (void)raw_unlinkat(parent_fd, raw_name, 0);
        (void)unlinkat(parent_fd, musl_directory, AT_REMOVEDIR);
        (void)raw_unlinkat(parent_fd, raw_directory, AT_REMOVEDIR);
        if (close(parent_fd) != 0 && status == 0)
            status = 55;
    }
    if (rmdir(template) != 0 && status == 0)
        status = 56;
    (void)umask(saved_umask);
    return status;
}
