/* Static crabc-libc x86-64 sys/stat compatibility fixture.
 *
 * The same C body runs first through the pinned musl 1.2.6 C/POSIX oracle and
 * then through a freestanding candidate linked only with the selected crabc
 * static archive. Candidate startup is the adjacent test-only assembly shim:
 * it installs one zero-initialized initial-TLS scratch block so this fixture
 * can observe the selected `errno` boundary. That shim is not a crabc CRT,
 * pthread/TLS implementation, dynamic loader, or general application-startup
 * claim.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/syscall.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long width");
_Static_assert(sizeof(struct stat) == 144, "x86 struct stat size");
_Static_assert(_Alignof(struct stat) == 8, "x86 struct stat alignment");
_Static_assert(offsetof(struct stat, st_dev) == 0, "x86 stat st_dev offset");
_Static_assert(offsetof(struct stat, st_ino) == 8, "x86 stat st_ino offset");
_Static_assert(offsetof(struct stat, st_nlink) == 16, "x86 stat st_nlink offset");
_Static_assert(offsetof(struct stat, st_mode) == 24, "x86 stat st_mode offset");
_Static_assert(offsetof(struct stat, st_uid) == 28, "x86 stat st_uid offset");
_Static_assert(offsetof(struct stat, st_gid) == 32, "x86 stat st_gid offset");
_Static_assert(offsetof(struct stat, st_rdev) == 40, "x86 stat st_rdev offset");
_Static_assert(offsetof(struct stat, st_size) == 48, "x86 stat st_size offset");
_Static_assert(offsetof(struct stat, st_blksize) == 56, "x86 stat st_blksize offset");
_Static_assert(offsetof(struct stat, st_blocks) == 64, "x86 stat st_blocks offset");
_Static_assert(offsetof(struct stat, st_atim) == 72, "x86 stat st_atim offset");
_Static_assert(offsetof(struct stat, st_mtim) == 88, "x86 stat st_mtim offset");
_Static_assert(offsetof(struct stat, st_ctim) == 104, "x86 stat st_ctim offset");
_Static_assert(SYS_fstat == 5, "x86 fstat syscall number");
_Static_assert(SYS_openat == 257, "x86 openat syscall number");
_Static_assert(SYS_close == 3, "x86 close syscall number");
_Static_assert(SYS_newfstatat == 262, "x86 newfstatat syscall number");
_Static_assert(AT_FDCWD == -100, "x86 AT_FDCWD value");
_Static_assert(AT_SYMLINK_NOFOLLOW == 0x100, "x86 AT_SYMLINK_NOFOLLOW value");

extern int __xstat(int, const char *, struct stat *);
extern int __lxstat(int, const char *, struct stat *);
extern int __fxstat(int, int, struct stat *);
extern int __fxstatat(int, int, const char *, struct stat *, int);

/* This fixture intentionally does not use C `open` or `close`: candidate
 * linkage must prove only the selected stat/errno archive boundary. */
static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
                         long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_openat(const char *path, int flags)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD, (long)path, flags, 0);
}

static void raw_close(int file_descriptor)
{
    if (file_descriptor >= 0)
        (void)raw_syscall1(SYS_close, file_descriptor);
}

static int same_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_size == right->st_size &&
           left->st_nlink == right->st_nlink;
}

static int valid_regular_file(const struct stat *value)
{
    return S_ISREG(value->st_mode) && value->st_size == 11 &&
           value->st_nlink >= 1 && value->st_blksize > 0 &&
           value->st_atim.tv_nsec >= 0 && value->st_atim.tv_nsec < 1000000000L &&
           value->st_mtim.tv_nsec >= 0 && value->st_mtim.tv_nsec < 1000000000L &&
           value->st_ctim.tv_nsec >= 0 && value->st_ctim.tv_nsec < 1000000000L;
}

/* The runner enters an otherwise empty temporary directory containing one
 * eleven-byte regular `file` and a `link` symlink to it. This keeps every
 * pathname observation fixed without using an unselected C setup API. */
int crabc_x86_64_stat_compat_probe(void)
{
    struct stat followed;
    struct stat nofollow;
    struct stat descriptor;
    struct stat relative;
    struct stat current_directory;
    struct stat historical;
    int directory_fd = -1;
    int file_fd = -1;
    int status = 0;

    if (stat("link", &followed) != 0 || !valid_regular_file(&followed)) {
        status = 1;
        goto finish;
    }
    if (lstat("link", &nofollow) != 0 || !S_ISLNK(nofollow.st_mode) ||
        nofollow.st_size != 4) {
        status = 2;
        goto finish;
    }
    directory_fd = raw_openat(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        status = 3;
        goto finish;
    }
    file_fd = raw_openat("file", O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        status = 4;
        goto finish;
    }
    if (fstat(file_fd, &descriptor) != 0 ||
        !same_identity(&followed, &descriptor)) {
        status = 5;
        goto finish;
    }
    if (fstatat(directory_fd, "file", &relative, 0) != 0 ||
        !same_identity(&followed, &relative)) {
        status = 6;
        goto finish;
    }
    if (fstatat(AT_FDCWD, "link", &current_directory, 0) != 0 ||
        !same_identity(&followed, &current_directory)) {
        status = 7;
        goto finish;
    }
    if (fstatat(AT_FDCWD, "link", &current_directory, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_identity(&nofollow, &current_directory)) {
        status = 8;
        goto finish;
    }
    if (__xstat(0, "link", &historical) != 0 ||
        !same_identity(&followed, &historical)) {
        status = 9;
        goto finish;
    }
    if (__lxstat(0, "link", &historical) != 0 ||
        !same_identity(&nofollow, &historical)) {
        status = 10;
        goto finish;
    }
    if (__fxstat(0, file_fd, &historical) != 0 ||
        !same_identity(&followed, &historical)) {
        status = 11;
        goto finish;
    }
    if (__fxstatat(0, directory_fd, "file", &historical, 0) != 0 ||
        !same_identity(&followed, &historical)) {
        status = 12;
        goto finish;
    }
    errno = 0;
    if (stat("missing", &historical) != -1 || errno != ENOENT) {
        status = 13;
        goto finish;
    }
    errno = 0;
    if (fstat(-1, &historical) != -1 || errno != EBADF) {
        status = 14;
        goto finish;
    }
    errno = 0;
    if (fstatat(AT_FDCWD, "file", &historical, 0x40000000) != -1 ||
        errno != EINVAL) {
        status = 15;
        goto finish;
    }

finish:
    raw_close(file_fd);
    raw_close(directory_fd);
    return status;
}

#ifndef CRABC_STAT_COMPAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_stat_compat_probe();
}
#endif
