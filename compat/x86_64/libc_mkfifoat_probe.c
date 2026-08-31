/* Static crabc-libc x86-64 mkfifoat compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat/openat,
 * newfstatat, unlinkat, and close calls create, observe, and remove only the
 * fixture-owned directory. `mkfifoat` is the only candidate C entry. The
 * runner's child-local shell umask is zero solely to make the kernel-applied
 * mode observable. This does not select C umask, mkfifo/mknod/mknodat, device
 * nodes, or general pathname policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_REMOVEDIR = 0x200,
    FIXTURE_EBADF = 9,
    FIXTURE_EEXIST = 17,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINTR = 4,
    FIXTURE_O_DIRECTORY = 0200000,
};

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4,
               "x86 LP64 mode_t ABI");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(S_IFMT == 0170000 && S_IFIFO == 0010000 && S_IRWXU == 0700,
               "x86 FIFO mode constants");
_Static_assert(AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   O_DIRECTORY == FIXTURE_O_DIRECTORY,
               "x86 directory fixture constants");
_Static_assert(SYS_close == 3 && SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_mknodat == 259 && SYS_newfstatat == 262 &&
                   SYS_unlinkat == 263,
               "Linux x86 FIFO fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EEXIST == FIXTURE_EEXIST &&
                   EFAULT == FIXTURE_EFAULT && EINTR == FIXTURE_EINTR,
               "Linux x86 FIFO errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkfifoat),
                                             int (*)(int, const char *, mode_t)),
               "mkfifoat declaration");

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

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
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

static int open_fixture_directory(const char *path)
{
    long descriptor;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)path, 0700) != 0)
        return -1;
    descriptor = raw_syscall3(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)path, O_RDONLY | O_DIRECTORY);
    if (descriptor < 0) {
        (void)raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
            (long)(uintptr_t)path, AT_REMOVEDIR);
        return -1;
    }
    return (int)descriptor;
}

static int check_fifo_at(int dirfd, const char *path, mode_t expected_mode)
{
    struct stat observed;

    if (raw_syscall4(SYS_newfstatat, dirfd, (long)(uintptr_t)path,
        (long)(uintptr_t)&observed, 0) != 0)
        return 1;
    if (!S_ISFIFO(observed.st_mode))
        return 2;
    if ((observed.st_mode & 0777) != expected_mode)
        return 3;
    return 0;
}

static int remove_fifo_at(int dirfd, const char *path)
{
    return raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path, 0) == 0
        ? 0
        : -1;
}

static int check_one_fifo(int dirfd, const char *path, mode_t mode)
{
    int status;

    errno = EINTR;
    if (mkfifoat(dirfd, path, mode) != 0)
        return 1;
    if (errno != EINTR)
        return 2;
    status = check_fifo_at(dirfd, path, mode);
    if (status != 0) {
        (void)remove_fifo_at(dirfd, path);
        return 10 + status;
    }

    errno = 0;
    if (mkfifoat(dirfd, path, mode) != -1 || errno != EEXIST) {
        (void)remove_fifo_at(dirfd, path);
        return 20;
    }
    if (remove_fifo_at(dirfd, path) != 0)
        return 21;
    return 0;
}

int crabc_x86_64_mkfifoat_probe(void)
{
    static const char parent[] = "mkfifoat-parent";
    static const char mode_fifo[] = "mkfifoat-mode-0640";
    static const char zero_fifo[] = "mkfifoat-mode-0000";
    static const char bad_descriptor_fifo[] = "mkfifoat-bad-descriptor";
    int dirfd;
    int status;

    dirfd = open_fixture_directory(parent);
    if (dirfd < 0)
        return 1;

    status = check_one_fifo(dirfd, mode_fifo, 0640);
    if (status == 0) {
        status = check_one_fifo(dirfd, zero_fifo, 0000);
        if (status != 0)
            status += 40;
    }
    if (status == 0) {
        errno = 0;
        if (mkfifoat(-1, bad_descriptor_fifo, 0600) != -1 || errno != EBADF)
            status = 90;
    }
    if (status == 0) {
        errno = 0;
        if (mkfifoat(dirfd, (const char *)0, 0600) != -1 || errno != EFAULT)
            status = 91;
    }

    if (raw_syscall1(SYS_close, dirfd) != 0 && status == 0)
        status = 92;
    if (raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, AT_REMOVEDIR) != 0 && status == 0)
        status = 93;
    return status;
}

#ifndef CRABC_MKFIFOAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_mkfifoat_probe();
}
#endif
