/* Static crabc-libc x86-64 mkfifoat compatibility fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Raw mkdirat/openat,
 * newfstatat, unlinkat, umask, write, and close calls create, observe, and
 * remove only fixture-owned entries. `mkfifoat` is the only candidate C entry.
 * Each process starts with umask zero; raw umask changes it within that process
 * to observe kernel mode masking. No fixture call changes the process CWD.
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
    FIXTURE_ENOENT = 2,
    FIXTURE_ENOTDIR = 20,
    FIXTURE_O_DIRECTORY = 0200000,
    FIXTURE_O_NONBLOCK = 04000,
};

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4,
               "x86 LP64 mode_t ABI");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
               "x86 LP64 stat record");
_Static_assert(S_IFMT == 0170000 && S_IFIFO == 0010000 && S_IRWXU == 0700,
               "x86 FIFO mode constants");
_Static_assert(AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   O_DIRECTORY == FIXTURE_O_DIRECTORY &&
                   O_NONBLOCK == FIXTURE_O_NONBLOCK &&
                   AT_FDCWD == FIXTURE_AT_FDCWD,
               "x86 directory fixture constants");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_umask == 95 &&
                   SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_mknodat == 259 && SYS_newfstatat == 262 &&
                   SYS_unlinkat == 263,
               "Linux x86 FIFO fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EEXIST == FIXTURE_EEXIST &&
                   EFAULT == FIXTURE_EFAULT && EINTR == FIXTURE_EINTR &&
                   ENOENT == FIXTURE_ENOENT && ENOTDIR == FIXTURE_ENOTDIR,
               "Linux x86 FIFO errno values");

#define RECORD(message) do { \
    static const char record[] = message "\n"; \
    if (raw_syscall3(SYS_write, 1, (long)(uintptr_t)record, \
        sizeof(record) - 1) != (long)(sizeof(record) - 1)) \
        status = 100; \
} while (0)
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

static int create_fifo(int dirfd, const char *path, mode_t mode,
    mode_t expected_mode)
{
    int status;

    errno = EINTR;
    if (mkfifoat(dirfd, path, mode) != 0)
        return 1;
    if (errno != EINTR)
        return 2;
    status = check_fifo_at(dirfd, path, expected_mode);
    if (status != 0)
        return 10 + status;

    return 0;
}

static int expect_failure(int dirfd, const char *path, mode_t mode,
    int expected_errno)
{
    errno = EINTR;
    return mkfifoat(dirfd, path, mode) == -1 && errno == expected_errno
        ? 0
        : -1;
}

static int remove_fifo_if_present(int dirfd, const char *path)
{
    long result = raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path, 0);

    return result == 0 || result == -ENOENT ? 0 : -1;
}

int crabc_x86_64_mkfifoat_probe(void)
{
    static const char parent[] = "mkfifoat-parent";
    static const char mode_fifo[] = "mode-0640";
    static const char zero_fifo[] = "mode-0000";
    static const char masked_fifo[] = "mode-masked";
    static const char shared_name[] = "same-name";
    static const char cwd_path[] = "mkfifoat-parent/same-name";
    static const char missing_child[] = "missing/child";
    static const char bad_descriptor_fifo[] = "mkfifoat-bad-descriptor";
    struct stat cwd_stat;
    struct stat dirfd_stat;
    int dirfd = -1;
    int fifo_fd = -1;
    int status = 0;

    dirfd = open_fixture_directory(parent);
    if (dirfd < 0)
        return 1;

    status = create_fifo(dirfd, mode_fifo, 0640, 0640);
    if (status == 0)
        RECORD("dirfd-mode-0640");
    if (status == 0) {
        status = create_fifo(dirfd, zero_fifo, 0000, 0000);
        if (status == 0)
            RECORD("dirfd-mode-0000");
    }
    if (status == 0) {
        if (expect_failure(dirfd, mode_fifo, 0600, EEXIST) != 0)
            status = 30;
        else
            RECORD("duplicate-eexist");
    }
    if (status == 0) {
        if (create_fifo(FIXTURE_AT_FDCWD, shared_name, 0600, 0600) != 0 ||
            create_fifo(dirfd, shared_name, 0640, 0640) != 0 ||
            raw_syscall4(SYS_newfstatat, FIXTURE_AT_FDCWD,
                (long)(uintptr_t)shared_name, (long)(uintptr_t)&cwd_stat, 0) != 0 ||
            raw_syscall4(SYS_newfstatat, dirfd,
                (long)(uintptr_t)shared_name, (long)(uintptr_t)&dirfd_stat, 0) != 0 ||
            cwd_stat.st_dev != dirfd_stat.st_dev ||
            cwd_stat.st_ino == dirfd_stat.st_ino ||
            check_fifo_at(FIXTURE_AT_FDCWD, cwd_path, 0640) != 0)
            status = 40;
        else
            RECORD("cwd-and-dirfd-resolution");
    }
    if (status == 0) {
        if (raw_syscall1(SYS_umask, 0027) != 0)
            status = 50;
        else if (create_fifo(dirfd, masked_fifo, 0777, 0750) != 0)
            status = 51;
        if (raw_syscall1(SYS_umask, 0000) != 0027 && status == 0)
            status = 52;
        if (status == 0)
            RECORD("umask-0027-mode-0750");
    }
    if (status == 0) {
        if (expect_failure(-1, bad_descriptor_fifo, 0600, EBADF) != 0 ||
            expect_failure(dirfd, (const char *)0, 0600, EFAULT) != 0 ||
            expect_failure(dirfd, missing_child, 0600, ENOENT) != 0 ||
            expect_failure(dirfd, "", 0600, ENOENT) != 0)
            status = 60;
        else
            RECORD("invalid-and-missing-path-errors");
    }
    if (status == 0) {
        fifo_fd = (int)raw_syscall3(SYS_openat, dirfd,
            (long)(uintptr_t)mode_fifo, O_RDONLY | FIXTURE_O_NONBLOCK);
        if (fifo_fd < 0 ||
            expect_failure(fifo_fd, "child", 0600, ENOTDIR) != 0)
            status = 70;
        else
            RECORD("nondirectory-fd-enotdir");
    }
    if (fifo_fd >= 0 && raw_syscall1(SYS_close, fifo_fd) != 0 && status == 0)
        status = 71;
    if (status == 0) {
        if (expect_failure(fifo_fd, bad_descriptor_fifo, 0600, EBADF) != 0)
            status = 72;
        else
            RECORD("closed-fd-ebadf");
    }

    if (remove_fifo_if_present(FIXTURE_AT_FDCWD, shared_name) != 0 && status == 0)
        status = 80;
    if (remove_fifo_if_present(dirfd, shared_name) != 0 && status == 0)
        status = 81;
    if (remove_fifo_if_present(dirfd, masked_fifo) != 0 && status == 0)
        status = 82;
    if (remove_fifo_if_present(dirfd, zero_fifo) != 0 && status == 0)
        status = 83;
    if (remove_fifo_if_present(dirfd, mode_fifo) != 0 && status == 0)
        status = 84;
    if (raw_syscall1(SYS_close, dirfd) != 0 && status == 0)
        status = 85;
    if (raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)parent, AT_REMOVEDIR) != 0 && status == 0)
        status = 86;
    if (status == 0)
        RECORD("cleanup-complete");
    return status;
}

#ifndef CRABC_MKFIFOAT_FREESTANDING
int main(void)
{
    return crabc_x86_64_mkfifoat_probe();
}
#endif
