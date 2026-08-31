/* Static crabc-libc x86-64 sync_file_range compatibility fixture.
 *
 * The same GNU project-header C body first runs through pinned musl 1.2.6 and
 * then through a true freestanding crabc archive. Raw Linux setup creates one
 * regular file and one pipe in the runner-owned directory; only
 * sync_file_range is a candidate C entry. The fixture compares the direct
 * x86 request on a zero-length-through-EOF range, invalid flags, a pipe, and
 * a closed descriptor. It proves a range-writeback request, not persistence,
 * metadata, pathname opening, descriptor lifecycle, or filesystem policy.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_REMOVEDIR = 0x200,
    FIXTURE_EBADF = 9,
    FIXTURE_EINTR = 4,
    FIXTURE_EINVAL = 22,
    FIXTURE_EOPNOTSUPP = 95,
    FIXTURE_ESPIPE = 29,
    FIXTURE_O_CREAT = 0100,
    FIXTURE_O_EXCL = 0200,
    FIXTURE_O_RDWR = 02,
    FIXTURE_SEEK_CUR = 1,
};

_Static_assert(sizeof(off_t) == 8 && _Alignof(off_t) == 8 &&
                   __builtin_types_compatible_p(off_t, long),
               "x86 sync_file_range off_t ABI");
_Static_assert(SYNC_FILE_RANGE_WAIT_BEFORE == 1 &&
                   SYNC_FILE_RANGE_WRITE == 2 &&
                   SYNC_FILE_RANGE_WAIT_AFTER == 4,
               "x86 sync_file_range flags");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_lseek == 8 &&
                   SYS_openat == 257 && SYS_mkdirat == 258 &&
                   SYS_unlinkat == 263 && SYS_sync_file_range == 277 &&
                   SYS_pipe2 == 293,
               "Linux x86 sync_file_range fixture syscall numbers");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD &&
                   AT_REMOVEDIR == FIXTURE_AT_REMOVEDIR &&
                   O_CREAT == FIXTURE_O_CREAT && O_EXCL == FIXTURE_O_EXCL &&
                   O_RDWR == FIXTURE_O_RDWR && SEEK_CUR == FIXTURE_SEEK_CUR,
               "x86 sync_file_range fixture constants");
_Static_assert(EBADF == FIXTURE_EBADF && EINTR == FIXTURE_EINTR &&
                   EINVAL == FIXTURE_EINVAL && EOPNOTSUPP == FIXTURE_EOPNOTSUPP &&
                   ESPIPE == FIXTURE_ESPIPE,
               "x86 sync_file_range errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync_file_range),
    int (*)(int, off_t, off_t, unsigned)), "sync_file_range declaration");

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

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
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

static long raw_sync_file_range(int fd, off_t offset, off_t nbytes,
    unsigned flags)
{
    return raw_syscall4(SYS_sync_file_range, fd, offset, nbytes,
                        (long)flags);
}

static int remove_path_at(int dirfd, const char *path, int flags)
{
    return raw_syscall3(SYS_unlinkat, dirfd, (long)(uintptr_t)path, flags) == 0
        ? 0
        : -1;
}

static int check_regular_result(int candidate, int candidate_errno, long raw)
{
    if (raw == 0)
        return candidate == 0 && candidate_errno == EINTR ? 0 : 1;
    if (raw == -FIXTURE_EOPNOTSUPP)
        return candidate == -1 && candidate_errno == EOPNOTSUPP ? 0 : 2;
    return 3;
}

int crabc_x86_64_sync_file_range_probe(void)
{
    static const char directory[] = "sync-file-range-root";
    static const char file[] = "sync-file-range-root/file";
    static const unsigned char payload[] = {'c', 'r', 'a', 'b', 'c'};
    static const unsigned flags = SYNC_FILE_RANGE_WAIT_BEFORE |
                                  SYNC_FILE_RANGE_WRITE |
                                  SYNC_FILE_RANGE_WAIT_AFTER;
    int pipe_fds[2] = {-1, -1};
    int descriptor = -1;
    int candidate;
    int candidate_errno;
    long before;
    long raw;
    int status = 0;

    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, 0700) != 0)
        return 1;
    descriptor = (int)raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)file, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0)
        status = 2;
    if (status == 0 && raw_syscall3(SYS_write, descriptor,
        (long)(uintptr_t)payload, sizeof(payload)) != (long)sizeof(payload))
        status = 3;
    before = status == 0 ? raw_syscall3(SYS_lseek, descriptor, 0,
                                        FIXTURE_SEEK_CUR) : -1;
    if (status == 0 && before != (long)sizeof(payload))
        status = 4;

    if (status == 0) {
        errno = EINTR;
        candidate = sync_file_range(descriptor, 0, 0, flags);
        candidate_errno = errno;
        raw = raw_sync_file_range(descriptor, 0, 0, flags);
        if (check_regular_result(candidate, candidate_errno, raw) != 0)
            status = 10;
        else if (raw_syscall3(SYS_lseek, descriptor, 0, FIXTURE_SEEK_CUR) !=
                 before)
            status = 11;
    }
    if (status == 0) {
        errno = 0;
        raw = raw_sync_file_range(descriptor, 0, 0, flags | 0x08U);
        if (sync_file_range(descriptor, 0, 0, flags | 0x08U) != -1 ||
            errno != EINVAL || raw != -FIXTURE_EINVAL)
            status = 20;
        else if (raw_syscall3(SYS_lseek, descriptor, 0, FIXTURE_SEEK_CUR) !=
                 before)
            status = 21;
    }
    if (status == 0 && raw_syscall2(SYS_pipe2,
        (long)(uintptr_t)pipe_fds, 0) != 0)
        status = 30;
    if (status == 0) {
        errno = 0;
        raw = raw_sync_file_range(pipe_fds[0], 0, 0, flags);
        if (sync_file_range(pipe_fds[0], 0, 0, flags) != -1 ||
            errno != ESPIPE || raw != -FIXTURE_ESPIPE)
            status = 31;
    }
    if (status == 0) {
        errno = 0;
        raw = raw_sync_file_range(-1, 0, 0, flags);
        if (sync_file_range(-1, 0, 0, flags) != -1 || errno != EBADF ||
            raw != -FIXTURE_EBADF)
            status = 32;
    }

    if (pipe_fds[0] >= 0 && raw_syscall1(SYS_close, pipe_fds[0]) != 0 &&
        status == 0)
        status = 40;
    if (pipe_fds[1] >= 0 && raw_syscall1(SYS_close, pipe_fds[1]) != 0 &&
        status == 0)
        status = 41;
    if (descriptor >= 0 && raw_syscall1(SYS_close, descriptor) != 0 &&
        status == 0)
        status = 42;
    if (remove_path_at(FIXTURE_AT_FDCWD, file, 0) != 0 && status == 0)
        status = 43;
    if (remove_path_at(FIXTURE_AT_FDCWD, directory, AT_REMOVEDIR) != 0 &&
        status == 0)
        status = 44;
    return status;
}

#ifndef CRABC_SYNC_FILE_RANGE_FREESTANDING
int main(void)
{
    return crabc_x86_64_sync_file_range_probe();
}
#endif
