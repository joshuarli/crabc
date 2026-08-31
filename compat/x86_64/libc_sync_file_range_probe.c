/* Static x86-64 GNU sync_file_range C ABI and pinned-musl behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a true static crabc archive. The named boundary issues only a
 * descriptor-range writeback request: a raw-created, immediately unlinked
 * regular file retains its current position, the wrapper's result/errno maps
 * exactly to a sibling raw syscall, invalid flags report EINVAL, and a bad
 * descriptor reports EBADF. Fixture-local raw syscalls create, dirty, seek,
 * inspect, close, and unlink the disposable file; they are not selected C
 * descriptor, pathname, writeback-policy, or durability APIs.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>

enum {
    PATH_CAPACITY = 80,
    FILE_POSITION = 3,
};

typedef int (*sync_file_range_signature)(int, off_t, off_t, unsigned);

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(off_t) == sizeof(long), "x86 LP64 off_t ABI");
_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_lseek == 8 &&
    SYS_getpid == 39 && SYS_openat == 257 && SYS_unlinkat == 263 &&
    SYS_sync_file_range == 277,
    "x86 selected sync_file_range fixture syscall numbers");
_Static_assert(AT_FDCWD == -100 && O_RDWR == 02 && O_CREAT == 0100 &&
    O_EXCL == 0200 && O_CLOEXEC == 02000000,
    "x86 selected sync_file_range fixture constants");
_Static_assert(SYNC_FILE_RANGE_WAIT_BEFORE == 1 &&
    SYNC_FILE_RANGE_WRITE == 2 && SYNC_FILE_RANGE_WAIT_AFTER == 4,
    "x86 sync_file_range flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync_file_range),
    sync_file_range_signature), "sync_file_range declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

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
    register long argument4_r10 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(argument4_r10)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_openat(const char *path, int flags, unsigned mode)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)path,
        flags, mode);
}

static int raw_unlinkat(const char *path)
{
    return (int)raw_syscall3(SYS_unlinkat, AT_FDCWD,
        (long)(uintptr_t)path, 0);
}

static void raw_close(int descriptor)
{
    if (descriptor >= 0)
        (void)raw_syscall1(SYS_close, descriptor);
}

static int make_path(char path[PATH_CAPACITY])
{
    static const char prefix[] = "/tmp/crabc-x86-static-sync-file-range-";
    char reverse_digits[20];
    long process_id = raw_syscall0(SYS_getpid);
    size_t digits = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    do {
        reverse_digits[digits++] = (char)('0' + (process_id % 10));
        process_id /= 10;
    } while (process_id != 0 && digits < sizeof(reverse_digits));
    if (process_id != 0 || sizeof(prefix) + digits > PATH_CAPACITY)
        return -1;

    for (index = 0; index < sizeof(prefix) - 1; ++index)
        path[index] = prefix[index];
    while (digits != 0)
        path[index++] = reverse_digits[--digits];
    path[index] = '\0';
    return 0;
}

static int check_regular_range(int descriptor)
{
    static const char payload[] = "range";
    const unsigned flags = SYNC_FILE_RANGE_WAIT_BEFORE |
        SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    long raw_result;
    int result;
    int observed_errno;

    if (raw_syscall3(SYS_write, descriptor, (long)(uintptr_t)payload,
            sizeof(payload) - 1) != (long)(sizeof(payload) - 1))
        return 1;
    if (raw_syscall3(SYS_lseek, descriptor, FILE_POSITION, SEEK_SET) !=
        FILE_POSITION)
        return 2;

    raw_result = raw_syscall4(SYS_sync_file_range, descriptor, 0, 0, flags);
    errno = E2BIG;
    result = sync_file_range(descriptor, 0, 0, flags);
    observed_errno = errno;
    if (raw_result == 0) {
        if (result != 0 || observed_errno != E2BIG)
            return 3;
    } else if (raw_result >= -4095 && raw_result < 0) {
        if (result != -1 || observed_errno != (int)-raw_result)
            return 4;
    } else {
        return 5;
    }
    if (raw_syscall3(SYS_lseek, descriptor, 0, SEEK_CUR) != FILE_POSITION)
        return 6;

    errno = ERANGE;
    if (sync_file_range(descriptor, 0, 0, 0x80000000U) != -1 ||
        errno != EINVAL)
        return 7;
    return 0;
}

static int check_fixture(void)
{
    char path[PATH_CAPACITY];
    int descriptor = -1;
    int status;

    if (make_path(path) != 0)
        return 1;
    (void)raw_unlinkat(path);
    descriptor = raw_openat(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0)
        return 2;
    status = check_regular_range(descriptor);
    if (status != 0)
        goto cleanup;

    errno = E2BIG;
    if (sync_file_range(-1, 0, 0, 0) != -1 || errno != EBADF)
        status = 8;

cleanup:
    raw_close(descriptor);
    (void)raw_unlinkat(path);
    return status;
}

int crabc_x86_64_sync_file_range_probe(void)
{
    return check_fixture();
}

#ifndef CRABC_SYNC_FILE_RANGE_FREESTANDING
int main(void)
{
    return crabc_x86_64_sync_file_range_probe();
}
#endif
