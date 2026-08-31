/* Static crabc-libc x86-64 GNU syncfs fixture.
 *
 * The project-header C body first executes through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * archive.  It selects only direct syncfs C ABI and initial-TLS errno
 * translation.  Fixture-local raw setup/cleanup makes an unlinked regular
 * file and writes bytes; it does not select C descriptor lifecycle, a
 * filesystem policy, or any storage-durability claim. It makes no power-loss durability assertion.
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
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_write == 1 && SYS_open == 2 && SYS_close == 3 &&
    SYS_getpid == 39 && SYS_unlink == 87 && SYS_syncfs == 306,
    "x86 selected syncfs fixture syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&syncfs), int (*)(int)),
    "GNU syncfs declaration");

static long raw0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory"
    );
    return result;
}

static long raw1(long number, long argument)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument)
        : "rcx", "r11", "memory"
    );
    return result;
}

static long raw3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory"
    );
    return result;
}

static int open_unlinked_fixture_file(void)
{
    static const char prefix[] = "/tmp/crabc-x86-static-syncfs-";
    char path[64];
    char digits[24];
    unsigned long process_id = (unsigned long)raw0(SYS_getpid);
    unsigned digit_count = 0;
    unsigned index = 0;
    long descriptor;

    while (prefix[index] != '\0') {
        path[index] = prefix[index];
        ++index;
    }
    do {
        digits[digit_count++] = (char)('0' + process_id % 10U);
        process_id /= 10U;
    } while (process_id != 0U);
    while (digit_count != 0U)
        path[index++] = digits[--digit_count];
    path[index] = '\0';

    descriptor = raw3(SYS_open, (long)(uintptr_t)path,
        O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0)
        return -1;
    if (raw1(SYS_unlink, (long)(uintptr_t)path) != 0) {
        (void)raw1(SYS_close, descriptor);
        return -1;
    }
    if (raw3(SYS_write, descriptor, (long)(uintptr_t)"syncfs", 6) != 6) {
        (void)raw1(SYS_close, descriptor);
        return -1;
    }
    return (int)descriptor;
}

static int check_success(int descriptor)
{
    int (*volatile function)(int) = syncfs;

    /* Success retains the caller's stale errno; no durability is measured. */
    errno = ERANGE;
    if (syncfs(descriptor) != 0 || errno != ERANGE)
        return 1;
    errno = E2BIG;
    if (function(descriptor) != 0 || errno != E2BIG)
        return 2;
    return 0;
}

static int check_closed_descriptor(int descriptor)
{
    int (*volatile function)(int) = syncfs;

    if (raw1(SYS_close, descriptor) != 0)
        return 1;
    errno = 0;
    if (syncfs(descriptor) != -1 || errno != EBADF)
        return 2;
    errno = 0;
    if (function(descriptor) != -1 || errno != EBADF)
        return 3;
    return 0;
}

int crabc_x86_64_syncfs_probe(void)
{
    int descriptor = open_unlinked_fixture_file();
    int result;

    if (descriptor < 0)
        return 1;
    result = check_success(descriptor);
    if (result != 0) {
        (void)raw1(SYS_close, descriptor);
        return 10 + result;
    }
    result = check_closed_descriptor(descriptor);
    return result == 0 ? 0 : 20 + result;
}

#ifndef CRABC_SYNCFS_FREESTANDING
int main(void)
{
    return crabc_x86_64_syncfs_probe();
}
#endif
