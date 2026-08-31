/* Native Linux/x86-64 static posix_close C ABI evidence.
 *
 * One project-header C body first runs through pinned musl 1.2.6 and then
 * through a true freestanding crabc archive. Fixture-local raw pipe2/close
 * calls create and clean only two anonymous descriptor slots. `posix_close`
 * is the sole candidate C entry: it must close normally, preserve stale errno
 * on success, ignore its flags word exactly as musl does, and translate an
 * invalid descriptor into -1/EBADF. This does not select generic descriptor
 * I/O, close cancellation/AIO coordination, descriptor ownership, or a
 * filesystem/runtime policy.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    FIXTURE_EBADF = 9,
    FIXTURE_EINTR = 4,
    FIXTURE_E2BIG = 7,
};

typedef int (*posix_close_signature)(int, int);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
               "x86 posix_close int ABI");
_Static_assert(SYS_close == 3 && SYS_pipe2 == 293,
               "Linux x86 posix_close fixture syscall numbers");
_Static_assert(EBADF == FIXTURE_EBADF && EINTR == FIXTURE_EINTR &&
                   E2BIG == FIXTURE_E2BIG,
               "Linux x86 posix_close errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_close),
                                             posix_close_signature),
               "posix_close declaration");

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

int crabc_x86_64_posix_close_probe(void)
{
    int descriptors[2] = { -1, -1 };
    const posix_close_signature function = posix_close;
    int status = 0;

    if (raw_syscall2(SYS_pipe2, (long)(uintptr_t)descriptors, 0) != 0)
        return 1;

    errno = EINTR;
    if (posix_close(descriptors[0], 0x7fffffff) != 0)
        status = 2;
    else if (errno != EINTR)
        status = 3;
    else if (raw_syscall1(SYS_close, descriptors[0]) != -EBADF)
        status = 4;

    if (status == 0) {
        errno = E2BIG;
        if (function(descriptors[1], -1) != 0)
            status = 5;
        else if (errno != E2BIG)
            status = 6;
        else if (raw_syscall1(SYS_close, descriptors[1]) != -EBADF)
            status = 7;
    }

    if (status == 0) {
        errno = 0;
        if (posix_close(-1, 0) != -1 || errno != EBADF)
            status = 8;
    }
    if (status == 0) {
        errno = 0;
        if (function(-1, 0x1234) != -1 || errno != EBADF)
            status = 9;
    }

    (void)raw_syscall1(SYS_close, descriptors[0]);
    (void)raw_syscall1(SYS_close, descriptors[1]);
    return status;
}

#ifndef CRABC_POSIX_CLOSE_FREESTANDING
int main(void)
{
    return crabc_x86_64_posix_close_probe();
}
#endif
