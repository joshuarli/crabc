/* Static x86-64 ulimit C ABI and runtime differential fixture.
 *
 * One project-header body first runs through pinned musl 1.2.6 and then
 * through a true `-nostdlib -static` crabc archive. It proves only musl's
 * legacy RLIMIT_FSIZE block query/set adapter: the no-vararg GET and unknown
 * command paths, the UL_SETFSIZE long vararg, 512-byte conversion, and stale
 * errno success. The rounded soft-limit mutation is contained to each
 * disposable reference/candidate process; no general resource API is claimed.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <ulimit.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long width");
_Static_assert(sizeof(rlim_t) == 8, "x86 rlim_t width");
_Static_assert(sizeof(struct rlimit) == 16 && _Alignof(struct rlimit) == 8,
    "x86 rlimit layout");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0 &&
    offsetof(struct rlimit, rlim_max) == 8, "x86 rlimit fields");
_Static_assert(RLIMIT_FSIZE == 1 && UL_GETFSIZE == 1 && UL_SETFSIZE == 2,
    "musl ulimit resource and commands");
_Static_assert(SYS_prlimit64 == 302, "x86 Linux prlimit64 number");

typedef long (*ulimit_signature)(int, ...);

static long raw_syscall4(long number, long first, long second, long third,
    long fourth)
{
    register long r10 __asm__("r10") = fourth;
    long result;

    __asm__ volatile (
        "syscall"
        : "=a" (result), "+r" (r10)
        : "a" (number), "D" (first), "S" (second), "d" (third)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_is_linux_error(long value)
{
    return value < 0 && value >= -4095;
}

static int raw_get_fsize_limit(struct rlimit *output)
{
    long result = raw_syscall4(SYS_prlimit64, 0, RLIMIT_FSIZE, 0,
        (long)output);

    return raw_is_linux_error(result) ? -1 : 0;
}

int crabc_x86_64_ulimit_probe(void)
{
    const ulimit_signature function = ulimit;
    struct rlimit before;
    struct rlimit after;
    unsigned long long expected_current;
    long expected_blocks;

    if (raw_get_fsize_limit(&before) != 0)
        return 1;
    expected_blocks = (long)(before.rlim_cur / 512ULL);
    expected_current = ((unsigned long long)expected_blocks) * 512ULL;

    errno = E2BIG;
    if (function(UL_GETFSIZE) != expected_blocks)
        return 2;
    if (errno != E2BIG)
        return 3;

    /* Musl queries the same limit for every command other than SETFSIZE. */
    errno = E2BIG;
    if (function(1977) != expected_blocks)
        return 4;
    if (errno != E2BIG)
        return 5;

    errno = E2BIG;
    if (function(UL_SETFSIZE, expected_blocks) != expected_blocks)
        return 6;
    if (errno != E2BIG)
        return 7;
    if (raw_get_fsize_limit(&after) != 0)
        return 8;
    if (after.rlim_cur != (rlim_t)expected_current ||
        after.rlim_max != before.rlim_max)
        return 9;

    errno = E2BIG;
    if (function(UL_GETFSIZE) != expected_blocks)
        return 10;
    return errno == E2BIG ? 0 : 11;
}

#ifndef CRABC_ULIMIT_FREESTANDING
int main(void)
{
    return crabc_x86_64_ulimit_probe();
}
#endif
