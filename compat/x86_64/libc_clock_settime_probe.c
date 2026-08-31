/* Static crabc-libc x86-64 selected clock_settime error-ABI fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate. It invokes only
 * Linux-rejected clock IDs, so this fixture never requests a valid realtime
 * clock mutation. It observes the ordinary C -1/errno conversion for the
 * direct wrapper, not a clock-setting authority, state, or policy contract.
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
#include <stddef.h>
#include <sys/syscall.h>
#include <time.h>

typedef int (*clock_settime_signature)(clockid_t, const struct timespec *);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8, "x86 timespec field offsets");
_Static_assert(SYS_clock_settime == 227, "x86 clock_settime syscall number");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1,
    "selected non-mutating clock IDs");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_settime),
    clock_settime_signature), "clock_settime declaration");

static volatile clock_settime_signature clock_settime_function = clock_settime;

static int check_invalid_clock(void)
{
    const struct timespec request = {0, 0};

    errno = ERANGE;
    if (clock_settime_function((clockid_t)-1, &request) != -1 ||
        (errno != EINVAL && errno != EPERM))
        return 1;
    return 0;
}

static int check_monotonic_rejection(void)
{
    const struct timespec request = {0, 0};

    errno = E2BIG;
    if (clock_settime_function(CLOCK_MONOTONIC, &request) != -1 ||
        (errno != EINVAL && errno != EPERM))
        return 1;
    return 0;
}

int crabc_x86_64_clock_settime_probe(void)
{
    int status = check_invalid_clock();

    if (status != 0)
        return 10 + status;
    status = check_monotonic_rejection();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_CLOCK_SETTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_settime_probe();
}
#endif
