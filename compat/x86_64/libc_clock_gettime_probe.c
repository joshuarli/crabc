/* Static crabc-libc x86-64 selected clock_gettime fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves only clock_gettime's ordinary zero-or--1/errno
 * boundary. It does not select vDSO policy, clock resolution/mutation,
 * calendar state, POSIX timers, CRT, loader, sysroot, or public x86 support.
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

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8, "x86 timespec field offsets");
_Static_assert(SYS_clock_gettime == 228, "x86 clock_gettime syscall number");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 &&
    CLOCK_PROCESS_CPUTIME_ID == 2, "selected clock IDs");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_gettime),
    int (*)(clockid_t, struct timespec *)), "clock_gettime declaration");

static int normalized(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static int check_success_and_errno(void)
{
    struct timespec realtime;
    struct timespec monotonic_before;
    struct timespec monotonic_after;
    struct timespec cpu_before;
    struct timespec cpu_after;
    volatile unsigned long long checksum = 0;
    const int preserved_errno = ERANGE;

    errno = preserved_errno;
    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0 ||
        errno != preserved_errno || !normalized(&realtime))
        return 1;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic_before) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic_after) != 0 ||
        !normalized(&monotonic_before) || !normalized(&monotonic_after) ||
        monotonic_after.tv_sec < monotonic_before.tv_sec ||
        (monotonic_after.tv_sec == monotonic_before.tv_sec &&
         monotonic_after.tv_nsec < monotonic_before.tv_nsec))
        return 2;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_before) != 0)
        return 3;
    for (unsigned long long value = 0; value < 500000ULL; ++value)
        checksum += value << (value & 15);
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_after) != 0 ||
        !normalized(&cpu_before) || !normalized(&cpu_after) || checksum == 0 ||
        cpu_after.tv_sec < cpu_before.tv_sec ||
        (cpu_after.tv_sec == cpu_before.tv_sec &&
         cpu_after.tv_nsec < cpu_before.tv_nsec))
        return 4;
    return 0;
}

static int check_errors(void)
{
    struct timespec output;

    errno = 0;
    if (clock_gettime(-1, &output) != -1 || errno != EINVAL)
        return 1;
    return 0;
}

int crabc_x86_64_clock_gettime_probe(void)
{
    int status = check_success_and_errno();

    if (status != 0)
        return 10 + status;
    status = check_errors();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_CLOCK_GETTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_gettime_probe();
}
#endif
