/* Static crabc-libc x86-64 selected time-observation fixture.
 *
 * The same project-header C body is intended to execute first through pinned
 * musl 1.2.6 and then through a freestanding executable linked solely with
 * the selected crabc libc.a.  It specifies a deliberately bounded direct
 * clock-observation block: clock(3), time(3), timespec_get(3),
 * clock_getres(3), and gettimeofday(3). The separate scalar difftime
 * fixture owns the binary64 conversion. This artifact does not select
 * calendar or timezone state, clock mutation, POSIX timers, cancellation,
 * CRT, loader, sysroot, or public x86 support.
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
#include <sys/time.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(time_t) == 8 && sizeof(clock_t) == 8,
    "x86 time scalar widths");
_Static_assert(sizeof(struct timespec) == 16 &&
    _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec field offsets");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
    "x86 timeval layout");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval field offsets");
_Static_assert(SYS_gettimeofday == 96 && SYS_clock_gettime == 228 &&
    SYS_clock_getres == 229,
    "x86 selected time syscall numbers");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 &&
    CLOCK_PROCESS_CPUTIME_ID == 2 && TIME_UTC == 1,
    "selected clock constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock),
    clock_t (*)(void)), "clock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&time),
    time_t (*)(time_t *)), "time declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timespec_get),
    int (*)(struct timespec *, int)), "timespec_get declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_getres),
    int (*)(clockid_t, struct timespec *)), "clock_getres declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),
    int (*)(struct timeval *restrict, void *restrict)),
    "gettimeofday declaration");

static int normalized_timespec(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static int normalized_timeval(const struct timeval *value)
{
    return value->tv_usec >= 0 && value->tv_usec < 1000000L;
}

static int not_before(const struct timespec *left, const struct timespec *right)
{
    return left->tv_sec > right->tv_sec ||
        (left->tv_sec == right->tv_sec && left->tv_nsec >= right->tv_nsec);
}

static int check_wall_clock_and_errno(void)
{
    struct timespec before;
    struct timespec after;
    struct timespec c11;
    struct timespec resolution;
    struct timeval wall;
    time_t stored;
    time_t returned;
    const int preserved_errno = ERANGE;

    errno = preserved_errno;
    if (clock_gettime(CLOCK_REALTIME, &before) != 0 ||
        !normalized_timespec(&before))
        return 1;
    returned = time(&stored);
    if (returned != stored || returned <= 0 || errno != preserved_errno)
        return 2;
    if (time(NULL) <= 0 || errno != preserved_errno)
        return 3;
    if (gettimeofday(&wall, NULL) != 0 || !normalized_timeval(&wall) ||
        errno != preserved_errno)
        return 4;
    if (gettimeofday(NULL, NULL) != 0 || errno != preserved_errno)
        return 5;
    if (timespec_get(&c11, TIME_UTC) != TIME_UTC ||
        !normalized_timespec(&c11) || errno != preserved_errno)
        return 6;
    if (clock_getres(CLOCK_MONOTONIC, &resolution) != 0 ||
        !normalized_timespec(&resolution) ||
        (resolution.tv_sec == 0 && resolution.tv_nsec == 0) ||
        errno != preserved_errno)
        return 7;
    if (clock_gettime(CLOCK_REALTIME, &after) != 0 ||
        !normalized_timespec(&after) || !not_before(&after, &before))
        return 8;

    /* Both integer-second views must be from the observed realtime window. */
    if (returned < before.tv_sec - 1 || returned > after.tv_sec + 1 ||
        wall.tv_sec < before.tv_sec - 1 || wall.tv_sec > after.tv_sec + 1 ||
        c11.tv_sec < before.tv_sec - 1 || c11.tv_sec > after.tv_sec + 1)
        return 9;
    return 0;
}

static int check_cpu_clock(void)
{
    clock_t before;
    clock_t after;
    volatile unsigned long long checksum = 0;
    const int preserved_errno = E2BIG;

    errno = preserved_errno;
    before = clock();
    for (unsigned long long value = 0; value < 500000ULL; ++value)
        checksum += value << (value & 15);
    after = clock();
    if (before < 0 || after < before || checksum == 0 ||
        errno != preserved_errno)
        return 1;
    return 0;
}

static int check_error_conventions(void)
{
    struct timespec value;

    errno = 0;
    if (clock_getres(-1, &value) != -1 || errno != EINVAL)
        return 1;
    errno = ERANGE;
    if (timespec_get(&value, 0) != 0 || errno != ERANGE)
        return 2;
    return 0;
}

int crabc_x86_64_time_observation_probe(void)
{
    int status = check_wall_clock_and_errno();

    if (status != 0)
        return 10 + status;
    status = check_cpu_clock();
    if (status != 0)
        return 30 + status;
    status = check_error_conventions();
    return status == 0 ? 0 : 50 + status;
}

#ifndef CRABC_TIME_OBSERVATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_time_observation_probe();
}
#endif
