/*
 * Pinned-musl Linux/x86-64 ftime differential and static-candidate body.
 *
 * The same one-symbol project-header C body first runs through pinned musl
 * 1.2.6 and then through the selected `-nostdlib -static` candidate. It
 * proves only musl's historical realtime snapshot adapter: a valid caller
 * record receives seconds, milliseconds, and fixed zero timezone/dst fields,
 * while the selected clock query preserves stale errno on success. This is
 * not clock mutation, timer behavior, calendar policy, or signal runtime.
 */

#define _POSIX_C_SOURCE 200809L

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/timeb.h>
#include <time.h>

_Static_assert(sizeof(time_t) == 8, "x86 time_t width");
_Static_assert(sizeof(struct timeb) == 16 && _Alignof(struct timeb) == 8,
    "x86 timeb layout");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(CLOCK_REALTIME == 0, "x86 realtime clock value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ftime),
    int (*)(struct timeb *)), "ftime declaration");

typedef int (*ftime_function)(struct timeb *);

/* Parentheses retain the public C ABI boundary rather than a builtin. */
static ftime_function volatile direct_ftime = (ftime);

static int milliseconds_in_range(const struct timeb *value,
    const struct timespec *before, const struct timespec *after)
{
    int64_t value_milliseconds;
    int64_t before_milliseconds;
    int64_t after_milliseconds;

    if (value->time < 0 || value->millitm >= 1000)
        return 1;
    value_milliseconds = (int64_t)value->time * 1000 + value->millitm;
    before_milliseconds = (int64_t)before->tv_sec * 1000 +
        before->tv_nsec / 1000000;
    after_milliseconds = (int64_t)after->tv_sec * 1000 +
        after->tv_nsec / 1000000;
    return value_milliseconds < before_milliseconds ||
        value_milliseconds > after_milliseconds;
}

static int check_snapshot_and_stale_errno(void)
{
    struct timespec before;
    struct timespec after;
    struct timeb value = { 0, 0, 0, 0 };

    if (clock_gettime(CLOCK_REALTIME, &before) != 0)
        return 1;
    errno = ERANGE;
    if (direct_ftime(&value) != 0)
        return 2;
    if (errno != ERANGE)
        return 3;
    if (clock_gettime(CLOCK_REALTIME, &after) != 0)
        return 4;
    if (milliseconds_in_range(&value, &before, &after) != 0)
        return 5;
    if (value.timezone != 0 || value.dstflag != 0)
        return 6;
    return 0;
}

int crabc_x86_64_ftime_probe(void)
{
    return check_snapshot_and_stale_errno();
}

#ifndef CRABC_FTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_ftime_probe();
}
#endif
