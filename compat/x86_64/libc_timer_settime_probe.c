/* Static crabc-libc x86-64 selected timer_settime error-ABI fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6, then
 * through a dependency-free -nostdlib -static candidate. In a fresh process
 * that creates no POSIX timers, it passes only nonnegative opaque timer bits
 * 0 and INT_MAX, a valid nonzero request record, flags=0, and initialized
 * output storage. It proves -1/EINVAL and input/output preservation only; it
 * neither creates, arms, queries, observes, nor deletes a valid POSIX timer.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

typedef int (*timer_settime_signature)(timer_t, int,
    const struct itimerspec *, struct itimerspec *);

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(timer_t) == 8 && _Alignof(timer_t) == 8,
    "x86 opaque timer_t ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec ABI");
_Static_assert(sizeof(struct itimerspec) == 32 &&
    _Alignof(struct itimerspec) == 8, "x86 itimerspec ABI");
_Static_assert(__builtin_offsetof(struct itimerspec, it_interval) == 0,
    "x86 itimerspec interval offset");
_Static_assert(__builtin_offsetof(struct itimerspec, it_value) == 16,
    "x86 itimerspec value offset");
_Static_assert(SYS_timer_settime == 223,
    "x86 timer_settime syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timer_settime),
    timer_settime_signature), "timer_settime declaration");

static volatile timer_settime_signature timer_settime_function = timer_settime;

static int request_is_unchanged(const struct itimerspec *value)
{
    return value->it_interval.tv_sec == 0 && value->it_interval.tv_nsec == 0 &&
        value->it_value.tv_sec == 0 && value->it_value.tv_nsec == 1;
}

static int record_is_unchanged(const struct itimerspec *value)
{
    return value->it_interval.tv_sec == 101 && value->it_interval.tv_nsec == 102 &&
        value->it_value.tv_sec == 103 && value->it_value.tv_nsec == 104;
}

static int check_rejected_timer(timer_t timer, int sentinel)
{
    struct itimerspec request = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
        .it_value = { .tv_sec = 0, .tv_nsec = 1 },
    };
    struct itimerspec old_value = {
        .it_interval = { .tv_sec = 101, .tv_nsec = 102 },
        .it_value = { .tv_sec = 103, .tv_nsec = 104 },
    };

    errno = sentinel;
    if (timer_settime_function(timer, 0, &request, &old_value) != -1 ||
        errno != EINVAL)
        return 1;
    if (!request_is_unchanged(&request))
        return 2;
    if (!record_is_unchanged(&old_value))
        return 3;
    return 0;
}

int crabc_x86_64_timer_settime_probe(void)
{
    int status = check_rejected_timer((timer_t)0, ERANGE);

    if (status != 0)
        return 10 + status;
    status = check_rejected_timer((timer_t)(uintptr_t)INT_MAX, E2BIG);
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_TIMER_SETTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_timer_settime_probe();
}
#endif
