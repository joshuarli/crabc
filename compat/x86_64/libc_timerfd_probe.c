/* Static crabc-libc x86-64 timerfd fixture.
 *
 * The common project-header C body runs first through pinned musl 1.2.6 and
 * then through a true dependency-free `-nostdlib -static` crabc candidate.
 * It selects direct timer descriptor creation/query/control and ordinary
 * descriptor consumption only; it creates no process timer, signal policy,
 * callback, timer registry, or event loop.
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
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

enum {
    NANOSECONDS_PER_MILLISECOND = 1000000,
    NANOSECONDS_PER_SECOND = 1000000000,
};

_Static_assert(sizeof(struct timespec) == 16 &&
    offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec ABI");
_Static_assert(sizeof(struct itimerspec) == 32 &&
    _Alignof(struct itimerspec) == 8 &&
    offsetof(struct itimerspec, it_interval) == 0 &&
    offsetof(struct itimerspec, it_value) == 16,
    "x86 itimerspec ABI");
_Static_assert(TFD_NONBLOCK == 0x00000800 && TFD_CLOEXEC == 0x00080000 &&
    TFD_TIMER_ABSTIME == 1 && TFD_TIMER_CANCEL_ON_SET == 2,
    "x86 timerfd flags");
_Static_assert(SYS_timerfd_create == 283 && SYS_timerfd_settime == 286 &&
    SYS_timerfd_gettime == 287,
    "x86 timerfd syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_create),
    int (*)(int, int)), "timerfd_create declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_settime),
    int (*)(int, int, const struct itimerspec *, struct itimerspec *)),
    "timerfd_settime declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timerfd_gettime),
    int (*)(int, struct itimerspec *)), "timerfd_gettime declaration");

static int timespec_is_zero(const struct timespec *value)
{
    return value->tv_sec == 0 && value->tv_nsec == 0;
}

static int timespec_is_canonical_nonnegative(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
        value->tv_nsec < NANOSECONDS_PER_SECOND;
}

static int spec_is_zero(const struct itimerspec *value)
{
    return timespec_is_zero(&value->it_interval) &&
        timespec_is_zero(&value->it_value);
}

static int test_create_and_control(void)
{
    struct itimerspec current = {0};
    struct itimerspec old_value = {0};
    struct itimerspec invalid = {0};
    struct itimerspec one_shot = {
        .it_value = { .tv_sec = 0, .tv_nsec = NANOSECONDS_PER_MILLISECOND },
    };
    struct itimerspec periodic = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 20000000 },
        .it_value = { .tv_sec = 0, .tv_nsec = 500000000 },
    };
    struct itimerspec zero = {0};
    struct pollfd ready;
    uint64_t expirations = 0;
    int descriptor = -1;
    int result = 1;

    errno = 0;
    if (timerfd_create(-1, 0) != -1 || errno != EINVAL)
        return result;
    errno = 0;
    if (timerfd_create(CLOCK_MONOTONIC, 0x00000001) != -1 || errno != EINVAL)
        return 2;

    errno = ERANGE;
    descriptor = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (descriptor < 0 || errno != ERANGE ||
        fcntl(descriptor, F_GETFD) != FD_CLOEXEC ||
        (fcntl(descriptor, F_GETFL) & O_NONBLOCK) == 0) {
        result = 3;
        goto cleanup;
    }

    errno = E2BIG;
    if (timerfd_gettime(descriptor, &current) != 0 || errno != E2BIG ||
        !spec_is_zero(&current)) {
        result = 4;
        goto cleanup;
    }
    errno = 0;
    if (timerfd_gettime(-1, &current) != -1 || errno != EBADF) {
        result = 5;
        goto cleanup;
    }
#ifdef CRABC_TIMERFD_FREESTANDING
    errno = 0;
    if (timerfd_gettime(descriptor, 0) != -1 || errno != EFAULT) {
        result = 6;
        goto cleanup;
    }
#endif

    invalid.it_value.tv_nsec = NANOSECONDS_PER_SECOND;
    errno = 0;
    if (timerfd_settime(descriptor, 0, &invalid, 0) != -1 || errno != EINVAL) {
        result = 7;
        goto cleanup;
    }
    errno = 0;
    if (timerfd_settime(descriptor, 0x00000004, &one_shot, 0) != -1 ||
        errno != EINVAL) {
        result = 8;
        goto cleanup;
    }
#ifdef CRABC_TIMERFD_FREESTANDING
    errno = 0;
    if (timerfd_settime(descriptor, 0, 0, 0) != -1 || errno != EFAULT) {
        result = 9;
        goto cleanup;
    }
#endif

    errno = ERANGE;
    if (timerfd_settime(descriptor, 0, &one_shot, &old_value) != 0 ||
        errno != ERANGE || !spec_is_zero(&old_value)) {
        result = 10;
        goto cleanup;
    }
    if (timerfd_gettime(descriptor, &current) != 0 ||
        !timespec_is_zero(&current.it_interval) ||
        !timespec_is_canonical_nonnegative(&current.it_value)) {
        result = 11;
        goto cleanup;
    }

    ready.fd = descriptor;
    ready.events = POLLIN;
    ready.revents = 0;
    if (poll(&ready, 1, 1000) != 1 || (ready.revents & POLLIN) == 0) {
        result = 12;
        goto cleanup;
    }
    errno = E2BIG;
    if (read(descriptor, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations) ||
        expirations == 0 || errno != E2BIG) {
        result = 13;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, &expirations, sizeof(expirations)) != -1 ||
        errno != EAGAIN) {
        result = 14;
        goto cleanup;
    }

    errno = ERANGE;
    if (timerfd_settime(descriptor, 0, &periodic, &old_value) != 0 ||
        errno != ERANGE || !spec_is_zero(&old_value)) {
        result = 15;
        goto cleanup;
    }
    if (timerfd_gettime(descriptor, &current) != 0 ||
        current.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        current.it_interval.tv_nsec != periodic.it_interval.tv_nsec ||
        !timespec_is_canonical_nonnegative(&current.it_value)) {
        result = 16;
        goto cleanup;
    }
    if (timerfd_settime(descriptor, 0, &zero, &old_value) != 0 ||
        old_value.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        old_value.it_interval.tv_nsec != periodic.it_interval.tv_nsec) {
        result = 17;
        goto cleanup;
    }
    if (timerfd_gettime(descriptor, &current) != 0 || !spec_is_zero(&current)) {
        result = 18;
        goto cleanup;
    }
    result = 0;

cleanup:
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0)
        result = 19;
    return result;
}

static int test_realtime_cancel_on_set_flag(void)
{
    struct itimerspec past_absolute = {
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
    };
    struct itimerspec zero = {0};
    int descriptor;

    descriptor = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    if (descriptor < 0)
        return 1;
    if (timerfd_settime(descriptor,
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &past_absolute, 0) != 0) {
        (void)close(descriptor);
        return 2;
    }
    if (timerfd_settime(descriptor, 0, &zero, 0) != 0 || close(descriptor) != 0)
        return 3;
    return 0;
}

int crabc_x86_64_timerfd_probe(void)
{
    int result = test_create_and_control();

    if (result != 0)
        return result;
    result = test_realtime_cancel_on_set_flag();
    if (result != 0)
        return 32 + result;
    return 0;
}

#ifndef CRABC_TIMERFD_FREESTANDING
int main(void)
{
    return crabc_x86_64_timerfd_probe();
}
#endif
