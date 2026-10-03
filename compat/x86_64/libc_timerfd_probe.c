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
#ifndef CRABC_TIMERFD_FREESTANDING
#include <string.h>
#endif

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

static int test_realtime_cancel_on_set_lifecycle(void)
{
    /* A past absolute deadline proves readiness without changing realtime. */
    struct itimerspec past_absolute = {
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
    };
    struct itimerspec zero = {0};
    struct itimerspec old_value = {0};
    struct itimerspec current = {0};
    struct pollfd ready;
    uint64_t expirations = 0;
    int descriptor;
    int result = 1;

    descriptor = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
    if (descriptor < 0)
        return result;
    ready.fd = descriptor;
    ready.events = POLLIN;
    ready.revents = 0;

    errno = ERANGE;
    if (timerfd_settime(descriptor,
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &past_absolute, 0) != 0 ||
        errno != ERANGE) {
        result = 2;
        goto cleanup;
    }
    if (poll(&ready, 1, 1000) != 1 || (ready.revents & POLLIN) == 0) {
        result = 3;
        goto cleanup;
    }

    /* A rejected flag must leave the pending expiration readable. */
    errno = 0;
    if (timerfd_settime(descriptor,
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET | 4, &zero, 0) != -1 ||
        errno != EINVAL) {
        result = 4;
        goto cleanup;
    }
    ready.revents = 0;
    if (poll(&ready, 1, 0) != 1 || (ready.revents & POLLIN) == 0) {
        result = 5;
        goto cleanup;
    }

    if (timerfd_settime(descriptor, 0, &zero, &old_value) != 0 ||
        !spec_is_zero(&old_value) ||
        timerfd_gettime(descriptor, &current) != 0 || !spec_is_zero(&current)) {
        result = 6;
        goto cleanup;
    }
    ready.revents = 0;
    if (poll(&ready, 1, 0) != 0 || ready.revents != 0) {
        result = 7;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, &expirations, sizeof(expirations)) != -1 ||
        errno != EAGAIN) {
        result = 8;
        goto cleanup;
    }

    if (timerfd_settime(descriptor,
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
            &past_absolute, &old_value) != 0 || !spec_is_zero(&old_value)) {
        result = 9;
        goto cleanup;
    }
    ready.revents = 0;
    if (poll(&ready, 1, 1000) != 1 || (ready.revents & POLLIN) == 0) {
        result = 10;
        goto cleanup;
    }
    errno = E2BIG;
    if (read(descriptor, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations) ||
        expirations != 1 || errno != E2BIG) {
        result = 11;
        goto cleanup;
    }
    ready.revents = 0;
    if (poll(&ready, 1, 0) != 0 || ready.revents != 0) {
        result = 12;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, &expirations, sizeof(expirations)) != -1 ||
        errno != EAGAIN) {
        result = 13;
        goto cleanup;
    }
    result = 0;

cleanup:
    if (close(descriptor) != 0 && result == 0)
        result = 14;
    return result;
}

static int test_absolute_overrun_shared_descriptor(void)
{
    struct itimerspec past_periodic = {
        .it_interval = { .tv_sec = 60, .tv_nsec = 0 },
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
    };
    struct itimerspec past_one_shot = {
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
    };
    struct itimerspec current = {0};
    struct pollfd ready;
    uint64_t expirations = 0;
    int descriptor = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    int alias = -1;
    int result = 1;

    if (descriptor < 0)
        return result;
    alias = dup(descriptor);
    if (alias < 0) {
        result = 2;
        goto cleanup;
    }
    errno = 0;
    if (timerfd_settime(descriptor, TFD_TIMER_ABSTIME,
            &past_periodic, 0) != 0 || errno != 0) {
        result = 3;
        goto cleanup;
    }
    if (timerfd_gettime(alias, &current) != 0 ||
        current.it_interval.tv_sec != 60 || current.it_interval.tv_nsec != 0 ||
        !timespec_is_canonical_nonnegative(&current.it_value)) {
        result = 4;
        goto cleanup;
    }
    /* An already elapsed absolute deadline may become readable after the
     * kernel processes the expiration, rather than inside settime(). */
    ready.fd = alias;
    ready.events = POLLIN;
    ready.revents = 0;
    if (poll(&ready, 1, 1000) != 1 || (ready.revents & POLLIN) == 0) {
        result = 14;
        goto cleanup;
    }
    errno = 0;
    if (read(alias, &expirations, sizeof(expirations) - 1) != -1 ||
        errno != EINVAL) {
        result = 5;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations)) {
        result = 6;
        goto cleanup;
    }
    if (expirations < 2) {
        result = 13;
        goto cleanup;
    }
    errno = 0;
    if (read(alias, &expirations, sizeof(expirations)) != -1 ||
        errno != EAGAIN) {
        result = 16;
        goto cleanup;
    }
    if (timerfd_settime(alias, TFD_TIMER_ABSTIME,
            &past_one_shot, 0) != 0) {
        result = 7;
        goto cleanup;
    }
    if (close(descriptor) != 0) {
        result = 8;
        descriptor = -1;
        goto cleanup;
    }
    descriptor = -1;
    ready.revents = 0;
    if (poll(&ready, 1, 1000) != 1 || (ready.revents & POLLIN) == 0) {
        result = 15;
        goto cleanup;
    }
    if (read(alias, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations) || expirations != 1) {
        result = 9;
        goto cleanup;
    }
    errno = 0;
    if (read(alias, &expirations, sizeof(expirations)) != -1 ||
        errno != EAGAIN) {
        result = 10;
        goto cleanup;
    }
    result = 0;

cleanup:
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0)
        result = 11;
    if (alias >= 0 && close(alias) != 0 && result == 0)
        result = 12;
    return result;
}

int crabc_x86_64_timerfd_probe(void)
{
    int result = test_create_and_control();

    if (result != 0)
        return result;
    result = test_realtime_cancel_on_set_lifecycle();
    if (result != 0)
        return 32 + result;
    result = test_absolute_overrun_shared_descriptor();
    if (result != 0)
        return 48 + result;
    return 0;
}

#ifndef CRABC_TIMERFD_FREESTANDING
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "ordinary-shared"))
        return test_absolute_overrun_shared_descriptor();
    return crabc_x86_64_timerfd_probe();
}
#endif
