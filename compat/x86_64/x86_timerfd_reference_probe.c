/* Pinned-musl/raw Linux/x86-64 timerfd ABI and lifecycle reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(sizeof(struct itimerspec) == 32, "x86 itimerspec size");
_Static_assert(_Alignof(struct itimerspec) == 8, "x86 itimerspec alignment");
_Static_assert(offsetof(struct itimerspec, it_interval) == 0,
               "x86 itimerspec interval offset");
_Static_assert(offsetof(struct itimerspec, it_value) == 16,
               "x86 itimerspec value offset");
_Static_assert(SYS_timerfd_create == 283, "x86 timerfd_create syscall");
_Static_assert(SYS_timerfd_settime == 286, "x86 timerfd_settime syscall");
_Static_assert(SYS_timerfd_gettime == 287, "x86 timerfd_gettime syscall");
_Static_assert(CLOCK_REALTIME == 0, "CLOCK_REALTIME");
_Static_assert(CLOCK_MONOTONIC == 1, "CLOCK_MONOTONIC");
_Static_assert(CLOCK_BOOTTIME == 7, "CLOCK_BOOTTIME");
_Static_assert(CLOCK_REALTIME_ALARM == 8, "CLOCK_REALTIME_ALARM");
_Static_assert(CLOCK_BOOTTIME_ALARM == 9, "CLOCK_BOOTTIME_ALARM");
_Static_assert(TFD_NONBLOCK == 0x00000800, "TFD_NONBLOCK");
_Static_assert(TFD_CLOEXEC == 0x00080000, "TFD_CLOEXEC");
_Static_assert(TFD_TIMER_ABSTIME == 0x00000001, "TFD_TIMER_ABSTIME");
_Static_assert(TFD_TIMER_CANCEL_ON_SET == 0x00000002,
               "TFD_TIMER_CANCEL_ON_SET");

typedef int (*timerfd_create_fn)(clockid_t clock_id, int flags);
typedef int (*timerfd_settime_fn)(int fd, int flags,
                                  const struct itimerspec *new_value,
                                  struct itimerspec *old_value);
typedef int (*timerfd_gettime_fn)(int fd, struct itimerspec *current_value);

static int raw_timerfd_create(clockid_t clock_id, int flags)
{
    return (int)syscall(SYS_timerfd_create, clock_id, flags);
}

static int raw_timerfd_settime(int fd, int flags,
                               const struct itimerspec *new_value,
                               struct itimerspec *old_value)
{
    return (int)syscall(SYS_timerfd_settime, fd, flags, new_value, old_value);
}

static int raw_timerfd_gettime(int fd, struct itimerspec *current_value)
{
    return (int)syscall(SYS_timerfd_gettime, fd, current_value);
}

static int canonical_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L;
}

static int zero_itimerspec(const struct itimerspec *value)
{
    return value->it_interval.tv_sec == 0 && value->it_interval.tv_nsec == 0 &&
           value->it_value.tv_sec == 0 && value->it_value.tv_nsec == 0;
}

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static int create_succeeds(timerfd_create_fn create, clockid_t clock_id)
{
    int timer = create(clock_id, TFD_CLOEXEC);

    if (timer < 0)
        return 0;
    return close(timer) == 0;
}

static int alarm_create_matches(clockid_t clock_id)
{
    int musl_timer;
    int musl_error;
    int raw_timer;
    int raw_error;
    int matches;

    errno = 0;
    musl_timer = timerfd_create(clock_id, TFD_CLOEXEC);
    musl_error = errno;
    errno = 0;
    raw_timer = raw_timerfd_create(clock_id, TFD_CLOEXEC);
    raw_error = errno;
    matches = (musl_timer >= 0) == (raw_timer >= 0);
    if (musl_timer < 0)
        matches = matches && musl_error == EPERM && raw_error == EPERM;
    if (musl_timer >= 0 && close(musl_timer) != 0)
        matches = 0;
    if (raw_timer >= 0 && close(raw_timer) != 0)
        matches = 0;
    return matches;
}

static int invalid_create_matches(void)
{
    int musl_result;
    int musl_error;
    int raw_result;
    int raw_error;

    errno = 0;
    musl_result = timerfd_create(-1, 0);
    musl_error = errno;
    errno = 0;
    raw_result = raw_timerfd_create(-1, 0);
    raw_error = errno;
    return musl_result == -1 && raw_result == -1 && musl_error == EINVAL &&
           raw_error == EINVAL;
}

static int future_create_flag_matches(void)
{
    int musl_result;
    int musl_error;
    int raw_result;
    int raw_error;

    errno = 0;
    musl_result = timerfd_create(CLOCK_MONOTONIC, 0x00000001);
    musl_error = errno;
    errno = 0;
    raw_result = raw_timerfd_create(CLOCK_MONOTONIC, 0x00000001);
    raw_error = errno;
    return musl_result == -1 && raw_result == -1 && musl_error == EINVAL &&
           raw_error == EINVAL;
}

static int check_realtime_cancel_on_set(timerfd_create_fn create,
                                        timerfd_settime_fn settime,
                                        timerfd_gettime_fn gettime)
{
    struct itimerspec zero = {{0, 0}, {0, 0}};
    struct itimerspec absolute;
    struct itimerspec current;
    struct timespec now;
    int timer;

    timer = create(CLOCK_REALTIME, TFD_CLOEXEC);
    if (timer < 0)
        return 1;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return 2;
    absolute.it_interval.tv_sec = 0;
    absolute.it_interval.tv_nsec = 0;
    absolute.it_value.tv_sec = now.tv_sec + 1;
    absolute.it_value.tv_nsec = now.tv_nsec;
    if (settime(timer, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &absolute,
                NULL) != 0)
        return 3;
    if (gettime(timer, &current) != 0 ||
        !canonical_timespec(&current.it_interval) ||
        !canonical_timespec(&current.it_value))
        return 4;
    if (settime(timer, 0, &zero, NULL) != 0 || close(timer) != 0)
        return 5;
    return 0;
}

static int check_lifecycle(timerfd_create_fn create, timerfd_settime_fn settime,
                           timerfd_gettime_fn gettime)
{
    struct itimerspec zero = {{0, 0}, {0, 0}};
    struct itimerspec one_shot = {{0, 0}, {0, 1000000L}};
    struct itimerspec periodic = {{2, 0}, {5, 0}};
    struct itimerspec invalid = {{0, 0}, {0, 1000000000L}};
    struct itimerspec previous;
    struct itimerspec current;
    struct pollfd ready;
    uint64_t expirations = 0;
    int pipe_fds[2] = {-1, -1};
    int timer;
    int result;

    timer = create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer < 0)
        return 1;
    if (fcntl(timer, F_GETFD) < 0 || (fcntl(timer, F_GETFD) & FD_CLOEXEC) == 0)
        return 2;
    if (gettime(timer, &current) != 0 || !zero_itimerspec(&current))
        return 3;
    errno = 0;
    if (!expect_error((int)read(timer, &expirations, sizeof(expirations)), EAGAIN))
        return 4;

    errno = 0;
    if (!expect_error(settime(timer, 0, &invalid, NULL), EINVAL))
        return 5;
    errno = 0;
    if (!expect_error(settime(timer, 0x00000004, &one_shot, NULL), EINVAL))
        return 6;

    if (settime(timer, 0, &one_shot, &previous) != 0 ||
        !zero_itimerspec(&previous))
        return 7;
    if (gettime(timer, &current) != 0 ||
        !canonical_timespec(&current.it_interval) ||
        !canonical_timespec(&current.it_value))
        return 8;

    ready.fd = timer;
    ready.events = POLLIN;
    ready.revents = 0;
    if (poll(&ready, 1, 100) != 1 || (ready.revents & POLLIN) == 0)
        return 9;
    if (read(timer, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations) ||
        expirations == 0)
        return 10;
    errno = 0;
    if (!expect_error((int)read(timer, &expirations, sizeof(expirations)), EAGAIN))
        return 11;

    if (settime(timer, 0, &periodic, &previous) != 0 ||
        !zero_itimerspec(&previous))
        return 12;
    if (gettime(timer, &current) != 0 ||
        current.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        current.it_interval.tv_nsec != periodic.it_interval.tv_nsec ||
        !canonical_timespec(&current.it_value))
        return 13;

    if (settime(timer, 0, &zero, &previous) != 0 ||
        previous.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        previous.it_interval.tv_nsec != periodic.it_interval.tv_nsec)
        return 14;
    if (gettime(timer, &current) != 0 || !zero_itimerspec(&current))
        return 15;

    if (pipe(pipe_fds) != 0)
        return 16;
    errno = 0;
    result = gettime(pipe_fds[0], &current);
    if (!expect_error(result, EINVAL))
        return 17;
    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 || close(timer) != 0)
        return 18;
    return 0;
}

int main(void)
{
    int failure;

    if (!create_succeeds(timerfd_create, CLOCK_REALTIME) ||
        !create_succeeds(raw_timerfd_create, CLOCK_REALTIME) ||
        !create_succeeds(timerfd_create, CLOCK_MONOTONIC) ||
        !create_succeeds(raw_timerfd_create, CLOCK_MONOTONIC) ||
        !create_succeeds(timerfd_create, CLOCK_BOOTTIME) ||
        !create_succeeds(raw_timerfd_create, CLOCK_BOOTTIME))
        return 10;
    if (!alarm_create_matches(CLOCK_REALTIME_ALARM) ||
        !alarm_create_matches(CLOCK_BOOTTIME_ALARM))
        return 11;
    if (!invalid_create_matches() || !future_create_flag_matches())
        return 12;

    failure = check_lifecycle(timerfd_create, timerfd_settime, timerfd_gettime);
    if (failure != 0)
        return 20 + failure;
    failure = check_lifecycle(raw_timerfd_create, raw_timerfd_settime,
                              raw_timerfd_gettime);
    if (failure != 0)
        return 50 + failure;
    failure = check_realtime_cancel_on_set(timerfd_create, timerfd_settime,
                                           timerfd_gettime);
    if (failure != 0)
        return 80 + failure;
    failure = check_realtime_cancel_on_set(raw_timerfd_create, raw_timerfd_settime,
                                           raw_timerfd_gettime);
    if (failure != 0)
        return 90 + failure;

    puts("layout=size32 align8 offsets=0,16 syscalls=283,286,287 clocks=all-linux flags=known+future-forwarded lifecycle=musl+raw-relative,absolute,cancel-flag,periodic-setting expirations=u64 errors=EINVAL,EAGAIN,EPERM");
    return 0;
}
