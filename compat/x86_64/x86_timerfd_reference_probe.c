/* Pinned-musl Linux/x86-64 timerfd ABI and lifecycle reference. */

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
_Static_assert(TFD_NONBLOCK == 0x00000800, "TFD_NONBLOCK");
_Static_assert(TFD_CLOEXEC == 0x00080000, "TFD_CLOEXEC");
_Static_assert(TFD_TIMER_ABSTIME == 0x00000001, "TFD_TIMER_ABSTIME");
_Static_assert(TFD_TIMER_CANCEL_ON_SET == 0x00000002,
               "TFD_TIMER_CANCEL_ON_SET");

static int canonical_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L;
}

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

int main(void)
{
    struct itimerspec zero = {{0, 0}, {0, 0}};
    struct itimerspec one_shot = {{0, 0}, {0, 1000000L}};
    struct itimerspec invalid = {{0, 0}, {0, 1000000000L}};
    struct itimerspec previous;
    struct itimerspec current;
    struct pollfd ready;
    uint64_t expirations = 0;
    int pipe_fds[2] = {-1, -1};
    int timer = -1;

    timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer < 0)
        return 10;
    if (fcntl(timer, F_GETFD) < 0 || (fcntl(timer, F_GETFD) & FD_CLOEXEC) == 0)
        return 11;
    if (timerfd_gettime(timer, &current) != 0 || current.it_interval.tv_sec != 0 ||
        current.it_interval.tv_nsec != 0 || current.it_value.tv_sec != 0 ||
        current.it_value.tv_nsec != 0)
        return 12;
    errno = 0;
    if (!expect_error((int)read(timer, &expirations, sizeof(expirations)), EAGAIN))
        return 13;

    errno = 0;
    if (!expect_error(timerfd_create(-1, 0), EINVAL))
        return 14;
    errno = 0;
    if (!expect_error(timerfd_settime(timer, 0, &invalid, NULL), EINVAL))
        return 15;
    errno = 0;
    if (!expect_error(timerfd_settime(timer, 0x00000004, &one_shot, NULL), EINVAL))
        return 16;

    if (timerfd_settime(timer, 0, &one_shot, &previous) != 0 ||
        previous.it_interval.tv_sec != 0 || previous.it_interval.tv_nsec != 0 ||
        previous.it_value.tv_sec != 0 || previous.it_value.tv_nsec != 0)
        return 17;
    if (timerfd_gettime(timer, &current) != 0 ||
        !canonical_timespec(&current.it_interval) ||
        !canonical_timespec(&current.it_value))
        return 18;

    ready.fd = timer;
    ready.events = POLLIN;
    ready.revents = 0;
    if (poll(&ready, 1, 100) != 1 || (ready.revents & POLLIN) == 0)
        return 19;
    if (read(timer, &expirations, sizeof(expirations)) != (ssize_t)sizeof(expirations) ||
        expirations == 0)
        return 20;
    errno = 0;
    if (!expect_error((int)read(timer, &expirations, sizeof(expirations)), EAGAIN))
        return 21;

    if (timerfd_settime(timer, 0, &zero, &previous) != 0 ||
        previous.it_interval.tv_sec != 0 || previous.it_interval.tv_nsec != 0)
        return 22;
    if (timerfd_gettime(timer, &current) != 0 || current.it_interval.tv_sec != 0 ||
        current.it_interval.tv_nsec != 0 || current.it_value.tv_sec != 0 ||
        current.it_value.tv_nsec != 0)
        return 23;

    if (pipe(pipe_fds) != 0)
        return 24;
    errno = 0;
    if (!expect_error(timerfd_gettime(pipe_fds[0], &current), EINVAL))
        return 25;
    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 || close(timer) != 0)
        return 26;

    puts("layout=size32 align8 offsets=0,16 syscalls=283,286,287 flags=checked cloexec=enabled disarmed=zero arm=readable expirations=u64 disarm=zero errors=EINVAL,EAGAIN");
    return 0;
}
