#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

extern int timerfd_create(int, int);
extern int timerfd_gettime(int, struct itimerspec *);
extern int timerfd_settime(int, int, const struct itimerspec *,
                           struct itimerspec *);
extern int signalfd(int, const sigset_t *, int);

#define CLOCK_MONOTONIC 1
#define TFD_NONBLOCK 0x800
#define TFD_CLOEXEC 0x80000
#define SFD_NONBLOCK 0x800
#define SFD_CLOEXEC 0x80000

static int timerfd_case(void)
{
    struct itimerspec initial = { { 0, 0 }, { 0, 0 } };
    struct itimerspec armed = { { 0, 0 }, { 0, 5000000 } };
    struct itimerspec current;
    struct pollfd pollfd;
    uint64_t expirations = 0;
    int fd;

    errno = 0;
    if (timerfd_create(-1, 0) != -1 || errno != EINVAL)
        return 1;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0)
        return 2;
    if (timerfd_gettime(fd, &initial) != 0 ||
        initial.it_interval.tv_sec != 0 || initial.it_interval.tv_nsec != 0 ||
        initial.it_value.tv_sec != 0 || initial.it_value.tv_nsec != 0)
        return 3;

    if (timerfd_settime(fd, 0, &armed, NULL) != 0)
        return 4;
    pollfd.fd = fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;
    if (poll(&pollfd, 1, 1000) != 1 || !(pollfd.revents & POLLIN))
        return 5;
    if (read(fd, &expirations, sizeof expirations) != (ssize_t)sizeof expirations ||
        expirations != 1)
        return 6;
    if (timerfd_gettime(fd, &current) != 0 ||
        current.it_interval.tv_sec != 0 || current.it_interval.tv_nsec != 0 ||
        current.it_value.tv_sec != 0 || current.it_value.tv_nsec != 0)
        return 7;

    close(fd);
    return 0;
}

static int signalfd_case(void)
{
    unsigned char info[128];
    sigset_t mask;
    uint32_t signo;
    ssize_t length;
    int fd;

    if (sigemptyset(&mask) != 0 || sigaddset(&mask, SIGUSR1) != 0)
        return 10;
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
        return 11;

    fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0)
        return 12;
    if (raise(SIGUSR1) != 0)
        return 13;
    memset(info, 0, sizeof info);
    length = read(fd, info, sizeof info);
    memcpy(&signo, info, sizeof signo);
    if (length != (ssize_t)sizeof info || signo != SIGUSR1)
        return 14;
    close(fd);
    return 0;
}

int main(void)
{
    int result = timerfd_case();
    if (result != 0)
        return result;
    result = signalfd_case();
    if (result != 0)
        return result;
    puts("m4 timer signal fds ok");
    return 0;
}
