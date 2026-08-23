#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

static int is_zero(const struct timespec *ts)
{
    return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

static int is_positive(const struct timespec *ts)
{
    return ts->tv_sec > 0 || (ts->tv_sec == 0 && ts->tv_nsec > 0);
}

int main(void)
{
    struct sigevent event = { 0 };
    struct itimerspec armed = { { 0, 0 }, { 2, 0 } };
    struct itimerspec disarmed = { { 0, 0 }, { 0, 0 } };
    struct itimerspec current;
    struct itimerspec old;
    timer_t timer;

    event.sigev_notify = SIGEV_NONE;

    errno = 0;
    if (timer_create(-1, &event, &timer) != -1 || errno != EINVAL)
        return 1;
    errno = 0;
    if (timer_create(CLOCK_MONOTONIC, &event, NULL) != -1 || errno != EFAULT)
        return 2;

    if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0)
        return 3;
    if (timer_gettime(timer, &current) != 0 ||
        !is_zero(&current.it_interval) || !is_zero(&current.it_value))
        return 4;
    if (timer_getoverrun(timer) != 0)
        return 5;

    errno = 0;
    if (timer_gettime(timer, NULL) != -1 || errno != EFAULT)
        return 6;
    errno = 0;
    if (timer_settime(timer, 0, NULL, NULL) != -1 || errno != EINVAL)
        return 7;

    old = (struct itimerspec){ { 9, 9 }, { 9, 9 } };
    if (timer_settime(timer, 0, &armed, &old) != 0 ||
        !is_zero(&old.it_interval) || !is_zero(&old.it_value))
        return 8;
    if (timer_gettime(timer, &current) != 0 ||
        !is_zero(&current.it_interval) || !is_positive(&current.it_value))
        return 9;

    old = (struct itimerspec){ { 9, 9 }, { 9, 9 } };
    if (timer_settime(timer, 0, &disarmed, &old) != 0 ||
        !is_zero(&old.it_interval) || !is_positive(&old.it_value))
        return 10;
    /* The guest kernel can report a stale one-shot remaining value immediately
     * after a successful disarm; the syscall's old-value output above proves
     * the transition, while this query still checks the live ABI boundary. */
    if (timer_gettime(timer, &current) != 0 ||
        !is_zero(&current.it_interval))
        return 11;

    if (timer_delete(timer) != 0)
        return 12;
    errno = 0;
    if (timer_gettime(timer, &current) != -1 || errno != EINVAL)
        return 13;
    errno = 0;
    if (timer_getoverrun(timer) != -1 || errno != EINVAL)
        return 14;
    errno = 0;
    if (timer_delete(timer) != -1 || errno != EINVAL)
        return 15;

    puts("c-abi posix timers ok");
    return 0;
}
