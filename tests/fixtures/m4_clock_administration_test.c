#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>

int main(void)
{
    struct timex tx;
    struct timeval remaining = { 7, 11 };
    struct timeval invalid_adjustment = { 0, 1000000 };
    int state;

    errno = 0;
    if (adjtimex(NULL) != -1 || errno != EFAULT)
        return 1;

    memset(&tx, 0, sizeof tx);
    state = adjtimex(&tx);
    if (state < TIME_OK || state > TIME_ERROR || tx.time.tv_sec <= 0)
        return 2;

    memset(&tx, 0, sizeof tx);
    state = clock_adjtime(CLOCK_REALTIME, &tx);
    if (state < TIME_OK || state > TIME_ERROR || tx.time.tv_sec <= 0)
        return 3;

    if (adjtime(NULL, &remaining) != 0 || remaining.tv_usec < 0 ||
        remaining.tv_usec >= 1000000)
        return 4;

    errno = 0;
    if (adjtime(&invalid_adjustment, NULL) != -1 || errno != EINVAL)
        return 5;

    /* Linux may check CAP_SYS_TIME before dereferencing the timeval, so the
     * safe invalid-pointer probe is EFAULT on a privileged runner and EPERM
     * inside this unprivileged Docker container.  It never changes the clock. */
    errno = 0;
    if (settimeofday((const struct timeval *)1, NULL) != -1 ||
        (errno != EFAULT && errno != EPERM))
        return 6;

    errno = 0;
    if (stime(NULL) != -1 || errno != EFAULT)
        return 7;

    errno = 0;
    if (clock_adjtime(-1, NULL) != -1 ||
        (errno != EINVAL && errno != EFAULT))
        return 8;

    puts("m4 clock administration ok");
    return 0;
}
