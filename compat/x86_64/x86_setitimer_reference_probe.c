/* Pinned-musl Linux/x86-64 setitimer ABI and contained behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#include <errno.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

struct guarded_itimerval {
    struct itimerval value;
    unsigned char trailing[16];
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(struct timeval) == 16, "x86 timeval size");
_Static_assert(_Alignof(struct timeval) == 8, "x86 timeval alignment");
_Static_assert(offsetof(struct timeval, tv_sec) == 0,
               "x86 timeval seconds");
_Static_assert(offsetof(struct timeval, tv_usec) == 8,
               "x86 timeval microseconds");
_Static_assert(sizeof(struct itimerval) == 32, "x86 itimerval size");
_Static_assert(_Alignof(struct itimerval) == 8, "x86 itimerval alignment");
_Static_assert(offsetof(struct itimerval, it_interval) == 0,
               "x86 itimerval interval offset");
_Static_assert(offsetof(struct itimerval, it_value) == 16,
               "x86 itimerval current-value offset");
_Static_assert(offsetof(struct guarded_itimerval, trailing) == 32,
               "guard begins after the kernel record");
_Static_assert(SYS_setitimer == 38, "x86 setitimer syscall number");
_Static_assert(ITIMER_REAL == 0, "ITIMER_REAL selector");
_Static_assert(ITIMER_VIRTUAL == 1, "ITIMER_VIRTUAL selector");
_Static_assert(ITIMER_PROF == 2, "ITIMER_PROF selector");

static const struct itimerval first_setting = {
    { 7, 0 },
    { 60, 0 },
};

static const struct itimerval second_setting = {
    { 11, 0 },
    { 120, 0 },
};

static const struct itimerval disarmed_setting = {
    { 0, 0 },
    { 0, 0 },
};

static const struct itimerval invalid_setting = {
    { 0, 0 },
    { 0, 1000000 },
};

static int trailing_is_unchanged(const struct guarded_itimerval *value)
{
    for (size_t index = 0; index < sizeof(value->trailing); ++index) {
        if (value->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int timeval_is_zero(const struct timeval *value)
{
    return value->tv_sec == 0 && value->tv_usec == 0;
}

static int timeval_is_remaining(const struct timeval *value, long maximum)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
           value->tv_usec < 1000000 &&
           (value->tv_sec != 0 || value->tv_usec != 0) &&
           value->tv_sec <= maximum;
}

static int old_matches_setting(const struct itimerval *old,
                               const struct itimerval *setting)
{
    return old->it_interval.tv_sec == setting->it_interval.tv_sec &&
           old->it_interval.tv_usec == setting->it_interval.tv_usec &&
           timeval_is_remaining(&old->it_value, setting->it_value.tv_sec);
}

static int run_musl_exchange(void)
{
    struct guarded_itimerval old;

    /* The child owns every armed timer; its parent has no timer state to
     * observe or inherit from this operation. */
    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
        return 1;

    memset(&old, 0xa5, sizeof(old));
    if (setitimer(ITIMER_REAL, &first_setting, &old.value) != 0 ||
        !timeval_is_zero(&old.value.it_interval) ||
        !timeval_is_zero(&old.value.it_value) ||
        !trailing_is_unchanged(&old))
        return 2;

    memset(&old, 0xa5, sizeof(old));
    if (setitimer(ITIMER_REAL, &second_setting, &old.value) != 0 ||
        !old_matches_setting(&old.value, &first_setting) ||
        !trailing_is_unchanged(&old))
        return 3;

    memset(&old, 0xa5, sizeof(old));
    if (setitimer(ITIMER_REAL, &disarmed_setting, &old.value) != 0 ||
        !old_matches_setting(&old.value, &second_setting) ||
        !trailing_is_unchanged(&old))
        return 4;

    return 0;
}

static int run_raw_exchange(void)
{
    struct guarded_itimerval old;

    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
        return 1;

    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &first_setting, &old.value) != 0 ||
        !timeval_is_zero(&old.value.it_interval) ||
        !timeval_is_zero(&old.value.it_value) ||
        !trailing_is_unchanged(&old))
        return 2;

    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &second_setting, &old.value) != 0 ||
        !old_matches_setting(&old.value, &first_setting) ||
        !trailing_is_unchanged(&old))
        return 3;

    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &disarmed_setting, &old.value) != 0 ||
        !old_matches_setting(&old.value, &second_setting) ||
        !trailing_is_unchanged(&old))
        return 4;

    return 0;
}

static int run_musl_invalid(void)
{
    struct guarded_itimerval old;

    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
        return 1;
    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (setitimer(ITIMER_REAL, &invalid_setting, &old.value) != -1 ||
        errno != EINVAL || !trailing_is_unchanged(&old))
        return 2;
    return 0;
}

static int run_raw_invalid(void)
{
    struct guarded_itimerval old;

    if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
        return 1;
    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &invalid_setting, &old.value) != -1 ||
        errno != EINVAL || !trailing_is_unchanged(&old))
        return 2;
    return 0;
}

static int run_in_child(int (*test)(void))
{
    pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0)
        _exit(test());

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return 2;
    return WEXITSTATUS(status) == 0 ? 0 : 3;
}

int main(void)
{
    if (run_in_child(run_musl_exchange) != 0)
        return 10;
    if (run_in_child(run_raw_exchange) != 0)
        return 11;
    if (run_in_child(run_musl_invalid) != 0)
        return 12;
    if (run_in_child(run_raw_invalid) != 0)
        return 13;

    puts("layout=timeval16/8 itimerval32/8 offsets=timeval0,8/itimerval0,16 syscall=38 selectors=0,1,2 musl=old/new/disarm direct=old/new/disarm invalid=EINVAL");
    return 0;
}
