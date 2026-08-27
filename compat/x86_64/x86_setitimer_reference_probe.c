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

/* `alarm` observes this fractional prior value through its required ceiling
 * conversion. Keep the value far enough from the next whole-second boundary
 * that a short-lived native probe cannot naturally cross it. */
static const struct itimerval alarm_seed_setting = {
    { 0, 0 },
    { 604800, 999999 },
};

static const struct itimerval alarm_replacement_setting = {
    { 0, 0 },
    { 120, 0 },
};

/* Musl writes ualarm's arguments directly to tv_usec. Its C wrapper therefore
 * has a valid-input domain below one second; use that domain for the C oracle.
 */
static const struct itimerval ualarm_setting = {
    { 0, 200000 },
    { 0, 900000 },
};

static const int timer_kinds[] = {
    ITIMER_REAL,
    ITIMER_VIRTUAL,
    ITIMER_PROF,
};

static int ignore_timer_signals(void)
{
    return signal(SIGALRM, SIG_IGN) != SIG_ERR &&
           signal(SIGVTALRM, SIG_IGN) != SIG_ERR &&
           signal(SIGPROF, SIG_IGN) != SIG_ERR;
}

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

static int itimerval_is_disarmed(const struct itimerval *value)
{
    return timeval_is_zero(&value->it_interval) &&
           timeval_is_zero(&value->it_value);
}

static int run_musl_exchange(void)
{
    struct guarded_itimerval old;

    /* The child owns every armed timer; its parent has no timer state to
     * observe or inherit from this operation. */
    if (!ignore_timer_signals())
        return 1;

    for (size_t index = 0; index < sizeof(timer_kinds) / sizeof(timer_kinds[0]); ++index) {
        int kind = timer_kinds[index];

        memset(&old, 0xa5, sizeof(old));
        if (setitimer(kind, &first_setting, &old.value) != 0 ||
            !itimerval_is_disarmed(&old.value) || !trailing_is_unchanged(&old))
            return 2;

        memset(&old, 0xa5, sizeof(old));
        if (setitimer(kind, &second_setting, &old.value) != 0 ||
            !old_matches_setting(&old.value, &first_setting) ||
            !trailing_is_unchanged(&old))
            return 3;

        memset(&old, 0xa5, sizeof(old));
        if (setitimer(kind, &disarmed_setting, &old.value) != 0 ||
            !old_matches_setting(&old.value, &second_setting) ||
            !trailing_is_unchanged(&old))
            return 4;
    }

    return 0;
}

static int run_raw_exchange(void)
{
    struct guarded_itimerval old;

    if (!ignore_timer_signals())
        return 1;

    for (size_t index = 0; index < sizeof(timer_kinds) / sizeof(timer_kinds[0]); ++index) {
        int kind = timer_kinds[index];

        memset(&old, 0xa5, sizeof(old));
        errno = 0;
        if (syscall(SYS_setitimer, kind, &first_setting, &old.value) != 0 ||
            !itimerval_is_disarmed(&old.value) || !trailing_is_unchanged(&old))
            return 2;

        memset(&old, 0xa5, sizeof(old));
        errno = 0;
        if (syscall(SYS_setitimer, kind, &second_setting, &old.value) != 0 ||
            !old_matches_setting(&old.value, &first_setting) ||
            !trailing_is_unchanged(&old))
            return 3;

        memset(&old, 0xa5, sizeof(old));
        errno = 0;
        if (syscall(SYS_setitimer, kind, &disarmed_setting, &old.value) != 0 ||
            !old_matches_setting(&old.value, &second_setting) ||
            !trailing_is_unchanged(&old))
            return 4;
    }

    return 0;
}

static int run_musl_invalid(void)
{
    struct guarded_itimerval old;

    if (!ignore_timer_signals())
        return 1;
    for (size_t index = 0; index < sizeof(timer_kinds) / sizeof(timer_kinds[0]); ++index) {
        memset(&old, 0xa5, sizeof(old));
        errno = 0;
        if (setitimer(timer_kinds[index], &invalid_setting, &old.value) != -1 ||
            errno != EINVAL || !trailing_is_unchanged(&old))
            return 2;
    }
    return 0;
}

static int run_raw_invalid(void)
{
    struct guarded_itimerval old;

    if (!ignore_timer_signals())
        return 1;
    for (size_t index = 0; index < sizeof(timer_kinds) / sizeof(timer_kinds[0]); ++index) {
        memset(&old, 0xa5, sizeof(old));
        errno = 0;
        if (syscall(SYS_setitimer, timer_kinds[index], &invalid_setting, &old.value) != -1 ||
            errno != EINVAL || !trailing_is_unchanged(&old))
            return 2;
    }
    return 0;
}

static int run_musl_alarm_alias(void)
{
    struct guarded_itimerval current;

    if (!ignore_timer_signals())
        return 1;
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &alarm_seed_setting, NULL) != 0)
        return 2;
    if (alarm(alarm_replacement_setting.it_value.tv_sec) != 604801U)
        return 3;

    memset(&current, 0xa5, sizeof(current));
    if (getitimer(ITIMER_REAL, &current.value) != 0 ||
        !timeval_is_zero(&current.value.it_interval) ||
        !timeval_is_remaining(&current.value.it_value,
                              alarm_replacement_setting.it_value.tv_sec) ||
        !trailing_is_unchanged(&current))
        return 4;

    if (alarm(0) > (unsigned int)alarm_replacement_setting.it_value.tv_sec)
        return 5;
    memset(&current, 0xa5, sizeof(current));
    if (getitimer(ITIMER_REAL, &current.value) != 0 ||
        !itimerval_is_disarmed(&current.value) || !trailing_is_unchanged(&current))
        return 6;
    return 0;
}

static int run_raw_alarm_equivalent(void)
{
    struct guarded_itimerval old;

    if (!ignore_timer_signals())
        return 1;
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &alarm_seed_setting, NULL) != 0)
        return 2;
    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &alarm_replacement_setting, &old.value) != 0 ||
        !timeval_is_zero(&old.value.it_interval) ||
        old.value.it_value.tv_sec != alarm_seed_setting.it_value.tv_sec ||
        old.value.it_value.tv_usec <= 0 || old.value.it_value.tv_usec >= 1000000 ||
        !trailing_is_unchanged(&old))
        return 3;
    if ((unsigned long)old.value.it_value.tv_sec +
            (unsigned long)(old.value.it_value.tv_usec != 0) != 604801UL)
        return 4;

    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &disarmed_setting, NULL) != 0)
        return 5;
    return 0;
}

static int run_musl_ualarm_alias(void)
{
    struct guarded_itimerval current;
    unsigned int old;

    if (!ignore_timer_signals())
        return 1;
    if (ualarm((useconds_t)ualarm_setting.it_value.tv_usec,
               (useconds_t)ualarm_setting.it_interval.tv_usec) != 0)
        return 2;

    memset(&current, 0xa5, sizeof(current));
    if (getitimer(ITIMER_REAL, &current.value) != 0 ||
        current.value.it_interval.tv_sec != 0 ||
        current.value.it_interval.tv_usec != ualarm_setting.it_interval.tv_usec ||
        !timeval_is_remaining(&current.value.it_value, 0) ||
        !trailing_is_unchanged(&current))
        return 3;

    old = ualarm(0, 0);
    if (old == 0 || old > (unsigned int)ualarm_setting.it_value.tv_usec)
        return 4;
    memset(&current, 0xa5, sizeof(current));
    if (getitimer(ITIMER_REAL, &current.value) != 0 ||
        !itimerval_is_disarmed(&current.value) || !trailing_is_unchanged(&current))
        return 5;
    return 0;
}

static int run_musl_ualarm_invalid_boundary(void)
{
    struct guarded_itimerval current;
    unsigned int old;

    if (!ignore_timer_signals())
        return 1;
    if (ualarm((useconds_t)ualarm_setting.it_value.tv_usec,
               (useconds_t)ualarm_setting.it_interval.tv_usec) != 0)
        return 2;

    /* Musl returns a value derived from an uninitialized old setting after
     * this failed setitimer call, so establish only errno and unchanged state.
     */
    errno = 0;
    (void)ualarm(1000000, 0);
    if (errno != EINVAL)
        return 3;

    memset(&current, 0xa5, sizeof(current));
    if (getitimer(ITIMER_REAL, &current.value) != 0 ||
        current.value.it_interval.tv_sec != 0 ||
        current.value.it_interval.tv_usec != ualarm_setting.it_interval.tv_usec ||
        !timeval_is_remaining(&current.value.it_value, 0) ||
        !trailing_is_unchanged(&current))
        return 4;

    old = ualarm(0, 0);
    if (old == 0 || old > (unsigned int)ualarm_setting.it_value.tv_usec)
        return 5;
    return 0;
}

static int run_raw_ualarm_equivalent(void)
{
    struct guarded_itimerval old;
    unsigned long old_microseconds;

    if (!ignore_timer_signals())
        return 1;
    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &ualarm_setting, &old.value) != 0 ||
        !itimerval_is_disarmed(&old.value) || !trailing_is_unchanged(&old))
        return 2;

    memset(&old, 0xa5, sizeof(old));
    errno = 0;
    if (syscall(SYS_setitimer, ITIMER_REAL, &disarmed_setting, &old.value) != 0 ||
        old.value.it_interval.tv_sec != ualarm_setting.it_interval.tv_sec ||
        old.value.it_interval.tv_usec != ualarm_setting.it_interval.tv_usec ||
        !timeval_is_remaining(&old.value.it_value, 0) ||
        !trailing_is_unchanged(&old))
        return 3;
    old_microseconds = (unsigned long)old.value.it_value.tv_sec * 1000000UL +
                       (unsigned long)old.value.it_value.tv_usec;
    if (old_microseconds == 0 ||
        old_microseconds > (unsigned long)ualarm_setting.it_value.tv_usec)
        return 4;
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
    if (run_in_child(run_musl_alarm_alias) != 0)
        return 14;
    if (run_in_child(run_raw_alarm_equivalent) != 0)
        return 15;
    if (run_in_child(run_musl_ualarm_alias) != 0)
        return 16;
    if (run_in_child(run_musl_ualarm_invalid_boundary) != 0)
        return 17;
    if (run_in_child(run_raw_ualarm_equivalent) != 0)
        return 18;

    puts("layout=timeval16/8 itimerval32/8 offsets=timeval0,8/itimerval0,16 syscall=38 selectors=0,1,2 musl=old/new/disarm direct=old/new/disarm aliases=alarm-ceil,ualarm-subsecond,ualarm-invalid=EINVAL invalid=EINVAL");
    return 0;
}
