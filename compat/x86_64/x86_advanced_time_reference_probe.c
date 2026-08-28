/*
 * Pinned-musl/raw Linux/x86-64 advanced-clock and POSIX-timer reference.
 *
 * This short-lived private oracle compares the native Linux syscall records
 * with pinned musl's C/POSIX entry points.  It intentionally creates only
 * `SIGEV_NONE` timers, never changes CLOCK_REALTIME, installs no signal
 * handler, and deletes every timer it creates.  The fixture therefore proves
 * the narrow staged Rust boundary without selecting a C timer ABI or a
 * process-global timer/signal policy for crabc.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 &&
                   sizeof(size_t) == 8 && sizeof(time_t) == 8,
               "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4, "x86 raw timer ID width");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(timer_t) == 8, "x86 public timer_t width");

_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(offsetof(struct timespec, tv_sec) == 0,
               "x86 timespec seconds offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec nanoseconds offset");
_Static_assert(sizeof(struct itimerspec) == 32, "x86 itimerspec size");
_Static_assert(_Alignof(struct itimerspec) == 8,
               "x86 itimerspec alignment");
_Static_assert(offsetof(struct itimerspec, it_interval) == 0,
               "x86 itimerspec interval offset");
_Static_assert(offsetof(struct itimerspec, it_value) == 16,
               "x86 itimerspec value offset");
_Static_assert(sizeof(struct sigevent) == 64, "x86 sigevent size");
_Static_assert(_Alignof(struct sigevent) == 8, "x86 sigevent alignment");
_Static_assert(offsetof(struct sigevent, sigev_value) == 0,
               "x86 sigevent value offset");
_Static_assert(offsetof(struct sigevent, sigev_signo) == 8,
               "x86 sigevent signal offset");
_Static_assert(offsetof(struct sigevent, sigev_notify) == 12,
               "x86 sigevent notification offset");
_Static_assert(offsetof(struct sigevent, sigev_notify_thread_id) == 16,
               "x86 sigevent thread-id offset");

_Static_assert(CLOCK_MONOTONIC == 1, "CLOCK_MONOTONIC");
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2,
               "CLOCK_PROCESS_CPUTIME_ID");
_Static_assert(SIGEV_NONE == 1, "SIGEV_NONE");
_Static_assert(SIGEV_THREAD_ID == 4, "SIGEV_THREAD_ID");
_Static_assert(TIMER_ABSTIME == 1, "TIMER_ABSTIME");
_Static_assert(SYS_timer_create == 222, "x86 timer_create syscall");
_Static_assert(SYS_timer_settime == 223, "x86 timer_settime syscall");
_Static_assert(SYS_timer_gettime == 224, "x86 timer_gettime syscall");
_Static_assert(SYS_timer_getoverrun == 225,
               "x86 timer_getoverrun syscall");
_Static_assert(SYS_timer_delete == 226, "x86 timer_delete syscall");
_Static_assert(SYS_clock_settime == 227, "x86 clock_settime syscall");
_Static_assert(SYS_clock_getres == 229, "x86 clock_getres syscall");

enum {
    GUARD_SIZE = 16,
    GUARD_BYTE = 0xa5,
};

/* Linux 5.10 forwards these non-ABSTIME bits through common_timer_set and
 * ignores them. Exercise a low known-adjacent bit, another low unknown bit,
 * and the sign bit through both the C wrapper and the raw syscall. */
static const int forwarded_ignored_timer_settime_flags[] = {
    0x00000002,
    0x00000004,
    INT_MIN,
};

struct guarded_timespec {
    struct timespec value;
    unsigned char trailing[GUARD_SIZE];
};

struct guarded_itimerspec {
    struct itimerspec value;
    unsigned char trailing[GUARD_SIZE];
};

struct guarded_raw_timer_id {
    int value;
    unsigned char trailing[GUARD_SIZE];
};

struct guarded_musl_timer_id {
    timer_t value;
    unsigned char trailing[GUARD_SIZE];
};

_Static_assert(offsetof(struct guarded_timespec, trailing) ==
                   sizeof(struct timespec),
               "timespec guard begins after the record");
_Static_assert(offsetof(struct guarded_itimerspec, trailing) ==
                   sizeof(struct itimerspec),
               "itimerspec guard begins after the record");
_Static_assert(offsetof(struct guarded_raw_timer_id, trailing) == sizeof(int),
               "raw timer ID guard begins after the kernel word");
_Static_assert(offsetof(struct guarded_musl_timer_id, trailing) ==
                   sizeof(timer_t),
               "musl timer ID guard begins after public timer_t");

typedef uintptr_t timer_handle;

struct timer_operations {
    int (*create)(const struct sigevent *event, timer_handle *timer);
    int (*settime)(timer_handle timer, int flags,
                   const struct itimerspec *new_value,
                   struct itimerspec *old_value);
    int (*gettime)(timer_handle timer, struct itimerspec *value);
    int (*getoverrun)(timer_handle timer);
    int (*delete)(timer_handle timer);
};

static int raw_timer_create(clockid_t clock_id, const struct sigevent *event,
                            int *timer_id)
{
    return (int)syscall(SYS_timer_create, clock_id, event, timer_id);
}

static int raw_timer_settime(int timer_id, int flags,
                             const struct itimerspec *new_value,
                             struct itimerspec *old_value)
{
    return (int)syscall(SYS_timer_settime, timer_id, flags, new_value,
                        old_value);
}

static int raw_timer_gettime(int timer_id, struct itimerspec *value)
{
    return (int)syscall(SYS_timer_gettime, timer_id, value);
}

static int raw_timer_getoverrun(int timer_id)
{
    return (int)syscall(SYS_timer_getoverrun, timer_id);
}

static int raw_timer_delete(int timer_id)
{
    return (int)syscall(SYS_timer_delete, timer_id);
}

static int raw_clock_getres(clockid_t clock_id, struct timespec *value)
{
    return (int)syscall(SYS_clock_getres, clock_id, value);
}

static int raw_clock_settime(clockid_t clock_id, const struct timespec *value)
{
    return (int)syscall(SYS_clock_settime, clock_id, value);
}

static int raw_create_handle(const struct sigevent *event, timer_handle *timer)
{
    int raw_timer = -1;
    int result = raw_timer_create(CLOCK_MONOTONIC, event, &raw_timer);

    if (result == 0)
        *timer = (uint32_t)raw_timer;
    return result;
}

static int raw_settime_handle(timer_handle timer, int flags,
                              const struct itimerspec *new_value,
                              struct itimerspec *old_value)
{
    return raw_timer_settime((int)timer, flags, new_value, old_value);
}

static int raw_gettime_handle(timer_handle timer, struct itimerspec *value)
{
    return raw_timer_gettime((int)timer, value);
}

static int raw_getoverrun_handle(timer_handle timer)
{
    return raw_timer_getoverrun((int)timer);
}

static int raw_delete_handle(timer_handle timer)
{
    return raw_timer_delete((int)timer);
}

static int musl_create_handle(const struct sigevent *event, timer_handle *timer)
{
    timer_t musl_timer;
    int result = timer_create(CLOCK_MONOTONIC, (struct sigevent *)event,
                              &musl_timer);

    if (result == 0)
        *timer = (uintptr_t)musl_timer;
    return result;
}

static int musl_settime_handle(timer_handle timer, int flags,
                               const struct itimerspec *new_value,
                               struct itimerspec *old_value)
{
    return timer_settime((timer_t)timer, flags, new_value, old_value);
}

static int musl_gettime_handle(timer_handle timer, struct itimerspec *value)
{
    return timer_gettime((timer_t)timer, value);
}

static int musl_getoverrun_handle(timer_handle timer)
{
    return timer_getoverrun((timer_t)timer);
}

static int musl_delete_handle(timer_handle timer)
{
    return timer_delete((timer_t)timer);
}

static const struct timer_operations raw_timers = {
    raw_create_handle,
    raw_settime_handle,
    raw_gettime_handle,
    raw_getoverrun_handle,
    raw_delete_handle,
};

static const struct timer_operations musl_timers = {
    musl_create_handle,
    musl_settime_handle,
    musl_gettime_handle,
    musl_getoverrun_handle,
    musl_delete_handle,
};

static void guard_fill(void *value, size_t size)
{
    memset(value, GUARD_BYTE, size);
}

static int bytes_are_guarded(const void *value, size_t size)
{
    const unsigned char *bytes = value;
    size_t index;

    for (index = 0; index < size; index++) {
        if (bytes[index] != GUARD_BYTE)
            return 0;
    }
    return 1;
}

static int timespec_is_normalized(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L;
}

static int itimerspec_is_normalized(const struct itimerspec *value)
{
    return timespec_is_normalized(&value->it_interval) &&
           timespec_is_normalized(&value->it_value);
}

static int itimerspec_is_zero(const struct itimerspec *value)
{
    return value->it_interval.tv_sec == 0 && value->it_interval.tv_nsec == 0 &&
           value->it_value.tv_sec == 0 && value->it_value.tv_nsec == 0;
}

/* SIGEV_NONE's Linux 5.10 timer query can retain a stale hrtimer expiry after
 * disarm. A zero interval is therefore the observable disarmed state here;
 * the retained value must still be a bounded normalized duration. */
static int itimerspec_has_zero_interval(const struct itimerspec *value)
{
    return value->it_interval.tv_sec == 0 && value->it_interval.tv_nsec == 0 &&
           timespec_is_normalized(&value->it_value);
}

static int timespec_not_later_than(const struct timespec *left,
                                   const struct timespec *right)
{
    return left->tv_sec < right->tv_sec ||
           (left->tv_sec == right->tv_sec && left->tv_nsec <= right->tv_nsec);
}

static int trailing_is_unchanged(const unsigned char *trailing)
{
    return bytes_are_guarded(trailing, GUARD_SIZE);
}

static int expect_errno(int result, int error)
{
    return result == -1 && errno == error;
}

static int monotonic_settime_error(int result, int error)
{
    return result == -1 && (error == EINVAL || error == EPERM);
}

static struct sigevent sigev_none(void)
{
    struct sigevent event;

    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_NONE;
    return event;
}

static int check_timer_id_guards(void)
{
    struct sigevent event = sigev_none();
    struct guarded_musl_timer_id musl_timer;
    struct guarded_raw_timer_id raw_timer;

    guard_fill(&musl_timer, sizeof(musl_timer));
    if (timer_create(CLOCK_MONOTONIC, &event, &musl_timer.value) != 0 ||
        !trailing_is_unchanged(musl_timer.trailing))
        return 0;
    if (timer_delete(musl_timer.value) != 0)
        return 0;

    guard_fill(&raw_timer, sizeof(raw_timer));
    if (raw_timer_create(CLOCK_MONOTONIC, &event, &raw_timer.value) != 0 ||
        !trailing_is_unchanged(raw_timer.trailing))
        return 0;
    return raw_timer_delete(raw_timer.value) == 0;
}

static int check_getres(void)
{
    struct guarded_timespec musl_value;
    struct guarded_timespec raw_value;

    guard_fill(&musl_value, sizeof(musl_value));
    if (clock_getres(CLOCK_MONOTONIC, &musl_value.value) != 0 ||
        !timespec_is_normalized(&musl_value.value) ||
        !trailing_is_unchanged(musl_value.trailing))
        return 0;

    guard_fill(&raw_value, sizeof(raw_value));
    if (raw_clock_getres(CLOCK_MONOTONIC, &raw_value.value) != 0 ||
        !timespec_is_normalized(&raw_value.value) ||
        !trailing_is_unchanged(raw_value.trailing))
        return 0;

    return musl_value.value.tv_sec == raw_value.value.tv_sec &&
           musl_value.value.tv_nsec == raw_value.value.tv_nsec;
}

static clockid_t encoded_process_cpu_clock(pid_t pid)
{
    /* Keep the raw kernel encoding defined even for the rejected test PID. */
    return (clockid_t)(((uint32_t)(-(int64_t)pid - 1) << 3) |
                       CLOCK_PROCESS_CPUTIME_ID);
}

static int check_process_clock_ids(void)
{
    const pid_t missing_pid = INT_MAX - 1;
    const pid_t self = getpid();
    clockid_t current_clock;
    clockid_t self_clock;
    clockid_t missing_clock = 0;
    struct guarded_timespec musl_value;
    struct guarded_timespec raw_value;
    struct guarded_timespec missing_value;

    if (self <= 0 || self > 268435455)
        return 0;
    if (clock_getcpuclockid(0, &current_clock) != 0 || current_clock != -6)
        return 0;
    if (clock_getcpuclockid(self, &self_clock) != 0 ||
        self_clock != encoded_process_cpu_clock(self))
        return 0;

    guard_fill(&musl_value, sizeof(musl_value));
    if (clock_getres(self_clock, &musl_value.value) != 0 ||
        !timespec_is_normalized(&musl_value.value) ||
        !trailing_is_unchanged(musl_value.trailing))
        return 0;
    guard_fill(&raw_value, sizeof(raw_value));
    if (raw_clock_getres(self_clock, &raw_value.value) != 0 ||
        !timespec_is_normalized(&raw_value.value) ||
        !trailing_is_unchanged(raw_value.trailing) ||
        raw_value.value.tv_sec != musl_value.value.tv_sec ||
        raw_value.value.tv_nsec != musl_value.value.tv_nsec)
        return 0;

    if (clock_getcpuclockid(missing_pid, &missing_clock) != ESRCH)
        return 0;
    guard_fill(&missing_value, sizeof(missing_value));
    errno = 0;
    if (!expect_errno(raw_clock_getres(encoded_process_cpu_clock(missing_pid),
                                       &missing_value.value),
                      EINVAL) ||
        !bytes_are_guarded(&missing_value, sizeof(missing_value)))
        return 0;
    return 1;
}

static int check_monotonic_settime(void)
{
    struct guarded_timespec musl_request;
    struct guarded_timespec raw_request;
    int musl_result;
    int musl_error;
    int raw_result;
    int raw_error;

    guard_fill(&musl_request, sizeof(musl_request));
    musl_request.value.tv_sec = 0;
    musl_request.value.tv_nsec = 0;
    errno = 0;
    musl_result = clock_settime(CLOCK_MONOTONIC, &musl_request.value);
    musl_error = errno;
    if (!monotonic_settime_error(musl_result, musl_error) ||
        !trailing_is_unchanged(musl_request.trailing))
        return 0;

    guard_fill(&raw_request, sizeof(raw_request));
    raw_request.value.tv_sec = 0;
    raw_request.value.tv_nsec = 0;
    errno = 0;
    raw_result = raw_clock_settime(CLOCK_MONOTONIC, &raw_request.value);
    raw_error = errno;
    return monotonic_settime_error(raw_result, raw_error) &&
           trailing_is_unchanged(raw_request.trailing);
}

static int check_timer_lifecycle(const struct timer_operations *operations)
{
    const struct itimerspec zero = {{0, 0}, {0, 0}};
    const struct itimerspec one_shot = {{0, 0}, {1, 0}};
    const struct itimerspec periodic = {{2, 0}, {5, 0}};
    const struct itimerspec invalid_nanoseconds = {{0, 0}, {0, 1000000000L}};
    struct sigevent event = sigev_none();
    struct guarded_itimerspec old_value;
    struct guarded_itimerspec current_value;
    struct timespec now;
    struct itimerspec absolute;
    timer_handle timer;
    size_t flag_index;

    if (operations->create(&event, &timer) != 0)
        return 1;

    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        !itimerspec_is_zero(&current_value.value) ||
        !trailing_is_unchanged(current_value.trailing))
        return 2;

    guard_fill(&old_value, sizeof(old_value));
    errno = 0;
    if (!expect_errno(operations->settime(timer, 0, &invalid_nanoseconds,
                                          &old_value.value),
                      EINVAL) ||
        !bytes_are_guarded(&old_value, sizeof(old_value)))
        return 3;
    for (flag_index = 0;
         flag_index < sizeof(forwarded_ignored_timer_settime_flags) /
                          sizeof(forwarded_ignored_timer_settime_flags[0]);
         flag_index++) {
        guard_fill(&old_value, sizeof(old_value));
        if (operations->settime(timer,
                                forwarded_ignored_timer_settime_flags[flag_index],
                                &zero, &old_value.value) != 0 ||
            !itimerspec_is_zero(&old_value.value) ||
            !trailing_is_unchanged(old_value.trailing))
            return 4;
    }

    guard_fill(&old_value, sizeof(old_value));
    if (operations->settime(timer, 0, &one_shot, &old_value.value) != 0 ||
        !itimerspec_is_zero(&old_value.value) ||
        !trailing_is_unchanged(old_value.trailing))
        return 5;
    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        !itimerspec_is_normalized(&current_value.value) ||
        current_value.value.it_interval.tv_sec != 0 ||
        current_value.value.it_interval.tv_nsec != 0 ||
        !timespec_not_later_than(&current_value.value.it_value,
                                 &one_shot.it_value) ||
        !trailing_is_unchanged(current_value.trailing) ||
        operations->getoverrun(timer) < 0)
        return 6;

    guard_fill(&old_value, sizeof(old_value));
    if (operations->settime(timer, 0, &periodic, &old_value.value) != 0 ||
        !itimerspec_is_normalized(&old_value.value) ||
        old_value.value.it_interval.tv_sec != 0 ||
        old_value.value.it_interval.tv_nsec != 0 ||
        !trailing_is_unchanged(old_value.trailing))
        return 7;
    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        current_value.value.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        current_value.value.it_interval.tv_nsec != periodic.it_interval.tv_nsec ||
        !timespec_is_normalized(&current_value.value.it_value) ||
        !timespec_not_later_than(&current_value.value.it_value,
                                 &periodic.it_value) ||
        !trailing_is_unchanged(current_value.trailing))
        return 8;

    guard_fill(&old_value, sizeof(old_value));
    if (operations->settime(timer, 0, &zero, &old_value.value) != 0 ||
        old_value.value.it_interval.tv_sec != periodic.it_interval.tv_sec ||
        old_value.value.it_interval.tv_nsec != periodic.it_interval.tv_nsec ||
        !timespec_is_normalized(&old_value.value.it_value) ||
        !trailing_is_unchanged(old_value.trailing))
        return 9;
    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        !itimerspec_has_zero_interval(&current_value.value) ||
        !timespec_not_later_than(&current_value.value.it_value,
                                 &periodic.it_value) ||
        !trailing_is_unchanged(current_value.trailing))
        return 10;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        !timespec_is_normalized(&now) || now.tv_sec > INT64_MAX - 60)
        return 11;
    absolute.it_interval.tv_sec = 0;
    absolute.it_interval.tv_nsec = 0;
    absolute.it_value.tv_sec = now.tv_sec + 60;
    absolute.it_value.tv_nsec = now.tv_nsec;
    guard_fill(&old_value, sizeof(old_value));
    if (operations->settime(timer, TIMER_ABSTIME, &absolute, &old_value.value) !=
            0 ||
        !itimerspec_has_zero_interval(&old_value.value) ||
        !timespec_not_later_than(&old_value.value.it_value,
                                 &periodic.it_value) ||
        !trailing_is_unchanged(old_value.trailing))
        return 12;
    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        current_value.value.it_interval.tv_sec != 0 ||
        current_value.value.it_interval.tv_nsec != 0 ||
        !timespec_is_normalized(&current_value.value.it_value) ||
        !timespec_not_later_than(&current_value.value.it_value,
                                 &(struct timespec){60, 0}) ||
        !trailing_is_unchanged(current_value.trailing))
        return 13;

    guard_fill(&old_value, sizeof(old_value));
    if (operations->settime(timer, 0, &zero, &old_value.value) != 0 ||
        !itimerspec_has_zero_interval(&old_value.value) ||
        !timespec_not_later_than(&old_value.value.it_value,
                                 &(struct timespec){60, 0}) ||
        !trailing_is_unchanged(old_value.trailing))
        return 14;
    guard_fill(&current_value, sizeof(current_value));
    if (operations->gettime(timer, &current_value.value) != 0 ||
        !itimerspec_has_zero_interval(&current_value.value) ||
        !timespec_not_later_than(&current_value.value.it_value,
                                 &(struct timespec){60, 0}) ||
        !trailing_is_unchanged(current_value.trailing))
        return 15;
    if (operations->delete(timer) != 0)
        return 16;
    return 0;
}

int main(void)
{
    int failure;

    if (!check_timer_id_guards())
        return 1;
    if (!check_getres())
        return 2;
    if (!check_process_clock_ids())
        return 3;
    if (!check_monotonic_settime())
        return 4;

    failure = check_timer_lifecycle(&musl_timers);
    if (failure != 0)
        return 20 + failure;
    failure = check_timer_lifecycle(&raw_timers);
    if (failure != 0)
        return 50 + failure;

    puts("layout=timespec16/8 itimerspec32/8 sigevent64/8 offsets=timespec0,8/itimerspec0,16/sigevent0,8,12,16 syscalls=timer:222,223,224,225,226/clock:227,229 process-clock=encoded,current,missing:raw-EINVAL,musl-ESRCH getres=musl+raw-normalized settime=monotonic-no-mutate:EINVAL|EPERM timers=SIGEV_NONE:initial,one-shot,periodic,disarm-interval-zero:stale-value,delete flags=ABSTIME+0x2,0x4,0x80000000-forwarded-ignored errors=invalid-nsec-EINVAL");
    return 0;
}
