/* Static crabc-libc x86-64 selected clock_nanosleep fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a.  It proves clock_nanosleep's zero-or-positive-errno result,
 * nanosleep's -1/errno result, interrupted relative remainders, and absolute
 * deadline retry. Fixture-local raw clock_gettime/setitimer calls and the already
 * selected simple sigaction/mask boundary merely make interruptions
 * deterministic; they do not select C clock queries, interval timers,
 * generic signal policy, pthread cancellation, CRT, loader, sysroot, or
 * public x86 support.
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
#include <signal.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8, "x86 timespec field offsets");
_Static_assert(sizeof(sigset_t) == 128 && sizeof(struct sigaction) == 152,
    "x86 signal records");
_Static_assert(SYS_clock_gettime == 228 && SYS_clock_nanosleep == 230 &&
    SYS_nanosleep == 35 && SYS_setitimer == 38 && SYS_write == 1,
    "x86 fixture syscall numbers");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 && TIMER_ABSTIME == 1,
    "selected clock constants");
_Static_assert(CLOCK_THREAD_CPUTIME_ID == 3,
    "musl clock_nanosleep precheck clock ID");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_nanosleep),
    int (*)(int, int, const struct timespec *, struct timespec *)),
    "clock_nanosleep declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nanosleep),
    int (*)(const struct timespec *, struct timespec *)),
    "nanosleep declaration");

struct raw_timeval {
    long tv_sec;
    long tv_usec;
};

struct raw_itimerval {
    struct raw_timeval it_interval;
    struct raw_timeval it_value;
};

_Static_assert(sizeof(struct raw_timeval) == 16,
    "x86 fixture timeval layout");
_Static_assert(sizeof(struct raw_itimerval) == 32,
    "x86 fixture itimerval layout");

static volatile sig_atomic_t signal_delivered;

static void interrupt_handler(int signal_number)
{
    if (signal_number == SIGALRM)
        signal_delivered = 1;
}

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

/* Raw output keeps the identical oracle/candidate fixture independent of stdio. */
static int emit(const char *message)
{
    long length = 0;
    while (message[length])
        length++;
    return raw_syscall3(SYS_write, 1, (long)(void *)message, length) == length
        ? 0 : -1;
}

static int emit_number(int value)
{
    char digits[12];
    int length = 0;
    unsigned int magnitude;

    if (value < 0) {
        if (emit("-") != 0)
            return -1;
        magnitude = (unsigned int)(-(long)value);
    } else {
        magnitude = (unsigned int)value;
    }
    do {
        digits[length++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    for (int i = length - 1; i >= 0; i--)
        if (raw_syscall3(SYS_write, 1, (long)(void *)&digits[i], 1) != 1)
            return -1;
    return 0;
}

static int emit_result(const char *name, int result, int observed_errno)
{
    return emit(name) || emit("=") || emit_number(result) || emit("/") ||
        emit_number(observed_errno) || emit("\n") ? -1 : 0;
}

static int raw_clock_gettime(struct timespec *value)
{
    return raw_syscall2(SYS_clock_gettime, CLOCK_MONOTONIC,
        (long)(void *)value) == 0 ? 0 : -1;
}

/* Fixture-only timer delivery; this is not a selected C setitimer ABI. */
static int raw_arm_alarm(long microseconds)
{
    struct raw_itimerval value = { { 0, 0 }, { 0, microseconds } };

    return raw_syscall3(SYS_setitimer, 0, (long)(void *)&value, 0) == 0 ? 0 : -1;
}

static int positive_remainder(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L &&
           (value->tv_sec != 0 || value->tv_nsec != 0);
}

static int less_than_request(const struct timespec *remaining,
    const struct timespec *request)
{
    return remaining->tv_sec < request->tv_sec ||
        (remaining->tv_sec == request->tv_sec &&
         remaining->tv_nsec < request->tv_nsec);
}

static int install_interrupt_handler(struct sigaction *saved_action,
    sigset_t *saved_mask)
{
    struct sigaction action = { 0 };
    sigset_t unblocked;

    if (sigaction(SIGALRM, 0, saved_action) != 0 ||
        sigprocmask(SIG_SETMASK, 0, saved_mask) != 0)
        return -1;
    action.sa_handler = interrupt_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGALRM, &action, 0) != 0 ||
        sigemptyset(&unblocked) != 0 ||
        sigaddset(&unblocked, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &unblocked, 0) != 0)
        return -1;
    signal_delivered = 0;
    return 0;
}

static int restore_interrupt_handler(const struct sigaction *saved_action,
    const sigset_t *saved_mask)
{
    int status = 0;

    if (raw_arm_alarm(0) != 0)
        status = -1;
    if (sigaction(SIGALRM, saved_action, 0) != 0)
        status = -1;
    if (sigprocmask(SIG_SETMASK, saved_mask, 0) != 0)
        status = -1;
    return status;
}

static int check_immediate_and_error_conventions(void)
{
    const struct timespec zero = { 0, 0 };
    const struct timespec invalid = { 0, 1000000000L };
    const struct timespec negative = { -1, 0 };
    const int preserved_errno = ERANGE;
    struct timespec absolute_remaining = { 123, 456 };

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &zero, 0) != 0 ||
        errno != preserved_errno)
        return 1;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_REALTIME, 0, &zero, 0) != 0 ||
        errno != preserved_errno)
        return 2;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &zero,
            &absolute_remaining) != 0 ||
        absolute_remaining.tv_sec != 123 || absolute_remaining.tv_nsec != 456 ||
        errno != preserved_errno)
        return 3;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &invalid, 0) != EINVAL ||
        errno != preserved_errno)
        return 4;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_MONOTONIC, 0, 0, 0) != EFAULT ||
        errno != preserved_errno)
        return 5;

    errno = preserved_errno;
    if (clock_nanosleep(-1, 0, &zero, 0) != EINVAL ||
        errno != preserved_errno)
        return 6;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &zero, 0) != EINVAL ||
        errno != preserved_errno)
        return 7;

    errno = preserved_errno;
    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &negative, 0) != EINVAL ||
        errno != preserved_errno)
        return 8;

    /* These pairs establish which error wins without assuming syscall order. */
    const struct {
        const char *name;
        int clock_id;
        int flags;
        const struct timespec *request;
    } precedence[] = {
        { "invalid-clock-null", -1, 0, 0 },
        { "thread-clock-null", CLOCK_THREAD_CPUTIME_ID, 0, 0 },
        { "invalid-clock-timespec", -1, 0, &invalid },
        { "thread-clock-timespec", CLOCK_THREAD_CPUTIME_ID, 0, &invalid },
        { "realtime-null", CLOCK_REALTIME, 0, 0 },
        { "monotonic-null", CLOCK_MONOTONIC, 0, 0 },
        { "invalid-flags-timespec", CLOCK_MONOTONIC, 2, &invalid },
        { "invalid-flags-null", CLOCK_MONOTONIC, 2, 0 },
    };
    for (unsigned int i = 0; i < sizeof(precedence) / sizeof(precedence[0]); i++) {
        errno = preserved_errno;
        int result = clock_nanosleep(precedence[i].clock_id,
            precedence[i].flags, precedence[i].request, 0);
        if (emit_result(precedence[i].name, result, errno) != 0 ||
            errno != preserved_errno)
            return 9;
    }

    return 0;
}

static int check_relative_interruption(int clock_id, const char *label)
{
    const struct timespec requested = { 2, 0 };
    const int preserved_errno = E2BIG;
    struct timespec remaining = { -1, -1 };
    struct sigaction saved_action;
    sigset_t saved_mask;
    int result;
    int status = 0;

    if (install_interrupt_handler(&saved_action, &saved_mask) != 0)
        return 1;
    errno = preserved_errno;
    if (raw_arm_alarm(20000) != 0) {
        status = 2;
        goto cleanup;
    }
    result = clock_nanosleep(clock_id, 0, &requested, &remaining);
    if (result != EINTR || !signal_delivered || !positive_remainder(&remaining) ||
        !less_than_request(&remaining, &requested) ||
        errno != preserved_errno)
        status = 3;
    if (!status && emit(label) != 0)
        status = 5;

cleanup:
    return restore_interrupt_handler(&saved_action, &saved_mask) == 0 ? status : 4;
}

static int check_absolute_interruption(void)
{
    const int preserved_errno = EBUSY;
    struct timespec requested;
    struct timespec observed;
    struct sigaction saved_action;
    sigset_t saved_mask;
    struct timespec remaining = { 123, 456 };
    int result;
    int status = 0;

    if (install_interrupt_handler(&saved_action, &saved_mask) != 0)
        return 1;
    if (raw_clock_gettime(&requested) != 0) {
        status = 2;
        goto cleanup;
    }
    requested.tv_sec += 1;
    errno = preserved_errno;
    if (raw_arm_alarm(20000) != 0) {
        status = 3;
        goto cleanup;
    }
    result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &requested,
        &remaining);
    if (result != EINTR || !signal_delivered || errno != preserved_errno ||
        remaining.tv_sec != 123 || remaining.tv_nsec != 456)
        status = 4;
    if (!status && emit("monotonic-absolute-eintr=unchanged-remainder\n") != 0)
        status = 6;

    if (!status) {
        /* Retry the original deadline. The second wait must finish at or
         * after that deadline and leave the ignored remainder untouched. */
        signal_delivered = 0;
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &requested,
            &remaining);
        if (result != 0 || signal_delivered || errno != preserved_errno ||
            remaining.tv_sec != 123 || remaining.tv_nsec != 456 ||
            raw_clock_gettime(&observed) != 0 ||
            observed.tv_sec < requested.tv_sec ||
            (observed.tv_sec == requested.tv_sec &&
             observed.tv_nsec < requested.tv_nsec))
            status = 7;
        if (!status && emit("monotonic-absolute-retry=deadline\n") != 0)
            status = 8;
    }

cleanup:
    return restore_interrupt_handler(&saved_action, &saved_mask) == 0 ? status : 5;
}

static int check_nanosleep(void)
{
    const struct timespec zero = { 0, 0 };
    const struct timespec invalid = { 0, 1000000000L };
    const struct timespec negative = { -1, 0 };
    const struct timespec requested = { 1, 0 };
    struct timespec remaining = { -1, -1 };
    struct sigaction saved_action;
    sigset_t saved_mask;
    int result;
    int status = 0;

    errno = ERANGE;
    if (nanosleep(&zero, 0) != 0 || errno != ERANGE)
        return 1;
    if (emit("nanosleep-zero=0/preserved\n") != 0)
        return 2;

    errno = ERANGE;
    result = nanosleep(&invalid, 0);
    if (emit_result("nanosleep-invalid-nsec", result, errno) != 0 ||
        result != -1 || errno != EINVAL)
        return 3;
    errno = ERANGE;
    result = nanosleep(&negative, 0);
    if (emit_result("nanosleep-negative-sec", result, errno) != 0 ||
        result != -1 || errno != EINVAL)
        return 4;
    errno = ERANGE;
    result = nanosleep(0, 0);
    if (emit_result("nanosleep-null", result, errno) != 0 ||
        result != -1 || errno != EFAULT)
        return 5;

    if (install_interrupt_handler(&saved_action, &saved_mask) != 0)
        return 6;
    if (raw_arm_alarm(20000) != 0) {
        status = 7;
        goto cleanup;
    }
    errno = ERANGE;
    result = nanosleep(&requested, &remaining);
    if (result != -1 || errno != EINTR || !signal_delivered ||
        !positive_remainder(&remaining) ||
        !less_than_request(&remaining, &requested)) {
        status = 8;
        goto cleanup;
    }
    if (emit("nanosleep-eintr=bounded-remainder\n") != 0) {
        status = 9;
        goto cleanup;
    }
    result = nanosleep(&remaining, 0);
    if (result != 0 || errno != EINTR ||
        emit("nanosleep-retry=completed\n") != 0)
        status = 10;

cleanup:
    return restore_interrupt_handler(&saved_action, &saved_mask) == 0 ? status : 11;
}

int crabc_x86_64_clock_nanosleep_probe(void)
{
    int status;

    status = check_immediate_and_error_conventions();
    if (status != 0)
        return 10 + status;
    status = check_relative_interruption(CLOCK_MONOTONIC,
        "monotonic-relative-eintr=bounded-remainder\n");
    if (status != 0)
        return 20 + status;
    status = check_relative_interruption(CLOCK_REALTIME,
        "realtime-relative-eintr=bounded-remainder\n");
    if (status != 0)
        return 25 + status;
    status = check_absolute_interruption();
    if (status != 0)
        return 30 + status;
    status = check_nanosleep();
    if (status != 0)
        return 40 + status;
    return 0;
}

#ifndef CRABC_CLOCK_NANOSLEEP_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_nanosleep_probe();
}
#endif
