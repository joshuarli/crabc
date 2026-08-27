/* Pinned-musl Linux/x86-64 clock_nanosleep(2) behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t size");
_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(__builtin_offsetof(struct timespec, tv_sec) == 0,
               "x86 timespec tv_sec offset");
_Static_assert(__builtin_offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec tv_nsec offset");
_Static_assert(SYS_clock_nanosleep == 230,
               "x86 clock_nanosleep syscall number");
_Static_assert(TIMER_ABSTIME == 1, "Linux TIMER_ABSTIME value");

static volatile sig_atomic_t signal_delivered;

static void interrupt_handler(int signal_number)
{
    (void)signal_number;
    signal_delivered = 1;
}

static int positive_remainder(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L &&
           (value->tv_sec != 0 || value->tv_nsec != 0);
}

static int run_musl_interrupted(void)
{
    struct timespec requested = { 2, 0 };
    struct timespec remaining = { -1, -1 };
    struct sigaction action = { 0 };
    struct sigaction old_action;

    action.sa_handler = interrupt_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGALRM, &action, &old_action) != 0)
        return 1;
    signal_delivered = 0;
    /*
     * The child starts without its parent's interval timer.  ualarm returns
     * a previous timer's remaining duration, not a success status, so the
     * valid request must not interpret a nonzero return as failure.
     */
    (void)ualarm(20000, 0);

    int result = clock_nanosleep(CLOCK_MONOTONIC, 0, &requested, &remaining);
    int valid = result == EINTR && signal_delivered &&
                positive_remainder(&remaining);
    if (sigaction(SIGALRM, &old_action, NULL) != 0)
        return 3;
    return valid ? 0 : 4;
}

static int run_raw_interrupted(void)
{
    struct timespec requested = { 2, 0 };
    struct timespec remaining = { -1, -1 };
    struct sigaction action = { 0 };
    struct sigaction old_action;

    action.sa_handler = interrupt_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGALRM, &action, &old_action) != 0)
        return 1;
    signal_delivered = 0;
    /*
     * The child starts without its parent's interval timer.  ualarm returns
     * a previous timer's remaining duration, not a success status, so the
     * valid request must not interpret a nonzero return as failure.
     */
    (void)ualarm(20000, 0);

    errno = 0;
    long result = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0,
                          &requested, &remaining);
    int valid = result == -1 && errno == EINTR && signal_delivered &&
                positive_remainder(&remaining);
    if (sigaction(SIGALRM, &old_action, NULL) != 0)
        return 3;
    return valid ? 0 : 4;
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
    struct timespec zero = { 0, 0 };
    struct timespec invalid = { 0, 1000000000L };
    struct timespec now;
    struct timespec past;

    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &zero, NULL) != 0)
        return 10;
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &zero, NULL) != 0)
        return 11;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 12;
    past.tv_sec = now.tv_sec > 0 ? now.tv_sec - 1 : 0;
    past.tv_nsec = 0;
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &past, NULL) != 0)
        return 13;
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, &past,
                NULL) != 0)
        return 14;

    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &invalid, NULL) != EINVAL)
        return 20;
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &invalid, NULL) != -1 ||
        errno != EINVAL)
        return 21;

    if (run_in_child(run_musl_interrupted) != 0)
        return 30;
    if (run_in_child(run_raw_interrupted) != 0)
        return 31;

    puts("layout=timespec16/8 syscall=230 relative-zero=musl0/raw0 absolute-past=musl0/raw0 malformed-nsec=EINVAL musl-convention=positive-error/raw-errno eintr=musl-remainder/raw-remainder");
    return 0;
}
