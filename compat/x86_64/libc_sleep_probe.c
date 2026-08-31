/* Static crabc-libc x86-64 selected sleep fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc libc.a. It proves only musl's one-call sleep wrapper: zero seconds
 * completes with stale errno, while a fixture-local SIGALRM interruption
 * returns a nonzero whole-second remainder and publishes EINTR through the
 * selected nanosleep boundary. Raw setitimer plus the already selected simple
 * signal setup are deterministic fixture plumbing, not timer or signal policy.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
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
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(sigset_t) == 128 && sizeof(struct sigaction) == 152,
    "x86 signal records");
_Static_assert(SYS_setitimer == 38, "x86 fixture setitimer syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sleep),
    unsigned int (*)(unsigned int)), "sleep declaration");

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

/* Fixture-only timer delivery; this is not a selected C setitimer ABI. */
static int raw_arm_alarm(long microseconds)
{
    struct raw_itimerval value = { { 0, 0 }, { 0, microseconds } };

    return raw_syscall3(SYS_setitimer, 0, (long)(void *)&value, 0) == 0 ? 0 : -1;
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

static int check_zero_completion(void)
{
    const int preserved_errno = ERANGE;

    errno = preserved_errno;
    return sleep(0) == 0 && errno == preserved_errno ? 0 : 1;
}

static int check_interrupted_remainder(void)
{
    const unsigned int requested = 2;
    struct sigaction saved_action;
    sigset_t saved_mask;
    unsigned int remaining;
    int status = 0;

    if (install_interrupt_handler(&saved_action, &saved_mask) != 0)
        return 1;
    if (raw_arm_alarm(20000) != 0) {
        status = 2;
        goto cleanup;
    }
    errno = 0;
    remaining = sleep(requested);
    if (remaining == 0 || remaining >= requested || errno != EINTR ||
        !signal_delivered)
        status = 3;

cleanup:
    return restore_interrupt_handler(&saved_action, &saved_mask) == 0 ? status : 4;
}

int crabc_x86_64_sleep_probe(void)
{
    int status = check_zero_completion();

    if (status != 0)
        return 10 + status;
    status = check_interrupted_remainder();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_SLEEP_FREESTANDING
int main(void)
{
    return crabc_x86_64_sleep_probe();
}
#endif
