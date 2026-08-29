/* Static crabc-libc x86-64 process-signal execution fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It joins the existing simple signal action/set/mask boundary
 * to one coherent execution state flow: install, block, kill/queue/raise,
 * timed/infinite waits, sigsuspend delivery, and restoration. The raw
 * clone/pipe/wait/exit machinery below exists only to make an EINTR-to-queued
 * signal transition deterministic; it is fixture-local and does not select a
 * C lifecycle, pthread, clone, or process-supervisor API.
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
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    RETRY_PAYLOAD = 0x4d,
    QUEUE_PAYLOAD = 0x6b,
};

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(pid_t) == 4,
    "x86 scalar ABI");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 sigset_t ABI");
_Static_assert(sizeof(union sigval) == 8 && _Alignof(union sigval) == 8,
    "x86 sigval ABI");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
    "x86 siginfo ABI");
_Static_assert(offsetof(siginfo_t, si_signo) == 0 &&
    offsetof(siginfo_t, si_errno) == 4 &&
    offsetof(siginfo_t, si_code) == 8 &&
    offsetof(siginfo_t, si_pid) == 16 &&
    offsetof(siginfo_t, si_uid) == 20 &&
    offsetof(siginfo_t, si_value) == 24,
    "x86 queued siginfo ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_pipe == 22 && SYS_getpid == 39 && SYS_clone == 56 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_kill == 62 && SYS_rt_sigprocmask == 14 &&
    SYS_rt_sigtimedwait == 128 && SYS_rt_sigqueueinfo == 129 &&
    SYS_gettid == 186 && SYS_tkill == 200,
    "x86 selected and fixture-only signal syscall numbers");
_Static_assert(SIGUSR1 == 10 && SIGUSR2 == 12 && SI_QUEUE == -1,
    "x86 selected signal constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&kill),
    int (*)(int, int)), "kill declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&killpg),
    int (*)(pid_t, int)), "killpg declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&raise),
    int (*)(int)), "raise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigqueue),
    int (*)(pid_t, int, union sigval)), "sigqueue declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigtimedwait),
    int (*)(const sigset_t *, siginfo_t *, const struct timespec *)),
    "sigtimedwait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwaitinfo),
    int (*)(const sigset_t *, siginfo_t *)), "sigwaitinfo declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigwait),
    int (*)(const sigset_t *, int *)), "sigwait declaration");

struct retry_child {
    int release[2];
    int acknowledgement[2];
    pid_t child;
    int reaped;
};

static volatile sig_atomic_t delivered_signal;
static volatile sig_atomic_t retry_acknowledgement_descriptor = -1;

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
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

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static __attribute__((noreturn)) void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

/* This raw clone is fixture-only child containment, not an archive API. */
static __attribute__((noinline, returns_twice)) long raw_clone_sigchld(void)
{
    return raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
}

static int raw_close(int descriptor)
{
    return (int)raw_syscall1(SYS_close, descriptor);
}

static int raw_pipe(int descriptors[2])
{
    return (int)raw_syscall1(SYS_pipe, (long)descriptors);
}

static int raw_read_byte(int descriptor, char *byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_read, descriptor, (long)byte, 1);
    } while (result == -EINTR);
    return result == 1;
}

static int raw_write_byte(int descriptor, char byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_write, descriptor, (long)&byte, 1);
    } while (result == -EINTR);
    return result == 1;
}

static int raw_wait4_cleanup(pid_t child, int *status)
{
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)status, 0, 0);
    } while (result == -EINTR);
    return (int)result;
}

static void clear_siginfo(siginfo_t *info)
{
    unsigned char *bytes = (unsigned char *)(void *)info;

    for (size_t index = 0; index < sizeof(*info); ++index)
        bytes[index] = 0;
}

static void record_delivery(int signal)
{
    int descriptor = retry_acknowledgement_descriptor;

    delivered_signal = signal;
    if (descriptor >= 0) {
        char acknowledgement = 'A';

        /* Direct write is async-signal-safe fixture plumbing. */
        (void)raw_syscall3(SYS_write, descriptor, (long)&acknowledgement, 1);
    }
}

static void initialize_retry_child(struct retry_child *control)
{
    control->release[0] = -1;
    control->release[1] = -1;
    control->acknowledgement[0] = -1;
    control->acknowledgement[1] = -1;
    control->child = -1;
    control->reaped = 0;
}

static __attribute__((noreturn)) void retry_child_main(
    const int release[2], const int acknowledgement[2], pid_t parent)
{
    union sigval payload;
    char start;
    char acknowledgement_byte;

    if (raw_close(release[1]) != 0 || raw_close(acknowledgement[1]) != 0 ||
        !raw_read_byte(release[0], &start) ||
        raw_syscall2(SYS_kill, parent, SIGUSR1) != 0 ||
        !raw_read_byte(acknowledgement[0], &acknowledgement_byte))
        raw_exit(125);

    payload.sival_int = RETRY_PAYLOAD;
    if (sigqueue(parent, SIGRTMIN, payload) != 0)
        raw_exit(126);
    raw_exit(42);
}

static int spawn_retry_child(struct retry_child *control, pid_t parent)
{
    long clone_result;

    if (raw_pipe(control->release) != 0 || raw_pipe(control->acknowledgement) != 0)
        return 1;
    clone_result = raw_clone_sigchld();
    if (clone_result == 0)
        retry_child_main(control->release, control->acknowledgement, parent);
    if (clone_result < 0)
        return 2;
    control->child = (pid_t)clone_result;

    if (raw_close(control->release[0]) != 0)
        return 3;
    control->release[0] = -1;
    if (raw_close(control->acknowledgement[0]) != 0)
        return 4;
    control->acknowledgement[0] = -1;
    return 0;
}

static void cleanup_retry_child(struct retry_child *control)
{
    int status;

    if (control->release[0] >= 0)
        (void)raw_close(control->release[0]);
    if (control->release[1] >= 0)
        (void)raw_close(control->release[1]);
    if (control->acknowledgement[0] >= 0)
        (void)raw_close(control->acknowledgement[0]);
    if (control->acknowledgement[1] >= 0)
        (void)raw_close(control->acknowledgement[1]);
    if (control->child > 0 && !control->reaped) {
        (void)raw_syscall2(SYS_kill, control->child, SIGKILL);
        (void)raw_wait4_cleanup(control->child, &status);
    }
}

static int check_retry_after_eintr(const sigset_t *usr1_set,
    const sigset_t *realtime_set, pid_t parent)
{
    struct retry_child control;
    siginfo_t info;
    int status = 0;
    int result = 1;

    initialize_retry_child(&control);
    delivered_signal = 0;
    /* The outer test has SIGUSR1 blocked; make this handler interrupt the
     * waiting call while retaining SIGRTMIN in the wait mask. */
    if (sigprocmask(SIG_UNBLOCK, usr1_set, 0) != 0)
        goto cleanup;
    if (spawn_retry_child(&control, parent) != 0)
        goto cleanup_reblock;
    retry_acknowledgement_descriptor = control.acknowledgement[1];
    if (!raw_write_byte(control.release[1], 'R'))
        goto cleanup_reblock;
    clear_siginfo(&info);
    errno = ERANGE;
    if (sigtimedwait(realtime_set, &info, 0) != SIGRTMIN ||
        info.si_signo != SIGRTMIN || info.si_code != SI_QUEUE ||
        info.si_pid != control.child || info.si_value.sival_int != RETRY_PAYLOAD ||
        errno != ERANGE || delivered_signal != SIGUSR1)
        goto cleanup_reblock;
    if (raw_wait4_cleanup(control.child, &status) != control.child ||
        (status & 0x7f) != 0 || ((unsigned)status >> 8) != 42)
        goto cleanup_reblock;
    control.reaped = 1;
    result = 0;

cleanup_reblock:
    retry_acknowledgement_descriptor = -1;
    (void)sigprocmask(SIG_BLOCK, usr1_set, 0);
cleanup:
    cleanup_retry_child(&control);
    return result;
}

static int test_signal_execution(void)
{
    struct sigaction saved_action;
    struct sigaction action;
    sigset_t saved_mask;
    sigset_t selected;
    sigset_t usr1_set;
    sigset_t usr2_set;
    sigset_t realtime_set;
    sigset_t empty_set;
    sigset_t observed_mask;
    struct timespec zero_timeout = {0, 0};
    siginfo_t info;
    union sigval payload;
    int waited_signal = 0;
    int action_saved = 0;
    int mask_saved = 0;
    int result = 1;
    pid_t self = getpid();

    if (self <= 0)
        goto cleanup;
    if (sigaction(SIGUSR1, 0, &saved_action) != 0)
        goto cleanup;
    action_saved = 1;
    if (sigemptyset(&action.sa_mask) != 0)
        goto cleanup;
    action.sa_handler = record_delivery;
    /* Omit SA_RESTART so the retry child forces the C wrapper's EINTR loop. */
    action.sa_flags = 0;
    action.sa_restorer = 0;
    if (sigaction(SIGUSR1, &action, 0) != 0)
        goto cleanup;
    if (sigemptyset(&selected) != 0 || sigaddset(&selected, SIGUSR1) != 0 ||
        sigaddset(&selected, SIGUSR2) != 0 ||
        sigaddset(&selected, SIGRTMIN) != 0 ||
        sigemptyset(&usr1_set) != 0 || sigaddset(&usr1_set, SIGUSR1) != 0 ||
        sigemptyset(&usr2_set) != 0 || sigaddset(&usr2_set, SIGUSR2) != 0 ||
        sigemptyset(&realtime_set) != 0 ||
        sigaddset(&realtime_set, SIGRTMIN) != 0 ||
        sigemptyset(&empty_set) != 0)
        goto cleanup;
    if (sigprocmask(SIG_BLOCK, &selected, &saved_mask) != 0)
        goto cleanup;
    mask_saved = 1;

    /* Valid signal-zero permission checks preserve a successful caller errno. */
    errno = ERANGE;
    if (kill(self, 0) != 0 || errno != ERANGE)
        goto cleanup;
    errno = E2BIG;
    if (killpg(0, 0) != 0 || errno != E2BIG)
        goto cleanup;
    errno = 0;
    if (killpg(-1, 0) != -1 || errno != EINVAL)
        goto cleanup;

    /* Error paths must publish C errno, including musl's -1 sigwait result. */
    clear_siginfo(&info);
    errno = 0;
    if (sigtimedwait(&empty_set, &info, &zero_timeout) != -1 || errno != EAGAIN)
        goto cleanup;
    errno = 0;
    if (sigtimedwait(0, &info, &zero_timeout) != -1 || errno != EFAULT)
        goto cleanup;
    errno = 0;
    if (sigwait(0, &waited_signal) != -1 || errno != EFAULT)
        goto cleanup;

    /* kill -> sigtimedwait: blocked delivery is consumed without a handler. */
    errno = ERANGE;
    if (kill(self, SIGUSR1) != 0 || errno != ERANGE)
        goto cleanup;
    clear_siginfo(&info);
    if (sigtimedwait(&usr1_set, &info, 0) != SIGUSR1 ||
        info.si_signo != SIGUSR1 || info.si_code != SI_USER ||
        info.si_pid != self || info.si_uid != getuid() || errno != ERANGE)
        goto cleanup;

    /* sigqueue -> sigwaitinfo: retain the exact queued sender payload layout. */
    payload.sival_int = QUEUE_PAYLOAD;
    errno = E2BIG;
    if (sigqueue(self, SIGRTMIN, payload) != 0 || errno != E2BIG)
        goto cleanup;
    clear_siginfo(&info);
    if (sigwaitinfo(&realtime_set, &info) != SIGRTMIN ||
        info.si_signo != SIGRTMIN || info.si_errno != 0 ||
        info.si_code != SI_QUEUE || info.si_pid != self ||
        info.si_uid != getuid() || info.si_value.sival_int != QUEUE_PAYLOAD ||
        errno != E2BIG)
        goto cleanup;

    /* raise's protected tkill path restores this blocked outer mask. */
    errno = ERANGE;
    if (raise(SIGUSR2) != 0 || errno != ERANGE ||
        sigwait(&usr2_set, &waited_signal) != 0 || waited_signal != SIGUSR2 ||
        errno != ERANGE)
        goto cleanup;
    if (sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        sigismember(&observed_mask, SIGUSR1) != 1 ||
        sigismember(&observed_mask, SIGUSR2) != 1 ||
        sigismember(&observed_mask, SIGRTMIN) != 1)
        goto cleanup;

    if (check_retry_after_eintr(&usr1_set, &realtime_set, self) != 0)
        goto cleanup;

    /* A pending blocked signal wakes sigsuspend, which restores the block. */
    delivered_signal = 0;
    errno = ERANGE;
    if (kill(self, SIGUSR1) != 0 || errno != ERANGE ||
        sigsuspend(&empty_set) != -1 || errno != EINTR ||
        delivered_signal != SIGUSR1)
        goto cleanup;
    if (sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        sigismember(&observed_mask, SIGUSR1) != 1 ||
        sigismember(&observed_mask, SIGUSR2) != 1 ||
        sigismember(&observed_mask, SIGRTMIN) != 1)
        goto cleanup;

    result = 0;

cleanup:
    retry_acknowledgement_descriptor = -1;
    /* Never restore a saved disposition while a fixture signal could remain
     * pending. Our handler stays installed through this temporary unblock. */
    if (mask_saved)
        (void)sigprocmask(SIG_UNBLOCK, &selected, 0);
    if (action_saved)
        (void)sigaction(SIGUSR1, &saved_action, 0);
    if (mask_saved)
        (void)sigprocmask(SIG_SETMASK, &saved_mask, 0);
    return result;
}

int crabc_x86_64_signal_execution_probe(void)
{
    return test_signal_execution();
}

#ifndef CRABC_SIGNAL_EXECUTION_FREESTANDING
int main(void)
{
    return crabc_x86_64_signal_execution_probe();
}
#endif
