/* Static crabc-libc x86-64 readiness and signal-wait fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects the closed descriptor-readiness endpoints
 * `poll`, GNU `ppoll`, `select`, and `pselect`, plus `pause` and
 * `sigsuspend`. The already-selected pipe/descriptor and signal-action/mask
 * leaves only arrange observable readiness and a pending thread-directed
 * signal; they do not extend this artifact to C descriptor, process, or
 * general signal support. Fixture-local raw `tgkill` supplies deterministic
 * pending delivery without selecting `kill`, `raise`, process lifecycle,
 * pthread cancellation, timers, CRT, loader, sysroot, or public x86 support.
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
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum {
    SIGNAL_WORDS = sizeof(sigset_t) / sizeof(unsigned long),
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(nfds_t) == 8 && _Alignof(nfds_t) == 8,
    "x86 nfds_t layout");
_Static_assert(sizeof(struct pollfd) == 8 && _Alignof(struct pollfd) == 4 &&
    offsetof(struct pollfd, fd) == 0 &&
    offsetof(struct pollfd, events) == 4 &&
    offsetof(struct pollfd, revents) == 6,
    "x86 pollfd layout");
_Static_assert(FD_SETSIZE == 1024 && sizeof(fd_set) == 128 &&
    _Alignof(fd_set) == 8 && sizeof(((fd_set *)0)->fds_bits) == 128,
    "x86 fd_set layout");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8 &&
    offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval layout");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8 &&
    offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec layout");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8 &&
    SIGNAL_WORDS == 16, "x86 public sigset_t layout");
_Static_assert(SYS_poll == 7 && SYS_select == 23 && SYS_pause == 34 &&
    SYS_rt_sigsuspend == 130 && SYS_pselect6 == 270 && SYS_ppoll == 271,
    "x86 selected readiness syscall numbers");
_Static_assert(SYS_getpid == 39 && SYS_gettid == 186 && SYS_tgkill == 234,
    "x86 fixture-only signal delivery syscall numbers");
_Static_assert(POLLIN == 0x0001 && POLLHUP == 0x0010 && POLLNVAL == 0x0020,
    "x86 selected poll constants");
_Static_assert(SIGUSR1 == 10 && _NSIG == 65,
    "x86 selected signal constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&poll),
    int (*)(struct pollfd *, nfds_t, int)), "poll declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ppoll),
    int (*)(struct pollfd *, nfds_t, const struct timespec *,
        const sigset_t *)), "ppoll declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&select),
    int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *)),
    "select declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pselect),
    int (*)(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
        const sigset_t *)), "pselect declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pause), int (*)(void)),
    "pause declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigsuspend),
    int (*)(const sigset_t *)), "sigsuspend declaration");

static volatile sig_atomic_t delivered_signal;

/* `pause` cannot atomically exchange a temporary mask. A runtime assertion
 * would need a timer, child, or thread to race a delivery with entry to the
 * syscall; each would select behavior outside this bounded artifact and can
 * still be flaky. Keep its otherwise-unreachable call live for the static
 * link and let the runner pin its exact direct SYS_pause code path. */
static volatile sig_atomic_t pause_execution_disabled;

static void record_delivery(int signal)
{
    delivered_signal = signal;
}

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

/* This is fixture-local pending-delivery machinery, not a selected C ABI. */
static int raw_tgkill_self(int signal)
{
    long pid = raw_syscall0(SYS_getpid);
    long tid = raw_syscall0(SYS_gettid);

    if (pid < 0 || tid < 0)
        return -1;
    return raw_syscall3(SYS_tgkill, pid, tid, signal) == 0 ? 0 : -1;
}

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = left;
    const unsigned char *right_bytes = right;

    for (size_t index = 0; index < length; index++)
        if (left_bytes[index] != right_bytes[index])
            return 0;
    return 1;
}

static void close_if_open(int *file_descriptor)
{
    if (*file_descriptor >= 0) {
        (void)close(*file_descriptor);
        *file_descriptor = -1;
    }
}

static int mask_has_usr1(const sigset_t *mask)
{
    return sigismember(mask, SIGUSR1) == 1;
}

static int check_poll_and_ppoll(void)
{
    int pipe_fds[2] = { -1, -1 };
    struct pollfd descriptor = { 0 };
    struct timespec timeout = { 0, 0 };
    struct timespec saved_timeout;
    sigset_t empty = { 0 };
    sigset_t saved_empty;
    char byte = 0;
    int status = 0;

    if (pipe(pipe_fds) != 0)
        return 1;
    descriptor.fd = pipe_fds[0];
    descriptor.events = POLLIN;
    descriptor.revents = (short)0x7fff;
    if (poll(&descriptor, 1, 0) != 0 || descriptor.revents != 0) {
        status = 2;
        goto finish;
    }
    if (write(pipe_fds[1], "p", 1) != 1 ||
        poll(&descriptor, 1, 0) != 1 ||
        (descriptor.revents & POLLIN) == 0) {
        status = 3;
        goto finish;
    }
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'p') {
        status = 4;
        goto finish;
    }
    if (close(pipe_fds[1]) != 0) {
        status = 5;
        goto finish;
    }
    pipe_fds[1] = -1;
    descriptor.revents = 0;
    if (poll(&descriptor, 1, 0) != 1 ||
        (descriptor.revents & POLLHUP) == 0) {
        status = 6;
        goto finish;
    }
    if (close(pipe_fds[0]) != 0) {
        status = 7;
        goto finish;
    }
    pipe_fds[0] = -1;
    descriptor.revents = 0;
    errno = 0;
    if (poll(&descriptor, 1, 0) != 1 ||
        (descriptor.revents & POLLNVAL) == 0) {
        status = 8;
        goto finish;
    }
    errno = 0;
    if (poll(0, 1, 0) != -1 || errno != EFAULT) {
        status = 9;
        goto finish;
    }

    if (pipe(pipe_fds) != 0) {
        status = 10;
        goto finish;
    }
    if (sigemptyset(&empty) != 0) {
        status = 11;
        goto finish;
    }
    descriptor.fd = pipe_fds[0];
    descriptor.events = POLLIN;
    descriptor.revents = (short)0x7fff;
    saved_timeout = timeout;
    saved_empty = empty;
    if (ppoll(&descriptor, 1, &timeout, &empty) != 0 ||
        descriptor.revents != 0 ||
        !bytes_equal(&timeout, &saved_timeout, sizeof timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty)) {
        status = 12;
        goto finish;
    }
    if (write(pipe_fds[1], "q", 1) != 1) {
        status = 13;
        goto finish;
    }
    timeout.tv_sec = 5;
    timeout.tv_nsec = 123456789;
    saved_timeout = timeout;
    saved_empty = empty;
    descriptor.revents = 0;
    if (ppoll(&descriptor, 1, &timeout, &empty) != 1 ||
        (descriptor.revents & POLLIN) == 0 ||
        !bytes_equal(&timeout, &saved_timeout, sizeof timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty)) {
        status = 14;
        goto finish;
    }
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'q') {
        status = 15;
        goto finish;
    }
    if (close(pipe_fds[1]) != 0) {
        status = 16;
        goto finish;
    }
    pipe_fds[1] = -1;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
    saved_timeout = timeout;
    descriptor.revents = 0;
    if (ppoll(&descriptor, 1, &timeout, &empty) != 1 ||
        (descriptor.revents & POLLHUP) == 0 ||
        !bytes_equal(&timeout, &saved_timeout, sizeof timeout)) {
        status = 17;
        goto finish;
    }
    if (close(pipe_fds[0]) != 0) {
        status = 18;
        goto finish;
    }
    pipe_fds[0] = -1;
    saved_timeout = timeout;
    saved_empty = empty;
    if (ppoll(0, 0, &timeout, &empty) != 0 ||
        !bytes_equal(&timeout, &saved_timeout, sizeof timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty)) {
        status = 19;
        goto finish;
    }
    errno = 0;
    if (ppoll(0, 1, &timeout, &empty) != -1 || errno != EFAULT)
        status = 20;

finish:
    close_if_open(&pipe_fds[1]);
    close_if_open(&pipe_fds[0]);
    return status;
}

static int check_select_and_pselect(void)
{
    int pipe_fds[2] = { -1, -1 };
    fd_set read_fds;
    struct timeval select_timeout = { 0, 0 };
    struct timeval saved_select_timeout;
    struct timeval invalid_select_timeout;
    struct timespec pselect_timeout = { 0, 0 };
    struct timespec saved_pselect_timeout;
    struct timespec invalid_pselect_timeout;
    sigset_t empty = { 0 };
    sigset_t saved_empty;
    char byte = 0;
    int status = 0;

    if (pipe(pipe_fds) != 0)
        return 1;
    if (sigemptyset(&empty) != 0) {
        status = 2;
        goto finish;
    }

    FD_ZERO(&read_fds);
    FD_SET(pipe_fds[0], &read_fds);
    saved_select_timeout = select_timeout;
    if (select(pipe_fds[0] + 1, &read_fds, 0, 0, &select_timeout) != 0 ||
        FD_ISSET(pipe_fds[0], &read_fds) ||
        !bytes_equal(&select_timeout, &saved_select_timeout,
            sizeof select_timeout)) {
        status = 3;
        goto finish;
    }
    if (write(pipe_fds[1], "s", 1) != 1) {
        status = 4;
        goto finish;
    }
    /* Musl normalizes a nonnegative usec overflow in its local timeval copy.
     * A direct SYS_select call would expose kernel timeout mutation instead. */
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 1000000;
    saved_select_timeout = select_timeout;
    FD_ZERO(&read_fds);
    FD_SET(pipe_fds[0], &read_fds);
    if (select(pipe_fds[0] + 1, &read_fds, 0, 0, &select_timeout) != 1 ||
        !FD_ISSET(pipe_fds[0], &read_fds) ||
        !bytes_equal(&select_timeout, &saved_select_timeout,
            sizeof select_timeout)) {
        status = 5;
        goto finish;
    }
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 's') {
        status = 6;
        goto finish;
    }
    invalid_select_timeout.tv_sec = -1;
    invalid_select_timeout.tv_usec = 0;
    saved_select_timeout = invalid_select_timeout;
    errno = 0;
    if (select(0, 0, 0, 0, &invalid_select_timeout) != -1 ||
        errno != EINVAL ||
        !bytes_equal(&invalid_select_timeout, &saved_select_timeout,
            sizeof invalid_select_timeout)) {
        status = 7;
        goto finish;
    }
    invalid_select_timeout.tv_sec = 0;
    invalid_select_timeout.tv_usec = -1;
    saved_select_timeout = invalid_select_timeout;
    errno = 0;
    if (select(0, 0, 0, 0, &invalid_select_timeout) != -1 ||
        errno != EINVAL ||
        !bytes_equal(&invalid_select_timeout, &saved_select_timeout,
            sizeof invalid_select_timeout)) {
        status = 8;
        goto finish;
    }

    FD_ZERO(&read_fds);
    FD_SET(pipe_fds[0], &read_fds);
    saved_pselect_timeout = pselect_timeout;
    saved_empty = empty;
    if (pselect(pipe_fds[0] + 1, &read_fds, 0, 0, &pselect_timeout,
            &empty) != 0 ||
        FD_ISSET(pipe_fds[0], &read_fds) ||
        !bytes_equal(&pselect_timeout, &saved_pselect_timeout,
            sizeof pselect_timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty)) {
        status = 9;
        goto finish;
    }
    if (write(pipe_fds[1], "t", 1) != 1) {
        status = 10;
        goto finish;
    }
    pselect_timeout.tv_sec = 5;
    pselect_timeout.tv_nsec = 123456789;
    saved_pselect_timeout = pselect_timeout;
    saved_empty = empty;
    FD_ZERO(&read_fds);
    FD_SET(pipe_fds[0], &read_fds);
    if (pselect(pipe_fds[0] + 1, &read_fds, 0, 0, &pselect_timeout,
            &empty) != 1 ||
        !FD_ISSET(pipe_fds[0], &read_fds) ||
        !bytes_equal(&pselect_timeout, &saved_pselect_timeout,
            sizeof pselect_timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty)) {
        status = 11;
        goto finish;
    }
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 't') {
        status = 12;
        goto finish;
    }
    invalid_pselect_timeout.tv_sec = 0;
    invalid_pselect_timeout.tv_nsec = 1000000000;
    saved_pselect_timeout = invalid_pselect_timeout;
    errno = 0;
    if (pselect(0, 0, 0, 0, &invalid_pselect_timeout, &empty) != -1 ||
        errno != EINVAL ||
        !bytes_equal(&invalid_pselect_timeout, &saved_pselect_timeout,
            sizeof invalid_pselect_timeout)) {
        status = 13;
        goto finish;
    }
    saved_pselect_timeout = pselect_timeout;
    errno = 0;
    if (pselect(-1, 0, 0, 0, &pselect_timeout, &empty) != -1 ||
        errno != EINVAL ||
        !bytes_equal(&pselect_timeout, &saved_pselect_timeout,
            sizeof pselect_timeout)) {
        status = 14;
        goto finish;
    }

finish:
    close_if_open(&pipe_fds[1]);
    close_if_open(&pipe_fds[0]);
    return status;
}

static int check_atomic_signal_waits(void)
{
    struct sigaction saved_action = { 0 };
    struct sigaction action = { 0 };
    struct timespec ppoll_timeout = { 1, 0 };
    struct timespec pselect_timeout = { 1, 0 };
    struct timespec saved_timeout;
    sigset_t saved_mask = { 0 };
    sigset_t selected = { 0 };
    sigset_t empty = { 0 };
    sigset_t saved_empty;
    sigset_t observed_mask = { 0 };
    int action_saved = 0;
    int mask_saved = 0;
    int status = 0;

    if (sigaction(SIGUSR1, 0, &saved_action) != 0) {
        status = 1;
        goto finish;
    }
    action_saved = 1;
    if (sigprocmask(SIG_SETMASK, 0, &saved_mask) != 0) {
        status = 2;
        goto finish;
    }
    mask_saved = 1;
    if (sigemptyset(&selected) != 0 ||
        sigaddset(&selected, SIGUSR1) != 0 || sigemptyset(&empty) != 0) {
        status = 3;
        goto finish;
    }
    if (sigemptyset(&action.sa_mask) != 0) {
        status = 4;
        goto finish;
    }
    action.sa_handler = record_delivery;
    action.sa_flags = 0;
    if (sigaction(SIGUSR1, &action, 0) != 0) {
        status = 5;
        goto finish;
    }
    if (sigprocmask(SIG_BLOCK, &selected, 0) != 0 ||
        sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        !mask_has_usr1(&observed_mask)) {
        status = 6;
        goto finish;
    }

    saved_timeout = ppoll_timeout;
    saved_empty = empty;
    delivered_signal = 0;
    if (raw_tgkill_self(SIGUSR1) != 0) {
        status = 7;
        goto finish;
    }
    errno = 0;
    if (ppoll(0, 0, &ppoll_timeout, &empty) != -1 || errno != EINTR ||
        delivered_signal != SIGUSR1 ||
        !bytes_equal(&ppoll_timeout, &saved_timeout, sizeof ppoll_timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty) ||
        sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        !mask_has_usr1(&observed_mask)) {
        status = 8;
        goto finish;
    }

    saved_timeout = pselect_timeout;
    saved_empty = empty;
    delivered_signal = 0;
    if (raw_tgkill_self(SIGUSR1) != 0) {
        status = 9;
        goto finish;
    }
    errno = 0;
    if (pselect(0, 0, 0, 0, &pselect_timeout, &empty) != -1 ||
        errno != EINTR || delivered_signal != SIGUSR1 ||
        !bytes_equal(&pselect_timeout, &saved_timeout,
            sizeof pselect_timeout) ||
        !bytes_equal(&empty, &saved_empty, sizeof empty) ||
        sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        !mask_has_usr1(&observed_mask)) {
        status = 10;
        goto finish;
    }

    saved_empty = empty;
    delivered_signal = 0;
    if (raw_tgkill_self(SIGUSR1) != 0) {
        status = 11;
        goto finish;
    }
    errno = 0;
    if (sigsuspend(&empty) != -1 || errno != EINTR ||
        delivered_signal != SIGUSR1 ||
        !bytes_equal(&empty, &saved_empty, sizeof empty) ||
        sigprocmask(SIG_SETMASK, 0, &observed_mask) != 0 ||
        !mask_has_usr1(&observed_mask)) {
        status = 12;
        goto finish;
    }

finish:
    /* Restore the former mask before the former disposition: a failed wait
     * can leave SIGUSR1 pending, and its temporary handler remains safe while
     * the original mask is reinstated. */
    if (mask_saved && sigprocmask(SIG_SETMASK, &saved_mask, 0) != 0 &&
        status == 0)
        status = 13;
    if (action_saved && sigaction(SIGUSR1, &saved_action, 0) != 0 &&
        status == 0)
        status = 14;
    return status;
}

static int retain_pause_without_a_racy_runtime_wait(void)
{
    if (pause_execution_disabled)
        return pause();
    return 0;
}

int crabc_x86_64_readiness_waits_probe(void)
{
    int status;

    if (retain_pause_without_a_racy_runtime_wait() != 0)
        return 1;
    status = check_poll_and_ppoll();
    if (status != 0)
        return 10 + status;
    status = check_select_and_pselect();
    if (status != 0)
        return 40 + status;
    status = check_atomic_signal_waits();
    if (status != 0)
        return 70 + status;
    return 0;
}

#ifndef CRABC_READINESS_WAITS_FREESTANDING
int main(void)
{
    return crabc_x86_64_readiness_waits_probe();
}
#endif
