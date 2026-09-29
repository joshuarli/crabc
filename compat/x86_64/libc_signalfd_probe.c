/* Static crabc-libc x86-64 signalfd fixture.
 *
 * The common project-header C body runs first through pinned musl 1.2.6 and
 * then through a true dependency-free `-nostdlib -static` crabc candidate.
 * It selects one direct signal descriptor only; existing simple sigset/mask
 * calls provide fixture setup, while fixture-local raw kill delivery keeps
 * generic process-signaling API behavior outside this artifact.
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
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 sigset_t ABI");
_Static_assert(sizeof(struct signalfd_siginfo) == 128 &&
    _Alignof(struct signalfd_siginfo) == 8 &&
    offsetof(struct signalfd_siginfo, ssi_signo) == 0 &&
    offsetof(struct signalfd_siginfo, ssi_ptr) == 48 &&
    offsetof(struct signalfd_siginfo, ssi_addr) == 72 &&
    offsetof(struct signalfd_siginfo, ssi_call_addr) == 88 &&
    offsetof(struct signalfd_siginfo, ssi_arch) == 96,
    "x86 signalfd_siginfo ABI");
_Static_assert(SFD_NONBLOCK == 0x00000800 && SFD_CLOEXEC == 0x00080000,
    "x86 signalfd flags");
_Static_assert(SYS_getpid == 39 && SYS_kill == 62 && SYS_getuid == 102 &&
    SYS_rt_sigqueueinfo == 129 && SYS_signalfd4 == 289,
    "x86 signalfd fixture syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&signalfd),
    int (*)(int, const sigset_t *, int)), "signalfd declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "0"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long first, long second)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_kill_self(int signal_number)
{
    long process_id = raw_syscall0(SYS_getpid);

    return process_id <= 0 ||
        raw_syscall2(SYS_kill, process_id, signal_number) != 0;
}

static int raw_queue_self(int signal_number, int value)
{
    siginfo_t queued;
    volatile unsigned char *bytes = (volatile unsigned char *)&queued;

    /* Keep queue setup local to the fixture's raw syscall boundary. */
    for (size_t index = 0; index < sizeof(queued); ++index)
        bytes[index] = 0;

    queued.si_signo = signal_number;
    queued.si_code = SI_QUEUE;
    queued.si_pid = (pid_t)raw_syscall0(SYS_getpid);
    queued.si_uid = (uid_t)raw_syscall0(SYS_getuid);
    queued.si_value.sival_int = value;
    return raw_syscall3(SYS_rt_sigqueueinfo, queued.si_pid, signal_number,
        (long)&queued) != 0;
}

static int expect_queue_record(const struct signalfd_siginfo *record,
    int signal_number, int value)
{
    return record->ssi_signo != (uint32_t)signal_number ||
        record->ssi_code != SI_QUEUE || record->ssi_errno != 0 ||
        record->ssi_pid != (uint32_t)raw_syscall0(SYS_getpid) ||
        record->ssi_uid != (uint32_t)raw_syscall0(SYS_getuid) ||
        record->ssi_int != value;
}

static int test_create_read_and_update(void)
{
    sigset_t blocked;
    sigset_t old_mask;
    sigset_t usr1;
    sigset_t usr2;
    struct signalfd_siginfo info = {0};
    int descriptor = -1;
    int mask_installed = 0;
    int result = 1;

    if (sigemptyset(&blocked) != 0 || sigemptyset(&usr1) != 0 ||
        sigemptyset(&usr2) != 0 || sigaddset(&blocked, SIGUSR1) != 0 ||
        sigaddset(&blocked, SIGUSR2) != 0 || sigaddset(&usr1, SIGUSR1) != 0 ||
        sigaddset(&usr2, SIGUSR2) != 0)
        return result;

    errno = 0;
    if (signalfd(-1, &usr1, 0x00000001) != -1 || errno != EINVAL)
        return 2;
    errno = 0;
    if (signalfd(-1, 0, 0) != -1 || errno != EFAULT)
        return 3;

    if (sigprocmask(SIG_BLOCK, &blocked, &old_mask) != 0)
        return 4;
    mask_installed = 1;

    errno = ERANGE;
    descriptor = signalfd(-1, &usr1, SFD_NONBLOCK | SFD_CLOEXEC);
    if (descriptor < 0 || errno != ERANGE ||
        fcntl(descriptor, F_GETFD) != FD_CLOEXEC ||
        (fcntl(descriptor, F_GETFL) & O_NONBLOCK) == 0) {
        result = 5;
        goto cleanup;
    }

    errno = 0;
    if (read(descriptor, &info, sizeof(info)) != -1 || errno != EAGAIN) {
        result = 6;
        goto cleanup;
    }
    errno = E2BIG;
    if (raw_kill_self(SIGUSR1) ||
        read(descriptor, &info, sizeof(info)) != (ssize_t)sizeof(info) ||
        errno != E2BIG || info.ssi_signo != SIGUSR1 || info.ssi_errno != 0 ||
        info.ssi_code != SI_USER || info.ssi_pid != (uint32_t)raw_syscall0(SYS_getpid)) {
        result = 8;
        goto cleanup;
    }

    errno = ERANGE;
    if (signalfd(descriptor, &usr2, SFD_NONBLOCK) != descriptor ||
        errno != ERANGE) {
        result = 9;
        goto cleanup;
    }
    info = (struct signalfd_siginfo){0};
    errno = E2BIG;
    if (raw_kill_self(SIGUSR2) ||
        read(descriptor, &info, sizeof(info)) != (ssize_t)sizeof(info) ||
        errno != E2BIG || info.ssi_signo != SIGUSR2 || info.ssi_errno != 0 ||
        info.ssi_code != SI_USER || info.ssi_pid != (uint32_t)raw_syscall0(SYS_getpid)) {
        result = 10;
        goto cleanup;
    }

    result = 0;

cleanup:
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0)
        result = 11;
    if (mask_installed && sigprocmask(SIG_SETMASK, &old_mask, 0) != 0 && result == 0)
        result = 12;
    return result;
}

static int test_queued_order_mask_update_and_read_sizes(void)
{
    /* These Linux numbers sit above musl's reserved realtime signals. */
    enum { REALTIME_LOW = 36, REALTIME_HIGH = 37 };
    sigset_t blocked;
    sigset_t old_mask;
    sigset_t low_only;
    sigset_t high_only;
    struct signalfd_siginfo records[4];
    int descriptor = -1;
    int result = 20;

    if (sigemptyset(&blocked) != 0 || sigemptyset(&low_only) != 0 ||
        sigemptyset(&high_only) != 0 ||
        sigaddset(&blocked, SIGUSR1) != 0 ||
        sigaddset(&blocked, SIGUSR2) != 0 ||
        sigaddset(&blocked, REALTIME_LOW) != 0 ||
        sigaddset(&blocked, REALTIME_HIGH) != 0 ||
        sigaddset(&low_only, REALTIME_LOW) != 0 ||
        sigaddset(&high_only, REALTIME_HIGH) != 0)
        return result;
    if (sigprocmask(SIG_BLOCK, &blocked, &old_mask) != 0)
        return 21;

    descriptor = signalfd(-1, &blocked, SFD_NONBLOCK | SFD_CLOEXEC);
    if (descriptor < 0) {
        result = 22;
        goto cleanup;
    }

    /* A short buffer is invalid even when the descriptor is nonblocking. */
    errno = 0;
    if (read(descriptor, records, sizeof(records[0]) - 1) != -1 ||
        errno != EINVAL) {
        result = 23;
        goto cleanup;
    }

    /* Queue the higher realtime number first and duplicate each standard
     * signal. Linux retains one pending instance per standard number, while
     * each realtime instance keeps its payload and same-number FIFO order. */
    if (raw_queue_self(REALTIME_HIGH, 301) ||
        raw_queue_self(REALTIME_LOW, 101) ||
        raw_queue_self(SIGUSR2, 202) ||
        raw_queue_self(SIGUSR1, 201) ||
        raw_queue_self(SIGUSR2, 999) ||
        raw_queue_self(SIGUSR1, 999) ||
        raw_queue_self(REALTIME_LOW, 102) ||
        raw_queue_self(REALTIME_HIGH, 302)) {
        result = 24;
        goto cleanup;
    }

    errno = E2BIG;
    if (read(descriptor, records, 3 * sizeof(records[0]) + 17) !=
            (ssize_t)(3 * sizeof(records[0])) || errno != E2BIG ||
        expect_queue_record(&records[0], SIGUSR1, 201) ||
        expect_queue_record(&records[1], SIGUSR2, 202) ||
        expect_queue_record(&records[2], REALTIME_LOW, 101)) {
        result = 25;
        goto cleanup;
    }

    errno = ERANGE;
    if (signalfd(descriptor, &high_only, 0) != descriptor || errno != ERANGE) {
        result = 26;
        goto cleanup;
    }
    errno = E2BIG;
    if (read(descriptor, records, sizeof(records)) !=
            (ssize_t)(2 * sizeof(records[0])) || errno != E2BIG ||
        expect_queue_record(&records[0], REALTIME_HIGH, 301) ||
        expect_queue_record(&records[1], REALTIME_HIGH, 302)) {
        result = 27;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, records, sizeof(records)) != -1 || errno != EAGAIN) {
        result = 28;
        goto cleanup;
    }

    if (signalfd(descriptor, &low_only, 0) != descriptor) {
        result = 29;
        goto cleanup;
    }
    errno = E2BIG;
    if (read(descriptor, records, sizeof(records)) !=
            (ssize_t)sizeof(records[0]) || errno != E2BIG ||
        expect_queue_record(&records[0], REALTIME_LOW, 102)) {
        result = 30;
        goto cleanup;
    }
    errno = 0;
    if (read(descriptor, records, sizeof(records)) != -1 || errno != EAGAIN) {
        result = 31;
        goto cleanup;
    }
    result = 0;

cleanup:
    /* On failure, keep queued signals blocked while the process exits. */
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0)
        result = 32;
    if (result == 0 && sigprocmask(SIG_SETMASK, &old_mask, 0) != 0)
        result = 33;
    return result;
}

int crabc_x86_64_signalfd_probe(void)
{
    int result = test_create_read_and_update();

    return result != 0 ? result : test_queued_order_mask_update_and_read_sizes();
}

#ifndef CRABC_SIGNALFD_FREESTANDING
int main(void)
{
    return crabc_x86_64_signalfd_probe();
}
#endif
