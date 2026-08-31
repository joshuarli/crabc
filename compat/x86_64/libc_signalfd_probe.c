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
_Static_assert(SYS_getpid == 39 && SYS_kill == 62 && SYS_signalfd4 == 289,
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

static int raw_kill_self(int signal_number)
{
    long process_id = raw_syscall0(SYS_getpid);

    return process_id <= 0 ||
        raw_syscall2(SYS_kill, process_id, signal_number) != 0;
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

int crabc_x86_64_signalfd_probe(void)
{
    return test_create_read_and_update();
}

#ifndef CRABC_SIGNALFD_FREESTANDING
int main(void)
{
    return crabc_x86_64_signalfd_probe();
}
#endif
