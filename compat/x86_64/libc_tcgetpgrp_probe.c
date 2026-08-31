/* Static crabc-libc x86-64 tcgetpgrp compatibility fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked only with the selected archive.
 * Fixture-local raw syscalls make an ephemeral devpts pair and, in one child,
 * establish the kernel precondition for a foreground process group. They are
 * harness-only: the C boundary under test only reads that group through an
 * already-owned terminal descriptor and exports no session/process control.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    FIXTURE_EINTR = 4,
    FIXTURE_EBADF = 9,
    FIXTURE_ENOTTY = 25,
    FIXTURE_TIOCSCTTY = 0x540eUL,
    FIXTURE_TIOCGPGRP = 0x540fUL,
    FIXTURE_TIOCSPTLCK = 0x40045431UL,
    FIXTURE_TIOCGPTPEER = 0x5441UL,
    FIXTURE_PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
};

struct pty_pair {
    int master;
    int slave;
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(__builtin_types_compatible_p(pid_t, int),
    "x86 pid_t int ABI");
_Static_assert(SYS_close == 3 && SYS_getpid == 39 && SYS_fork == 57 &&
    SYS_exit == 60 && SYS_wait4 == 61 && SYS_setsid == 112 &&
    SYS_ioctl == 16 && SYS_openat == 257,
    "x86 fixture syscall numbers");
_Static_assert(O_RDONLY == 0 && O_RDWR == 2 && O_NOCTTY == 0x100 &&
    O_CLOEXEC == 0x80000, "x86 fixture descriptor flags");
_Static_assert(FIXTURE_TIOCSCTTY == 0x540eUL &&
    FIXTURE_TIOCGPGRP == 0x540fUL &&
    FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL, "x86 fixture request words");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetpgrp),
    pid_t (*)(int)), "tcgetpgrp declaration");

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

static int raw_close(int fd)
{
    return raw_syscall1(SYS_close, fd) == 0 ? 0 : -1;
}

static int raw_openat(const char *path, int flags)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)path,
        flags, 0);
}

static int open_pty_pair(struct pty_pair *pair)
{
    static const char ptmx_path[] = "/dev/ptmx";
    int unlocked = 0;
    long master;
    long slave;

    pair->master = -1;
    pair->slave = -1;
    master = raw_openat(ptmx_path, FIXTURE_PTY_FLAGS);
    if (master < 0)
        return -1;
    pair->master = (int)master;
    if (raw_syscall3(SYS_ioctl, pair->master, FIXTURE_TIOCSPTLCK,
            (long)(uintptr_t)&unlocked) != 0)
        goto failure;
    slave = raw_syscall3(SYS_ioctl, pair->master, FIXTURE_TIOCGPTPEER,
        FIXTURE_PTY_FLAGS);
    if (slave < 0)
        goto failure;
    pair->slave = (int)slave;
    return 0;

failure:
    (void)raw_close(pair->master);
    pair->master = -1;
    return -1;
}

static int wait_for_zero_exit(long child)
{
    int status = -1;
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)(uintptr_t)&status, 0, 0);
    } while (result == -FIXTURE_EINTR);
    return result == child && status == 0 ? 0 : -1;
}

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {
    }
}

static int child_reads_foreground_group(int slave)
{
    long pid;

    if (raw_syscall0(SYS_setsid) <= 0)
        return 1;
    pid = raw_syscall0(SYS_getpid);
    if (pid <= 0)
        return 2;
    if (raw_syscall3(SYS_ioctl, slave, FIXTURE_TIOCSCTTY, 0) != 0)
        return 3;

    errno = 313;
    if (tcgetpgrp(slave) != (pid_t)pid || errno != 313)
        return 4;
    return 0;
}

static int check_foreground_group(struct pty_pair pair)
{
    long child = raw_syscall0(SYS_fork);

    if (child < 0)
        return 1;
    if (child == 0) {
        int result;

        (void)raw_close(pair.master);
        result = child_reads_foreground_group(pair.slave);
        (void)raw_close(pair.slave);
        raw_exit(result == 0 ? 0 : 1);
    }

    (void)raw_close(pair.slave);
    pair.slave = -1;
    if (wait_for_zero_exit(child) != 0) {
        (void)raw_close(pair.master);
        return 2;
    }
    (void)raw_close(pair.master);
    return 0;
}

int crabc_x86_64_tcgetpgrp_probe(void)
{
    static const char null_path[] = "/dev/null";
    struct pty_pair pair;
    int null_fd;

    errno = 313;
    if (tcgetpgrp(-1) != -1 || errno != FIXTURE_EBADF)
        return 1;

    null_fd = raw_openat(null_path, O_RDONLY | O_CLOEXEC);
    if (null_fd < 0)
        return 2;
    errno = 313;
    if (tcgetpgrp(null_fd) != -1 || errno != FIXTURE_ENOTTY) {
        (void)raw_close(null_fd);
        return 3;
    }
    (void)raw_close(null_fd);

    if (open_pty_pair(&pair) != 0)
        return 4;
    return check_foreground_group(pair) == 0 ? 0 : 5;
}

#ifndef CRABC_TCGETPGRP_FREESTANDING
int main(void)
{
    return crabc_x86_64_tcgetpgrp_probe();
}
#endif
