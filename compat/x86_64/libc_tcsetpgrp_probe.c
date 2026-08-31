/* Static crabc-libc x86-64 tcsetpgrp compatibility fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked only with the selected archive.
 * Fixture-local raw syscalls make an ephemeral devpts pair and, in one child,
 * establish a session, controlling terminal, and a distinct child process
 * group. They are harness-only: the C boundary under test sends its caller's
 * supplied group to one fixed terminal request and exports no session or
 * process-control API.
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
    FIXTURE_TIOCSPGRP = 0x5410UL,
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
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_getpid == 39 && SYS_fork == 57 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_setpgid == 109 && SYS_setsid == 112 &&
    SYS_ioctl == 16 && SYS_openat == 257 && SYS_pipe2 == 293,
    "x86 fixture syscall numbers");
_Static_assert(O_RDONLY == 0 && O_RDWR == 2 && O_NOCTTY == 0x100 &&
    O_CLOEXEC == 0x80000, "x86 fixture descriptor flags");
_Static_assert(FIXTURE_TIOCSCTTY == 0x540eUL &&
    FIXTURE_TIOCGPGRP == 0x540fUL && FIXTURE_TIOCSPGRP == 0x5410UL &&
    FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL, "x86 fixture request words");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetpgrp),
    int (*)(int, pid_t)), "tcsetpgrp declaration");

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

static int raw_close(int fd)
{
    return raw_syscall1(SYS_close, fd) == 0 ? 0 : -1;
}

static int raw_openat(const char *path, int flags)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)path,
        flags, 0);
}

static int raw_read_one(int fd, uint8_t *byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_read, fd, (long)(uintptr_t)byte, 1);
    } while (result == -FIXTURE_EINTR);
    return result == 1 ? 0 : -1;
}

static int raw_write_one(int fd, const uint8_t *byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_write, fd, (long)(uintptr_t)byte, 1);
    } while (result == -FIXTURE_EINTR);
    return result == 1 ? 0 : -1;
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

static int child_assigns_foreground_group(int slave)
{
    int release_pipe[2] = { -1, -1 };
    int foreground_group = -1;
    long leader;
    long member;
    uint8_t release_byte = 1;
    int result = 0;

    if (raw_syscall0(SYS_setsid) <= 0)
        return 1;
    leader = raw_syscall0(SYS_getpid);
    if (leader <= 0)
        return 2;
    if (raw_syscall3(SYS_ioctl, slave, FIXTURE_TIOCSCTTY, 0) != 0)
        return 3;
    if (raw_syscall3(SYS_ioctl, slave, FIXTURE_TIOCGPGRP,
            (long)(uintptr_t)&foreground_group) != 0 ||
        foreground_group != (int)leader)
        return 4;
    if (raw_syscall2(SYS_pipe2, (long)(uintptr_t)release_pipe, O_CLOEXEC) != 0)
        return 5;

    member = raw_syscall0(SYS_fork);
    if (member < 0) {
        (void)raw_close(release_pipe[0]);
        (void)raw_close(release_pipe[1]);
        return 6;
    }
    if (member == 0) {
        (void)raw_close(release_pipe[1]);
        if (raw_read_one(release_pipe[0], &release_byte) != 0)
            raw_exit(1);
        (void)raw_close(release_pipe[0]);
        raw_exit(0);
    }

    (void)raw_close(release_pipe[0]);
    if (raw_syscall2(SYS_setpgid, member, member) != 0)
        result = 7;
    else if (member == leader)
        result = 8;
    else {
        errno = 313;
        if (tcsetpgrp(slave, (pid_t)member) != 0 || errno != 313)
            result = 9;
        else {
            foreground_group = -1;
            if (raw_syscall3(SYS_ioctl, slave, FIXTURE_TIOCGPGRP,
                    (long)(uintptr_t)&foreground_group) != 0 ||
                foreground_group != (int)member)
                result = 10;
        }
    }

    if (raw_write_one(release_pipe[1], &release_byte) != 0 && result == 0)
        result = 11;
    (void)raw_close(release_pipe[1]);
    if (wait_for_zero_exit(member) != 0 && result == 0)
        result = 12;
    return result;
}

static int check_foreground_group_assignment(struct pty_pair pair)
{
    long child = raw_syscall0(SYS_fork);

    if (child < 0)
        return 1;
    if (child == 0) {
        int result;

        (void)raw_close(pair.master);
        result = child_assigns_foreground_group(pair.slave);
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

int crabc_x86_64_tcsetpgrp_probe(void)
{
    static const char null_path[] = "/dev/null";
    struct pty_pair pair;
    int null_fd;

    errno = 313;
    if (tcsetpgrp(-1, 0) != -1 || errno != FIXTURE_EBADF)
        return 1;

    null_fd = raw_openat(null_path, O_RDONLY | O_CLOEXEC);
    if (null_fd < 0)
        return 2;
    errno = 313;
    if (tcsetpgrp(null_fd, 0) != -1 || errno != FIXTURE_ENOTTY) {
        (void)raw_close(null_fd);
        return 3;
    }
    (void)raw_close(null_fd);

    if (open_pty_pair(&pair) != 0)
        return 4;
    return check_foreground_group_assignment(pair) == 0 ? 0 : 5;
}

#ifndef CRABC_TCSETPGRP_FREESTANDING
int main(void)
{
    return crabc_x86_64_tcsetpgrp_probe();
}
#endif
