/* Static crabc-libc x86-64 isatty compatibility fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked only with the selected archive.
 * Fixture-local raw syscalls make an ephemeral devpts pair only to obtain a
 * known terminal descriptor; they select no public PTY or terminal control
 * API. The C boundary under test is only descriptor observation: a tty
 * succeeds and preserves errno, while an invalid descriptor and /dev/null
 * return false with their Linux errors.
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
    FIXTURE_EBADF = 9,
    FIXTURE_ENOTTY = 25,
    FIXTURE_TIOCGWINSZ = 0x5413UL,
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
_Static_assert(SYS_close == 3 && SYS_ioctl == 16 && SYS_openat == 257,
    "x86 fixture syscall numbers");
_Static_assert(O_RDONLY == 0 && O_RDWR == 2 && O_NOCTTY == 0x100 &&
    O_CLOEXEC == 0x80000, "x86 fixture descriptor flags");
_Static_assert(FIXTURE_TIOCGWINSZ == 0x5413UL &&
    FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL, "x86 fixture request words");
_Static_assert(__builtin_types_compatible_p(__typeof__(&isatty),
    int (*)(int)), "isatty declaration");

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

int crabc_x86_64_isatty_probe(void)
{
    static const char null_path[] = "/dev/null";
    struct pty_pair pair;
    int null_fd;
    int result = 0;

    if (open_pty_pair(&pair) != 0)
        return 1;

    errno = 313;
    if (isatty(pair.slave) != 1 || errno != 313)
        result = 2;

    errno = 313;
    if (result == 0 && (isatty(-1) != 0 || errno != FIXTURE_EBADF))
        result = 3;

    null_fd = raw_openat(null_path, O_RDONLY | O_CLOEXEC);
    if (null_fd < 0) {
        if (result == 0)
            result = 4;
    } else {
        errno = 313;
        if (result == 0 &&
            (isatty(null_fd) != 0 || errno != FIXTURE_ENOTTY))
            result = 5;
        (void)raw_close(null_fd);
    }

    (void)raw_close(pair.slave);
    (void)raw_close(pair.master);
    return result;
}

#ifndef CRABC_ISATTY_FREESTANDING
int main(void)
{
    return crabc_x86_64_isatty_probe();
}
#endif
