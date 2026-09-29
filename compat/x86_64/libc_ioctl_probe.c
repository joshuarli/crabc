/* Static crabc-libc x86-64 generic ioctl fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a true freestanding static candidate linked solely with the
 * selected crabc libc archive. It proves only the generic Linux ioctl=16
 * forwarder: pointer input/output, an integer third word consumed by a PTY
 * peer-open request, two named no-vararg descriptor requests, and errno
 * translation. The PTY is only a local argument-forwarding witness.
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
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 ioctl LP64 scalar widths");
_Static_assert(SYS_ioctl == 16 && SYS_write == 1 && SYS_close == 3 &&
    SYS_pipe == 22 && SYS_fcntl == 72 && SYS_openat == 257,
    "x86 selected ioctl fixture syscall numbers");
_Static_assert(FIONREAD == 0x541b && TIOCINQ == FIONREAD &&
    FIONBIO == 0x5421 && FIOCLEX == 0x5451 && FIONCLEX == 0x5450 &&
    TIOCSPTLCK == 0x40045431 && TIOCGPTPEER == 0x5441,
    "x86 selected generic ioctl request words");
_Static_assert(F_GETFD == 1 && F_GETFL == 3 && FD_CLOEXEC == 1 &&
    O_NONBLOCK == 04000 && O_RDWR == 2 && O_NOCTTY == 0x100 &&
    O_CLOEXEC == 0x80000,
    "x86 raw fcntl observation words");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioctl),
    int (*)(int, int, ...)), "musl ioctl declaration");

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

static int raw_close(int descriptor)
{
    return raw_syscall1(SYS_close, descriptor) == 0 ? 0 : -1;
}

static int raw_descriptor_flags(int descriptor)
{
    return (int)raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0);
}

static int raw_status_flags(int descriptor)
{
    return (int)raw_syscall3(SYS_fcntl, descriptor, F_GETFL, 0);
}

static int raw_openat(const char *path, int flags)
{
    return (int)raw_syscall4(SYS_openat, AT_FDCWD,
        (long)(uintptr_t)path, flags, 0);
}

static int close_pair(int descriptors[2])
{
    int status = 0;

    if (descriptors[0] >= 0 && raw_close(descriptors[0]) != 0)
        status = -1;
    if (descriptors[1] >= 0 && raw_close(descriptors[1]) != 0)
        status = -1;
    descriptors[0] = -1;
    descriptors[1] = -1;
    return status;
}

static int check_generic_ioctl(int read_descriptor)
{
    int available = -1;
    int alias_available = -1;
    int nonblocking = 1;
    int flags;

    errno = E2BIG;
    if (ioctl(read_descriptor, FIONREAD, &available) != 0 || available != 3 ||
        errno != E2BIG)
        return 1;

    errno = ERANGE;
    if (ioctl(read_descriptor, TIOCINQ, &alias_available) != 0 ||
        alias_available != available || errno != ERANGE)
        return 9;

    /* These two C calls intentionally omit the vararg. The candidate's
     * assembly entry supplies a zero third Linux word rather than reading an
     * unspecified SysV rdx register. */
    errno = ERANGE;
    if (ioctl(read_descriptor, FIOCLEX) != 0 || errno != ERANGE)
        return 2;
    flags = raw_descriptor_flags(read_descriptor);
    if (flags < 0 || (flags & FD_CLOEXEC) != FD_CLOEXEC)
        return 3;

    errno = E2BIG;
    if (ioctl(read_descriptor, FIONCLEX) != 0 || errno != E2BIG)
        return 4;
    flags = raw_descriptor_flags(read_descriptor);
    if (flags < 0 || (flags & FD_CLOEXEC) != 0)
        return 5;

    errno = ERANGE;
    if (ioctl(read_descriptor, FIONBIO, &nonblocking) != 0 || errno != ERANGE)
        return 6;
    flags = raw_status_flags(read_descriptor);
    if (flags < 0 || (flags & O_NONBLOCK) != O_NONBLOCK)
        return 7;

    errno = 0;
    if (ioctl(-1, FIOCLEX) != -1 || errno != EBADF)
        return 8;
    errno = E2BIG;
    if (ioctl(-1, FIONREAD, &available) != -1 || errno != EBADF ||
        available != 3)
        return 10;
    errno = E2BIG;
    if (ioctl(read_descriptor, 0x7fff, &available) != -1 ||
        errno != ENOTTY || available != 3)
        return 11;
    return 0;
}

static int check_scalar_ioctl(void)
{
    static const char ptmx_path[] = "/dev/ptmx";
    const int peer_flags = O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK;
    int master = raw_openat(ptmx_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    int unlocked = 0;
    int slave;
    int status = 0;

    if (master < 0)
        return 1;
    errno = E2BIG;
    if (ioctl(master, TIOCSPTLCK, &unlocked) != 0 || errno != E2BIG) {
        status = 2;
        goto close_master;
    }

    /* TIOCGPTPEER consumes an integer flags word. Both descriptor and file
     * status flags must survive the public variadic ABI and Linux syscall. */
    errno = ERANGE;
    slave = ioctl(master, TIOCGPTPEER, peer_flags);
    if (slave < 0 || errno != ERANGE) {
        status = 3;
        goto close_master;
    }
    if ((raw_descriptor_flags(slave) & FD_CLOEXEC) != FD_CLOEXEC ||
        (raw_status_flags(slave) & (O_ACCMODE | O_NONBLOCK)) !=
            (O_RDWR | O_NONBLOCK))
        status = 4;
    if (raw_close(slave) != 0)
        status = 5;

close_master:
    if (raw_close(master) != 0)
        status = 6;
    return status;
}

int crabc_x86_64_ioctl_probe(void)
{
    static const char payload[] = "abc";
    int descriptors[2] = {-1, -1};
    int status;
    int cleanup_status;

    if (raw_syscall1(SYS_pipe, (long)(void *)descriptors) != 0)
        return 1;
    if (raw_syscall3(SYS_write, descriptors[1], (long)(const void *)payload,
                     sizeof(payload) - 1) != (long)(sizeof(payload) - 1)) {
        (void)close_pair(descriptors);
        return 2;
    }

    status = check_generic_ioctl(descriptors[0]);
    cleanup_status = close_pair(descriptors);
    if (status != 0)
        return 10 + status;
    if (cleanup_status != 0)
        return 30;
    status = check_scalar_ioctl();
    return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_IOCTL_FREESTANDING
int main(void)
{
    return crabc_x86_64_ioctl_probe();
}
#endif
