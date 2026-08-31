/* Static crabc-libc x86-64 ttyname_r compatibility fixture.
 *
 * One project-header C body first runs through pinned musl 1.2.6, then
 * through a freestanding executable linked only with the selected archive.
 * Fixture-local raw syscalls make an ephemeral devpts pair only to obtain a
 * known terminal descriptor. The C boundary under test is only caller-buffered
 * terminal-path naming: musl's isatty check, /proc/self/fd readlink spelling,
 * bounded NUL termination, and stat/fstat identity confirmation.
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
    FIXTURE_EFAULT = 14,
    FIXTURE_ENOTTY = 25,
    FIXTURE_ERANGE = 34,
    FIXTURE_TIOCSPTLCK = 0x40045431UL,
    FIXTURE_TIOCGPTPEER = 0x5441UL,
    FIXTURE_PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
    FIXTURE_PATH_CAPACITY = 128,
    FIXTURE_PROC_PATH_CAPACITY = 32,
    FIXTURE_SENTINEL = 0xa5,
};

struct pty_pair {
    int master;
    int slave;
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_close == 3 && SYS_fstat == 5 && SYS_ioctl == 16 &&
    SYS_readlink == 89 && SYS_openat == 257 && SYS_newfstatat == 262,
    "x86 fixture syscall numbers");
_Static_assert(O_RDONLY == 0 && O_RDWR == 2 && O_NOCTTY == 0x100 &&
    O_CLOEXEC == 0x80000, "x86 fixture descriptor flags");
_Static_assert(FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL, "x86 fixture request words");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ttyname_r),
    int (*)(int, char *, size_t)), "ttyname_r declaration");

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

static int proc_fd_path(char path[FIXTURE_PROC_PATH_CAPACITY], int fd)
{
    static const char prefix[] = "/proc/self/fd/";
    unsigned int value = (unsigned int)fd;
    size_t index = 0;
    size_t digits;
    size_t end;

    while (prefix[index] != '\0') {
        path[index] = prefix[index];
        index++;
    }
    if (value == 0) {
        path[index] = '0';
        path[index + 1] = '\0';
        return 0;
    }
    digits = 0;
    for (unsigned int remaining = value; remaining != 0; remaining /= 10)
        digits++;
    if (index + digits + 1 > FIXTURE_PROC_PATH_CAPACITY)
        return -1;
    end = index + digits;
    path[end] = '\0';
    while (value != 0) {
        path[--end] = (char)('0' + value % 10);
        value /= 10;
    }
    return 0;
}

static int expected_terminal_name(int fd, const unsigned char *name,
    size_t capacity, size_t *length)
{
    char proc_path[FIXTURE_PROC_PATH_CAPACITY];
    char expected[FIXTURE_PATH_CAPACITY];
    long result;
    size_t index;

    if (proc_fd_path(proc_path, fd) != 0)
        return -1;
    result = raw_syscall3(SYS_readlink, (long)(uintptr_t)proc_path,
        (long)(uintptr_t)expected, sizeof(expected));
    if (result <= 0 || (size_t)result >= capacity)
        return -1;
    for (index = 0; index < (size_t)result; index++) {
        if (name[index] != (unsigned char)expected[index])
            return -1;
    }
    if (name[result] != '\0')
        return -1;
    *length = (size_t)result;
    return 0;
}

int crabc_x86_64_ttyname_r_probe(void)
{
    static const char null_path[] = "/dev/null";
    struct pty_pair pair;
    unsigned char name[FIXTURE_PATH_CAPACITY];
    unsigned char short_name[1];
    unsigned char zero_capacity_sentinel = FIXTURE_SENTINEL;
    int null_fd = -1;
    int result = 0;
    size_t length = 0;

    if (open_pty_pair(&pair) != 0)
        return 1;

    for (size_t index = 0; index < sizeof(name); index++)
        name[index] = FIXTURE_SENTINEL;
    errno = 313;
    if (ttyname_r(pair.slave, (char *)name, sizeof(name)) != 0 || errno != 313)
        result = 2;
    if (result == 0 && expected_terminal_name(pair.slave, name, sizeof(name),
            &length) != 0)
        result = 3;
    if (result == 0 && (length + 1 >= sizeof(name) ||
            name[length + 1] != FIXTURE_SENTINEL))
        result = 4;

    short_name[0] = FIXTURE_SENTINEL;
    errno = 313;
    if (result == 0 && (ttyname_r(pair.slave, (char *)short_name,
            sizeof(short_name)) != FIXTURE_ERANGE || errno != 313 ||
            short_name[0] != '/'))
        result = 5;

    errno = 313;
    if (result == 0 && (ttyname_r(pair.slave, (char *)0, 0) != FIXTURE_ERANGE ||
            errno != 313 || zero_capacity_sentinel != FIXTURE_SENTINEL))
        result = 6;

    errno = 313;
    if (result == 0 && (ttyname_r(pair.slave, (char *)0, sizeof(name)) !=
            FIXTURE_EFAULT || errno != FIXTURE_EFAULT))
        result = 7;

    errno = 313;
    if (result == 0 && (ttyname_r(-1, (char *)name, sizeof(name)) !=
            FIXTURE_EBADF || errno != FIXTURE_EBADF))
        result = 8;

    null_fd = raw_openat(null_path, O_RDONLY | O_CLOEXEC);
    if (null_fd < 0) {
        if (result == 0)
            result = 9;
    } else {
        errno = 313;
        if (result == 0 && (ttyname_r(null_fd, (char *)name, sizeof(name)) !=
                FIXTURE_ENOTTY || errno != FIXTURE_ENOTTY))
            result = 10;
        (void)raw_close(null_fd);
    }

    (void)raw_close(pair.slave);
    (void)raw_close(pair.master);
    return result;
}

#ifndef CRABC_TTYNAME_R_FREESTANDING
int main(void)
{
    return crabc_x86_64_ttyname_r_probe();
}
#endif
