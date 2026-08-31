/* Static x86-64 unlockpt C ABI and pinned-musl behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a true static crabc archive. The named boundary releases the lock on
 * one freshly allocated master PTY with its fixed TIOCSPTLCK request; fixture-
 * local raw syscalls allocate/observe/close that ephemeral descriptor only.
 * It does not select PTY naming, allocation, session, or generic ioctl APIs.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>

enum {
    FIXTURE_EBADF = 9,
    FIXTURE_ENOTTY = 25,
    FIXTURE_TIOCGPTPEER = 0x5441UL,
    FIXTURE_PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
};

typedef int (*unlockpt_signature)(int);

_Static_assert(sizeof(int) == 4 && _Alignof(int) == 4,
    "x86 int ABI");
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_close == 3 && SYS_ioctl == 16 && SYS_openat == 257,
    "x86 fixture syscall numbers");
_Static_assert(O_RDWR == 2 && O_NOCTTY == 0x100 && O_CLOEXEC == 0x80000,
    "x86 fixture descriptor flags");
_Static_assert(FIXTURE_TIOCGPTPEER == 0x5441UL,
    "x86 fixture PTY observation request");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unlockpt),
    unlockpt_signature), "unlockpt declaration");

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

static int check_error_translation(unlockpt_signature invoke)
{
    static const char null_path[] = "/dev/null";
    int null_fd;

    errno = 313;
    if (invoke(-1) != -1 || errno != FIXTURE_EBADF)
        return 1;

    null_fd = raw_openat(null_path, O_RDWR | O_CLOEXEC);
    if (null_fd < 0)
        return 2;
    errno = 313;
    if (unlockpt(null_fd) != -1 || errno != FIXTURE_ENOTTY) {
        (void)raw_close(null_fd);
        return 3;
    }
    if (raw_close(null_fd) != 0)
        return 4;
    return 0;
}

static int check_fresh_master_unlock(unlockpt_signature invoke)
{
    static const char ptmx_path[] = "/dev/ptmx";
    int master;
    long slave;

    master = raw_openat(ptmx_path, FIXTURE_PTY_FLAGS);
    if (master < 0)
        return 1;

    errno = 313;
    if (invoke(master) != 0 || errno != 313) {
        (void)raw_close(master);
        return 2;
    }

    /* The peer request is harness-only observation that unlockpt's fixed
       lock-release took effect on this freshly allocated devpts master. */
    slave = raw_syscall3(SYS_ioctl, master, FIXTURE_TIOCGPTPEER,
        FIXTURE_PTY_FLAGS);
    if (slave < 0) {
        (void)raw_close(master);
        return 3;
    }
    if (raw_close((int)slave) != 0 || raw_close(master) != 0)
        return 4;
    return 0;
}

int crabc_x86_64_unlockpt_probe(void)
{
    const unlockpt_signature invoke = unlockpt;
    int result = check_error_translation(invoke);

    if (result != 0)
        return result;
    return check_fresh_master_unlock(invoke) == 0 ? 0 : 16;
}

#ifndef CRABC_UNLOCKPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_unlockpt_probe();
}
#endif
