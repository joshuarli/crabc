/*
 * Pinned-musl/raw Linux/x86-64 basic pseudoterminal reference.
 *
 * This fixture establishes only the private Rust pair/name seam: `/dev/ptmx`
 * allocation, devpts validation/unlock, a newly owned `TIOCGPTPEER` slave,
 * and deterministic `/dev/pts/N` naming.  It intentionally has no
 * controlling-terminal, session, termios, queue-control, or generic-ioctl
 * behavior, and it does not select a C PTY API or public x86-64 support.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    PTY_OPEN_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
    PTY_NAME_BUFFER_LEN = 32,
};

_Static_assert(sizeof(int) == 4 && sizeof(unsigned int) == 4 &&
                   sizeof(long) == 8 && sizeof(size_t) == 8 &&
                   sizeof(void *) == 8,
               "x86 little-endian LP64 scalar widths");
_Static_assert(AT_FDCWD == -100, "x86 openat current-directory selector");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
                   SYS_ioctl == 16 && SYS_openat == 257,
               "x86 PTY lifecycle syscall numbers");
_Static_assert(O_RDWR == 0x2 && O_NOCTTY == 0x100 && O_CLOEXEC == 0x80000,
               "x86 closed PTY open flags");
_Static_assert(F_GETFD == 1 && FD_CLOEXEC == 1,
               "x86 close-on-exec descriptor flag ABI");
_Static_assert(TIOCGPTN == 0x80045430UL && TIOCSPTLCK == 0x40045431UL &&
                   TIOCGPTPEER == 0x5441UL,
               "Linux devpts ioctl request values");

enum pty_arm {
    RAW_SYSCALL_ARM,
    MUSL_WRAPPER_ARM,
};

static int raw_openat(const char *path, int flags)
{
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
}

static int raw_ioctl_pointer(int fd, unsigned long request, void *argument)
{
    return (int)syscall(SYS_ioctl, fd, request, argument);
}

static int raw_tiocgptpeer(int fd, int flags)
{
    return (int)syscall(SYS_ioctl, fd, TIOCGPTPEER, (unsigned long)flags);
}

static int openpt_for_arm(enum pty_arm arm)
{
    if (arm == RAW_SYSCALL_ARM)
        return raw_openat("/dev/ptmx", PTY_OPEN_FLAGS);
    return posix_openpt(PTY_OPEN_FLAGS);
}

static int ioctl_pointer_for_arm(enum pty_arm arm, int fd,
                                 unsigned long request, void *argument)
{
    if (arm == RAW_SYSCALL_ARM)
        return raw_ioctl_pointer(fd, request, argument);
    return ioctl(fd, request, argument);
}

static int tiocgptpeer_for_arm(enum pty_arm arm, int fd, int flags)
{
    if (arm == RAW_SYSCALL_ARM)
        return raw_tiocgptpeer(fd, flags);
    return ioctl(fd, TIOCGPTPEER, flags);
}

static ssize_t write_for_arm(enum pty_arm arm, int fd, const void *buffer,
                             size_t length)
{
    if (arm == RAW_SYSCALL_ARM)
        return (ssize_t)syscall(SYS_write, fd, buffer, length);
    return write(fd, buffer, length);
}

static ssize_t read_for_arm(enum pty_arm arm, int fd, void *buffer,
                            size_t length)
{
    if (arm == RAW_SYSCALL_ARM)
        return (ssize_t)syscall(SYS_read, fd, buffer, length);
    return read(fd, buffer, length);
}

static int close_for_arm(enum pty_arm arm, int fd)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_close, fd);
    return close(fd);
}

static int descriptor_has_requested_flags(int fd)
{
    int status_flags = fcntl(fd, F_GETFL);
    int descriptor_flags = fcntl(fd, F_GETFD);

    return status_flags >= 0 && (status_flags & O_ACCMODE) == O_RDWR &&
           descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0;
}

/*
 * The Rust seam derives its name directly from the kernel PTY number instead
 * of exposing musl's static `ptsname` storage.  Keep the reference formatter
 * allocation-free and require its short-buffer result to match `ptsname_r`.
 */
static int format_pts_name(unsigned int number, char *buffer, size_t length)
{
    static const char prefix[] = "/dev/pts/";
    char digits[10];
    size_t digit_count = 0;
    size_t name_length;
    unsigned int value = number;
    size_t index;

    do {
        digits[digit_count++] = (char)('0' + value % 10U);
        value /= 10U;
    } while (value != 0);

    name_length = sizeof(prefix) - 1 + digit_count;
    if (length < name_length + 1)
        return ERANGE;

    memcpy(buffer, prefix, sizeof(prefix) - 1);
    for (index = 0; index < digit_count; index++)
        buffer[sizeof(prefix) - 1 + index] = digits[digit_count - index - 1];
    buffer[name_length] = '\0';
    return 0;
}

static int descriptor_roundtrip(enum pty_arm arm, int master, int slave)
{
    static const char message[] = "pty-basic";
    char received[sizeof(message) - 1];
    ssize_t written;
    ssize_t read_count;

    written = write_for_arm(arm, slave, message, sizeof(message) - 1);
    if (written != (ssize_t)(sizeof(message) - 1))
        return 0;

    read_count = read_for_arm(arm, master, received, sizeof(received));
    return read_count == (ssize_t)sizeof(received) &&
           memcmp(received, message, sizeof(received)) == 0;
}

static int run_pty_lifecycle(enum pty_arm arm)
{
    char direct_name[PTY_NAME_BUFFER_LEN];
    char musl_name[PTY_NAME_BUFFER_LEN];
    char short_name[4];
    unsigned int number = 0;
    int unlocked = 0;
    int master = -1;
    int slave = -1;
    int status = 0;

    master = openpt_for_arm(arm);
    if (master < 0) {
        status = 10;
        goto cleanup;
    }
    if (!descriptor_has_requested_flags(master)) {
        status = 11;
        goto cleanup;
    }

    /* `grantpt` is musl's validation wrapper; the raw arm performs the same
       TIOCGPTN validation directly. Neither arm claims a C grant policy. */
    if (arm == MUSL_WRAPPER_ARM) {
        if (grantpt(master) != 0) {
            status = 12;
            goto cleanup;
        }
    } else if (ioctl_pointer_for_arm(arm, master, TIOCGPTN, &number) != 0) {
        status = 13;
        goto cleanup;
    }

    if (arm == MUSL_WRAPPER_ARM) {
        if (unlockpt(master) != 0) {
            status = 14;
            goto cleanup;
        }
    } else if (ioctl_pointer_for_arm(arm, master, TIOCSPTLCK, &unlocked) !=
               0) {
        status = 15;
        goto cleanup;
    }

    if (ioctl_pointer_for_arm(arm, master, TIOCGPTN, &number) != 0) {
        status = 16;
        goto cleanup;
    }
    if (format_pts_name(number, short_name, sizeof(short_name)) != ERANGE ||
        ptsname_r(master, short_name, sizeof(short_name)) != ERANGE) {
        status = 17;
        goto cleanup;
    }
    if (format_pts_name(number, direct_name, sizeof(direct_name)) != 0 ||
        ptsname_r(master, musl_name, sizeof(musl_name)) != 0 ||
        strcmp(direct_name, musl_name) != 0) {
        status = 18;
        goto cleanup;
    }

    slave = tiocgptpeer_for_arm(arm, master, PTY_OPEN_FLAGS);
    if (slave < 0) {
        status = 19;
        goto cleanup;
    }
    if (!descriptor_has_requested_flags(slave)) {
        status = 20;
        goto cleanup;
    }
    if (!descriptor_roundtrip(arm, master, slave)) {
        status = 21;
        goto cleanup;
    }

cleanup:
    if (slave >= 0 && close_for_arm(arm, slave) != 0 && status == 0)
        status = 30;
    if (master >= 0 && close_for_arm(arm, master) != 0 && status == 0)
        status = 31;
    return status;
}

static int check_nonpty_rejection(void)
{
    char name[PTY_NAME_BUFFER_LEN];
    unsigned int number = 0;
    int unlocked = 0;
    int null_fd = -1;
    int status = 0;

    null_fd = raw_openat("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0) {
        status = 10;
        goto cleanup;
    }

    errno = 0;
    if (raw_ioctl_pointer(null_fd, TIOCGPTN, &number) != -1 || errno != ENOTTY) {
        status = 11;
        goto cleanup;
    }
    errno = 0;
    if (raw_ioctl_pointer(null_fd, TIOCSPTLCK, &unlocked) != -1 ||
        errno != ENOTTY) {
        status = 12;
        goto cleanup;
    }
    errno = 0;
    if (raw_tiocgptpeer(null_fd, PTY_OPEN_FLAGS) != -1 || errno != ENOTTY) {
        status = 13;
        goto cleanup;
    }
    errno = 0;
    if (grantpt(null_fd) != -1 || errno != ENOTTY) {
        status = 14;
        goto cleanup;
    }
    errno = 0;
    if (unlockpt(null_fd) != -1 || errno != ENOTTY) {
        status = 15;
        goto cleanup;
    }
    if (ptsname_r(null_fd, name, sizeof(name)) != ENOTTY) {
        status = 16;
        goto cleanup;
    }

cleanup:
    if (null_fd >= 0 && close_for_arm(RAW_SYSCALL_ARM, null_fd) != 0 &&
        status == 0)
        status = 20;
    return status;
}

int main(void)
{
    if (check_nonpty_rejection() != 0)
        return 1;
    if (run_pty_lifecycle(RAW_SYSCALL_ARM) != 0)
        return 2;
    if (run_pty_lifecycle(MUSL_WRAPPER_ARM) != 0)
        return 3;

    puts("syscalls=openat:257,ioctl:16,read:0,write:1,close:3 ioctls=TIOCGPTN:0x80045430,TIOCSPTLCK:0x40045431,TIOCGPTPEER:0x5441 flags=RDWR|NOCTTY|CLOEXEC raw+musl=ptmx-lifecycle name=exact+ERANGE nonpty=ENOTTY peer=owned-noctty-cloexec io=slave-to-master-roundtrip c-api-selection=excluded");
    return 0;
}
