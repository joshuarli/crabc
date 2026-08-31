/* Static crabc-libc x86-64 getpass compatibility fixture.
 *
 * The same GNU-enabled C body first runs through pinned musl 1.2.6 and then
 * through a true freestanding crabc archive. Fixture-local raw syscalls own
 * one disposable devpts session solely to make /dev/tty deterministic. The
 * selected C surface is getpass itself: a fixed 128-byte static result,
 * no-echo canonical input, terminal-state restoration, prompt/newline I/O,
 * and the no-controlling-terminal ENXIO result. It does not select a public
 * PTY API, generic ioctl, process supervision, user databases, or a Rust
 * password API.
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
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

enum {
    FIXTURE_KERNEL_NCCS = 19,
    FIXTURE_PASSWORD_BYTES = 128,
    FIXTURE_CAPTURE_BYTES = 512,
    FIXTURE_EINTR = 4,
    FIXTURE_EIO = 5,
    FIXTURE_ENXIO = 6,
    FIXTURE_TIOCSCTTY = 0x540eUL,
    FIXTURE_TCGETS = 0x5401UL,
    FIXTURE_TIOCSPTLCK = 0x40045431UL,
    FIXTURE_TIOCGPTPEER = 0x5441UL,
    FIXTURE_PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
};

struct kernel_termios_x86 {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[FIXTURE_KERNEL_NCCS];
};

struct pty_pair {
    int master;
    int slave;
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_ioctl == 16 && SYS_fork == 57 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_setsid == 112 && SYS_openat == 257 &&
    SYS_pipe2 == 293, "x86 getpass fixture syscall numbers");
_Static_assert(sizeof(struct kernel_termios_x86) == 36 &&
    _Alignof(struct kernel_termios_x86) == 4,
    "x86 Linux kernel termios layout");
_Static_assert(sizeof(struct termios) == 60 && _Alignof(struct termios) == 4 &&
    NCCS == 32, "x86 public termios layout");
_Static_assert(FIXTURE_TIOCSCTTY == 0x540eUL && FIXTURE_TCGETS == 0x5401UL &&
    FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL,
    "x86 selected fixture terminal request words");
_Static_assert(FIXTURE_PTY_FLAGS == (O_RDWR | O_NOCTTY | O_CLOEXEC),
    "x86 private devpts flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpass),
    char *(*)(const char *)), "getpass declaration");

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

static int raw_write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *next = buffer;

    while (length != 0) {
        long result = raw_syscall3(SYS_write, fd, (long)(uintptr_t)next,
            (long)length);

        if (result > 0) {
            next += (size_t)result;
            length -= (size_t)result;
            continue;
        }
        if (result == -FIXTURE_EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int raw_read_exact(int fd, void *buffer, size_t length)
{
    uint8_t *next = buffer;

    while (length != 0) {
        long result = raw_syscall3(SYS_read, fd, (long)(uintptr_t)next,
            (long)length);

        if (result > 0) {
            next += (size_t)result;
            length -= (size_t)result;
            continue;
        }
        if (result == -FIXTURE_EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const uint8_t *left_bytes = left;
    const uint8_t *right_bytes = right;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left_bytes[index] != right_bytes[index])
            return 0;
    }
    return 1;
}

static int bytes_contain(const uint8_t *bytes, size_t length,
    const uint8_t *needle, size_t needle_length)
{
    size_t index;

    if (needle_length == 0 || needle_length > length)
        return 0;
    for (index = 0; index + needle_length <= length; ++index) {
        if (bytes_equal(bytes + index, needle, needle_length))
            return 1;
    }
    return 0;
}

static int bytes_have(const uint8_t *bytes, size_t length, uint8_t wanted)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] == wanted)
            return 1;
    }
    return 0;
}

static int c_string_equals(const char *actual, const char *expected,
    size_t expected_length)
{
    size_t index;

    if (actual == NULL)
        return 0;
    for (index = 0; index < expected_length; ++index) {
        if ((uint8_t)actual[index] != (uint8_t)expected[index])
            return 0;
    }
    return actual[expected_length] == '\0';
}

static int open_pty_pair(struct pty_pair *pair)
{
    static const char ptmx_path[] = "/dev/ptmx";
    int unlocked = 0;
    long master;
    long slave;

    pair->master = -1;
    pair->slave = -1;
    master = raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)ptmx_path,
        FIXTURE_PTY_FLAGS, 0);
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

static int check_no_controlling_tty(void)
{
    long child = raw_syscall0(SYS_fork);

    if (child < 0)
        return 1;
    if (child == 0) {
        errno = 0;
        if (raw_syscall0(SYS_setsid) <= 0)
            raw_exit(1);
        if (getpass(NULL) != NULL || errno != FIXTURE_ENXIO)
            raw_exit(2);
        raw_exit(0);
    }
    return wait_for_zero_exit(child) == 0 ? 0 : 2;
}

static int child_getpass_session(struct pty_pair pair, int report_fd)
{
    static const char first_prompt[] = "password: ";
    static const char first_answer[] = "s3cr3t";
    static const char second_prompt[] = "long: ";
    struct kernel_termios_x86 before;
    struct kernel_termios_x86 after;
    char *first;
    char *second;
    int report = 1;
    size_t index;

    (void)raw_close(pair.master);
    if (raw_syscall0(SYS_setsid) <= 0) {
        report = 2;
        goto done;
    }
    if (raw_syscall3(SYS_ioctl, pair.slave, FIXTURE_TIOCSCTTY, 0) != 0) {
        report = 3;
        goto done;
    }
    if (raw_syscall3(SYS_ioctl, pair.slave, FIXTURE_TCGETS,
            (long)(uintptr_t)&before) != 0) {
        report = 4;
        goto done;
    }

    first = getpass(first_prompt);
    if (!c_string_equals(first, first_answer, sizeof(first_answer) - 1)) {
        report = 5;
        goto done;
    }
    if (raw_syscall3(SYS_ioctl, pair.slave, FIXTURE_TCGETS,
            (long)(uintptr_t)&after) != 0 ||
        !bytes_equal(&before, &after, sizeof(before))) {
        report = 6;
        goto done;
    }

    second = getpass(second_prompt);
    if (second != first) {
        report = 7;
        goto done;
    }
    for (index = 0; index < FIXTURE_PASSWORD_BYTES - 1; ++index) {
        if (second[index] != 'a') {
            report = 8;
            goto done;
        }
    }
    if (second[FIXTURE_PASSWORD_BYTES - 1] != '\0') {
        report = 9;
        goto done;
    }
    if (raw_syscall3(SYS_ioctl, pair.slave, FIXTURE_TCGETS,
            (long)(uintptr_t)&after) != 0 ||
        !bytes_equal(&before, &after, sizeof(before))) {
        report = 10;
        goto done;
    }
    report = 0;

done:
    (void)raw_write_all(report_fd, &report, sizeof(report));
    (void)raw_close(report_fd);
    (void)raw_close(pair.slave);
    return report;
}

static int read_until_contains(int fd, uint8_t *output, size_t capacity,
    const uint8_t *needle, size_t needle_length, size_t *output_length)
{
    size_t length = 0;

    while (length < capacity) {
        long result = raw_syscall3(SYS_read, fd,
            (long)(uintptr_t)(output + length), (long)(capacity - length));

        if (result > 0) {
            length += (size_t)result;
            if (bytes_contain(output, length, needle, needle_length)) {
                *output_length = length;
                return 0;
            }
            continue;
        }
        if (result == -FIXTURE_EINTR)
            continue;
        return -1;
    }
    return -1;
}

static int drain_master(int fd, uint8_t *output, size_t capacity,
    size_t *output_length)
{
    size_t length = 0;

    while (length < capacity) {
        long result = raw_syscall3(SYS_read, fd,
            (long)(uintptr_t)(output + length), (long)(capacity - length));

        if (result > 0) {
            length += (size_t)result;
            continue;
        }
        if (result == -FIXTURE_EINTR)
            continue;
        if (result == 0 || result == -FIXTURE_EIO) {
            *output_length = length;
            return 0;
        }
        return -1;
    }
    return -1;
}

static int check_interactive_tty(void)
{
    static const uint8_t first_prompt[] = "password: ";
    static const uint8_t first_answer[] = "s3cr3t\n";
    static const uint8_t second_prompt[] = "long: ";
    uint8_t long_answer[FIXTURE_PASSWORD_BYTES + 1];
    uint8_t middle[FIXTURE_CAPTURE_BYTES];
    uint8_t trailing[FIXTURE_CAPTURE_BYTES];
    struct pty_pair pair;
    int report_pipe[2] = { -1, -1 };
    int report = -1;
    long child;
    size_t middle_length;
    size_t trailing_length;
    size_t index;

    for (index = 0; index < FIXTURE_PASSWORD_BYTES; ++index)
        long_answer[index] = 'a';
    long_answer[FIXTURE_PASSWORD_BYTES] = '\n';

    if (open_pty_pair(&pair) != 0)
        return 1;
    if (raw_syscall2(SYS_pipe2, (long)(uintptr_t)report_pipe, O_CLOEXEC) != 0)
        goto failure_pair;
    child = raw_syscall0(SYS_fork);
    if (child < 0)
        goto failure_pipe;
    if (child == 0) {
        (void)raw_close(report_pipe[0]);
        raw_exit(child_getpass_session(pair, report_pipe[1]) == 0 ? 0 : 1);
    }

    (void)raw_close(pair.slave);
    pair.slave = -1;
    (void)raw_close(report_pipe[1]);
    report_pipe[1] = -1;
    if (raw_read_exact(pair.master, middle, sizeof(first_prompt) - 1) != 0 ||
        !bytes_equal(middle, first_prompt, sizeof(first_prompt) - 1))
        return 2;
    if (raw_write_all(pair.master, first_answer, sizeof(first_answer) - 1) != 0)
        return 3;
    if (read_until_contains(pair.master, middle, sizeof(middle), second_prompt,
            sizeof(second_prompt) - 1, &middle_length) != 0)
        return 4;
    if (bytes_contain(middle, middle_length, first_answer,
            sizeof(first_answer) - 1) || !bytes_have(middle, middle_length, '\n'))
        return 5;
    if (raw_write_all(pair.master, long_answer, sizeof(long_answer)) != 0)
        return 6;
    if (raw_read_exact(report_pipe[0], &report, sizeof(report)) != 0)
        return 7;
    if (report != 0)
        return 64 + report;
    if (wait_for_zero_exit(child) != 0)
        return 8;
    if (drain_master(pair.master, trailing, sizeof(trailing), &trailing_length) != 0)
        return 9;
    if (bytes_have(trailing, trailing_length, 'a') ||
        !bytes_have(trailing, trailing_length, '\n'))
        return 10;
    (void)raw_close(report_pipe[0]);
    (void)raw_close(pair.master);
    return 0;

failure_pipe:
    (void)raw_close(report_pipe[0]);
    (void)raw_close(report_pipe[1]);
failure_pair:
    if (pair.slave >= 0)
        (void)raw_close(pair.slave);
    (void)raw_close(pair.master);
    return 11;
}

int crabc_x86_64_getpass_probe(void)
{
    int no_tty = check_no_controlling_tty();
    int interactive;

    if (no_tty != 0)
        return no_tty;
    interactive = check_interactive_tty();
    return interactive == 0 ? 0 : 32 + interactive;
}

#ifndef CRABC_GETPASS_FREESTANDING
int main(void)
{
    return crabc_x86_64_getpass_probe();
}
#endif
