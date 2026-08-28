/* Static crabc-libc x86-64 termios-control fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects a closed C record/control boundary: baud and
 * raw-mode helpers, named termios ioctls, and window-size records. Fixture-
 * local raw syscalls create and observe an ephemeral PTY; they do not select
 * generic ioctl, descriptor-opening, PTY, session, or process-control APIs.
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

enum {
    KERNEL_NCCS = 19,
    KERNEL_TERMIOS_BYTES = 36,
    PUBLIC_TERMIOS_BYTES = 60,
    PUBLIC_TERMIOS_TAIL_BYTES = 24,
    FIXTURE_PAGE_BYTES = 4096,
    FIXTURE_PROT_NONE = 0,
    FIXTURE_PROT_READ = 1,
    FIXTURE_PROT_WRITE = 2,
    FIXTURE_MAP_PRIVATE = 2,
    FIXTURE_MAP_ANONYMOUS = 0x20,
    PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
};

/* Fixture-private Linux UAPI request words. The selected artifact exports
 * named termios functions, not a public ioctl request vocabulary. */
#define FIXTURE_TCGETS 0x5401UL
#define FIXTURE_TCSETS 0x5402UL
#define FIXTURE_TCSETSW 0x5403UL
#define FIXTURE_TCSETSF 0x5404UL
#define FIXTURE_TCSBRK 0x5409UL
#define FIXTURE_TCXONC 0x540aUL
#define FIXTURE_TCFLSH 0x540bUL
#define FIXTURE_TIOCGWINSZ 0x5413UL
#define FIXTURE_TIOCSWINSZ 0x5414UL
#define FIXTURE_TIOCSPTLCK 0x40045431UL
#define FIXTURE_TIOCGPTPEER 0x5441UL

struct kernel_termios_x86 {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[KERNEL_NCCS];
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_close == 3 && SYS_mmap == 9 && SYS_mprotect == 10 &&
    SYS_munmap == 11 && SYS_ioctl == 16 && SYS_openat == 257,
    "x86 fixture syscall numbers");
_Static_assert(PTY_FLAGS == (O_RDWR | O_NOCTTY | O_CLOEXEC),
    "x86 PTY flags");
_Static_assert(FIXTURE_TCGETS == 0x5401UL && FIXTURE_TCSETS == 0x5402UL &&
    FIXTURE_TCSETSW == 0x5403UL && FIXTURE_TCSETSF == 0x5404UL &&
    FIXTURE_TCSBRK == 0x5409UL && FIXTURE_TCXONC == 0x540aUL &&
    FIXTURE_TCFLSH == 0x540bUL && FIXTURE_TIOCGWINSZ == 0x5413UL &&
    FIXTURE_TIOCSWINSZ == 0x5414UL,
    "x86 selected terminal request words");
_Static_assert(FIXTURE_TIOCSPTLCK == 0x40045431UL &&
    FIXTURE_TIOCGPTPEER == 0x5441UL, "x86 PTY setup request words");
_Static_assert(NCCS == 32 && sizeof(struct termios) == PUBLIC_TERMIOS_BYTES &&
    _Alignof(struct termios) == 4, "x86 public termios layout");
_Static_assert(offsetof(struct termios, c_iflag) == 0 &&
    offsetof(struct termios, c_oflag) == 4 &&
    offsetof(struct termios, c_cflag) == 8 &&
    offsetof(struct termios, c_lflag) == 12 &&
    offsetof(struct termios, c_line) == 16 &&
    offsetof(struct termios, c_cc) == 17,
    "x86 public termios prefix");
_Static_assert(sizeof(struct kernel_termios_x86) == KERNEL_TERMIOS_BYTES &&
    _Alignof(struct kernel_termios_x86) == 4,
    "x86 kernel termios layout");
_Static_assert(offsetof(struct kernel_termios_x86, c_iflag) == 0 &&
    offsetof(struct kernel_termios_x86, c_oflag) == 4 &&
    offsetof(struct kernel_termios_x86, c_cflag) == 8 &&
    offsetof(struct kernel_termios_x86, c_lflag) == 12 &&
    offsetof(struct kernel_termios_x86, c_line) == 16 &&
    offsetof(struct kernel_termios_x86, c_cc) == 17,
    "x86 kernel termios prefix");
_Static_assert(sizeof(struct winsize) == 8 && _Alignof(struct winsize) == 2 &&
    offsetof(struct winsize, ws_row) == 0 &&
    offsetof(struct winsize, ws_col) == 2 &&
    offsetof(struct winsize, ws_xpixel) == 4 &&
    offsetof(struct winsize, ws_ypixel) == 6,
    "x86 winsize layout");
_Static_assert(CBAUD == 0x100f && CIBAUD == 0x100f0000 &&
    B0 == 0 && B9600 == 13 && B115200 == 0010002,
    "x86 baud selectors");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetispeed),
    speed_t (*)(const struct termios *)), "cfgetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfgetospeed),
    speed_t (*)(const struct termios *)), "cfgetospeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetispeed),
    int (*)(struct termios *, speed_t)), "cfsetispeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetospeed),
    int (*)(struct termios *, speed_t)), "cfsetospeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfsetspeed),
    int (*)(struct termios *, speed_t)), "cfsetspeed declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&cfmakeraw),
    void (*)(struct termios *)), "cfmakeraw declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetattr),
    int (*)(int, struct termios *)), "tcgetattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetattr),
    int (*)(int, int, const struct termios *)), "tcsetattr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcflush),
    int (*)(int, int)), "tcflush declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcflow),
    int (*)(int, int)), "tcflow declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsendbreak),
    int (*)(int, int)), "tcsendbreak declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetwinsize),
    int (*)(int, struct winsize *)), "tcgetwinsize declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetwinsize),
    int (*)(int, const struct winsize *)), "tcsetwinsize declaration");

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

static long raw_syscall6(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5, long argument6)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;
    register long register6 __asm__("r9") = argument6;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5), "r"(register6)
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

static long raw_ioctl_pointer(int fd, unsigned long request, const void *argument)
{
    return raw_syscall3(SYS_ioctl, fd, (long)request,
        (long)(uintptr_t)argument);
}

static long raw_ioctl_word(int fd, unsigned long request, unsigned long argument)
{
    return raw_syscall3(SYS_ioctl, fd, (long)request, (long)argument);
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

static unsigned char *raw_map_two_pages(void)
{
    long result = raw_syscall6(SYS_mmap, 0, FIXTURE_PAGE_BYTES * 2,
        FIXTURE_PROT_READ | FIXTURE_PROT_WRITE,
        FIXTURE_MAP_PRIVATE | FIXTURE_MAP_ANONYMOUS, -1, 0);

    return result < 0 && result >= -4095 ? 0 : (unsigned char *)(uintptr_t)result;
}

static int raw_protect(void *address, size_t length, int protection)
{
    return raw_syscall3(SYS_mprotect, (long)(uintptr_t)address, (long)length,
        protection) == 0 ? 0 : -1;
}

static int raw_unmap(void *address, size_t length)
{
    return raw_syscall3(SYS_munmap, (long)(uintptr_t)address, (long)length, 0) == 0
        ? 0
        : -1;
}

static void fill_bytes(void *destination, size_t length, unsigned char value)
{
    unsigned char *bytes = (unsigned char *)destination;

    for (size_t index = 0; index < length; index++)
        bytes[index] = value;
}

static void copy_bytes(void *destination, const void *source, size_t length)
{
    unsigned char *to = (unsigned char *)destination;
    const unsigned char *from = (const unsigned char *)source;

    for (size_t index = 0; index < length; index++)
        to[index] = from[index];
}

static int equal_bytes(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = (const unsigned char *)left;
    const unsigned char *right_bytes = (const unsigned char *)right;

    for (size_t index = 0; index < length; index++)
        if (left_bytes[index] != right_bytes[index])
            return 0;
    return 1;
}

static int bytes_have_value(const void *source, size_t length, unsigned char value)
{
    const unsigned char *bytes = (const unsigned char *)source;

    for (size_t index = 0; index < length; index++)
        if (bytes[index] != value)
            return 0;
    return 1;
}

static int equal_except_control_flags(const struct termios *left,
    const struct termios *right)
{
    return equal_bytes(left, right, offsetof(struct termios, c_cflag)) &&
        equal_bytes((const unsigned char *)left + 12,
            (const unsigned char *)right + 12, PUBLIC_TERMIOS_BYTES - 12);
}

static int public_tail_has_value(const struct termios *attributes,
    unsigned char value)
{
    return bytes_have_value((const unsigned char *)attributes + KERNEL_TERMIOS_BYTES,
        PUBLIC_TERMIOS_TAIL_BYTES, value);
}

static int raw_open_pty_pair(int *master_out, int *slave_out)
{
    int unlocked = 0;
    int master = raw_openat("/dev/ptmx", PTY_FLAGS);
    int slave;

    if (master < 0)
        return -1;
    if (raw_ioctl_pointer(master, FIXTURE_TIOCSPTLCK, &unlocked) != 0) {
        (void)raw_close(master);
        return -1;
    }
    slave = (int)raw_ioctl_word(master, FIXTURE_TIOCGPTPEER, PTY_FLAGS);
    if (slave < 0) {
        (void)raw_close(master);
        return -1;
    }
    *master_out = master;
    *slave_out = slave;
    return 0;
}

static int test_speed_helpers(void)
{
    const unsigned char poison = 0xa5;
    struct termios attributes;
    struct termios before;
    uint32_t expected_flags;

    fill_bytes(&attributes, sizeof attributes, poison);
    attributes.c_cflag = CBAUD | CIBAUD | 0x40000000U;
    if (cfgetospeed(&attributes) != CBAUD ||
        cfgetispeed(&attributes) != CBAUD)
        return 1;
    attributes.c_cflag = B9600;
    if (cfgetispeed(&attributes) != B0)
        return 2;

    fill_bytes(&attributes, sizeof attributes, poison);
    attributes.c_cflag = 0x40000000U | CIBAUD | B38400;
    copy_bytes(&before, &attributes, sizeof attributes);
    expected_flags = (attributes.c_cflag & ~CBAUD) | B9600;
    errno = EDOM;
    if (cfsetospeed(&attributes, B9600) != 0 || errno != EDOM ||
        attributes.c_cflag != expected_flags ||
        !equal_except_control_flags(&attributes, &before))
        return 3;

    copy_bytes(&before, &attributes, sizeof attributes);
    expected_flags = (attributes.c_cflag & ~CIBAUD) |
        ((uint32_t)B115200 << 16);
    errno = EDOM;
    if (cfsetispeed(&attributes, B115200) != 0 || errno != EDOM ||
        attributes.c_cflag != expected_flags ||
        !equal_except_control_flags(&attributes, &before))
        return 4;

    fill_bytes(&attributes, sizeof attributes, poison);
    attributes.c_cflag = CIBAUD | B38400;
    errno = EDOM;
    if (cfsetspeed(&attributes, B9600) != 0 || errno != EDOM ||
        cfgetospeed(&attributes) != B9600 || cfgetispeed(&attributes) != B0 ||
        !public_tail_has_value(&attributes, poison))
        return 5;

    copy_bytes(&before, &attributes, sizeof attributes);
    errno = 0;
    if (cfsetospeed(&attributes, (speed_t)~0U) != -1 || errno != EINVAL ||
        !equal_bytes(&attributes, &before, sizeof attributes))
        return 6;
    errno = 0;
    if (cfsetispeed(&attributes, (speed_t)~0U) != -1 || errno != EINVAL ||
        !equal_bytes(&attributes, &before, sizeof attributes))
        return 7;
    errno = 0;
    if (cfsetspeed(&attributes, (speed_t)~0U) != -1 || errno != EINVAL ||
        !equal_bytes(&attributes, &before, sizeof attributes))
        return 8;
    errno = 0;
    if (cfsetospeed(0, (speed_t)~0U) != -1 || errno != EINVAL)
        return 9;
    errno = 0;
    if (cfsetispeed(0, (speed_t)~0U) != -1 || errno != EINVAL)
        return 10;
    errno = 0;
    if (cfsetspeed(0, (speed_t)~0U) != -1 || errno != EINVAL)
        return 11;

    fill_bytes(&attributes, sizeof attributes, poison);
    attributes.c_iflag = 0xffffffffU;
    attributes.c_oflag = 0xffffffffU;
    attributes.c_cflag = 0xffffffffU;
    attributes.c_lflag = 0xffffffffU;
    copy_bytes(&before, &attributes, sizeof attributes);
    errno = EDOM;
    cfmakeraw(&attributes);
    if (errno != EDOM ||
        attributes.c_iflag != (before.c_iflag &
            ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON)) ||
        attributes.c_oflag != (before.c_oflag & ~OPOST) ||
        attributes.c_lflag != (before.c_lflag &
            ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN)) ||
        attributes.c_cflag != ((before.c_cflag & ~(CSIZE | PARENB)) | CS8) ||
        attributes.c_cc[VMIN] != 1 || attributes.c_cc[VTIME] != 0 ||
        !public_tail_has_value(&attributes, poison))
        return 12;
    for (size_t index = 0; index < NCCS; index++) {
        if (index != VMIN && index != VTIME &&
            attributes.c_cc[index] != before.c_cc[index])
            return 13;
    }
    return 0;
}

static int test_non_terminal_errors(void)
{
    struct termios attributes;
    struct winsize size;
    int fd = raw_openat("/dev/null", O_RDWR | O_CLOEXEC);
    int result = 0;

    if (fd < 0)
        return 1;
    fill_bytes(&attributes, sizeof attributes, 0xa5);
    fill_bytes(&size, sizeof size, 0xa5);
    errno = 0;
    if (tcgetattr(fd, &attributes) != -1 || errno != ENOTTY)
        result = 2;
    errno = 0;
    if (result == 0 && tcsetattr(fd, TCSANOW, &attributes) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 3;
    errno = 0;
    if (result == 0 && tcflush(fd, TCIFLUSH) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 4;
    errno = 0;
    if (result == 0 && tcflow(fd, TCOON) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 5;
    errno = 0;
    if (result == 0 && tcsendbreak(fd, 1) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 6;
    errno = 0;
    if (result == 0 && tcgetwinsize(fd, &size) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 7;
    errno = 0;
    if (result == 0 && tcsetwinsize(fd, &size) != -1 ||
        (result == 0 && errno != ENOTTY))
        result = 8;
    if (raw_close(fd) != 0 && result == 0)
        result = 9;
    return result;
}

/* This pointer ends exactly at a readable page boundary. Pinned musl passes
 * it straight to TCSETS, whose Linux x86 input is the 36-byte prefix. A
 * future local 60-byte public-record copy would fault into the protected tail
 * instead of preserving that direct kernel boundary. */
static int test_tcsetattr_prefix_boundary(int fd,
    const struct kernel_termios_x86 *saved_attributes)
{
    unsigned char *mapping = raw_map_two_pages();
    unsigned char *prefix;
    struct kernel_termios_x86 observed;
    int result = 0;

    if (mapping == 0)
        return 1;
    prefix = mapping + FIXTURE_PAGE_BYTES - KERNEL_TERMIOS_BYTES;
    copy_bytes(prefix, saved_attributes, KERNEL_TERMIOS_BYTES);
    if (raw_protect(mapping + FIXTURE_PAGE_BYTES, FIXTURE_PAGE_BYTES,
        FIXTURE_PROT_NONE) != 0) {
        result = 2;
        goto cleanup;
    }
    errno = EDOM;
    if (tcsetattr(fd, TCSANOW, (const struct termios *)(const void *)prefix) != 0 ||
        errno != EDOM ||
        raw_ioctl_pointer(fd, FIXTURE_TCGETS, &observed) != 0 ||
        !equal_bytes(&observed, saved_attributes, sizeof observed))
        result = 3;

cleanup:
    if (raw_unmap(mapping, FIXTURE_PAGE_BYTES * 2) != 0 && result == 0)
        result = 4;
    return result;
}

static int test_termios_control(void)
{
    const unsigned char tail_poison = 0x5a;
    struct kernel_termios_x86 saved_attributes;
    struct kernel_termios_x86 observed_attributes;
    struct kernel_termios_x86 expected_attributes;
    struct winsize saved_size;
    struct winsize observed_size;
    struct winsize changed_size;
    struct termios public_attributes;
    struct termios changed_attributes;
    int master = -1;
    int slave = -1;
    int attributes_saved = 0;
    int size_saved = 0;
    int result = 0;

    if (raw_open_pty_pair(&master, &slave) != 0)
        return 1;
    if (raw_ioctl_pointer(slave, FIXTURE_TCGETS, &saved_attributes) != 0) {
        result = 2;
        goto cleanup;
    }
    attributes_saved = 1;
    if (raw_ioctl_pointer(slave, FIXTURE_TIOCGWINSZ, &saved_size) != 0) {
        result = 3;
        goto cleanup;
    }
    size_saved = 1;

    fill_bytes(&public_attributes, sizeof public_attributes, tail_poison);
    errno = EDOM;
    if (tcgetattr(slave, &public_attributes) != 0 || errno != EDOM ||
        !equal_bytes(&public_attributes, &saved_attributes,
            KERNEL_TERMIOS_BYTES) ||
        !public_tail_has_value(&public_attributes, tail_poison)) {
        result = 4;
        goto cleanup;
    }
    errno = 0;
    if (tcgetattr(slave, 0) != -1 || errno != EFAULT) {
        result = 5;
        goto cleanup;
    }
    if (test_tcsetattr_prefix_boundary(slave, &saved_attributes) != 0) {
        result = 6;
        goto cleanup;
    }

    for (int action = TCSANOW; action <= TCSAFLUSH; action++) {
        copy_bytes(&changed_attributes, &public_attributes,
            sizeof changed_attributes);
        changed_attributes.c_cc[VINTR] =
            (unsigned char)(public_attributes.c_cc[VINTR] ^ (action + 1));
        changed_attributes.c_cc[VEOL] =
            (unsigned char)(public_attributes.c_cc[VEOL] ^ (action + 5));
        copy_bytes(&expected_attributes, &changed_attributes,
            sizeof expected_attributes);
        errno = EDOM;
        if (tcsetattr(slave, action, &changed_attributes) != 0 || errno != EDOM ||
            raw_ioctl_pointer(slave, FIXTURE_TCGETS, &observed_attributes) != 0 ||
            !equal_bytes(&observed_attributes, &expected_attributes,
                sizeof observed_attributes) ||
            !public_tail_has_value(&changed_attributes, tail_poison) ||
            raw_ioctl_pointer(slave, FIXTURE_TCSETS, &saved_attributes) != 0) {
            result = 10 + action;
            goto cleanup;
        }
    }
    errno = 0;
    if (tcsetattr(-1, -1, 0) != -1 || errno != EINVAL) {
        result = 14;
        goto cleanup;
    }
    errno = 0;
    if (tcsetattr(slave, 3, 0) != -1 || errno != EINVAL) {
        result = 15;
        goto cleanup;
    }
    errno = 0;
    if (tcsetattr(slave, TCSANOW, 0) != -1 || errno != EFAULT ||
        raw_ioctl_pointer(slave, FIXTURE_TCGETS, &observed_attributes) != 0 ||
        !equal_bytes(&observed_attributes, &saved_attributes,
            sizeof observed_attributes)) {
        result = 16;
        goto cleanup;
    }

    for (int queue = TCIFLUSH; queue <= TCIOFLUSH; queue++) {
        errno = EDOM;
        if (tcflush(master, queue) != 0 || errno != EDOM) {
            result = 20 + queue;
            goto cleanup;
        }
    }
    errno = 0;
    if (tcflush(master, -1) != -1 || errno != EINVAL) {
        result = 23;
        goto cleanup;
    }

    errno = EDOM;
    if (tcflow(master, TCOOFF) != 0 || errno != EDOM ||
        tcflow(master, TCOON) != 0 || errno != EDOM ||
        tcflow(master, TCIOFF) != 0 || errno != EDOM ||
        tcflow(master, TCION) != 0 || errno != EDOM) {
        result = 24;
        goto cleanup;
    }
    errno = 0;
    if (tcflow(master, 4) != -1 || errno != EINVAL) {
        result = 25;
        goto cleanup;
    }
    errno = EDOM;
    if (tcsendbreak(master, 0) != 0 || errno != EDOM ||
        tcsendbreak(master, 1) != 0 || errno != EDOM) {
        result = 26;
        goto cleanup;
    }

    fill_bytes(&changed_size, sizeof changed_size, tail_poison);
    errno = EDOM;
    if (tcgetwinsize(slave, &changed_size) != 0 || errno != EDOM ||
        !equal_bytes(&changed_size, &saved_size, sizeof changed_size)) {
        result = 30;
        goto cleanup;
    }
    errno = 0;
    if (tcgetwinsize(slave, 0) != -1 || errno != EFAULT) {
        result = 31;
        goto cleanup;
    }
    changed_size.ws_row = saved_size.ws_row == UINT16_MAX ? 0 :
        (uint16_t)(saved_size.ws_row + 1U);
    changed_size.ws_col = saved_size.ws_col == UINT16_MAX ? 0 :
        (uint16_t)(saved_size.ws_col + 1U);
    changed_size.ws_xpixel = saved_size.ws_xpixel == UINT16_MAX ? 0 :
        (uint16_t)(saved_size.ws_xpixel + 1U);
    changed_size.ws_ypixel = saved_size.ws_ypixel == UINT16_MAX ? 0 :
        (uint16_t)(saved_size.ws_ypixel + 1U);
    errno = EDOM;
    if (tcsetwinsize(slave, &changed_size) != 0 || errno != EDOM ||
        raw_ioctl_pointer(slave, FIXTURE_TIOCGWINSZ, &observed_size) != 0 ||
        !equal_bytes(&observed_size, &changed_size, sizeof observed_size)) {
        result = 32;
        goto cleanup;
    }
    errno = 0;
    if (tcsetwinsize(slave, 0) != -1 || errno != EFAULT) {
        result = 33;
        goto cleanup;
    }

cleanup:
    if (size_saved)
        (void)raw_ioctl_pointer(slave, FIXTURE_TIOCSWINSZ, &saved_size);
    if (attributes_saved)
        (void)raw_ioctl_pointer(slave, FIXTURE_TCSETS, &saved_attributes);
    if (slave >= 0 && raw_close(slave) != 0 && result == 0)
        result = 40;
    if (master >= 0 && raw_close(master) != 0 && result == 0)
        result = 41;
    return result;
}

int crabc_x86_64_termios_control_probe(void)
{
    int result = test_speed_helpers();

    if (result != 0)
        return result;
    result = test_non_terminal_errors();
    if (result != 0)
        return 100 + result;
    result = test_termios_control();
    return result == 0 ? 0 : 200 + result;
}

#ifndef CRABC_TERMIOS_CONTROL_FREESTANDING
int main(void)
{
    return crabc_x86_64_termios_control_probe();
}
#endif
