/*
 * Pinned-musl/raw Linux/x86-64 terminal reference.
 *
 * This fixture is oracle evidence for the private Rust terminal facade. It
 * intentionally compares raw Linux ioctl/syscall paths with pinned musl
 * wrappers; it does not select a candidate C terminal ABI, errno/TLS model,
 * generic ioctl facade, or public x86-64 runtime support.
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

enum terminal_arm {
    RAW_SYSCALL_ARM,
    MUSL_WRAPPER_ARM,
};

enum {
    PTY_FLAGS = O_RDWR | O_NOCTTY | O_CLOEXEC,
    KERNEL_NCCS = 19,
    KERNEL_IBSHIFT = 16,
};

/* Linux x86-64's TCGETS wire record is deliberately not musl's public
   struct termios. The private Rust record follows this 36-byte UAPI shape. */
struct kernel_termios_x86 {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[KERNEL_NCCS];
};

_Static_assert(sizeof(int) == 4 && sizeof(unsigned int) == 4 &&
                   sizeof(long) == 8 && sizeof(size_t) == 8 &&
                   sizeof(void *) == 8,
               "x86 little-endian LP64 scalar widths");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
                   SYS_ioctl == 16 && SYS_getpid == 39 && SYS_fork == 57 &&
                   SYS_wait4 == 61 && SYS_setsid == 112 && SYS_openat == 257 &&
                   SYS_readlinkat == 267,
               "x86 terminal syscall numbers");
_Static_assert(O_RDWR == 0x2 && O_NOCTTY == 0x100 && O_CLOEXEC == 0x80000,
               "x86 terminal open flags");
_Static_assert(TCGETS == 0x5401UL && TCSETS == 0x5402UL &&
                   TCSETSW == 0x5403UL && TCSETSF == 0x5404UL &&
                   TCSBRK == 0x5409UL && TCXONC == 0x540aUL &&
                   TCFLSH == 0x540bUL && TIOCEXCL == 0x540cUL &&
                   TIOCNXCL == 0x540dUL && TIOCSCTTY == 0x540eUL &&
                   TIOCGPGRP == 0x540fUL && TIOCSPGRP == 0x5410UL &&
                   TIOCGWINSZ == 0x5413UL && TIOCSWINSZ == 0x5414UL &&
                   TIOCGSID == 0x5429UL,
               "x86 terminal ioctl request values");
_Static_assert(TIOCGPTN == 0x80045430UL && TIOCSPTLCK == 0x40045431UL &&
                   TIOCGPTPEER == 0x5441UL,
               "x86 devpts ioctl request values");
_Static_assert(CBAUD == 0x100fUL && CIBAUD == 0x100f0000UL &&
                   B9600 == 13,
               "x86 termios baud selectors");
_Static_assert(NCCS == 32 && sizeof(struct termios) == 60 &&
                   _Alignof(struct termios) == 4,
               "pinned musl x86 public termios ABI remains distinct");
_Static_assert(sizeof(struct kernel_termios_x86) == 36 &&
                   _Alignof(struct kernel_termios_x86) == 4 &&
                   offsetof(struct kernel_termios_x86, c_iflag) == 0 &&
                   offsetof(struct kernel_termios_x86, c_oflag) == 4 &&
                   offsetof(struct kernel_termios_x86, c_cflag) == 8 &&
                   offsetof(struct kernel_termios_x86, c_lflag) == 12 &&
                   offsetof(struct kernel_termios_x86, c_line) == 16 &&
                   offsetof(struct kernel_termios_x86, c_cc) == 17,
               "x86 TCGETS legacy kernel record ABI");
_Static_assert(sizeof(struct winsize) == 8 && _Alignof(struct winsize) == 2,
               "x86 winsize ABI");

#define CHECK(condition) \
    do { \
        if (!(condition)) \
            return __LINE__; \
    } while (0)

static int raw_openpt(void)
{
    return (int)syscall(SYS_openat, AT_FDCWD, "/dev/ptmx", PTY_FLAGS, 0);
}

static int raw_ioctl_pointer(int fd, unsigned long request, void *argument)
{
    return (int)syscall(SYS_ioctl, fd, request, argument);
}

static int raw_ioctl_word(int fd, unsigned long request, unsigned long argument)
{
    return (int)syscall(SYS_ioctl, fd, request, argument);
}

static int openpt_for_arm(enum terminal_arm arm)
{
    return arm == RAW_SYSCALL_ARM ? raw_openpt() : posix_openpt(PTY_FLAGS);
}

static int ioctl_pointer_for_arm(enum terminal_arm arm, int fd,
                                 unsigned long request, void *argument)
{
    return arm == RAW_SYSCALL_ARM ? raw_ioctl_pointer(fd, request, argument)
                                  : ioctl(fd, request, argument);
}

static int ioctl_word_for_arm(enum terminal_arm arm, int fd,
                              unsigned long request, unsigned long argument)
{
    return arm == RAW_SYSCALL_ARM ? raw_ioctl_word(fd, request, argument)
                                  : ioctl(fd, request, argument);
}

static int close_for_arm(enum terminal_arm arm, int fd)
{
    return arm == RAW_SYSCALL_ARM ? (int)syscall(SYS_close, fd) : close(fd);
}

static int make_pair(enum terminal_arm arm, int *master_out, int *slave_out)
{
    unsigned int number = 0;
    int unlocked = 0;
    int master = openpt_for_arm(arm);
    int slave;

    if (master < 0)
        return 1;
    if (arm == MUSL_WRAPPER_ARM) {
        if (grantpt(master) != 0 || unlockpt(master) != 0) {
            close_for_arm(arm, master);
            return 2;
        }
    } else {
        if (raw_ioctl_pointer(master, TIOCGPTN, &number) != 0 ||
            raw_ioctl_pointer(master, TIOCSPTLCK, &unlocked) != 0) {
            close_for_arm(arm, master);
            return 3;
        }
    }
    if (ioctl_pointer_for_arm(arm, master, TIOCGPTN, &number) != 0 ||
        number > INT32_MAX) {
        close_for_arm(arm, master);
        return 4;
    }
    slave = ioctl_word_for_arm(arm, master, TIOCGPTPEER, PTY_FLAGS);
    if (slave < 0) {
        close_for_arm(arm, master);
        return 5;
    }
    *master_out = master;
    *slave_out = slave;
    return 0;
}

static int copy_public_to_kernel(const struct termios *source,
                                 struct kernel_termios_x86 *destination)
{
    destination->c_iflag = source->c_iflag;
    destination->c_oflag = source->c_oflag;
    destination->c_cflag = source->c_cflag;
    destination->c_lflag = source->c_lflag;
    destination->c_line = source->c_line;
    memcpy(destination->c_cc, source->c_cc, KERNEL_NCCS);
    return 0;
}

static void make_kernel_raw(struct kernel_termios_x86 *attributes)
{
    attributes->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
                             IGNCR | ICRNL | IXON);
    attributes->c_oflag &= ~OPOST;
    attributes->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    attributes->c_cflag = (attributes->c_cflag & ~(CSIZE | PARENB)) | CS8;
    attributes->c_cc[VMIN] = 1;
    attributes->c_cc[VTIME] = 0;
}

static int compare_kernel_and_public(int fd)
{
    struct kernel_termios_x86 raw = {0};
    struct kernel_termios_x86 converted = {0};
    struct termios public = {0};

    if (raw_ioctl_pointer(fd, TCGETS, &raw) != 0 || tcgetattr(fd, &public) != 0)
        return 0;
    copy_public_to_kernel(&public, &converted);
    return memcmp(&raw, &converted, sizeof(raw)) == 0;
}

static int get_kernel_for_arm(enum terminal_arm arm, int fd,
                              struct kernel_termios_x86 *out)
{
    if (arm == RAW_SYSCALL_ARM)
        return raw_ioctl_pointer(fd, TCGETS, out);

    struct termios public = {0};
    if (tcgetattr(fd, &public) != 0)
        return -1;
    return copy_public_to_kernel(&public, out);
}

static int set_kernel_for_arm(enum terminal_arm arm, int fd, int action,
                              const struct kernel_termios_x86 *value)
{
    if (arm == RAW_SYSCALL_ARM) {
        struct kernel_termios_x86 mutable_value = *value;
        return raw_ioctl_pointer(fd, TCSETS + (unsigned long)action, &mutable_value);
    }

    struct termios public = {0};
    if (tcgetattr(fd, &public) != 0)
        return -1;
    public.c_iflag = value->c_iflag;
    public.c_oflag = value->c_oflag;
    public.c_cflag = value->c_cflag;
    public.c_lflag = value->c_lflag;
    public.c_line = value->c_line;
    memcpy(public.c_cc, value->c_cc, KERNEL_NCCS);
    return tcsetattr(fd,
                     action == 0 ? TCSANOW : action == 1 ? TCSADRAIN : TCSAFLUSH,
                     &public);
}

static int raw_mode_for_arm(enum terminal_arm arm, int fd,
                            const struct kernel_termios_x86 *original,
                            struct kernel_termios_x86 *raw_mode)
{
    if (arm == RAW_SYSCALL_ARM) {
        *raw_mode = *original;
        make_kernel_raw(raw_mode);
        return 0;
    }

    struct termios public = {0};
    if (tcgetattr(fd, &public) != 0)
        return -1;
    cfmakeraw(&public);
    return copy_public_to_kernel(&public, raw_mode);
}

static int check_termios_and_queue(enum terminal_arm arm, int master, int slave)
{
    struct kernel_termios_x86 original = {0};
    struct kernel_termios_x86 changed = {0};
    struct kernel_termios_x86 observed = {0};
    struct kernel_termios_x86 raw_mode = {0};
    struct winsize original_size = {0};
    struct winsize changed_size = {0};
    struct winsize observed_size = {0};
    int queue;
    int flow;

    CHECK(compare_kernel_and_public(slave));
    CHECK(get_kernel_for_arm(arm, slave, &original) == 0);
    CHECK(raw_mode_for_arm(arm, slave, &original, &raw_mode) == 0);
    CHECK(set_kernel_for_arm(arm, slave, 0, &raw_mode) == 0);
    CHECK(get_kernel_for_arm(arm, slave, &observed) == 0);
    CHECK(memcmp(&raw_mode, &observed, sizeof(raw_mode)) == 0);
    CHECK(observed.c_cc[VMIN] == 1 && observed.c_cc[VTIME] == 0);
    CHECK(set_kernel_for_arm(arm, slave, 0, &original) == 0);

    changed = original;
    changed.c_cc[VINTR] = '/';
    changed.c_cc[VEOL] = 'c';
    changed.c_cflag = (changed.c_cflag & ~(CBAUD | CIBAUD)) |
                      B9600 | ((unsigned long)B9600 << KERNEL_IBSHIFT);
    CHECK(set_kernel_for_arm(arm, slave, 0, &changed) == 0);
    CHECK(get_kernel_for_arm(arm, slave, &observed) == 0);
    CHECK(observed.c_cc[VINTR] == '/' && observed.c_cc[VEOL] == 'c');
    CHECK((observed.c_cflag & CBAUD) == B9600);
    CHECK((observed.c_cflag & CIBAUD) == ((unsigned long)B9600 << KERNEL_IBSHIFT));
    changed.c_cflag &= ~CIBAUD;
    CHECK(set_kernel_for_arm(arm, slave, 0, &changed) == 0);
    CHECK(get_kernel_for_arm(arm, slave, &observed) == 0);
    CHECK((observed.c_cflag & CBAUD) == B9600);
    CHECK((observed.c_cflag & CIBAUD) == B0);
    CHECK(set_kernel_for_arm(arm, slave, 0, &original) == 0);
    CHECK(set_kernel_for_arm(arm, slave, 1, &original) == 0);
    CHECK(set_kernel_for_arm(arm, slave, 2, &original) == 0);

    for (queue = 0; queue <= 2; queue++) {
        if (arm == RAW_SYSCALL_ARM)
            CHECK(raw_ioctl_word(master, TCFLSH, (unsigned long)queue) == 0);
        else
            CHECK(tcflush(master, queue) == 0);
    }
    if (arm == RAW_SYSCALL_ARM) {
        CHECK(raw_ioctl_word(master, TCSBRK, 1) == 0);
        CHECK(raw_ioctl_word(master, TCSBRK, 0) == 0);
    } else {
        CHECK(tcdrain(master) == 0);
        CHECK(tcsendbreak(master, 0) == 0);
    }
    for (flow = 0; flow <= 3; flow++) {
        if (arm == RAW_SYSCALL_ARM)
            CHECK(raw_ioctl_word(master, TCXONC, (unsigned long)flow) == 0);
        else
            CHECK(tcflow(master, flow) == 0);
    }

    CHECK(ioctl_pointer_for_arm(arm, slave, TIOCGWINSZ, &original_size) == 0);
    changed_size = original_size;
    changed_size.ws_row = (uint16_t)(changed_size.ws_row + 1U);
    changed_size.ws_col = (uint16_t)(changed_size.ws_col + 1U);
    CHECK(ioctl_pointer_for_arm(arm, slave, TIOCSWINSZ, &changed_size) == 0);
    CHECK(ioctl_pointer_for_arm(arm, slave, TIOCGWINSZ, &observed_size) == 0);
    CHECK(memcmp(&changed_size, &observed_size, sizeof(changed_size)) == 0);
    CHECK(ioctl_pointer_for_arm(arm, slave, TIOCSWINSZ, &original_size) == 0);
    return 0;
}

static int check_tty_name_and_exclusive(enum terminal_arm arm, int master, int slave)
{
    char name[128];
    char proc_path[64];
    char raw_name[128];
    struct stat fd_stat;
    struct stat path_stat;
    ssize_t raw_length;
    int reopened;

    CHECK(isatty(slave) == 1);
    CHECK(ttyname_r(slave, name, sizeof(name)) == 0);
    CHECK(strncmp(name, "/dev/pts/", 9) == 0);
    CHECK(fstat(slave, &fd_stat) == 0 && stat(name, &path_stat) == 0);
    CHECK(fd_stat.st_dev == path_stat.st_dev && fd_stat.st_ino == path_stat.st_ino);
    CHECK(snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", slave) > 0);
    raw_length = syscall(SYS_readlinkat, AT_FDCWD, proc_path, raw_name,
                         sizeof(raw_name) - 1);
    CHECK(raw_length > 0 && raw_length < (ssize_t)sizeof(raw_name));
    raw_name[raw_length] = '\0';
    CHECK(strcmp(raw_name, name) == 0);

    CHECK(ioctl_word_for_arm(arm, slave, TIOCEXCL, 0) == 0);
    reopened = open(name, PTY_FLAGS);
    CHECK(reopened < 0 ? errno == EBUSY : close(reopened) == 0);
    CHECK(ioctl_word_for_arm(arm, slave, TIOCNXCL, 0) == 0);
    reopened = open(name, PTY_FLAGS);
    CHECK(reopened >= 0 && close(reopened) == 0);
    (void)master;
    return 0;
}

static int terminal_session_child(enum terminal_arm arm, int slave)
{
    pid_t pid;
    int session = 0;
    int foreground = 0;

    if (arm == RAW_SYSCALL_ARM) {
        if (syscall(SYS_setsid) < 0)
            return 1;
        pid = (pid_t)syscall(SYS_getpid);
    } else {
        if (setsid() < 0)
            return 2;
        pid = getpid();
    }
    if (pid <= 0 || ioctl_word_for_arm(arm, slave, TIOCSCTTY, 0) != 0)
        return 3;
    if (ioctl_pointer_for_arm(arm, slave, TIOCGSID, &session) != 0 ||
        ioctl_pointer_for_arm(arm, slave, TIOCGPGRP, &foreground) != 0 ||
        session != pid || foreground != pid)
        return 4;
    if (ioctl_pointer_for_arm(arm, slave, TIOCSPGRP, &pid) != 0 ||
        ioctl_pointer_for_arm(arm, slave, TIOCGPGRP, &foreground) != 0 ||
        foreground != pid)
        return 5;
    return 0;
}

static int check_session(enum terminal_arm arm, int slave)
{
    pid_t child = arm == RAW_SYSCALL_ARM ? (pid_t)syscall(SYS_fork) : fork();
    int status = 0;
    pid_t reaped;

    if (child < 0)
        return 1;
    if (child == 0)
        _exit(terminal_session_child(arm, slave));
    reaped = arm == RAW_SYSCALL_ARM
                 ? (pid_t)syscall(SYS_wait4, child, &status, 0, NULL)
                 : waitpid(child, &status, 0);
    return reaped == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 2;
}

static int check_non_terminal_errors(void)
{
    struct kernel_termios_x86 attributes = {0};
    struct termios public_attributes = {0};
    struct winsize size = {0};
    int fd = raw_openpt();
    int null_fd;

    if (fd < 0)
        return 1;
    if (close(fd) != 0)
        return 2;
    null_fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (null_fd < 0)
        return 3;
    errno = 0;
    if (raw_ioctl_pointer(null_fd, TCGETS, &attributes) != -1 || errno != ENOTTY)
        return 4;
    errno = 0;
    if (tcgetattr(null_fd, &public_attributes) != -1 || errno != ENOTTY)
        return 5;
    errno = 0;
    if (raw_ioctl_pointer(null_fd, TIOCGWINSZ, &size) != -1 || errno != ENOTTY)
        return 6;
    errno = 0;
    if (tcdrain(null_fd) != -1 || errno != ENOTTY)
        return 7;
    errno = 0;
    if (ioctl(null_fd, TIOCEXCL) != -1 || errno != ENOTTY)
        return 8;
    return close(null_fd) == 0 ? 0 : 9;
}

static int run_terminal_arm(enum terminal_arm arm)
{
    int master = -1;
    int slave = -1;
    int result = make_pair(arm, &master, &slave);

    if (result != 0)
        return 10 + result;
    result = check_termios_and_queue(arm, master, slave);
    if (result == 0)
        result = check_tty_name_and_exclusive(arm, master, slave);
    if (result == 0)
        result = check_session(arm, slave);
    if (close_for_arm(arm, slave) != 0 && result == 0)
        result = 80;
    if (close_for_arm(arm, master) != 0 && result == 0)
        result = 81;
    return result;
}

int main(void)
{
    int status;

    status = check_non_terminal_errors();
    if (status != 0) {
        fprintf(stderr, "non-terminal terminal ioctl check failed: %d\n", status);
        return 1;
    }
    status = run_terminal_arm(RAW_SYSCALL_ARM);
    if (status != 0) {
        fprintf(stderr, "raw terminal arm failed: %d\n", status);
        return 2;
    }
    status = run_terminal_arm(MUSL_WRAPPER_ARM);
    if (status != 0) {
        fprintf(stderr, "pinned-musl terminal arm failed: %d\n", status);
        return 3;
    }

    puts("syscalls=ioctl:16,setsid:112,fork:57,wait4:61,openat:257,readlinkat:267 kernel-termios=36/4@0,4,8,12,16,17 musl-termios=60/4,nccs=32 winsize=8/2 ioctls=TCGETS-SETSF,TCSBRK,TCXONC,TCFLSH,TIOCEXCL,TIOCNXCL,TIOCSCTTY,TIOC{G,S}PGRP,TIOCGSID,TIOC{G,S}WINSZ raw+musl=pty-rawmode-termios-queue-exclusive-ttyname-session nonpty=ENOTTY c-api-selection=excluded");
    return 0;
}
