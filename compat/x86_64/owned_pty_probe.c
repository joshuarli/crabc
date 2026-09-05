#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utmp.h>

#define CHECK(c) do { if (!(c)) { dprintf(2, "owned pty line %d errno %d\n", __LINE__, errno); _exit(77); } } while (0)

static int descriptor_count(void) {
    int saved = errno, count = 0;
    for (int fd = 0; fd < 128; fd++) if (fcntl(fd, F_GETFD) >= 0) count++;
    errno = saved;
    return count;
}
static void require_cancel_state(int expected) {
    int previous = -1;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    CHECK(previous == expected);
    CHECK(pthread_setcancelstate(previous, 0) == 0);
}
/* Fixed Linux 5.10 filter/program ABI belongs only to this failure fixture;
   installed consumers do not acquire a dependency on kernel policy headers. */
struct pty_filter { unsigned short code; unsigned char yes, no; unsigned value; };
struct pty_program { unsigned short count; struct pty_filter *instructions; };
_Static_assert(sizeof(struct pty_filter) == 8 && offsetof(struct pty_program, instructions) == 8, "Linux filter ABI");
#define FILTER_LOAD(offset) {0x20, 0, 0, offset}
#define FILTER_EQUAL(value, yes, no) {0x15, yes, no, value}
#define FILTER_RETURN(value) {0x06, 0, 0, value}
static void install_filter(struct pty_filter *instructions, unsigned count) {
    struct pty_program program = { (unsigned short)count, instructions };
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &program) == 0);
}
static void deny_syscall(int number, int error) {
    struct pty_filter instructions[] = {
        FILTER_LOAD(0),
        FILTER_EQUAL(number, 0, 1),
        FILTER_RETURN(0x00050000 | error),
        FILTER_RETURN(0x7fff0000),
    };
    install_filter(instructions, sizeof instructions / sizeof *instructions);
}
static void deny_argument(int number, unsigned argument, unsigned value, int error) {
    struct pty_filter instructions[] = {
        FILTER_LOAD(0),
        FILTER_EQUAL(number, 0, 3),
        FILTER_LOAD(16 + 8 * argument),
        FILTER_EQUAL(value, 0, 1),
        FILTER_RETURN(0x00050000 | error),
        FILTER_RETURN(0x7fff0000),
    };
    install_filter(instructions, sizeof instructions / sizeof *instructions);
}
static void deny_open_path(char *path) {
    uintptr_t address = (uintptr_t)path;
    struct pty_filter instructions[] = {
        FILTER_LOAD(0),
        FILTER_EQUAL(SYS_open, 0, 5),
        FILTER_LOAD(16),
        FILTER_EQUAL((unsigned)address, 0, 3),
        FILTER_LOAD(16 + 4),
        FILTER_EQUAL((unsigned)(address >> 32), 0, 1),
        FILTER_RETURN(0x00050000 | EACCES),
        FILTER_RETURN(0x7fff0000),
    };
    install_filter(instructions, sizeof instructions / sizeof *instructions);
}
static void require_child(pid_t child, int code) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == code);
}
static void raw_terminal(int fd, struct termios *settings) {
    CHECK(tcgetattr(fd, settings) == 0);
    cfmakeraw(settings);
    CHECK(tcsetattr(fd, TCSANOW, settings) == 0);
}
static int same_descriptor(int a, int b) {
    struct stat first, second;
    CHECK(fstat(a, &first) == 0 && fstat(b, &second) == 0);
    return first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}
static void naming_case(void) {
    int baseline = descriptor_count();
    int m = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
    CHECK(m >= 0 && fcntl(m, F_GETFD) == FD_CLOEXEC);
    CHECK((fcntl(m, F_GETFL) & (O_ACCMODE | O_NONBLOCK)) == (O_RDWR | O_NONBLOCK));
    CHECK(grantpt(m) == 0 && unlockpt(m) == 0);
    unsigned number;
    CHECK(ioctl(m, TIOCGPTN, &number) == 0);
    char expected[32], name[32], truncated[5];
    CHECK(snprintf(expected, sizeof expected, "/dev/pts/%u", number) > 0);
    errno = EDOM;
    CHECK(ptsname_r(m, name, sizeof name) == 0 && errno == EDOM && !strcmp(name, expected));
    CHECK(ptsname_r(m, 0, sizeof name) == ERANGE && errno == EDOM);
    memset(truncated, 'X', sizeof truncated);
    CHECK(ptsname_r(m, truncated, 1) == ERANGE && truncated[0] == 0 && truncated[1] == 'X');
    CHECK(ptsname_r(m, truncated, sizeof truncated) == ERANGE && !strcmp(truncated, "/dev"));
    CHECK(ptsname_r(-1, name, sizeof name) == EBADF && errno == EDOM);
    int nullfd = open("/dev/null", O_RDWR); CHECK(nullfd >= 0);
    CHECK(ptsname_r(nullfd, name, sizeof name) == ENOTTY && errno == EDOM);
    CHECK(tcgetsid(nullfd) == -1 && errno == ENOTTY);
    CHECK(close(nullfd) == 0);
    CHECK(tcgetsid(-1) == -1 && errno == EBADF);
    errno = EDOM;
    char *first = ptsname(m); CHECK(first && !strcmp(first, expected));
    int other = posix_openpt(O_RDWR | O_NOCTTY); CHECK(other >= 0 && unlockpt(other) == 0);
    char other_name[32]; CHECK(ptsname_r(other, other_name, sizeof other_name) == 0);
    char *second = ptsname(other); CHECK(first == second && !strcmp(first, other_name) && strcmp(first, expected));
    CHECK(ptsname(-1) == 0 && errno == EBADF && !strcmp(first, other_name));
    int slave = open(expected, O_RDWR | O_NOCTTY), other_slave = open(other_name, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0 && other_slave >= 0);
    errno = ENOMSG;
    char *tty_first = ttyname(slave); CHECK(tty_first && !strcmp(tty_first, expected) && errno == ENOMSG);
    char *tty_second = ttyname(other_slave); CHECK(tty_first == tty_second && !strcmp(tty_first, other_name));
    CHECK(ttyname(-1) == 0 && errno == EBADF && !strcmp(tty_first, other_name));
    CHECK(close(slave) == 0 && close(other_slave) == 0 && close(m) == 0 && close(other) == 0);
    CHECK(descriptor_count() == baseline);
}
static void openpty_case(void) {
    int baseline = descriptor_count(), m = -101, s = -102;
    char name[32]; memset(name, 'X', sizeof name);
    CHECK(openpty(&m, &s, name, 0, 0) == 0 && m >= 0 && s >= 0 && m != s);
    CHECK(!strncmp(name, "/dev/pts/", 9) && name[20] == 'X');
    CHECK(fcntl(m, F_GETFD) == 0 && fcntl(s, F_GETFD) == 0 && !strcmp(ttyname(s), name));
    CHECK((fcntl(m, F_GETFL) & O_ACCMODE) == O_RDWR && (fcntl(s, F_GETFL) & O_ACCMODE) == O_RDWR);
    struct termios settings; raw_terminal(s, &settings);
    CHECK(close(m) == 0 && close(s) == 0);
    struct winsize window = { 37, 91, 640, 480 }, observed;
    int previous;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    CHECK(openpty(&m, &s, 0, &settings, &window) == 0);
    require_cancel_state(PTHREAD_CANCEL_DISABLE);
    CHECK(pthread_setcancelstate(previous, 0) == 0);
    struct termios actual; CHECK(tcgetattr(s, &actual) == 0);
    CHECK(actual.c_iflag == settings.c_iflag && actual.c_oflag == settings.c_oflag);
    CHECK(actual.c_lflag == settings.c_lflag && !memcmp(actual.c_cc, settings.c_cc, 19) /* Linux TCGETS control-byte prefix. */);
    CHECK(ioctl(s, TIOCGWINSZ, &observed) == 0 && !memcmp(&window, &observed, sizeof window));
    char byte;
    CHECK(write(m, "M", 1) == 1 && read(s, &byte, 1) == 1 && byte == 'M');
    CHECK(write(s, "S", 1) == 1 && read(m, &byte, 1) == 1 && byte == 'S');
    CHECK(close(m) == 0 && close(s) == 0 && descriptor_count() == baseline);
}
static void no_controlling_terminal_case(void) {
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        CHECK(setsid() == getpid());
        int m, s; CHECK(openpty(&m, &s, 0, 0, 0) == 0);
        CHECK(tcgetsid(s) == -1 && errno == ENOTTY);
        CHECK(close(m) == 0 && close(s) == 0); _exit(0);
    }
    require_child(pid, 0);
}
static void optional_errors_case(void) {
    struct termios settings = {0}; struct winsize window = {19, 29, 0, 0};
    deny_argument(SYS_ioctl, 1, TCSETS, EPERM);
    deny_argument(SYS_ioctl, 1, TIOCSWINSZ, EINVAL);
    int m = -101, s = -102;
    CHECK(openpty(&m, &s, 0, &settings, &window) == 0 && m >= 0 && s >= 0);
    CHECK(errno == EINVAL); require_cancel_state(PTHREAD_CANCEL_ENABLE);
    CHECK(close(m) == 0 && close(s) == 0);
}
static void open_failure_case(const char *which) {
    int baseline = descriptor_count(), m = -101, s = -102;
    char name[32]; memset(name, 'X', sizeof name);
    int expected;
    if (!strcmp(which, "master-failure")) {
        deny_syscall(SYS_open, ENOSPC); deny_syscall(SYS_openat, ENOSPC);
        CHECK(posix_openpt(O_RDWR | O_NOCTTY) == -1 && errno == EAGAIN);
        expected = ENOSPC;
    } else if (!strcmp(which, "unlock-failure")) {
        deny_argument(SYS_ioctl, 1, TIOCSPTLCK, EACCES); expected = EACCES;
    } else if (!strcmp(which, "number-failure")) {
        deny_argument(SYS_ioctl, 1, TIOCGPTN, EIO); expected = EIO;
    } else { deny_open_path(name); expected = EACCES; }
    CHECK(openpty(&m, &s, name, 0, 0) == -1 && errno == expected);
    CHECK(m == -101 && s == -102 && descriptor_count() == baseline);
    if (!strcmp(which, "slave-failure")) CHECK(!strncmp(name, "/dev/pts/", 9));
    else CHECK(name[0] == 'X');
    require_cancel_state(PTHREAD_CANCEL_ENABLE);
}
static void login_case(void) {
    for (int target = -1; target <= 3; target++) {
        int m, s; char name[32];
        CHECK(openpty(&m, &s, name, 0, 0) == 0);
        struct termios settings; raw_terminal(s, &settings);
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            CHECK(close(m) == 0);
            if (target >= 0 && target <= 2) { CHECK(dup2(s, target) == target); CHECK(close(s) == 0); s = target; }
            if (target == 3) CHECK(setsid() == getpid());
            CHECK(login_tty(s) == 0);
            if (target == 3) CHECK(errno == EPERM); /* Failed second setsid is ignored. */
            CHECK(getsid(0) == getpid() && tcgetsid(0) == getpid() && tcgetpgrp(0) == getpid());
            CHECK(same_descriptor(0, 1) && same_descriptor(1, 2) && !strcmp(ttyname(0), name));
            if (s > 2) CHECK(fcntl(s, F_GETFD) == -1 && errno == EBADF);
            CHECK(write(1, "terminal\n", 9) == 9); _exit(0);
        }
        CHECK(close(s) == 0);
        char bytes[9]; size_t offset = 0;
        while (offset < sizeof bytes) { ssize_t n = read(m, bytes + offset, sizeof bytes - offset); CHECK(n > 0); offset += n; }
        CHECK(!memcmp(bytes, "terminal\n", sizeof bytes));
        require_child(child, 0); CHECK(close(m) == 0);
    }
}
static void login_failures_case(void) {
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        int fd = open("/dev/null", O_RDWR); CHECK(fd >= 0);
        struct stat before, after; CHECK(fstat(1, &before) == 0);
        CHECK(login_tty(fd) == -1 && errno == ENOTTY);
        CHECK(getsid(0) == getpid() && fcntl(fd, F_GETFD) >= 0 && fstat(1, &after) == 0);
        CHECK(before.st_dev == after.st_dev && before.st_ino == after.st_ino); _exit(0);
    }
    require_child(child, 0);
    int m, s; CHECK(openpty(&m, &s, 0, 0, 0) == 0);
    child = fork(); CHECK(child >= 0);
    if (!child) {
        CHECK(close(m) == 0);
        struct stat before, after; CHECK(fstat(1, &before) == 0);
        deny_argument(SYS_dup2, 1, 1, EACCES);
        CHECK(login_tty(s) == 0 && errno == EACCES); /* dup2 errors do not replace success. */
        CHECK(same_descriptor(0, 2) && fstat(1, &after) == 0);
        CHECK(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
        CHECK(fcntl(s, F_GETFD) == -1 && errno == EBADF); _exit(0);
    }
    require_child(child, 0); CHECK(close(m) == 0 && close(s) == 0);
}
static int prepare_calls, parent_calls, child_calls, cancel_in_prepare;
static void prepare(void) {
    prepare_calls++;
    sigset_t mask; CHECK(pthread_sigmask(SIG_SETMASK, 0, &mask) == 0);
    CHECK(sigismember(&mask, SIGUSR1) && sigismember(&mask, SIGUSR2));
    require_cancel_state(PTHREAD_CANCEL_DISABLE);
    int cloexec = 0, saved = errno;
    for (int fd = 3; fd < 128; fd++) if (fcntl(fd, F_GETFD) == FD_CLOEXEC) cloexec++;
    errno = saved; CHECK(cloexec == 2);
    if (cancel_in_prepare) CHECK(pthread_cancel(pthread_self()) == 0);
}
static void parent(void) { parent_calls++; }
static void child(void) { child_calls++; }
static void install_initial_mask(sigset_t *saved) {
    sigset_t mask; CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR2) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &mask, saved) == 0);
}
static void require_initial_mask(void) {
    sigset_t mask; CHECK(pthread_sigmask(SIG_SETMASK, 0, &mask) == 0);
    CHECK(!sigismember(&mask, SIGUSR1) && sigismember(&mask, SIGUSR2));
}
static void forkpty_case(const char *which) {
    sigset_t saved; install_initial_mask(&saved);
    CHECK(pthread_atfork(prepare, parent, child) == 0);
    int baseline = descriptor_count(), m = -101;
    char name[32]; memset(name, 'X', sizeof name);
    int expected = 0;
    if (!strcmp(which, "pipe-failure")) { deny_syscall(SYS_pipe2, ENFILE); expected = ENFILE; }
    else if (!strcmp(which, "fork-failure")) { deny_syscall(SYS_fork, EAGAIN); deny_syscall(SYS_clone, EAGAIN); expected = EAGAIN; }
    else if (!strcmp(which, "child-login-failure")) { deny_argument(SYS_ioctl, 1, TIOCSCTTY, EACCES); expected = EACCES; }
    struct winsize window = {23, 83, 720, 480}, observed;
    pid_t pid = forkpty(&m, name, 0, &window);
    if (!pid) {
        CHECK(m == -101 && prepare_calls == 1 && parent_calls == 0 && child_calls == 1);
        require_initial_mask(); require_cancel_state(PTHREAD_CANCEL_ENABLE);
        CHECK(getsid(0) == getpid() && tcgetsid(0) == getpid() && tcgetpgrp(0) == getpid());
        CHECK(same_descriptor(0, 1) && same_descriptor(1, 2) && !strcmp(ttyname(0), name));
        CHECK(ioctl(0, TIOCGWINSZ, &observed) == 0 && !memcmp(&window, &observed, sizeof window));
        CHECK(write(1, "child", 5) == 5); _exit(23);
    }
    if (expected) {
        CHECK(pid == -1 && errno == expected && m == -101);
        CHECK(descriptor_count() == baseline);
        CHECK(waitpid(-1, 0, WNOHANG) == -1 && errno == ECHILD);
    } else {
        CHECK(pid > 0 && m >= 0 && fcntl(m, F_GETFD) == 0);
        char data[5]; size_t offset = 0;
        while (offset < sizeof data) { ssize_t n = read(m, data + offset, sizeof data - offset); CHECK(n > 0); offset += n; }
        CHECK(!memcmp(data, "child", sizeof data)); require_child(pid, 23); CHECK(close(m) == 0);
    }
    CHECK(!strncmp(name, "/dev/pts/", 9));
    CHECK(prepare_calls == (expected == ENFILE ? 0 : 1) && parent_calls == prepare_calls && child_calls == 0);
    require_initial_mask(); require_cancel_state(PTHREAD_CANCEL_ENABLE);
    CHECK(pthread_sigmask(SIG_SETMASK, &saved, 0) == 0);
}
static atomic_int completed, cleaned;
static int canceled_master = -1, naming_master, naming_slave;
static void cleanup(void *unused) {
    (void)unused;
    if (canceled_master >= 0) CHECK(close(canceled_master) == 0);
    atomic_store(&cleaned, 1);
}
static void *cancel_before_worker(void *argument) {
    intptr_t operation = (intptr_t)argument;
    CHECK(pthread_cancel(pthread_self()) == 0);
    int m = -101, s = -102;
    if (operation == 0) (void)posix_openpt(O_RDWR | O_NOCTTY);
    else if (operation == 1) (void)openpty(&m, &s, 0, 0, 0);
    else (void)forkpty(&m, 0, 0, 0);
    atomic_store(&completed, 1); return 0;
}
static void *cancel_naming_worker(void *unused) {
    (void)unused; char name[32];
    CHECK(pthread_cancel(pthread_self()) == 0);
    CHECK(ptsname(naming_master) != 0 && ptsname_r(naming_master, name, sizeof name) == 0);
    CHECK(ttyname(naming_slave) != 0);
    atomic_store(&completed, 1); pthread_testcancel(); return 0;
}
static void *cancel_forkpty_worker(void *unused) {
    (void)unused;
    sigset_t saved; install_initial_mask(&saved);
    pthread_cleanup_push(cleanup, 0);
    int m = -101;
    pid_t pid = forkpty(&m, 0, 0, 0);
    if (!pid) _exit(31);
    CHECK(pid > 0 && m >= 0);
    canceled_master = m;
    require_initial_mask(); require_cancel_state(PTHREAD_CANCEL_ENABLE);
    /* Pending cancellation must not interrupt forkpty's handshake. Reap the
       disposable child without a new C cancellation point, then deliver it. */
    int status = 0; CHECK(syscall(SYS_wait4, pid, &status, 0, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 31);
    atomic_store(&completed, 1); pthread_testcancel();
    pthread_cleanup_pop(1);
    return 0;
}
static void cancellation_case(void) {
    int baseline = descriptor_count();
    for (intptr_t operation = 0; operation < 3; operation++) {
        pthread_t worker; void *result = 0;
        atomic_store(&completed, 0);
        CHECK(pthread_create(&worker, 0, cancel_before_worker, (void *)operation) == 0);
        CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(!atomic_load(&completed) && descriptor_count() == baseline);
    }
    CHECK(openpty(&naming_master, &naming_slave, 0, 0, 0) == 0);
    pthread_t worker; void *result = 0;
    CHECK(pthread_create(&worker, 0, cancel_naming_worker, 0) == 0);
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED && atomic_load(&completed));
    CHECK(close(naming_master) == 0 && close(naming_slave) == 0);
    CHECK(pthread_atfork(prepare, parent, child) == 0); cancel_in_prepare = 1;
    atomic_store(&completed, 0);
    CHECK(pthread_create(&worker, 0, cancel_forkpty_worker, 0) == 0);
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&completed) && atomic_load(&cleaned) && descriptor_count() == baseline);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "naming")) naming_case();
    else if (!strcmp(argv[1], "openpty")) openpty_case();
    else if (!strcmp(argv[1], "no-controlling-terminal")) no_controlling_terminal_case();
    else if (!strcmp(argv[1], "optional-errors")) optional_errors_case();
    else if (!strcmp(argv[1], "master-failure") || !strcmp(argv[1], "unlock-failure") ||
             !strcmp(argv[1], "number-failure") || !strcmp(argv[1], "slave-failure")) open_failure_case(argv[1]);
    else if (!strcmp(argv[1], "login")) login_case();
    else if (!strcmp(argv[1], "login-failures")) login_failures_case();
    else if (!strcmp(argv[1], "forkpty") || !strcmp(argv[1], "pipe-failure") ||
             !strcmp(argv[1], "fork-failure") || !strcmp(argv[1], "child-login-failure")) forkpty_case(argv[1]);
    else if (!strcmp(argv[1], "cancellation")) cancellation_case();
    else CHECK(0);
    puts("owned pty: PASS"); return 0;
}
