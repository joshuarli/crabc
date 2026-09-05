#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

/* Musl exposes this ABI-only alias without a public header declaration. */
extern void (*__sysv_signal(int, void (*)(int)))(int);
#define CHECK(c) do { if (!(c)) { dprintf(2, "signal helpers line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)
static volatile sig_atomic_t first_calls, second_calls;
static void first(int sig) { if (sig == SIGUSR1) first_calls++; }
static void second(int sig) { if (sig == SIGUSR1) second_calls++; }
static void require_action(void (*handler)(int), int restart) {
    struct sigaction action;
    CHECK(sigaction(SIGUSR1, 0, &action) == 0);
    CHECK(action.sa_handler == handler && !!(action.sa_flags & SA_RESTART) == restart);
    CHECK(!sigismember(&action.sa_mask, SIGUSR1));
}
static void action_cases(void) {
    struct sigaction saved;
    sigset_t saved_mask, mask;
    CHECK(sigaction(SIGUSR1, 0, &saved) == 0);
    CHECK(sigprocmask(SIG_SETMASK, 0, &saved_mask) == 0);
    void (*(*volatile bsd_entry)(int, void (*)(int)))(int) = bsd_signal;
    void (*(*volatile sysv_entry)(int, void (*)(int)))(int) = __sysv_signal;
    void (*(*volatile signal_entry)(int, void (*)(int)))(int) = signal;
    CHECK(bsd_entry == signal_entry && sysv_entry == signal_entry);
    CHECK(bsd_entry(SIGUSR1, first) != SIG_ERR); require_action(first, 1);
    CHECK(sysv_entry(SIGUSR1, second) == first); require_action(second, 1);
    CHECK(sigset(SIGUSR1, first) == second); require_action(first, 0);
    errno = EDOM;
    CHECK(sighold(SIGUSR1) == 0 && errno == EDOM);
    CHECK(raise(SIGUSR1) == 0 && first_calls == 0);
    CHECK(sigset(SIGUSR1, SIG_HOLD) == SIG_HOLD);
    CHECK(sigset(SIGUSR1, second) == SIG_HOLD);
    CHECK(first_calls == 0 && second_calls == 1);
    CHECK(sigset(SIGUSR1, SIG_IGN) == second);
    CHECK(sigignore(SIGUSR1) == 0); require_action(SIG_IGN, 0);
    CHECK(sighold(SIGUSR1) == 0 && sigrelse(SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_SETMASK, 0, &mask) == 0 && !sigismember(&mask, SIGUSR1));
    int invalid[] = {-1, 0, 32, 33, 34, 65};
    for (unsigned i = 0; i < sizeof invalid / sizeof *invalid; i++) {
        int sig = invalid[i];
        CHECK(sighold(sig) == -1 && errno == EINVAL);
        CHECK(sigrelse(sig) == -1 && errno == EINVAL);
        CHECK(sigignore(sig) == -1 && errno == EINVAL);
        CHECK(sigset(sig, first) == SIG_ERR && errno == EINVAL);
        CHECK(bsd_entry(sig, first) == SIG_ERR && errno == EINVAL);
        CHECK(sysv_entry(sig, first) == SIG_ERR && errno == EINVAL);
    }
    CHECK(sigignore(SIGKILL) == -1 && errno == EINVAL);
    CHECK(sigignore(SIGSTOP) == -1 && errno == EINVAL);
    CHECK(sigaction(SIGUSR1, &saved, 0) == 0);
    CHECK(sigprocmask(SIG_SETMASK, &saved_mask, 0) == 0);
}
static void deny_syscall(int number, int error) {
    /* Fixed Linux 5.10 sock_filter/sock_fprog layout; no installed kernel
     * header dependency and no policy code in the implementation. */
    struct instruction { unsigned short code; unsigned char yes, no; unsigned value; };
    struct program { unsigned short count; struct instruction *instructions; };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0}, {0x15, 0, 1, (unsigned)number},
        {0x06, 0, 0, 0x00050000 | (unsigned)error}, {0x06, 0, 0, 0x7fff0000},
    };
    struct program program = {sizeof instructions / sizeof *instructions, instructions};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &program) == 0);
}
static void interrupt_bookkeeping(int failed, int restart) {
    if (failed) CHECK(sigset(SIGKILL, first) == SIG_ERR && errno == EINVAL);
    else if (restart) CHECK(__sysv_signal(SIGUSR1, first) != SIG_ERR);
    else CHECK(sigset(SIGUSR1, first) != SIG_ERR);
    sem_t semaphore;
    CHECK(sem_init(&semaphore, 0, 0) == 0);
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_nsec += 30000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    deny_syscall(SYS_futex, EINTR);
    CHECK(sem_timedwait(&semaphore, &deadline) == -1);
    CHECK(errno == (restart ? ETIMEDOUT : EINTR));
    CHECK(sem_destroy(&semaphore) == 0);
}
static void partial_action_failure(void) {
    CHECK(sigset(SIGUSR1, first) != SIG_ERR);
    deny_syscall(SYS_rt_sigprocmask, EPERM);
    CHECK(sigset(SIGUSR1, second) == SIG_ERR && errno == EPERM);
    require_action(second, 0); /* Source does not roll back the first syscall. */
    CHECK(sigset(SIGUSR1, SIG_HOLD) == SIG_ERR && errno == EPERM);
    require_action(second, 0);
    CHECK(sighold(SIGUSR1) == -1 && errno == EPERM);
    CHECK(sigrelse(SIGUSR1) == -1 && errno == EPERM);
}
static sem_t canceled_wait;
static atomic_int worker_ready;
static void *cancellation_worker(void *unused) {
    (void)unused;
    CHECK(sigset(SIGUSR1, first) != SIG_ERR);
    CHECK(sighold(SIGUSR2) == 0 && sigrelse(SIGUSR2) == 0);
    for (int sig = 32; sig <= 34; sig++) {
        CHECK(sighold(sig) == -1 && errno == EINVAL);
        CHECK(sigignore(sig) == -1 && errno == EINVAL);
        CHECK(sigset(sig, SIG_IGN) == SIG_ERR && errno == EINVAL);
    }
    atomic_store(&worker_ready, 1);
    sem_wait(&canceled_wait);
    return (void *)1;
}
static void cancellation_case(void) {
    CHECK(sem_init(&canceled_wait, 0, 0) == 0);
    pthread_t worker;
    CHECK(pthread_create(&worker, 0, cancellation_worker, 0) == 0);
    while (!atomic_load(&worker_ready)) sched_yield();
    CHECK(pthread_cancel(worker) == 0);
    void *result;
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(sem_destroy(&canceled_wait) == 0);
}
static int redirect_stderr(int write_fd) {
    int saved = dup(2); CHECK(saved >= 0);
    CHECK(dup2(write_fd, 2) == 2);
    return saved;
}
static void restore_stderr(int saved) {
    CHECK(dup2(saved, 2) == 2 && close(saved) == 0);
}
static void reporting_case(void) {
    int channel[2]; CHECK(pipe(channel) == 0);
    int saved = redirect_stderr(channel[1]); CHECK(close(channel[1]) == 0);
    CHECK(fwide(stderr, 0) == 0);
    CHECK(setlocale(LC_ALL, "POSIX") != 0);
    errno = EDOM; psignal(SIGUSR1, "notice"); CHECK(errno == EDOM && fwide(stderr, 0) == 0);
    errno = ECHILD; psignal(0, 0); CHECK(errno == ECHILD);
    siginfo_t info; memset(&info, 0, sizeof info); info.si_signo = SIGTERM;
    errno = EBUSY; psiginfo(&info, ""); CHECK(errno == EBUSY && fwide(stderr, 0) == 0);
    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != 0);
    CHECK(fwide(stderr, 1) > 0);
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    errno = ENOTTY; psignal(SIGTERM, "wide"); CHECK(errno == ENOTTY && fwide(stderr, 0) > 0);
    CHECK(fputwc(0x03bb, stderr) == 0x03bb); /* Retained UTF-8 orientation locale. */
    CHECK(fflush(stderr) == 0);
    restore_stderr(saved);
    char observed[256]; ssize_t count = read(channel[0], observed, sizeof observed);
    static const char expected[] = "notice: User defined signal 1\nUnknown signal\n: Terminated\nwide: Terminated\n\xce\xbb";
    CHECK(count == (ssize_t)sizeof expected - 1 && !memcmp(observed, expected, sizeof expected - 1));
    CHECK(close(channel[0]) == 0);
    saved = dup(2); CHECK(saved >= 0 && close(2) == 0);
    errno = EDOM; psignal(SIGTERM, "closed");
    int error = errno, stream_error = ferror(stderr), orientation = fwide(stderr, 0);
    restore_stderr(saved);
    CHECK(error == EBADF && stream_error && orientation > 0);
    clearerr(stderr);
}
static void partial_reporting_case(void) {
    int channel[2]; CHECK(pipe2(channel, O_NONBLOCK) == 0);
    /* Pipe capacity is harness setup, outside the selected fcntl profile. */
    int capacity = syscall(SYS_fcntl, channel[1], F_GETPIPE_SZ); CHECK(capacity >= 4096);
    char page[4096]; memset(page, 'F', sizeof page);
    int filled = 0;
    while (filled < capacity) { ssize_t n = write(channel[1], page, sizeof page); CHECK(n > 0); filled += n; }
    CHECK(filled == capacity && read(channel[0], page, sizeof page) == sizeof page);
    int saved = redirect_stderr(channel[1]); CHECK(close(channel[1]) == 0);
    char message[4081]; memset(message, 'A', sizeof message - 1); message[sizeof message - 1] = 0;
    errno = EDOM; psignal(SIGUSR1, message);
    int error = errno, stream_error = ferror(stderr), orientation = fwide(stderr, 0);
    restore_stderr(saved);
    CHECK(error == EAGAIN && stream_error && orientation == 0);
    size_t total = 0;
    ssize_t n;
    while ((n = read(channel[0], page, sizeof page)) > 0) {
        for (ssize_t i = 0; i < n; i++, total++) CHECK(page[i] == (total < (size_t)capacity - 4096 ? 'F' : 'A'));
    }
    CHECK(n == 0 && total == (size_t)capacity - 4096 + 4080);
    CHECK(close(channel[0]) == 0);
    clearerr(stderr);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "actions")) action_cases();
    else if (!strcmp(argv[1], "interrupt")) interrupt_bookkeeping(0, 0);
    else if (!strcmp(argv[1], "failed-interrupt")) interrupt_bookkeeping(1, 0);
    else if (!strcmp(argv[1], "restart")) interrupt_bookkeeping(0, 1);
    else if (!strcmp(argv[1], "partial-action")) partial_action_failure();
    else if (!strcmp(argv[1], "cancellation")) cancellation_case();
    else if (!strcmp(argv[1], "reporting")) reporting_case();
    else if (!strcmp(argv[1], "partial-reporting")) partial_reporting_case();
    else CHECK(0);
    puts("owned-signal-helpers-ok");
    return 0;
}
