/* Pinned-musl Linux/x86-64 epoll ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* x86-64 Linux keeps epoll_event packed despite its 64-bit data union. */
_Static_assert(sizeof(struct epoll_event) == 12, "x86 epoll_event size");
_Static_assert(_Alignof(struct epoll_event) == 1, "x86 epoll_event alignment");
_Static_assert(offsetof(struct epoll_event, events) == 0,
               "x86 epoll_event events offset");
_Static_assert(offsetof(struct epoll_event, data) == 4,
               "x86 epoll_event data offset");
_Static_assert(sizeof(unsigned long) == 8, "x86 kernel signal-mask word size");

_Static_assert(SYS_epoll_create1 == 291, "x86 epoll_create1 syscall number");
_Static_assert(SYS_epoll_ctl == 233, "x86 epoll_ctl syscall number");
_Static_assert(SYS_epoll_pwait == 281, "x86 epoll_pwait syscall number");

_Static_assert(EPOLL_CLOEXEC == 0x00080000, "x86 EPOLL_CLOEXEC");
_Static_assert(EPOLL_NONBLOCK == 0x00000800, "x86 EPOLL_NONBLOCK");
_Static_assert(EPOLLIN == 0x0001, "x86 EPOLLIN");
_Static_assert(EPOLLPRI == 0x0002, "x86 EPOLLPRI");
_Static_assert(EPOLLOUT == 0x0004, "x86 EPOLLOUT");
_Static_assert(EPOLLERR == 0x0008, "x86 EPOLLERR");
_Static_assert(EPOLLHUP == 0x0010, "x86 EPOLLHUP");
_Static_assert(EPOLLNVAL == 0x0020, "x86 EPOLLNVAL");
_Static_assert(EPOLLRDNORM == 0x0040, "x86 EPOLLRDNORM");
_Static_assert(EPOLLRDBAND == 0x0080, "x86 EPOLLRDBAND");
_Static_assert(EPOLLWRNORM == 0x0100, "x86 EPOLLWRNORM");
_Static_assert(EPOLLWRBAND == 0x0200, "x86 EPOLLWRBAND");
_Static_assert(EPOLLMSG == 0x0400, "x86 EPOLLMSG");
_Static_assert(EPOLLRDHUP == 0x2000, "x86 EPOLLRDHUP");
_Static_assert(EPOLLEXCLUSIVE == (1U << 28), "x86 EPOLLEXCLUSIVE");
_Static_assert(EPOLLWAKEUP == (1U << 29), "x86 EPOLLWAKEUP");
_Static_assert(EPOLLONESHOT == (1U << 30), "x86 EPOLLONESHOT");
_Static_assert(EPOLLET == (1U << 31), "x86 EPOLLET");
_Static_assert(EPOLL_CTL_ADD == 1, "x86 EPOLL_CTL_ADD");
_Static_assert(EPOLL_CTL_DEL == 2, "x86 EPOLL_CTL_DEL");
_Static_assert(EPOLL_CTL_MOD == 3, "x86 EPOLL_CTL_MOD");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static volatile sig_atomic_t masked_signal_seen;

static void masked_signal_handler(int signal_number)
{
    (void)signal_number;
    masked_signal_seen = 1;
}

static long raw_epoll_pwait(int epoll_fd, struct epoll_event *events,
                            int maxevents, int timeout,
                            const unsigned long *mask)
{
    return syscall(SYS_epoll_pwait, epoll_fd, events, maxevents, timeout, mask,
                   sizeof(*mask));
}

static int masked_wait_restores_signal_mask(int epoll_fd, int raw)
{
    struct sigaction action;
    struct sigaction old_action;
    struct epoll_event observed;
    struct timespec delay = { 0, 10 * 1000 * 1000 };
    sigset_t selected;
    sigset_t previous;
    sigset_t restored;
    sigset_t empty;
    unsigned long raw_empty = 0;
    pid_t child;
    int result;
    int result_errno;
    int status;
    int failed = 0;

    memset(&action, 0, sizeof(action));
    action.sa_handler = masked_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGUSR1, &action, &old_action) != 0 ||
        sigemptyset(&selected) != 0 || sigaddset(&selected, SIGUSR1) != 0 ||
        sigemptyset(&empty) != 0 ||
        sigprocmask(SIG_BLOCK, &selected, &previous) != 0)
        return 1;

    masked_signal_seen = 0;
    child = fork();
    if (child == 0) {
        if (nanosleep(&delay, NULL) != 0 || kill(getppid(), SIGUSR1) != 0)
            _Exit(1);
        _Exit(0);
    }
    if (child < 0) {
        sigprocmask(SIG_SETMASK, &previous, NULL);
        sigaction(SIGUSR1, &old_action, NULL);
        return 2;
    }

    errno = 0;
    if (raw)
        result = (int)raw_epoll_pwait(epoll_fd, &observed, 1, 1000, &raw_empty);
    else
        result = epoll_pwait(epoll_fd, &observed, 1, 1000, &empty);
    result_errno = errno;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        failed = 1;
    if (result != -1 || result_errno != EINTR || !masked_signal_seen)
        failed = 1;
    if (sigprocmask(SIG_SETMASK, NULL, &restored) != 0 ||
        !sigismember(&restored, SIGUSR1))
        failed = 1;
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 ||
        sigaction(SIGUSR1, &old_action, NULL) != 0)
        failed = 1;
    return failed;
}

static int ready_token(int epoll_fd, uint64_t token)
{
    struct epoll_event result[2];
    return epoll_wait(epoll_fd, result, 2, 0) == 1 &&
           result[0].data.u64 == token && (result[0].events & EPOLLIN);
}

static int no_ready_events(int epoll_fd)
{
    struct epoll_event result[2];
    return epoll_wait(epoll_fd, result, 2, 0) == 0;
}

static int eventfd_composition(void)
{
    int counter = eventfd(0, EFD_NONBLOCK);
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event interest = { .events = EPOLLIN | EPOLLOUT,
                                    .data.u64 = 0x1234 };
    struct epoll_event result[2];
    struct pollfd polled = { .fd = counter, .events = POLLIN | POLLOUT };
    eventfd_t value;
    int duplicate;

    if (counter < 0 || epoll_fd < 0 ||
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, counter, &interest))
        return 100;
    if (poll(&polled, 1, 0) != 1 || polled.revents != POLLOUT ||
        eventfd_write(counter, UINT64_MAX - 2) || eventfd_write(counter, 1))
        return 101;
    errno = 0;
    if (!expect_error(eventfd_write(counter, 1), EAGAIN) ||
        poll(&polled, 1, 0) != 1 || polled.revents != POLLIN ||
        epoll_wait(epoll_fd, result, 2, 0) != 1 || result[0].events != EPOLLIN ||
        result[0].data.u64 != 0x1234)
        return 102;
    if (eventfd_read(counter, &value) || value != UINT64_MAX - 1 ||
        poll(&polled, 1, 0) != 1 || polled.revents != POLLOUT ||
        epoll_wait(epoll_fd, result, 2, 0) != 1 || result[0].events != EPOLLOUT ||
        close(counter))
        return 103;

    counter = eventfd(2, EFD_NONBLOCK | EFD_SEMAPHORE);
    interest.events = EPOLLIN | EPOLLONESHOT;
    interest.data.u64 = 11;
    if (counter < 0 || epoll_ctl(epoll_fd, EPOLL_CTL_ADD, counter, &interest) ||
        !ready_token(epoll_fd, 11) || eventfd_read(counter, &value) || value != 1 ||
        !no_ready_events(epoll_fd))
        return 104;
    polled.fd = counter;
    polled.events = POLLIN;
    interest.data.u64 = 22;
    if (poll(&polled, 1, 0) != 1 || polled.revents != POLLIN ||
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, counter, &interest) ||
        !ready_token(epoll_fd, 22) || eventfd_read(counter, &value) || value != 1)
        return 105;
    interest.events = EPOLLIN | EPOLLET;
    interest.data.u64 = 44;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, counter, &interest) ||
        !no_ready_events(epoll_fd) || eventfd_write(counter, 2) ||
        !ready_token(epoll_fd, 44) || eventfd_read(counter, &value) || value != 1 ||
        !no_ready_events(epoll_fd) || eventfd_read(counter, &value) || value != 1)
        return 106;
    errno = 0;
    if (!expect_error(eventfd_read(counter, &value), EAGAIN) ||
        eventfd_write(counter, 1) || !ready_token(epoll_fd, 44) || close(counter))
        return 107;

    counter = eventfd(1, EFD_NONBLOCK);
    duplicate = dup(counter);
    interest.events = EPOLLIN;
    interest.data.u64 = 51;
    if (counter < 0 || duplicate < 0 ||
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, counter, &interest) || close(counter) ||
        !ready_token(epoll_fd, 51))
        return 108;
    interest.data.u64 = 52;
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, duplicate, &interest), ENOENT) ||
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, duplicate, &interest) ||
        epoll_wait(epoll_fd, result, 2, 0) != 2 ||
        !((result[0].data.u64 == 51 && result[1].data.u64 == 52) ||
          (result[0].data.u64 == 52 && result[1].data.u64 == 51)) ||
        eventfd_read(duplicate, &value) || value != 1 || !no_ready_events(epoll_fd) ||
        eventfd_write(duplicate, 1) || epoll_wait(epoll_fd, result, 2, 0) != 2 ||
        close(duplicate) || !no_ready_events(epoll_fd) || close(epoll_fd))
        return 109;
    return 0;
}

/* Linux x86 siginfo keeps its payload union eight-byte aligned after the
 * three 32-bit discriminator words. Descriptor records have another layout. */
_Static_assert(sizeof(siginfo_t) == 128, "x86 siginfo size");
_Static_assert(_Alignof(siginfo_t) == 8, "x86 siginfo alignment");
_Static_assert(offsetof(siginfo_t, si_signo) == 0, "x86 siginfo signo");
_Static_assert(offsetof(siginfo_t, si_errno) == 4, "x86 siginfo errno");
_Static_assert(offsetof(siginfo_t, si_code) == 8, "x86 siginfo code");
_Static_assert(offsetof(siginfo_t, si_pid) == 16, "x86 siginfo pid");
_Static_assert(offsetof(siginfo_t, si_uid) == 20, "x86 siginfo uid");
_Static_assert(offsetof(siginfo_t, si_value) == 24, "x86 siginfo value");
_Static_assert(offsetof(siginfo_t, si_status) == 24, "x86 siginfo child status");
_Static_assert(sizeof(struct timespec) == 16, "x86 wait timeout size");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "x86 timeout nanoseconds");

static volatile sig_atomic_t synchronous_wait_interrupted;

static void synchronous_wait_handler(int signal_number)
{
    (void)signal_number;
    synchronous_wait_interrupted = 1;
}

struct synchronous_wait_send {
    pid_t tid;
    int queued;
};

static void *synchronous_wait_sender(void *argument)
{
    const struct synchronous_wait_send *send = argument;
    pid_t tid = send->tid;
    char path[96], observed[256];
    const struct timespec delay = { 0, 1000000 };
    int attempt;
    snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", (int)tid);
    for (attempt = 0; attempt < 3000; ++attempt) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t length;
        if (fd < 0)
            return (void *)1;
        length = read(fd, observed, sizeof(observed));
        close(fd);
        if (length >= 4 && memcmp(observed, "128 ", 4) == 0) {
            if (send->queued) {
                union sigval value = { .sival_int = 7654321 };
                return sigqueue(getpid(), SIGRTMAX, value) ? (void *)1 : NULL;
            }
            return syscall(SYS_tgkill, getpid(), tid, SIGUSR2) ? (void *)1 : NULL;
        }
        nanosleep(&delay, NULL);
    }
    return (void *)1;
}

static int synchronous_wait_composition(void)
{
    sigset_t selected, previous, realtime, only_usr1, current, interrupt;
    siginfo_t info;
    struct sigaction action = { 0 }, old_action;
    struct timespec zero = { 0, 0 }, invalid = { 0, 1000000000 }, timeout = { 5, 0 };
    union sigval value;
    pthread_t sender;
    void *sender_result;
    pid_t child;
    struct synchronous_wait_send send;
    unsigned long raw_mask;
    int status, result, result_errno;
    if (sigemptyset(&selected) || sigaddset(&selected, SIGUSR1) ||
        sigaddset(&selected, SIGRTMIN) || sigaddset(&selected, SIGRTMAX) ||
        sigaddset(&selected, SIGCHLD) || sigprocmask(SIG_BLOCK, &selected, &previous) ||
        sigemptyset(&only_usr1) || sigaddset(&only_usr1, SIGUSR1) ||
        sigemptyset(&realtime) || sigaddset(&realtime, SIGRTMIN) ||
        sigaddset(&realtime, SIGRTMAX))
        return 1;
    errno = 0;
    if (!expect_error(sigtimedwait(&only_usr1, &info, &zero), EAGAIN) || kill(getpid(), SIGUSR1))
        return 2;
    errno = 0;
    if (!expect_error(sigtimedwait(&only_usr1, &info, &invalid), EINVAL))
        return 3;
    invalid.tv_nsec = -1;
    errno = 0;
    if (!expect_error(sigtimedwait(&only_usr1, &info, &invalid), EINVAL))
        return 3;
    invalid.tv_sec = -1;
    invalid.tv_nsec = 0;
    errno = 0;
    if (!expect_error(sigtimedwait(&only_usr1, &info, &invalid), EINVAL))
        return 3;
    errno = ERANGE;
    if (sigtimedwait(&only_usr1, &info, &zero) != SIGUSR1 || info.si_signo != SIGUSR1 ||
        info.si_code != SI_USER || info.si_pid != getpid() || info.si_uid != getuid() ||
        info.si_errno != 0 || errno != ERANGE)
        return 4;
    value.sival_int = 1234567;
    if (sigqueue(getpid(), SIGRTMIN, value))
        return 5;
    value.sival_int = -1234567;
    if (sigqueue(getpid(), SIGRTMIN, value))
        return 5;
    value.sival_int = INT32_MIN;
    if (sigqueue(getpid(), SIGRTMAX, value))
        return 5;
    errno = ERANGE;
    if (sigwaitinfo(&realtime, &info) != SIGRTMIN || info.si_value.sival_int != 1234567 ||
        info.si_code != SI_QUEUE || info.si_pid != getpid() || errno != ERANGE ||
        sigwaitinfo(&realtime, &info) != SIGRTMIN || info.si_value.sival_int != -1234567 ||
        sigwaitinfo(&realtime, &info) != SIGRTMAX || info.si_value.sival_int != INT32_MIN)
        return 6;
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGRTMIN;
    info.si_code = SI_QUEUE;
    info.si_pid = -7;
    info.si_uid = getuid();
    info.si_value.sival_int = 7;
    if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMIN, &info) ||
        sigwaitinfo(&realtime, &info) != SIGRTMIN || info.si_pid != -7 ||
        info.si_value.sival_int != 7)
        return 7;
    send = (struct synchronous_wait_send){ .tid = (pid_t)syscall(SYS_gettid), .queued = 1 };
    if (pthread_create(&sender, NULL, synchronous_wait_sender, &send))
        return 13;
    result = sigtimedwait(&realtime, &info, &timeout);
    if (pthread_join(sender, &sender_result) || sender_result || result != SIGRTMAX ||
        info.si_code != SI_QUEUE || info.si_value.sival_int != 7654321)
        return 14;
    child = fork();
    if (child == 0)
        _Exit(42);
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 42)
        return 8;
    sigemptyset(&only_usr1);
    sigaddset(&only_usr1, SIGCHLD);
    if (sigtimedwait(&only_usr1, &info, &zero) != SIGCHLD || info.si_pid != child ||
        info.si_code != CLD_EXITED || info.si_status != 42)
        return 9;
    action.sa_handler = synchronous_wait_handler;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGUSR2, &action, &old_action) ||
        sigemptyset(&interrupt) || sigaddset(&interrupt, SIGUSR2) ||
        sigprocmask(SIG_UNBLOCK, &interrupt, NULL))
        return 10;
    synchronous_wait_interrupted = 0;
    send = (struct synchronous_wait_send){ .tid = (pid_t)syscall(SYS_gettid), .queued = 0 };
    memcpy(&raw_mask, &realtime, sizeof(raw_mask));
    if (pthread_create(&sender, NULL, synchronous_wait_sender, &send))
        return 11;
    errno = ERANGE;
    result = (int)syscall(SYS_rt_sigtimedwait, &raw_mask, &info, &timeout, sizeof(raw_mask));
    result_errno = errno;
    if (pthread_join(sender, &sender_result) || sender_result || result != -1 ||
        result_errno != EINTR || !synchronous_wait_interrupted ||
        timeout.tv_sec != 5 || timeout.tv_nsec != 0 ||
        sigprocmask(SIG_SETMASK, NULL, &current) ||
        sigismember(&current, SIGUSR1) != 1 || sigismember(&current, SIGRTMIN) != 1 ||
        sigismember(&current, SIGRTMAX) != 1 || sigismember(&current, SIGCHLD) != 1 ||
        sigaction(SIGUSR2, &old_action, NULL) || sigprocmask(SIG_SETMASK, &previous, NULL))
        return 12;
    return 0;
}

static void *signal_mask_worker(void *unused)
{
    sigset_t inherited, selected, pending, changed;
    struct signalfd_siginfo info;
    int fd;
    (void)unused;
    if (sigprocmask(SIG_SETMASK, NULL, &inherited) ||
        sigismember(&inherited, SIGUSR1) != 1 ||
        sigismember(&inherited, SIGUSR2) != 1 ||
        sigismember(&inherited, SIGRTMAX) != 1 ||
        sigemptyset(&selected) || sigaddset(&selected, SIGUSR1))
        return (void *)1;
    fd = signalfd(-1, &selected, SFD_NONBLOCK);
    if (fd < 0 || raise(SIGUSR1) || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 1 ||
        read(fd, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_signo != SIGUSR1 || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 0 || close(fd) ||
        sigprocmask(SIG_UNBLOCK, &selected, NULL) ||
        sigprocmask(SIG_SETMASK, NULL, &changed) ||
        sigismember(&changed, SIGUSR1) != 0 ||
        sigprocmask(SIG_SETMASK, &inherited, NULL))
        return (void *)1;
    return NULL;
}

static int signal_mask_composition(void)
{
    sigset_t previous, selected, current, full, remaining, pending;
    struct signalfd_siginfo info;
    pthread_t worker;
    void *worker_result;
    unsigned long canary[3] = { 0x11223344, 0, 0x55667788 };
    const unsigned long reserved = (1UL << 31) | (1UL << 32) | (1UL << 33);
    const unsigned long unmaskable = (1UL << 8) | (1UL << 18);
    int fd;
    if (sigfillset(&full) || sigprocmask(SIG_SETMASK, &full, &previous) ||
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &canary[1], 8) ||
        sigprocmask(SIG_SETMASK, &previous, NULL) ||
        canary[0] != 0x11223344 || canary[2] != 0x55667788 ||
        canary[1] != (~0UL & ~reserved & ~unmaskable))
        return 1;
    if (sigemptyset(&selected) || sigaddset(&selected, SIGUSR1) ||
        sigaddset(&selected, SIGUSR2) || sigaddset(&selected, SIGRTMAX) ||
        sigprocmask(SIG_BLOCK, &selected, &previous) ||
        pthread_create(&worker, NULL, signal_mask_worker, NULL) ||
        pthread_join(worker, &worker_result) || worker_result ||
        sigprocmask(SIG_SETMASK, NULL, &current) ||
        sigismember(&current, SIGUSR1) != 1 ||
        sigismember(&current, SIGUSR2) != 1 ||
        sigismember(&current, SIGRTMAX) != 1)
        return 2;
    if (raise(SIGUSR1) || raise(SIGUSR2) || raise(SIGRTMAX) ||
        sigpending(&pending) || sigismember(&pending, SIGUSR1) != 1 ||
        sigismember(&pending, SIGUSR2) != 1 || sigismember(&pending, SIGRTMAX) != 1 ||
        sigemptyset(&remaining) || sigaddset(&remaining, SIGUSR1))
        return 3;
    fd = signalfd(-1, &remaining, SFD_NONBLOCK);
    if (fd < 0 || read(fd, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_signo != SIGUSR1 || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 0 ||
        sigismember(&pending, SIGUSR2) != 1 || sigismember(&pending, SIGRTMAX) != 1)
        return 4;
    if (sigemptyset(&remaining) || sigaddset(&remaining, SIGUSR2) ||
        sigaddset(&remaining, SIGRTMAX) || signalfd(fd, &remaining, 0) != fd ||
        read(fd, &info, sizeof(info)) != sizeof(info) || info.ssi_signo != SIGUSR2 ||
        read(fd, &info, sizeof(info)) != sizeof(info) || info.ssi_signo != (uint32_t)SIGRTMAX ||
        sigpending(&pending) || sigismember(&pending, SIGUSR2) != 0 ||
        sigismember(&pending, SIGRTMAX) != 0 || close(fd))
        return 5;
    if (sigemptyset(&remaining) || sigaddset(&remaining, SIGUSR1) ||
        sigprocmask(SIG_UNBLOCK, &remaining, NULL) ||
        sigprocmask(SIG_SETMASK, NULL, &current) || sigismember(&current, SIGUSR1) != 0 ||
        sigismember(&current, SIGUSR2) != 1 || sigismember(&current, SIGRTMAX) != 1 ||
        sigprocmask(SIG_SETMASK, &previous, NULL))
        return 6;
    return 0;
}

struct queue_thread_control { int ready; int release; int result; };

static void *queue_thread_receiver(void *opaque)
{
    struct queue_thread_control *control = opaque;
    pid_t tid = syscall(SYS_gettid);
    char released;
    sigset_t selected, pending;
    siginfo_t info;
    struct timespec zero = { 0, 0 };
    control->result = 1;
    if (write(control->ready, &tid, sizeof tid) != sizeof tid ||
        read(control->release, &released, 1) != 1 || sigpending(&pending) ||
        sigismember(&pending, SIGRTMIN) != 1 || sigismember(&pending, SIGRTMAX) != 1 ||
        sigemptyset(&selected) || sigaddset(&selected, SIGRTMIN) ||
        sigtimedwait(&selected, &info, &zero) != SIGRTMIN ||
        info.si_code != SI_QUEUE || info.si_pid != getpid() ||
        info.si_uid != getuid() || info.si_value.sival_int != 101 ||
        sigemptyset(&selected) || sigaddset(&selected, SIGRTMAX) ||
        sigtimedwait(&selected, &info, &zero) != SIGRTMAX ||
        info.si_code != SI_TKILL || info.si_pid != getpid())
        return NULL;
    control->result = 0;
    return NULL;
}

static int queue_process_composition(void)
{
    sigset_t selected, previous, single, pending;
    siginfo_t info;
    struct signalfd_siginfo record;
    struct timespec zero = { 0, 0 }, timeout = { 5, 0 };
    union sigval value;
    int fd, ready[2], release[2], child_ready[2], status;
    pid_t tid, child;
    pthread_t thread;
    struct queue_thread_control control;
    char marker;
    if (sigemptyset(&selected) || sigaddset(&selected, SIGUSR1) ||
        sigaddset(&selected, SIGRTMIN) || sigaddset(&selected, SIGRTMAX) ||
        sigprocmask(SIG_BLOCK, &selected, &previous) ||
        sigemptyset(&single) || sigaddset(&single, SIGUSR1)) return 1;
    fd = signalfd(-1, &single, SFD_NONBLOCK | SFD_CLOEXEC);
    value.sival_int = 11;
    if (fd < 0 || sigqueue(getpid(), SIGUSR1, value)) return 2;
    value.sival_int = 22;
    if (sigqueue(getpid(), SIGUSR1, value) || read(fd, &record, sizeof record) != sizeof record ||
        record.ssi_code != SI_QUEUE || record.ssi_pid != (unsigned)getpid() ||
        record.ssi_uid != getuid() || record.ssi_errno != 0 || record.ssi_int != 11 ||
        read(fd, &record, sizeof record) != -1 || errno != EAGAIN || close(fd)) return 3;
    if (sigemptyset(&single) || sigaddset(&single, SIGRTMIN)) return 4;
    const int values[] = { INT32_MAX, INT32_MIN, -1234567 };
    for (unsigned i = 0; i < 3; ++i) {
        value.sival_int = values[i];
        if (sigqueue(getpid(), SIGRTMIN, value)) return 5;
    }
    for (unsigned i = 0; i < 3; ++i)
        if (sigtimedwait(&single, &info, &zero) != SIGRTMIN || info.si_errno != 0 ||
            info.si_code != SI_QUEUE || info.si_pid != getpid() || info.si_uid != getuid() ||
            info.si_value.sival_int != values[i]) return 6;
    memset(&info, 0, sizeof info);
    info.si_signo = SIGRTMAX;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();
    info.si_value.sival_int = INT32_MIN;
    if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMAX, &info) ||
        sigemptyset(&single) || sigaddset(&single, SIGRTMAX) ||
        sigtimedwait(&single, &info, &zero) != SIGRTMAX || info.si_errno != 0 ||
        info.si_code != SI_QUEUE || info.si_pid != getpid() || info.si_uid != getuid() ||
        (uintptr_t)info.si_value.sival_ptr != UINT32_C(0x80000000)) return 15;
    value.sival_int = 0;
    if (sigqueue(INT32_MAX, SIGUSR1, value) != -1 || errno != ESRCH ||
        pipe(ready) || pipe(release)) return 7;
    control = (struct queue_thread_control){ ready[1], release[0], 1 };
    if (pthread_create(&thread, NULL, queue_thread_receiver, &control) ||
        read(ready[0], &tid, sizeof tid) != sizeof tid) return 8;
    value.sival_int = 7;
    if (sigqueue(tid, SIGUSR1, value) || sigemptyset(&single) ||
        sigaddset(&single, SIGUSR1) || sigtimedwait(&single, &info, &zero) != SIGUSR1 ||
        info.si_code != SI_QUEUE || info.si_value.sival_int != 7 ||
        sigemptyset(&single) || sigaddset(&single, SIGRTMIN)) return 9;
    value.sival_int = 101;
    if (sigqueue(getpid(), SIGRTMIN, value) || syscall(SYS_tgkill, getpid(), tid, SIGRTMAX) ||
        sigpending(&pending) || sigismember(&pending, SIGRTMIN) != 1 ||
        sigismember(&pending, SIGRTMAX) != 0 || write(release[1], "r", 1) != 1 ||
        pthread_join(thread, NULL) || control.result) return 10;
    if (close(ready[0]) || close(ready[1]) || close(release[0]) || close(release[1]) ||
        pipe(child_ready)) return 11;
    child = fork();
    if (child == -1) return 12;
    if (!child) {
        close(child_ready[0]);
        if (write(child_ready[1], "r", 1) != 1 ||
            sigtimedwait(&single, &info, &timeout) != SIGRTMIN ||
            info.si_code != SI_QUEUE || info.si_pid != getppid() ||
            info.si_uid != getuid() || info.si_value.sival_int != -1234) _exit(1);
        _exit(0);
    }
    close(child_ready[1]);
    if (read(child_ready[0], &marker, 1) != 1 ||
        syscall(SYS_tgkill, getpid(), child, SIGRTMIN) != -1 || errno != ESRCH) return 13;
    value.sival_int = -1234;
    if (sigqueue(child, SIGRTMIN, value) || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) || close(child_ready[0]) ||
        sigpending(&pending) || sigismember(&pending, SIGRTMIN) != 0 ||
        sigprocmask(SIG_SETMASK, &previous, NULL)) return 14;
    return 0;
}

static int signalfd_composition(void)
{
    sigset_t selected, previous, empty, pending;
    struct signalfd_siginfo info;
    struct epoll_event interest = { .events = EPOLLIN, .data.u64 = 61 };
    struct epoll_event result[2];
    struct pollfd polled[2];
    eventfd_t value;
    int signal_fd, counter, epoll_fd, descriptor_flags, status_flags, duplicate;
    unsigned char short_record[127];
    union sigval queued = { .sival_int = -1234567 };

    if (signal_mask_composition())
        return 129;
    if (synchronous_wait_composition())
        return 130;
    int queue_result = queue_process_composition();
    if (queue_result) {
        fprintf(stderr, "queued signal composition failed at %d\n", queue_result);
        return 131;
    }
    if (sigemptyset(&selected) || sigaddset(&selected, SIGUSR1) ||
        sigemptyset(&empty) || sigprocmask(SIG_BLOCK, &selected, &previous))
        return 120;
    signal_fd = signalfd(-1, &selected, SFD_NONBLOCK | SFD_CLOEXEC);
    counter = eventfd(0, EFD_NONBLOCK);
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (signal_fd < 0 || counter < 0 || epoll_fd < 0 ||
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &interest))
        return 121;
    interest.data.u64 = 62;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, counter, &interest))
        return 122;
    polled[0] = (struct pollfd){ .fd = signal_fd, .events = POLLIN };
    polled[1] = (struct pollfd){ .fd = counter, .events = POLLIN };
    errno = 0;
    if (!expect_error(read(signal_fd, &info, sizeof(info)), EAGAIN) ||
        poll(polled, 2, 0) != 0 || eventfd_write(counter, 3) || raise(SIGUSR1) ||
        poll(polled, 2, 0) != 2 || polled[0].revents != POLLIN ||
        polled[1].revents != POLLIN || epoll_wait(epoll_fd, result, 2, 0) != 2 ||
        !((result[0].data.u64 == 61 && result[1].data.u64 == 62) ||
          (result[0].data.u64 == 62 && result[1].data.u64 == 61)))
        return 123;
    errno = 0;
    if (!expect_error(read(signal_fd, short_record, sizeof(short_record)), EINVAL))
        return 127;
    if (read(signal_fd, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_signo != SIGUSR1 || info.ssi_pid != (uint32_t)getpid() ||
        info.ssi_uid != getuid() || info.ssi_code != SI_TKILL || info.ssi_errno != 0 ||
        eventfd_read(counter, &value) || value != 3 || poll(polled, 2, 0) != 0 ||
        !no_ready_events(epoll_fd))
        return 124;
    if (sigqueue(getpid(), SIGUSR1, queued) ||
        read(signal_fd, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_code != SI_QUEUE || info.ssi_int != -1234567 ||
        info.ssi_pid != (uint32_t)getpid() || info.ssi_uid != getuid())
        return 128;
    if (signalfd(signal_fd, &empty, 0) != signal_fd || raise(SIGUSR1) ||
        poll(polled, 2, 0) != 0 || !no_ready_events(epoll_fd) ||
        sigpending(&pending) || sigismember(&pending, SIGUSR1) != 1 ||
        signalfd(signal_fd, &selected, 0) != signal_fd ||
        poll(polled, 2, 0) != 1 || polled[0].revents != POLLIN ||
        !ready_token(epoll_fd, 61))
        return 125;
    descriptor_flags = fcntl(signal_fd, F_GETFD);
    status_flags = fcntl(signal_fd, F_GETFL);
    if (read(signal_fd, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_signo != SIGUSR1 || sigpending(&pending) ||
        sigismember(&pending, SIGUSR1) != 0 ||
        descriptor_flags < 0 || !(descriptor_flags & FD_CLOEXEC) ||
        status_flags < 0 || !(status_flags & O_NONBLOCK) ||
        (duplicate = dup(signal_fd)) < 0 || close(signal_fd))
        return 126;
    errno = 0;
    if (!expect_error(fcntl(signal_fd, F_GETFD), EBADF) || raise(SIGUSR1) ||
        read(duplicate, &info, sizeof(info)) != sizeof(info) ||
        info.ssi_signo != SIGUSR1 || close(duplicate) ||
        !no_ready_events(epoll_fd) || close(counter) || close(epoll_fd) ||
        sigprocmask(SIG_SETMASK, &previous, NULL))
        return 126;
    return 0;
}

static int isolated_event_composition(void)
{
    pid_t child = fork();
    int status;
    if (child < 0)
        return 1;
    if (child == 0) {
        int result = eventfd_composition();
        if (!result)
            result = signalfd_composition();
        if (result)
            fprintf(stderr, "event composition failed at %d\n", result);
        _Exit(result);
    }
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR)
            return 1;
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(void)
{
    const uint64_t added_data = UINT64_C(0x1122334455667788);
    const uint64_t modified_data = UINT64_C(0x8877665544332211);
    struct epoll_event interest;
    struct epoll_event observed;
    int pipe_fds[2] = {-1, -1};
    int legacy_epoll_fd = -1;
    int epoll_fd = -1;
    sigset_t empty;
    unsigned long raw_empty = 0;
    char byte;

    legacy_epoll_fd = epoll_create(1);
    if (legacy_epoll_fd < 0)
        return 1;
    if (fcntl(legacy_epoll_fd, F_GETFD) < 0 ||
        (fcntl(legacy_epoll_fd, F_GETFD) & FD_CLOEXEC) != 0)
        return 2;
    if (close(legacy_epoll_fd) != 0)
        return 3;
    errno = 0;
    if (!expect_error(epoll_create(0), EINVAL))
        return 4;

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
        return 10;
    if (fcntl(epoll_fd, F_GETFD) < 0 ||
        (fcntl(epoll_fd, F_GETFD) & FD_CLOEXEC) == 0)
        return 11;

    /* Only EPOLL_CLOEXEC is accepted by epoll_create1. */
    errno = 0;
    if (!expect_error(epoll_create1(EPOLL_NONBLOCK), EINVAL))
        return 12;

    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 13;

    if (sigemptyset(&empty) != 0)
        return 32;
    if (pipe(pipe_fds) != 0)
        return 14;
    /* Linux accepts unassigned event-mask bits; retain them for the kernel. */
    interest.events = EPOLLIN | UINT32_C(0x00000800);
    interest.data.u64 = added_data;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fds[0], &interest) != 0)
        return 15;
    if (syscall(SYS_epoll_ctl, epoll_fd, EPOLL_CTL_MOD, pipe_fds[0],
                &interest) != 0)
        return 31;
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 16;
    if (raw_epoll_pwait(epoll_fd, &observed, 1, 0, &raw_empty) != 0)
        return 33;

    if (write(pipe_fds[1], "x", 1) != 1)
        return 17;
    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, &empty) != 1 ||
        (observed.events & EPOLLIN) == 0 || observed.data.u64 != added_data)
        return 18;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'x')
        return 19;

    interest.events = EPOLLIN | EPOLLET;
    interest.data.u64 = modified_data;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, pipe_fds[0], &interest) != 0)
        return 20;
    if (write(pipe_fds[1], "y", 1) != 1)
        return 21;
    memset(&observed, 0, sizeof(observed));
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 1 ||
        (observed.events & EPOLLIN) == 0 || observed.data.u64 != modified_data)
        return 22;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'y')
        return 23;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pipe_fds[0], NULL) != 0)
        return 24;
    if (epoll_pwait(epoll_fd, &observed, 1, 0, NULL) != 0)
        return 25;
    if (masked_wait_restores_signal_mask(epoll_fd, 0) != 0)
        return 34;
    if (masked_wait_restores_signal_mask(epoll_fd, 1) != 0)
        return 35;

    /* Check representative kernel validation errors at the same boundary. */
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, 99, pipe_fds[0], &interest), EINVAL))
        return 26;
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, -1, &interest), EBADF))
        return 27;
    errno = 0;
    if (!expect_error(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pipe_fds[0], NULL),
                      ENOENT))
        return 28;
    errno = 0;
    if (!expect_error(epoll_pwait(epoll_fd, &observed, 0, 0, NULL), EINVAL))
        return 29;

    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 ||
        close(epoll_fd) != 0)
        return 30;

    if (isolated_event_composition())
        return 36;

    puts("layout=size12 align1 offsets=0,4 syscalls=291,233,281 legacy=positive-size cloexec=enabled future-event=musl+raw-accepted masked=musl+raw-restored empty=0 add=readable data=u64-preserved modify=updated delete=removed errors=EINVAL,EBADF,ENOENT");
    return 0;
}
