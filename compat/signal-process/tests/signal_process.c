/*
 * Bounded M6 signal/process workload.
 *
 * Each invocation runs exactly one subcase.  The Python runner invokes the
 * subcases in separate process groups, so a bad signal disposition, child, or
 * thread cannot leak into the next case.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int write_full(int fd, const void *buffer, size_t length) {
    const char *bytes = (const char *)buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int read_full(int fd, void *buffer, size_t length) {
    char *bytes = (char *)buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t read_count = read(fd, bytes + offset, length - offset);
        if (read_count > 0) {
            offset += (size_t)read_count;
        } else if (read_count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int emit(const char *message) {
    return write_full(STDOUT_FILENO, message, strlen(message));
}

static int fail_case(const char *name, int code) {
    char message[128];
    int length = snprintf(message, sizeof(message), "%s: failure=%d\n", name, code);
    if (length > 0 && (size_t)length < sizeof(message)) {
        (void)write_full(STDERR_FILENO, message, (size_t)length);
    }
    return 1;
}

/* SA_SIGINFO: sigqueue's queued integer must arrive as siginfo.si_value. */
static volatile sig_atomic_t siginfo_seen;
static volatile sig_atomic_t siginfo_value;
static volatile sig_atomic_t siginfo_code;

static void siginfo_handler(int signo, siginfo_t *info, void *context) {
    (void)context;
    siginfo_seen = signo;
    siginfo_code = info == NULL ? 0 : info->si_code;
    siginfo_value = info == NULL ? 0 : info->si_value.sival_int;
}

static int run_siginfo(void) {
    struct sigaction action;
    union sigval value;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = siginfo_handler;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        return fail_case("siginfo", 1);
    }

    value.sival_int = 0x13579;
    if (sigqueue(getpid(), SIGUSR1, value) != 0) {
        return fail_case("siginfo", 2);
    }
    if (siginfo_seen != SIGUSR1 || siginfo_code != SI_QUEUE ||
        siginfo_value != value.sival_int) {
        return fail_case("siginfo", 3);
    }
    return emit("siginfo: queued=1 data=1\n") == 0 ? 0 : 1;
}

/* SA_NODEFER: nested invocation must be observable in handler order. */
static volatile sig_atomic_t nodefer_depth;
static volatile sig_atomic_t nodefer_count;
static volatile sig_atomic_t nodefer_order[4];

static void nodefer_handler(int signo) {
    sig_atomic_t depth = nodefer_depth;
    (void)signo;
    if (nodefer_count < 4) {
        nodefer_order[nodefer_count++] = depth == 0 ? 'A' : 'B';
    }
    nodefer_depth = depth + 1;
    if (depth == 0) {
        (void)raise(SIGUSR2);
    }
    nodefer_depth = depth;
    if (nodefer_count < 4) {
        nodefer_order[nodefer_count++] = depth == 0 ? 'a' : 'b';
    }
}

static int run_nodefer(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = nodefer_handler;
    action.sa_flags = SA_NODEFER;
    if (sigaction(SIGUSR2, &action, NULL) != 0) {
        return fail_case("nodefer", 1);
    }
    if (raise(SIGUSR2) != 0) {
        return fail_case("nodefer", 2);
    }
    if (nodefer_count != 4 || nodefer_order[0] != 'A' ||
        nodefer_order[1] != 'B' || nodefer_order[2] != 'b' ||
        nodefer_order[3] != 'a') {
        return fail_case("nodefer", 3);
    }
    return emit("nodefer: nested=1 order=ABba\n") == 0 ? 0 : 1;
}

/* A blocked signal becomes pending and is delivered when the mask is lifted. */
static volatile sig_atomic_t mask_pending_seen;

static void mask_pending_handler(int signo) {
    mask_pending_seen = signo;
}

static int run_mask_pending(void) {
    struct sigaction action;
    sigset_t set;
    sigset_t pending;
    sigset_t old_mask;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = mask_pending_handler;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || sigemptyset(&set) != 0 ||
        sigaddset(&set, SIGUSR1) != 0 ||
        sigprocmask(SIG_BLOCK, &set, &old_mask) != 0) {
        return fail_case("mask-pending", 1);
    }
    mask_pending_seen = 0;
    if (raise(SIGUSR1) != 0 || sigpending(&pending) != 0 ||
        sigismember(&pending, SIGUSR1) != 1) {
        (void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return fail_case("mask-pending", 2);
    }
    if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0 ||
        mask_pending_seen != SIGUSR1) {
        (void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return fail_case("mask-pending", 3);
    }
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) != 0) {
        return fail_case("mask-pending", 4);
    }
    return emit("mask-pending: blocked=1 pending=1 delivered=1\n") == 0 ? 0 : 1;
}

/* SA_RESTART both survives sigaction and restarts a blocked pipe read. */
static volatile sig_atomic_t restart_seen;
static int restart_pipe_fd = -1;

static void restart_handler(int signo) {
    const char marker = 'r';
    restart_seen = signo;
    if (restart_pipe_fd >= 0) {
        (void)write(restart_pipe_fd, &marker, 1);
    }
}

static int run_sa_restart(void) {
    struct sigaction action;
    struct sigaction observed;
    int channel[2];
    char marker;
    ssize_t read_count;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = restart_handler;
    action.sa_flags = SA_RESTART;
    restart_seen = 0;
    if (pipe(channel) != 0) {
        return fail_case("sa-restart", 1);
    }
    restart_pipe_fd = channel[1];
    if (sigaction(SIGALRM, &action, NULL) != 0 ||
        sigaction(SIGALRM, NULL, &observed) != 0 ||
        (observed.sa_flags & SA_RESTART) == 0) {
        close(channel[0]);
        close(channel[1]);
        restart_pipe_fd = -1;
        return fail_case("sa-restart", 2);
    }
    alarm(1);
    read_count = read(channel[0], &marker, 1);
    alarm(0);
    close(channel[0]);
    close(channel[1]);
    restart_pipe_fd = -1;
    if (read_count != 1 || marker != 'r' || restart_seen != SIGALRM) {
        return fail_case("sa-restart", 3);
    }
    return emit("sa-restart: configured=1 delivered=1 restarted=1\n") == 0 ? 0 : 1;
}

/* SA_ONSTACK must run the handler on the registered alternate stack. */
static _Alignas(16) unsigned char alternate_stack_memory[SIGSTKSZ];
static volatile sig_atomic_t alternate_stack_seen;
static volatile sig_atomic_t alternate_stack_active;

static void alternate_stack_handler(int signo) {
    stack_t current;
    alternate_stack_seen = signo;
    if (sigaltstack(NULL, &current) == 0 && (current.ss_flags & SS_ONSTACK)) {
        alternate_stack_active = 1;
    }
}

static int run_altstack(void) {
    struct sigaction action;
    stack_t alternate;
    stack_t old_stack;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = alternate_stack_handler;
    action.sa_flags = SA_ONSTACK;
    alternate.ss_sp = alternate_stack_memory;
    alternate.ss_size = sizeof(alternate_stack_memory);
    alternate.ss_flags = 0;
    alternate_stack_seen = 0;
    alternate_stack_active = 0;
    if (sigaltstack(&alternate, &old_stack) != 0) {
        return fail_case("altstack", 1);
    }
    if (sigaction(SIGUSR1, &action, NULL) != 0 || raise(SIGUSR1) != 0 ||
        alternate_stack_seen != SIGUSR1 || !alternate_stack_active) {
        (void)sigaltstack(&old_stack, NULL);
        return fail_case("altstack", 1);
    }
    if (sigaltstack(&old_stack, NULL) != 0) {
        return fail_case("altstack", 2);
    }
    return emit("altstack: configured=1 onstack=1\n") == 0 ? 0 : 1;
}

/* pthread_kill targets a worker whose signal is blocked and then unblocked. */
static int thread_ready_fd;
static int thread_release_fd;
static int thread_result_fd;
static volatile sig_atomic_t thread_signal_seen;

static void thread_signal_handler(int signo) {
    thread_signal_seen = signo;
}

static void *thread_mask_worker(void *argument) {
    sigset_t set;
    sigset_t pending;
    char ready = '0';
    char release;
    char result[3] = {'0', '0', '0'};
    (void)argument;
    memset(&set, 0, sizeof(set));
    if (sigemptyset(&set) == 0 && sigaddset(&set, SIGUSR1) == 0 &&
        pthread_sigmask(SIG_BLOCK, &set, NULL) == 0) {
        ready = '1';
    }
    (void)write_full(thread_ready_fd, &ready, 1);
    if (read(thread_release_fd, &release, 1) == 1 && release == 'x') {
        result[0] = '1';
    }
    if (sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1) {
        result[1] = '1';
    }
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) == 0 &&
        thread_signal_seen == SIGUSR1) {
        result[2] = '1';
    }
    (void)write_full(thread_result_fd, result, sizeof(result));
    return (void *)(uintptr_t)(result[0] == '1' && result[1] == '1' &&
                                       result[2] == '1'
                                   ? 0
                                   : 1);
}

static int run_thread_mask(void) {
    int ready_pipe[2];
    int release_pipe[2];
    int result_pipe[2];
    struct sigaction action;
    pthread_t worker;
    char ready;
    char release = 'x';
    char result[3];
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = thread_signal_handler;
    if (sigaction(SIGUSR1, &action, NULL) != 0 || pipe(ready_pipe) != 0 ||
        pipe(release_pipe) != 0 || pipe(result_pipe) != 0) {
        return fail_case("thread-mask", 1);
    }
    thread_ready_fd = ready_pipe[1];
    thread_release_fd = release_pipe[0];
    thread_result_fd = result_pipe[1];
    thread_signal_seen = 0;
    if (pthread_create(&worker, NULL, thread_mask_worker, NULL) != 0) {
        return fail_case("thread-mask", 2);
    }
    int worker_ready = read_full(ready_pipe[0], &ready, 1) == 0 && ready == '1';
    close(ready_pipe[0]);
    int targeted = worker_ready && pthread_kill(worker, SIGUSR1) == 0;
    int released = write_full(release_pipe[1], &release, 1) == 0;
    close(release_pipe[1]);
    int result_ok = read_full(result_pipe[0], result, sizeof(result)) == 0;
    close(result_pipe[0]);
    void *worker_result = (void *)1;
    int joined = pthread_join(worker, &worker_result) == 0 && worker_result == 0;
    close(ready_pipe[1]);
    close(release_pipe[0]);
    close(result_pipe[1]);
    if (!worker_ready || !targeted || !released || !result_ok || !joined ||
        memcmp(result, "111", sizeof(result)) != 0) {
        return fail_case("thread-mask", 3);
    }
    return emit("thread-mask: blocked=1 pending=1 targeted=1 delivered=1\n") == 0 ? 0 : 1;
}

/* sigwait*, sigwaitinfo, and sigtimedwait consume already-pending signals. */
static int run_sigwait(void) {
    sigset_t set;
    sigset_t old_mask;
    siginfo_t info;
    struct timespec zero_timeout = {0, 0};
    int waited_signal = 0;
    if (sigemptyset(&set) != 0 || sigaddset(&set, SIGUSR1) != 0 ||
        sigprocmask(SIG_BLOCK, &set, &old_mask) != 0) {
        return fail_case("sigwait", 1);
    }
    int info_ok = raise(SIGUSR1) == 0 && sigwaitinfo(&set, &info) == SIGUSR1 &&
                  info.si_signo == SIGUSR1;
    int wait_ok = raise(SIGUSR1) == 0 && sigwait(&set, &waited_signal) == 0 &&
                  waited_signal == SIGUSR1;
    int timed_ok = raise(SIGUSR1) == 0 &&
                   sigtimedwait(&set, &info, &zero_timeout) == SIGUSR1 &&
                   info.si_signo == SIGUSR1;
    int restored = sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0;
    if (!info_ok || !wait_ok || !timed_ok || !restored) {
        return fail_case("sigwait", 2);
    }
    return emit("sigwait: sigwaitinfo=1 sigwait=1 sigtimedwait=1\n") == 0 ? 0 : 1;
}

/* A POSIX timer queues one SIGRTMIN with its configured value. */
static int run_timer(void) {
    sigset_t set;
    sigset_t old_mask;
    struct sigevent event;
    struct itimerspec expiration;
    siginfo_t info;
    timer_t timer;
    memset(&event, 0, sizeof(event));
    memset(&expiration, 0, sizeof(expiration));
    if (sigemptyset(&set) != 0 || sigaddset(&set, SIGRTMIN) != 0 ||
        sigprocmask(SIG_BLOCK, &set, &old_mask) != 0) {
        return fail_case("timer", 1);
    }
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGRTMIN;
    event.sigev_value.sival_int = 0x52;
    expiration.it_value.tv_nsec = 1;
    if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0 ||
        timer_settime(timer, 0, &expiration, NULL) != 0) {
        (void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return fail_case("timer", 2);
    }
    int delivered = sigwaitinfo(&set, &info) == SIGRTMIN;
    int correct = delivered && info.si_code == SI_TIMER &&
                  info.si_value.sival_int == 0x52;
    int deleted = timer_delete(timer) == 0;
    int restored = sigprocmask(SIG_SETMASK, &old_mask, NULL) == 0;
    if (!correct || !deleted || !restored) {
        return fail_case("timer", 3);
    }
    return emit("timer: delivered=1 queued=1\n") == 0 ? 0 : 1;
}

static int run_wait_signal(void) {
    pid_t child = fork();
    if (child < 0) {
        return fail_case("wait-signal", 1);
    }
    if (child == 0) {
        (void)signal(SIGTERM, SIG_DFL);
        (void)kill(getpid(), SIGTERM);
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGTERM) {
        return fail_case("wait-signal", 2);
    }
    return emit("wait-signal: signaled=1 status=SIGTERM\n") == 0 ? 0 : 1;
}

/* WNOHANG must report a live child, and a reaped child must become ECHILD. */
static int run_wait_nohang(void) {
    int control[2];
    if (pipe(control) != 0) {
        return fail_case("wait-nohang", 1);
    }
    pid_t child = fork();
    if (child < 0) {
        close(control[0]);
        close(control[1]);
        return fail_case("wait-nohang", 2);
    }
    if (child == 0) {
        char release;
        close(control[1]);
        ssize_t count = read(control[0], &release, 1);
        close(control[0]);
        _exit(count == 1 && release == 'x' ? 0 : 127);
    }

    close(control[0]);
    int status = 0;
    errno = 0;
    pid_t nohang = waitpid(child, &status, WNOHANG);
    int running = nohang == 0;
    char release = 'x';
    int released = write_full(control[1], &release, 1) == 0;
    close(control[1]);
    int waited = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                 WEXITSTATUS(status) == 0;
    errno = 0;
    pid_t no_child = waitpid(child, &status, WNOHANG);
    int echild = no_child == -1 && errno == ECHILD;
    if (!running || !released || !waited || !echild) {
        return fail_case("wait-nohang", 3);
    }
    return emit("wait-nohang: running=1 reaped=1 echild=1\n") == 0 ? 0 : 1;
}

/* pthread_atfork handlers have reverse prepare and forward parent/child order. */
static char atfork_prepare[8];
static char atfork_parent[8];
static char atfork_child[8];
static int atfork_prepare_count;
static int atfork_parent_count;
static int atfork_child_count;

static void atfork_prepare_a(void) { atfork_prepare[atfork_prepare_count++] = 'A'; }
static void atfork_prepare_b(void) { atfork_prepare[atfork_prepare_count++] = 'B'; }
static void atfork_prepare_c(void) { atfork_prepare[atfork_prepare_count++] = 'C'; }
static void atfork_parent_a(void) { atfork_parent[atfork_parent_count++] = 'A'; }
static void atfork_parent_b(void) { atfork_parent[atfork_parent_count++] = 'B'; }
static void atfork_parent_c(void) { atfork_parent[atfork_parent_count++] = 'C'; }
static void atfork_child_a(void) { atfork_child[atfork_child_count++] = 'A'; }
static void atfork_child_b(void) { atfork_child[atfork_child_count++] = 'B'; }
static void atfork_child_c(void) { atfork_child[atfork_child_count++] = 'C'; }

static int run_atfork(void) {
    enum { iterations = 8 };
    if (pthread_atfork(atfork_prepare_a, atfork_parent_a, atfork_child_a) != 0 ||
        pthread_atfork(atfork_prepare_b, atfork_parent_b, atfork_child_b) != 0 ||
        pthread_atfork(atfork_prepare_c, atfork_parent_c, atfork_child_c) != 0) {
        return fail_case("atfork", 1);
    }

    for (int iteration = 0; iteration < iterations; iteration++) {
        int channel[2];
        if (pipe(channel) != 0) {
            return fail_case("atfork", 2);
        }
        atfork_prepare_count = 0;
        atfork_parent_count = 0;
        atfork_child_count = 0;
        pid_t child = fork();
        if (child < 0) {
            close(channel[0]);
            close(channel[1]);
            return fail_case("atfork", 3);
        }
        if (child == 0) {
            char message[6];
            close(channel[0]);
            memcpy(message, atfork_prepare, 3);
            memcpy(message + 3, atfork_child, 3);
            (void)write_full(channel[1], message, sizeof(message));
            close(channel[1]);
            _exit(0);
        }

        close(channel[1]);
        char message[6];
        int child_message_ok = read_full(channel[0], message, sizeof(message)) == 0;
        close(channel[0]);
        int status = 0;
        int child_ok = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                       WEXITSTATUS(status) == 0;
        if (!child_message_ok || !child_ok || atfork_prepare_count != 3 ||
            atfork_parent_count != 3 || memcmp(atfork_prepare, "CBA", 3) != 0 ||
            memcmp(atfork_parent, "ABC", 3) != 0 || memcmp(message, "CBAABC", 6) != 0) {
            return fail_case("atfork", 4);
        }
    }
    return emit("atfork: iterations=8 prepare=CBA parent=ABC child=ABC\n") == 0 ? 0 : 1;
}

static int worker_ready_fd;
static int worker_release_fd;

static void *worker_main(void *argument) {
    (void)argument;
    char ready = 'r';
    char release = 0;
    int ready_ok = write_full(worker_ready_fd, &ready, 1) == 0;
    ssize_t release_count = read(worker_release_fd, &release, 1);
    return (void *)(uintptr_t)(ready_ok && release_count == 1 && release == 'x' ? 0 : 1);
}

/* A live worker exists at fork; the child only write()s, then execs itself. */
static int run_exec_check(int argc, char **argv) {
    if (argc != 3) {
        _exit(125);
    }
    char *end = NULL;
    long fd_value = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || fd_value < 0 || fd_value > 100000) {
        _exit(125);
    }
    const char message[] = "exec-ok\n";
    if (write_full((int)fd_value, message, sizeof(message) - 1) != 0) {
        _exit(126);
    }
    _exit(0);
}

static int run_fork_worker_exec(char **argv) {
    int ready_pipe[2];
    int release_pipe[2];
    int marker_pipe[2];
    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0 || pipe(marker_pipe) != 0) {
        return fail_case("fork-worker-exec", 1);
    }
    worker_ready_fd = ready_pipe[1];
    worker_release_fd = release_pipe[0];
    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        return fail_case("fork-worker-exec", 2);
    }
    char ready;
    int worker_ready = read_full(ready_pipe[0], &ready, 1) == 0 && ready == 'r';
    close(ready_pipe[0]);
    if (!worker_ready) {
        char release = 'x';
        (void)write_full(release_pipe[1], &release, 1);
        close(release_pipe[1]);
        (void)pthread_join(worker, NULL);
        close(ready_pipe[1]);
        return fail_case("fork-worker-exec", 3);
    }

    char marker_fd_text[32];
    int marker_text_length = snprintf(
        marker_fd_text, sizeof(marker_fd_text), "%d", marker_pipe[1]);
    if (marker_text_length <= 0 || (size_t)marker_text_length >= sizeof(marker_fd_text)) {
        char release = 'x';
        (void)write_full(release_pipe[1], &release, 1);
        close(release_pipe[1]);
        (void)pthread_join(worker, NULL);
        close(ready_pipe[1]);
        return fail_case("fork-worker-exec", 4);
    }
    pid_t child = fork();
    if (child < 0) {
        char release = 'x';
        (void)write_full(release_pipe[1], &release, 1);
        close(release_pipe[1]);
        (void)pthread_join(worker, NULL);
        close(ready_pipe[1]);
        return fail_case("fork-worker-exec", 5);
    }
    if (child == 0) {
        const char message[] = "child-safe\n";
        close(marker_pipe[0]);
        if (write_full(marker_pipe[1], message, sizeof(message) - 1) != 0) {
            _exit(124);
        }
        execl(argv[0], argv[0], "exec-check", marker_fd_text, (char *)NULL);
        _exit(127);
    }

    close(marker_pipe[1]);
    char marker[19];
    int marker_ok = read_full(marker_pipe[0], marker, sizeof(marker)) == 0 &&
                    memcmp(marker, "child-safe\nexec-ok\n", sizeof(marker)) == 0;
    close(marker_pipe[0]);
    int status = 0;
    int exec_ok = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0;
    char release = 'x';
    int release_ok = write_full(release_pipe[1], &release, 1) == 0;
    close(release_pipe[1]);
    void *worker_result = (void *)1;
    int join_ok = pthread_join(worker, &worker_result) == 0 && worker_result == 0;
    close(ready_pipe[1]);
    close(release_pipe[0]);
    if (!marker_ok || !exec_ok || !release_ok || !join_ok) {
        return fail_case("fork-worker-exec", 6);
    }
    return emit("fork-worker-exec: child-write=1 exec=1 worker=1\n") == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "exec-check") == 0) {
        return run_exec_check(argc, argv);
    }
    if (argc != 2) {
        return fail_case("signal-process", 1);
    }
    if (strcmp(argv[1], "siginfo") == 0) {
        return run_siginfo();
    }
    if (strcmp(argv[1], "nodefer") == 0) {
        return run_nodefer();
    }
    if (strcmp(argv[1], "mask-pending") == 0) {
        return run_mask_pending();
    }
    if (strcmp(argv[1], "sa-restart") == 0) {
        return run_sa_restart();
    }
    if (strcmp(argv[1], "altstack") == 0) {
        return run_altstack();
    }
    if (strcmp(argv[1], "thread-mask") == 0) {
        return run_thread_mask();
    }
    if (strcmp(argv[1], "sigwait") == 0) {
        return run_sigwait();
    }
    if (strcmp(argv[1], "timer") == 0) {
        return run_timer();
    }
    if (strcmp(argv[1], "wait-signal") == 0) {
        return run_wait_signal();
    }
    if (strcmp(argv[1], "wait-nohang") == 0) {
        return run_wait_nohang();
    }
    if (strcmp(argv[1], "atfork") == 0) {
        return run_atfork();
    }
    if (strcmp(argv[1], "fork-worker-exec") == 0) {
        return run_fork_worker_exec(argv);
    }
    return fail_case("signal-process", 2);
}
