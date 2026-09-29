#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Keep the pinned raise-race topology: one worker receives 100 fork signals,
 * raises 1000 other real-time signals, and waits for the handler's children.
 * The guarded mode rechecks child identity while waiting for fork signals:
 * a handler fork can copy an unfinished counter after the earlier check. */
enum { FORKS = 100, RAISES = 1000 };
static _Atomic int fork_signals;
static volatile sig_atomic_t raised_signals;
static volatile sig_atomic_t is_child;
static volatile sig_atomic_t callback_step;
static volatile sig_atomic_t callback_error;
static int fork_pids[FORKS];
static int fork_steps[FORKS];
static int fork_errors[FORKS];
static int worker_tid;
static int wait_in_main;
static int guarded_child_exit;
static int race_window_mode;
static int trace_enabled;

/* Fixed writes expose progress even when a timed-out process cannot flush
 * stdio. They are enabled only for the isolated diagnostic replay. */
#define TRACE_STAGE(message) do { \
    if (trace_enabled) { \
        static const char line[] = "stage=" message "\n"; \
        (void)write(STDERR_FILENO, line, sizeof(line) - 1); \
    } \
} while (0)

static void prepare_one(void) { if (callback_step != 1) callback_error = 1; callback_step = 2; }
static void prepare_two(void) { if (callback_step != 0) callback_error = 1; callback_step = 1; }
static void parent_one(void) { if (callback_step != 2) callback_error = 1; callback_step = 3; }
static void parent_two(void) { if (callback_step != 3) callback_error = 1; callback_step = 4; }
static void child_one(void) { if (callback_step != 2) callback_error = 1; callback_step = 3; }
static void child_two(void) { if (callback_step != 3) callback_error = 1; callback_step = 4; }

static void count_raise(int signal_number)
{
    (void)signal_number;
    raised_signals++;
}

static void fork_in_handler(int signal_number)
{
    (void)signal_number;
    int index = atomic_fetch_add_explicit(&fork_signals, 1, memory_order_relaxed);
    if (index >= FORKS) return;
    callback_step = 0;
    callback_error = 0;
    errno = 0;
    int pid = fork();
    int fork_errno = errno;
    if (pid == 0) {
        is_child = 1;
        if (callback_step != 4 || callback_error) _exit(42);
        return;
    }
    fork_pids[index] = pid;
    fork_steps[index] = callback_step;
    fork_errors[index] = pid < 0 ? fork_errno : callback_error;
}

static void print_disposition(const char *stage)
{
    struct sigaction action;
    if (sigaction(SIGCHLD, 0, &action)) _exit(90);
    printf("disposition stage=%s default=%d ignored=%d nocldwait=%d flags=%#x\n",
           stage, action.sa_handler == SIG_DFL, action.sa_handler == SIG_IGN,
           !!(action.sa_flags & SA_NOCLDWAIT), action.sa_flags);
}

static int receive_children(void)
{
    int seen[FORKS] = {0};
    int reaped = 0, echild = 0, other_error = 0, unexpected = 0, bad_status = 0;
    print_disposition("before-wait");
    TRACE_STAGE("before-wait-loop");
    for (int i = 0; i < FORKS; ++i) {
        int status = -1;
        errno = 0;
        int result = wait(&status);
        int wait_errno = errno;
        int index = -1;
        for (int j = 0; j < FORKS; ++j)
            if (fork_pids[j] == result && result > 0) { index = j; break; }
        if (result > 0) {
            ++reaped;
            if (index < 0 || seen[index]++) ++unexpected;
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) ++bad_status;
        } else if (wait_errno == ECHILD) {
            ++echild;
        } else {
            ++other_error;
        }
        int raw_status = -1;
        int raw_result = -2, raw_errno = 0;
        if (result < 0) {
            errno = 0;
            raw_result = (int)syscall(SYS_wait4, -1, &raw_status, WNOHANG, 0);
            raw_errno = errno;
        }
        printf("wait ordinal=%d pid=%d fork_index=%d status=%#x errno=%d raw=%d raw_status=%#x raw_errno=%d\n",
               i, result, index, status, wait_errno, raw_result, raw_status, raw_errno);
    }
    int missing = 0;
    for (int i = 0; i < FORKS; ++i) {
        printf("fork ordinal=%d pid=%d callback_step=%d callback_error=%d reaped=%d\n",
               i, fork_pids[i], fork_steps[i], fork_errors[i], seen[i]);
        if (fork_pids[i] <= 0 || fork_steps[i] != 4 || fork_errors[i] || !seen[i]) ++missing;
    }
    printf("summary worker_tid=%d wait_tid=%ld child=%d forks=%d raises=%d reaped=%d echild=%d other_error=%d unexpected=%d bad_status=%d missing=%d\n",
           worker_tid, syscall(SYS_gettid), is_child, atomic_load(&fork_signals), raised_signals,
           reaped, echild, other_error, unexpected, bad_status, missing);
    fflush(stdout);
    TRACE_STAGE("after-wait-loop");
    return reaped != FORKS || echild || other_error || unexpected || bad_status || missing;
}

static void *worker(void *argument)
{
    (void)argument;
    worker_tid = (int)syscall(SYS_gettid);
    if (!is_child) TRACE_STAGE("worker-start");
    for (int i = 0; i < RAISES; ++i)
        if (raise(SIGRTMIN)) _exit(91);
    if (raised_signals != RAISES) _exit(92);
    if (!is_child) TRACE_STAGE("worker-raised-all");
    if (is_child) _exit(0);
    /* This diagnostic fork is issued after the original child check. Its
     * child copies fewer than 100 fork signals and must exit inside the loop. */
    if (race_window_mode) {
        TRACE_STAGE("worker-race-window");
        if (raise(SIGRTMIN + 1)) _exit(93);
    }
    while (atomic_load_explicit(&fork_signals, memory_order_relaxed) < FORKS) {
        if (guarded_child_exit && is_child) _exit(0);
    }
    if (!is_child) TRACE_STAGE("worker-fork-signals-all");
    if (guarded_child_exit && is_child) _exit(0);
    if (wait_in_main) {
        if (!is_child) TRACE_STAGE("worker-return-main");
        return 0;
    }
    return (void *)(long)receive_children();
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "worker-wait") && strcmp(argv[1], "main-wait") &&
                      strcmp(argv[1], "worker-wait-guarded") && strcmp(argv[1], "main-wait-guarded") &&
                      strcmp(argv[1], "main-wait-race-window") &&
                      strcmp(argv[1], "main-wait-guarded-race-window"))) return 2;
    wait_in_main = !strncmp(argv[1], "main-wait", 9);
    guarded_child_exit = strstr(argv[1], "-guarded") != 0;
    race_window_mode = strstr(argv[1], "-race-window") != 0;
    trace_enabled = getenv("CRABC_SIGNAL_FORK_TRACE") != 0;
    if (pthread_atfork(prepare_one, parent_one, child_one) ||
        pthread_atfork(prepare_two, parent_two, child_two)) return 3;
    struct sigaction action = {0};
    action.sa_handler = count_raise;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGRTMIN, &action, 0)) return 4;
    action.sa_handler = fork_in_handler;
    if (sigaction(SIGRTMIN + 1, &action, 0)) return 5;
    print_disposition("before-create");
    TRACE_STAGE("main-before-create");
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 6;
    TRACE_STAGE("main-after-create");
    int first_signals = race_window_mode ? FORKS / 2 : FORKS;
    for (int i = 0; i < first_signals; ++i)
        if (pthread_kill(thread, SIGRTMIN + 1)) return 7;
    if (race_window_mode) {
        while (atomic_load_explicit(&fork_signals, memory_order_relaxed) <= first_signals) { }
        TRACE_STAGE("main-race-fork-seen");
        for (int i = first_signals + 1; i < FORKS; ++i)
            if (pthread_kill(thread, SIGRTMIN + 1)) return 7;
    }
    TRACE_STAGE("main-sent-fork-signals");
    void *worker_result = 0;
    TRACE_STAGE("main-before-join");
    if (pthread_join(thread, &worker_result)) return 8;
    TRACE_STAGE("main-after-join");
    if (wait_in_main) return receive_children();
    return (int)(long)worker_result;
}
