/* Pinned-musl/raw Linux/x86-64 exact-thread signal-delivery reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
               "x86 int and pid_t width");
_Static_assert(sizeof(sig_atomic_t) == sizeof(pid_t),
               "x86 signal-handler TID width");
_Static_assert(SYS_tkill == 200 && SYS_tgkill == 234 && SYS_gettid == 186,
               "x86 thread-signal syscall numbers");
_Static_assert(SIGUSR1 == 10, "x86 SIGUSR1 number");

enum invocation {
    INVOCATION_RAW_TGKILL,
    INVOCATION_MUSL_PTHREAD_KILL,
};

struct worker_context {
    int ready_write;
    int release_read;
    int result_write;
};

struct worker_ready {
    pid_t tid;
};

struct worker_result {
    unsigned char pending;
    unsigned char delivered;
    unsigned char handler_tid;
};

/*
 * The handler records only sig_atomic_t state. SYS_gettid is deliberately a
 * direct Linux evidence probe so the worker can prove the handler's actual
 * delivery TID; it is not a general signal-handler implementation pattern.
 */
static volatile sig_atomic_t delivered_signal;
static volatile sig_atomic_t handler_tid;

static void signal_handler(int signal)
{
    handler_tid = (sig_atomic_t)syscall(SYS_gettid);
    delivered_signal = signal;
}

static int read_full(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length != 0) {
        ssize_t result = read(fd, cursor, length);

        if (result > 0) {
            cursor += result;
            length -= (size_t)result;
            continue;
        }
        if (result == -1 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int write_full(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length != 0) {
        ssize_t result = write(fd, cursor, length);

        if (result > 0) {
            cursor += result;
            length -= (size_t)result;
            continue;
        }
        if (result == -1 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

/*
 * The main thread blocks SIGUSR1 before creating this worker, so both threads
 * have it blocked. After the caller targets this worker, its pending set proves
 * that the signal was queued for this particular live TID; unblocking then
 * proves delivery in that worker. The process-wide disposition is contained in
 * a disposable process below.
 */
static void *target_worker(void *argument)
{
    const struct worker_context *context = argument;
    struct worker_ready ready;
    struct worker_result result = { 0, 0, 0 };
    sigset_t target_set;
    sigset_t pending_set;
    char release;
    unsigned int tries;

    ready.tid = (pid_t)syscall(SYS_gettid);
    if (ready.tid <= 0 || sigemptyset(&target_set) != 0 ||
        sigaddset(&target_set, SIGUSR1) != 0 ||
        pthread_sigmask(SIG_BLOCK, &target_set, NULL) != 0 ||
        !write_full(context->ready_write, &ready, sizeof(ready)))
        return (void *)(uintptr_t)1;

    if (!read_full(context->release_read, &release, sizeof(release)) ||
        release != 'R')
        return (void *)(uintptr_t)1;

    if (sigpending(&pending_set) == 0 &&
        sigismember(&pending_set, SIGUSR1) == 1)
        result.pending = 1;

    if (pthread_sigmask(SIG_UNBLOCK, &target_set, NULL) != 0)
        return (void *)(uintptr_t)1;
    for (tries = 0; tries != 1024 && delivered_signal != SIGUSR1; ++tries)
        (void)sched_yield();
    if (delivered_signal == SIGUSR1) result.delivered = 1;
    if (handler_tid == (sig_atomic_t)ready.tid) result.handler_tid = 1;

    if (!write_full(context->result_write, &result, sizeof(result)))
        return (void *)(uintptr_t)1;
    return result.pending && result.delivered && result.handler_tid ? NULL
                                                                   : (void *)(uintptr_t)1;
}

static int raw_missing_tid_is_esrch(pid_t tgid)
{
    errno = 0;
    return syscall(SYS_tgkill, tgid, INT_MAX, SIGUSR1) == -1 &&
           errno == ESRCH;
}

static int raw_invalid_signal_is_einval(pid_t tgid, pid_t tid)
{
    /* Linux valid signal numbers stop at 64, so 65 is direct EINVAL input. */
    errno = 0;
    return syscall(SYS_tgkill, tgid, tid, 65) == -1 && errno == EINVAL;
}

/*
 * The raw arm calls exactly SYS_tgkill. musl 1.2.6 deliberately has no public
 * tgkill C API: its public pthread_kill implementation in
 * src/thread/pthread_kill.c uses SYS_tkill. That arm is therefore an adjacent
 * pinned-musl target-thread behavior oracle, not an assertion of tgkill API
 * equivalence or selection of pthread cancellation/signal-management APIs.
 */
static int run_targeted_delivery(enum invocation invocation)
{
    int ready_pipe[2];
    int release_pipe[2];
    int result_pipe[2];
    struct worker_context context;
    struct worker_ready ready;
    struct worker_result result;
    struct sigaction action = { 0 };
    struct sigaction old_action;
    sigset_t target_set;
    sigset_t old_set;
    pthread_t worker;
    void *worker_result;
    char release = 'R';
    pid_t tgid;

    delivered_signal = 0;
    handler_tid = 0;
    if (sigemptyset(&target_set) != 0 ||
        sigaddset(&target_set, SIGUSR1) != 0)
        return 10;

    action.sa_handler = signal_handler;
    action.sa_flags = 0;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGUSR1, &action, &old_action) != 0 ||
        sigprocmask(SIG_BLOCK, &target_set, &old_set) != 0)
        return 11;

    if (pipe(ready_pipe) != 0 || pipe(release_pipe) != 0 ||
        pipe(result_pipe) != 0)
        return 12;

    context.ready_write = ready_pipe[1];
    context.release_read = release_pipe[0];
    context.result_write = result_pipe[1];
    if (pthread_create(&worker, NULL, target_worker, &context) != 0)
        return 13;

    if (!read_full(ready_pipe[0], &ready, sizeof(ready))) return 14;
    tgid = getpid();
    if (ready.tid <= 0 || ready.tid == tgid) return 15;

    if (invocation == INVOCATION_RAW_TGKILL) {
        if (syscall(SYS_tgkill, tgid, ready.tid, SIGUSR1) != 0 ||
            !raw_missing_tid_is_esrch(tgid) ||
            !raw_invalid_signal_is_einval(tgid, ready.tid))
            return 16;
    } else if (pthread_kill(worker, SIGUSR1) != 0) {
        return 17;
    }

    if (!write_full(release_pipe[1], &release, sizeof(release)) ||
        !read_full(result_pipe[0], &result, sizeof(result)) ||
        pthread_join(worker, &worker_result) != 0 || worker_result != NULL ||
        !result.pending || !result.delivered || !result.handler_tid)
        return 18;

    if (sigprocmask(SIG_SETMASK, &old_set, NULL) != 0 ||
        sigaction(SIGUSR1, &old_action, NULL) != 0)
        return 19;
    return 0;
}

static int run_in_child(enum invocation invocation)
{
    int status;
    pid_t child = fork();

    if (child < 0) return -1;
    if (child == 0) _exit(run_targeted_delivery(invocation));
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int main(void)
{
    if (run_in_child(INVOCATION_RAW_TGKILL) != 0 ||
        run_in_child(INVOCATION_MUSL_PTHREAD_KILL) != 0)
        return 1;

    puts("tgkill=234 gettid=186 sigusr1=10 raw=live-worker:pending:handler-tid:delivered musl=pthread_kill-tkill:live-worker:pending:handler-tid:delivered errors=ESRCH,EINVAL child-contained c-api-tgkill=absent");
    return 0;
}
