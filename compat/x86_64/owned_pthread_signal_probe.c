/* Ordinary pthread signal delivery over the installed owned runtime.
 * Pinned musl 1.2.6 pthread_kill.c is the behavior oracle. A joinable worker's
 * handle remains valid after Linux task retirement and before its one join.
 * /proc observes that retirement without interpreting either libc's TCB. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "pthread-signal:%d errno=%d\n", __LINE__, errno); return 1; \
} } while (0)

struct worker_state {
    atomic_int ready;
    pthread_t handle;
    long tid;
};

static int receive_signal(struct worker_state *state)
{
    sigset_t signals;
    if (sigemptyset(&signals) || sigaddset(&signals, SIGUSR1)) return 1;
    state->handle = pthread_self();
    state->tid = syscall(SYS_gettid);
    atomic_store_explicit(&state->ready, 1, memory_order_release);
    const struct timespec deadline = { 5, 0 };
    siginfo_t information;
    int result = sigtimedwait(&signals, &information, &deadline);
    return result != SIGUSR1 || information.si_signo != SIGUSR1
        || information.si_code != SI_TKILL || information.si_pid != getpid();
}

static void *pthread_receiver(void *opaque)
{
    return (void *)(intptr_t)receive_signal(opaque);
}

static int c11_receiver(void *opaque)
{
    return receive_signal(opaque);
}

static int wait_for_ready(struct worker_state *state)
{
    const struct timespec pause = { 0, 1000000 };
    for (int retry = 0; retry < 5000; ++retry) {
        if (atomic_load_explicit(&state->ready, memory_order_acquire)) return 0;
        if (nanosleep(&pause, NULL)) return 1;
    }
    return 1;
}

static int wait_for_kernel_exit(long tid)
{
    char path[80];
    snprintf(path, sizeof path, "/proc/self/task/%ld", tid);
    const struct timespec pause = { 0, 1000000 };
    for (int retry = 0; retry < 5000; ++retry) {
        struct stat status;
        if (stat(path, &status)) return errno != ENOENT;
        if (nanosleep(&pause, NULL)) return 1;
    }
    return 1;
}

static int deliver_to_worker(int c11)
{
    struct worker_state state = { 0 };
    pthread_t worker;
    thrd_t c11_worker;
    if (c11) CHECK(thrd_create(&c11_worker, c11_receiver, &state) == thrd_success);
    else CHECK(pthread_create(&worker, NULL, pthread_receiver, &state) == 0);
    CHECK(wait_for_ready(&state) == 0);
    errno = ERANGE;
    CHECK(pthread_kill(state.handle, 0) == 0 && errno == ERANGE);
    CHECK(pthread_kill(state.handle, -1) == EINVAL && errno == ERANGE);
    CHECK(pthread_kill(state.handle, 65) == EINVAL && errno == ERANGE);
    CHECK(pthread_kill(state.handle, SIGUSR1) == 0 && errno == ERANGE);
    CHECK(wait_for_kernel_exit(state.tid) == 0);
    errno = ERANGE;
    CHECK(pthread_kill(state.handle, 0) == 0 && errno == ERANGE);
    CHECK(pthread_kill(state.handle, SIGUSR1) == 0 && errno == ERANGE);
    CHECK(pthread_kill(state.handle, -1) == EINVAL && errno == ERANGE);
    CHECK(pthread_kill(state.handle, 65) == EINVAL && errno == ERANGE);
    if (c11) {
        int result;
        CHECK(thrd_join(c11_worker, &result) == thrd_success && result == 0);
    } else {
        void *result;
        CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    }
    return 0;
}

static volatile sig_atomic_t self_deliveries;
static void receive_self(int signal)
{
    if (signal == SIGUSR2) ++self_deliveries;
}

int main(void)
{
    sigset_t signals, saved, observed;
    CHECK(sigemptyset(&signals) == 0 && sigaddset(&signals, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &signals, &saved) == 0);
    struct sigaction action = { 0 }, old_action;
    action.sa_handler = receive_self;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR2, &action, &old_action) == 0);
    CHECK(sigemptyset(&signals) == 0 && sigaddset(&signals, SIGUSR2) == 0);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &signals, NULL) == 0);
    errno = ERANGE;
    CHECK(pthread_kill(pthread_self(), SIGUSR2) == 0 && errno == ERANGE);
    CHECK(self_deliveries == 1);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &observed) == 0);
    CHECK(sigismember(&observed, SIGUSR1) == 1);
    CHECK(sigismember(&observed, SIGUSR2) == 0);
    CHECK(deliver_to_worker(0) == 0);
    CHECK(deliver_to_worker(1) == 0);
    CHECK(sigaction(SIGUSR2, &old_action, NULL) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &saved, NULL) == 0);
    return 0;
}
