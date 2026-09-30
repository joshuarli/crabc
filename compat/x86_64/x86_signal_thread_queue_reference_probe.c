/* Pinned-musl/raw same-process Linux/x86-64 thread-queue control. */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native little-endian Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

_Static_assert(SYS_rt_tgsigqueueinfo == 297 && SYS_gettid == 186,
    "x86-64 thread-queue syscall numbers");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
    "x86-64 signal-information record");

struct worker_context {
    int ready_write;
    int release_read;
    int result;
};

static int queue_thread(pid_t tid, int member, int value)
{
    siginfo_t info = {0};
    info.si_signo = member;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();
    info.si_value.sival_int = value;
    return syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, member, &info);
}

static int check(const siginfo_t *info, int member, int value)
{
    return info->si_signo == member && info->si_errno == 0 && info->si_code == SI_QUEUE &&
        info->si_pid == getpid() && info->si_uid == getuid() && info->si_value.sival_int == value;
}

static void *worker(void *argument)
{
    struct worker_context *context = argument;
    pid_t tid = syscall(SYS_gettid);
    sigset_t pending, realtime, ordinary;
    siginfo_t info;
    struct timespec zero = {0};
    const int values[] = { INT_MIN, INT_MAX, -1234567 };
    unsigned char release;

    context->result = 1;
    if (tid == getpid() || write(context->ready_write, &tid, sizeof tid) != sizeof tid ||
        read(context->release_read, &release, 1) != 1)
        return 0;
    if (sigpending(&pending) || sigismember(&pending, SIGRTMIN) != 1 ||
        sigismember(&pending, SIGUSR1) != 1)
        return 0;
    if (sigemptyset(&realtime) || sigaddset(&realtime, SIGRTMIN) ||
        sigemptyset(&ordinary) || sigaddset(&ordinary, SIGUSR1))
        return 0;
    for (unsigned i = 0; i < sizeof values / sizeof values[0]; ++i) {
        if (sigtimedwait(&realtime, &info, &zero) != SIGRTMIN || !check(&info, SIGRTMIN, values[i]))
            return 0;
    }
    if (sigwaitinfo(&ordinary, &info) != SIGUSR1 || !check(&info, SIGUSR1, 11) ||
        sigtimedwait(&ordinary, &info, &zero) != -1 || errno != EAGAIN)
        return 0;
    if (sigpending(&pending) || sigismember(&pending, SIGRTMIN) != 0 ||
        sigismember(&pending, SIGUSR1) != 0 || syscall(SYS_gettid) != tid)
        return 0;
    context->result = 0;
    return 0;
}

int main(void)
{
    int ready[2], release[2];
    pthread_t thread;
    struct worker_context context;
    pid_t tid;
    sigset_t selected, original_mask, pending;
    siginfo_t info;
    struct timespec zero = {0};
    const int values[] = { INT_MIN, INT_MAX, -1234567 };
    unsigned char go = 1;

    if (sigemptyset(&selected) || sigaddset(&selected, SIGUSR1) || sigaddset(&selected, SIGRTMIN) ||
        pthread_sigmask(SIG_BLOCK, &selected, &original_mask) || pipe(ready) || pipe(release))
        return 1;
    context = (struct worker_context){ .ready_write = ready[1], .release_read = release[0] };
    if (pthread_create(&thread, 0, worker, &context) || read(ready[0], &tid, sizeof tid) != sizeof tid)
        return 2;
    for (unsigned i = 0; i < sizeof values / sizeof values[0]; ++i) {
        errno = 1234;
        if (queue_thread(tid, SIGRTMIN, values[i]) || errno != 1234)
            return 3;
    }
    if (queue_thread(tid, SIGUSR1, 11) || queue_thread(tid, SIGUSR1, 22) ||
        sigpending(&pending) || sigismember(&pending, SIGRTMIN) != 0 ||
        sigismember(&pending, SIGUSR1) != 0 ||
        sigtimedwait(&selected, &info, &zero) != -1 || errno != EAGAIN)
        return 4;
    if (write(release[1], &go, 1) != 1 || pthread_join(thread, 0) || context.result)
        return 5;
    /* Joining user code can precede kernel TID retirement. No new worker is
     * created while this scoped task-membership observation finishes. */
    char task[64];
    struct timespec start, now;
    snprintf(task, sizeof task, "/proc/self/task/%d", tid);
    if (clock_gettime(CLOCK_MONOTONIC, &start))
        return 8;
    while (access(task, F_OK) == 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 5)
            return 8;
        sched_yield();
    }
    if (errno != ENOENT)
        return 8;
    int stale_result = queue_thread(tid, SIGRTMIN, 0);
    int stale_errno = errno;
    int absent_result = queue_thread(INT_MAX, SIGRTMIN, 0);
    int absent_errno = errno;
    if (stale_result != -1 || stale_errno != ESRCH || absent_result != -1 || absent_errno != ESRCH) {
        fprintf(stderr, "threadqueue error observations: stale=%d errno=%d absent=%d errno=%d\n",
            stale_result, stale_errno, absent_result, absent_errno);
        return 6;
    }
    if (queue_thread(syscall(SYS_gettid), SIGRTMIN, 7654321) ||
        sigtimedwait(&selected, &info, &zero) != SIGRTMIN || !check(&info, SIGRTMIN, 7654321) ||
        pthread_sigmask(SIG_SETMASK, &original_mask, 0))
        return 7;
    puts("threadqueue=297 target=known-worker,self pending=thread-only values=realtime-fifo,ordinary-first metadata=SI_QUEUE,pid,uid errors=ESRCH");
    return 0;
}
