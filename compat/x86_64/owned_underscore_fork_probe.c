#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { dprintf(2, "underscore fork line %d errno %d\n", __LINE__, errno); _Exit(1); } } while (0)
static volatile sig_atomic_t callbacks;
static _Thread_local int tls_value;
static atomic_int signal_completed;
static atomic_int signal_failures;
static atomic_int stop;
struct robust_head { void *next; long offset; void *pending; };
static _Thread_local struct robust_head *inherited_robust;
static _Thread_local void *inherited_robust_next;
static void hook(void) { callbacks++; }
static void wait_for(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 37);
}
/* Child reads inherited caller data, checks mask, then execs. No allocation,
 * stdio, loader mutation, or user cleanup runs in this restricted child. */
static pid_t transition(void) {
    pthread_t identity = pthread_self();
    pid_t pid = _Fork();
    if (!pid) {
        sigset_t mask;
        if (callbacks || tls_value != 73 || pthread_self() != identity) _Exit(91);
        /* Inspect already captured caller memory; do not invoke a mutex API
         * in this restricted child. Source __post_Fork retains the list but
         * clears its registration offset and in-flight transition. */
        if (inherited_robust && (inherited_robust->next != inherited_robust_next
            || inherited_robust->offset || inherited_robust->pending)) _Exit(94);
        if (sigprocmask(SIG_SETMASK, 0, &mask) || !sigismember(&mask, SIGUSR1)) _Exit(92);
        char *args[] = {"/consumer", "exec-child", 0};
        char *env[] = {0};
        execve(args[0], args, env);
        _Exit(93);
    }
    return pid;
}
static void *worker(void *arg) {
    (void)arg;
    pthread_mutex_t *mutex = mmap(0, sizeof *mutex, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(mutex != MAP_FAILED);
    pthread_mutexattr_t attributes;
    CHECK(pthread_mutexattr_init(&attributes) == 0);
    CHECK(pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST) == 0);
    CHECK(pthread_mutex_init(mutex, &attributes) == 0);
    CHECK(pthread_mutex_lock(mutex) == 0);
    size_t length;
    CHECK(syscall(SYS_get_robust_list, 0, &inherited_robust, &length) == 0);
    CHECK(inherited_robust && length == sizeof *inherited_robust);
    inherited_robust_next = inherited_robust->next;
    CHECK(inherited_robust_next != inherited_robust);
    tls_value = 73; errno = EDOM;
    pid_t pid = transition();
    CHECK(pid > 0 && errno == EDOM && callbacks == 0 && tls_value == 73);
    wait_for(pid);
    CHECK(pthread_mutex_unlock(mutex) == 0);
    CHECK(pthread_mutex_destroy(mutex) == 0);
    CHECK(pthread_mutexattr_destroy(&attributes) == 0);
    CHECK(munmap(mutex, sizeof *mutex) == 0);
    inherited_robust = 0;
    return 0;
}
static void handler(int sig) {
    (void)sig; int saved = errno;
    pid_t pid = transition();
    int status = 0;
    pid_t waited;
    do { waited = pid > 0 ? waitpid(pid, &status, 0) : -1; }
    while (waited < 0 && errno == EINTR);
    if (pid <= 0 || waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 37)
        atomic_fetch_add(&signal_failures, 1);
    atomic_fetch_add(&signal_completed, 1);
    errno = saved;
}
static void *empty(void *arg) { return arg; }
static void *churn(void *arg) {
    (void)arg; tls_value = 73;
    atomic_store(&signal_completed, 0);
    while (!atomic_load(&stop)) {
        pthread_t task;
        CHECK(pthread_create(&task, 0, empty, 0) == 0);
        CHECK(pthread_join(task, 0) == 0);
    }
    return 0;
}
static void signal_cases(void) {
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR2, &action, 0) == 0);
    pthread_t task;
    atomic_store(&signal_completed, -1);
    CHECK(pthread_create(&task, 0, churn, 0) == 0);
    while (atomic_load(&signal_completed) < 0) sched_yield();
    tls_value = 73;
    /* Deliver directly to the creator/reaper, exercising interruptions of
     * registry activity on a worker. This does not claim a deterministic
     * collision with the precise lock-holding instruction. */
    for (int i = 0; i < 32; i++) {
        CHECK(pthread_kill(task, SIGUSR2) == 0);
        while (atomic_load(&signal_completed) != i + 1) sched_yield();
        CHECK(!atomic_load(&signal_failures));
    }
    CHECK(raise(SIGUSR2) == 0);
    CHECK(atomic_load(&signal_completed) == 33 && !atomic_load(&signal_failures));
    atomic_store(&stop, 1); CHECK(pthread_join(task, 0) == 0);
}
static void error_cases(void) {
    struct instruction { unsigned short code; unsigned char yes, no; unsigned value; };
    struct program { unsigned short length; struct instruction *instructions; };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0}, {0x15, 1, 0, SYS_fork},
        {0x06, 0, 0, 0x7fff0000}, {0x06, 0, 0, 0x00050000 | EAGAIN},
    };
    struct program filter = {sizeof instructions / sizeof *instructions, instructions};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &filter) == 0);
    for (int i = 0; i < 2; i++) {
        errno = 0; CHECK(_Fork() == -1 && errno == EAGAIN && callbacks == 0);
        sigset_t mask; CHECK(pthread_sigmask(SIG_SETMASK, 0, &mask) == 0);
        CHECK(sigismember(&mask, SIGUSR1) && !sigismember(&mask, SIGUSR2));
    }
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "exec-child")) _Exit(37);
    CHECK(pthread_atfork(hook, hook, hook) == 0);
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked, SIGUSR1);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, 0) == 0);
    if (argc > 1 && !strcmp(argv[1], "errors")) error_cases();
    else if (argc > 1 && !strcmp(argv[1], "signal")) signal_cases();
    else {
        worker(0); pthread_t task;
        CHECK(pthread_create(&task, 0, worker, 0) == 0);
        CHECK(pthread_join(task, 0) == 0);
    }
    CHECK(callbacks == 0); puts("owned-underscore-fork-ok"); return 0;
}
