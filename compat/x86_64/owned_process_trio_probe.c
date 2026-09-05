#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { dprintf(2, "process trio line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)
static volatile int callbacks;
static void hook(void) { callbacks++; }
static pthread_key_t key;
static void *child_worker(void *arg) { return arg; }
static int child(void *arg) {
    sigset_t mask;
    CHECK(callbacks == 0);
    CHECK(pthread_getspecific(key) == arg);
    CHECK(pthread_sigmask(SIG_SETMASK, 0, &mask) == 0);
    CHECK(sigismember(&mask, SIGUSR1) == 1);
    CHECK(sigismember(&mask, SIGUSR2) == 0);
    pthread_t worker; void *result;
    CHECK(pthread_create(&worker, 0, child_worker, arg) == 0);
    CHECK(pthread_join(worker, &result) == 0 && result == arg);
    return 37;
}
static int raw_child(void *arg) {
    /* CLONE_VM has vfork's restricted context; touch only caller-owned data. */
    *(volatile int *)arg = 73;
    return 29;
}
static void wait_for(pid_t pid, int expected) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}
static int child_tid_callback(void *arg) {
    CHECK(*(int *)arg == syscall(SYS_gettid));
    return 23;
}
static void *clone_cases(void *unused) {
    (void)unused;
    size_t length = 1024 * 1024;
    char *stack = mmap(0, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    CHECK(pthread_setspecific(key, (void *)0x1234) == 0);
    sigset_t blocked, old;
    sigemptyset(&blocked); sigaddset(&blocked, SIGUSR1);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, &old) == 0);
    int flags[] = { CLONE_THREAD, CLONE_SETTLS, CLONE_CHILD_CLEARTID };
    for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
        errno = 0;
        CHECK(clone(child, stack + length, flags[i] | SIGCHLD, (void *)0x1234) == -1 && errno == EINVAL);
    }
    CHECK(clone(child, 0, SIGCHLD, (void *)0x1234) == -1 && errno == EINVAL);
    CHECK(clone(0, 0, SIGCHLD, 0) == -1 && errno == EINVAL);
    CHECK(clone(0, stack + length, SIGCHLD | CLONE_THREAD, 0) == -1 && errno == EINVAL);
    errno = EDOM;
    pid_t pid = clone(child, stack + length - 3, SIGCHLD, (void *)0x1234);
    CHECK(pid > 0 && errno == EDOM); wait_for(pid, 37);
    int parent_tid = -1, child_tid = -1;
    pid = clone(child, stack + length, SIGCHLD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID,
        (void *)0x1234, &parent_tid, (void *)0, &child_tid);
    CHECK(pid > 0 && parent_tid == pid && child_tid == -1); wait_for(pid, 37);
    int only_child_tid = -1;
    pid = clone(child_tid_callback, stack + length, SIGCHLD | CLONE_CHILD_SETTID,
        &only_child_tid, (void *)0, (void *)0, &only_child_tid);
    CHECK(pid > 0 && only_child_tid == -1); wait_for(pid, 23);
    int pidfd = -1;
    pid = clone(child, stack + length, SIGCHLD | CLONE_PIDFD, (void *)0x1234, &pidfd);
    CHECK(pid > 0 && pidfd >= 0 && (fcntl(pidfd, F_GETFD) & FD_CLOEXEC));
    wait_for(pid, 37); CHECK(close(pidfd) == 0);
    CHECK(clone(child, stack + length, SIGCHLD | CLONE_PIDFD | CLONE_PARENT_SETTID,
        (void *)0x1234, &parent_tid) == -1 && errno == EINVAL);
    volatile int shared = 0;
    pid = clone(raw_child, stack + length, SIGCHLD | CLONE_VM | CLONE_VFORK, (void *)&shared);
    CHECK(pid > 0 && shared == 73); wait_for(pid, 29);
    CHECK(callbacks == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &old, 0) == 0);
    CHECK(munmap(stack, length) == 0);
    return 0;
}
struct nested_robust {
    pthread_mutex_t first, second;
    char *stack;
};
static int nested_robust_grandchild(void *arg) {
    struct nested_robust *state = arg;
    CHECK(pthread_mutex_lock(&state->second) == 0);
    struct kernel_robust_head { void *next; long offset; void *pending; } *head;
    size_t length;
    CHECK(syscall(SYS_get_robust_list, 0, &head, &length) == 0);
    CHECK(head != 0 && length == sizeof *head);
    void *node = head->next;
    unsigned count = 0;
    while (node != head && count < 4) { node = *(void **)node; count++; }
    /* _Fork preserves the inherited linked head, even though its previous
     * lock still belongs to the previous process's TID. */
    CHECK(node == head && count == 2);
    CHECK(pthread_mutex_unlock(&state->second) == 0);
    return 0;
}
static int nested_robust_child(void *arg) {
    struct nested_robust *state = arg;
    CHECK(pthread_mutex_lock(&state->first) == 0);
    pid_t pid = clone(nested_robust_grandchild, state->stack + 1024 * 1024,
        SIGCHLD, state);
    CHECK(pid > 0); wait_for(pid, 0);
    CHECK(pthread_mutex_unlock(&state->first) == 0);
    return 0;
}
static void *nested_robust_worker(void *arg) {
    struct nested_robust *state = arg;
    pid_t pid = clone(nested_robust_child, state->stack + 2 * 1024 * 1024,
        SIGCHLD, state);
    CHECK(pid > 0); wait_for(pid, 0);
    return 0;
}
static void nested_robust_case(void) {
    struct nested_robust state;
    state.stack = mmap(0, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(state.stack != MAP_FAILED);
    pthread_mutexattr_t attr;
    CHECK(pthread_mutexattr_init(&attr) == 0);
    CHECK(pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) == 0);
    CHECK(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&state.first, &attr) == 0);
    CHECK(pthread_mutex_init(&state.second, &attr) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, nested_robust_worker, &state) == 0);
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(munmap(state.stack, 2 * 1024 * 1024) == 0);
}
static void vfork_cases(void) {
    volatile int shared = 0;
    pid_t pid = vfork();
    if (pid == 0) { shared = 91; _exit(43); }
    CHECK(pid > 0 && shared == 91); wait_for(pid, 43);
    CHECK(callbacks == 0);
    pid = vfork();
    if (pid == 0) {
        char *arguments[] = {"/consumer", "exec-child", 0};
        char *environment[] = {0};
        execve(arguments[0], arguments, environment);
        _exit(99);
    }
    CHECK(pid > 0); wait_for(pid, 43);
}
static void daemon_cases(int redirect) {
    /* Subreaper plus pipe makes both intermediate exits observable. */
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    int pipefd[2]; CHECK(pipe(pipefd) == 0);
    pid_t pid = fork(); CHECK(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        CHECK(chdir("/state") == 0);
        callbacks = 0;
        CHECK(daemon(redirect, !redirect) == 0);
        char cwd[32]; CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, redirect ? "/state" : "/"));
        if (redirect) {
            struct stat device, observed;
            CHECK(stat("/dev/null", &device) == 0);
            for (int fd = 0; fd < 3; fd++) {
                CHECK(fstat(fd, &observed) == 0);
                CHECK(observed.st_dev == device.st_dev && observed.st_ino == device.st_ino);
                CHECK((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);
            }
        }
        CHECK(getsid(0) != getpid());
        CHECK(callbacks == 4); /* prepare+child for each fork */
        CHECK(write(pipefd[1], "D", 1) == 1);
        _exit(0);
    }
    close(pipefd[1]);
    char byte; CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'D'); close(pipefd[0]);
    int status, count = 0;
    while ((pid = waitpid(-1, &status, 0)) > 0) { CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0); count++; }
    CHECK(errno == ECHILD && count == 3);
}
/* Linux 5.10 sock_filter/sock_fprog wire shape; deny only named calls in
 * this disposable process so every raw-error rollback is deterministic. */
static void deny_process_syscalls(void) {
    struct instruction { unsigned short code; unsigned char yes, no; unsigned value; };
    struct program { unsigned short length; struct instruction *instructions; };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0},
        {0x15, 3, 0, SYS_clone},
        {0x15, 2, 0, SYS_vfork},
        {0x15, 1, 0, SYS_fork},
        {0x06, 0, 0, 0x7fff0000},
        {0x06, 0, 0, 0x00050000 | EAGAIN},
    };
    struct program filter = {sizeof instructions / sizeof *instructions, instructions};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &filter) == 0);
}
static void error_cases(void) {
    CHECK(chdir("/state") == 0);
    CHECK(rename("/dev/null", "/dev/saved-null") == 0);
    errno = 0;
    CHECK(daemon(1, 0) == -1 && errno == ENOENT && callbacks == 0);
    CHECK(rename("/dev/saved-null", "/dev/null") == 0);
    char *stack = mmap(0, 1024 * 1024, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    sigset_t before, after;
    CHECK(pthread_sigmask(SIG_SETMASK, 0, &before) == 0);
    deny_process_syscalls();
    CHECK(clone(raw_child, stack + 1024 * 1024, SIGCHLD, 0) == -1 && errno == EAGAIN);
    CHECK(clone(raw_child, stack + 1024 * 1024, SIGCHLD | CLONE_VM, 0) == -1 && errno == EAGAIN);
    CHECK(pthread_sigmask(SIG_SETMASK, 0, &after) == 0);
    for (int sig = 1; sig < 65; sig++) CHECK(sigismember(&before, sig) == sigismember(&after, sig));
    CHECK(vfork() == -1 && errno == EAGAIN && callbacks == 0);
    CHECK(daemon(0, 1) == -1 && errno == EAGAIN && callbacks == 2);
    char cwd[8]; CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, "/"));
    /* A second failed non-VM call proves the abort lock was released. */
    CHECK(clone(raw_child, stack + 1024 * 1024, SIGCHLD, 0) == -1 && errno == EAGAIN);
}
static atomic_int sibling_running;
static void *sibling(void *unused) {
    (void)unused;
    while (atomic_load(&sibling_running)) sched_yield();
    return 0;
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "exec-child")) return 43;
    CHECK(pthread_atfork(hook, hook, hook) == 0);
    CHECK(pthread_key_create(&key, 0) == 0);
    if (argc > 1 && !strcmp(argv[1], "errors")) {
        error_cases(); puts("owned-process-trio-errors-ok"); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "redirect")) {
        daemon_cases(1); puts("owned-process-trio-redirect-ok"); return 0;
    }
    pthread_t other;
    atomic_store(&sibling_running, 1);
    CHECK(pthread_create(&other, 0, sibling, 0) == 0);
    clone_cases(0);
    pthread_t worker; CHECK(pthread_create(&worker, 0, clone_cases, 0) == 0);
    CHECK(pthread_join(worker, 0) == 0);
    nested_robust_case();
    atomic_store(&sibling_running, 0);
    CHECK(pthread_join(other, 0) == 0);
    vfork_cases();
    daemon_cases(0);
    puts("owned-process-trio-ok");
    return 0;
}
