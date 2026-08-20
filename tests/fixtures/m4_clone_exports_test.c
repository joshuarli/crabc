#define _GNU_SOURCE 1

#include <errno.h>
#include <pthread_atfork.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern pthread_t pthread_self(void);

#define STACK_SIZE (64 * 1024)

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static int callback(void *arg)
{
    return *(int *)arg;
}

static volatile int clone_atfork_state;

static void clone_prepare(void) { clone_atfork_state |= 1; }
static void clone_parent(void) { clone_atfork_state |= 2; }
static void clone_child(void) { clone_atfork_state |= 4; }

static int process_state_callback(void *arg)
{
    sigset_t observed;
    (void)arg;
    if (sigprocmask(SIG_BLOCK, (const sigset_t *)0, &observed) != 0)
        return 46;
    if (sigismember(&observed, SIGUSR1) != 1 ||
            sigismember(&observed, SIGUSR2) != 0)
        return 47;
    return clone_atfork_state == 0 && pthread_self() != (pthread_t)0 ? 45 : 48;
}

struct child_settid_arg {
    pid_t *ctid;
};

static int child_settid_callback(void *arg)
{
    struct child_settid_arg *state = arg;
    return *(state->ctid) == getpid() ? 43 : 44;
}

int main(void)
{
    static unsigned char stack[STACK_SIZE];
    static unsigned char parent_settid_stack[STACK_SIZE];
    static unsigned char child_settid_stack[STACK_SIZE];
    int result = 41;
    int status;
    pid_t child;
    pid_t parent_tid = 0;
    pid_t child_tid = 0;
    struct child_settid_arg child_settid = { &child_tid };
    sigset_t saved_mask;
    sigset_t one_signal;

    /* Non-CLONE_VM clone follows musl's process-state path: all signals are
     * blocked during setup, the caller's mask is restored before the callback,
     * and pthread_atfork handlers are not part of clone's contract. */
    CHECK(pthread_atfork(clone_prepare, clone_parent, clone_child) == 0,
          "clone atfork registration");
    CHECK(sigemptyset(&one_signal) == 0 && sigaddset(&one_signal, SIGUSR1) == 0 &&
              sigprocmask(SIG_BLOCK, &one_signal, &saved_mask) == 0,
          "clone mask setup");
    CHECK(sigemptyset(&one_signal) == 0 && sigaddset(&one_signal, SIGUSR2) == 0 &&
              sigprocmask(SIG_UNBLOCK, &one_signal, (sigset_t *)0) == 0,
          "clone mask setup 2");
    child = clone(process_state_callback, stack + STACK_SIZE, SIGCHLD, &result);
    CHECK(child > 0, "clone process state create");
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == 45,
          "clone process state callback");
    CHECK(clone_atfork_state == 0, "clone atfork isolation");
    CHECK(sigprocmask(SIG_BLOCK, (const sigset_t *)0, &one_signal) == 0 &&
              sigismember(&one_signal, SIGUSR1) == 1 &&
              sigismember(&one_signal, SIGUSR2) == 0,
          "clone parent mask restore");
    CHECK(sigprocmask(SIG_SETMASK, &saved_mask, (sigset_t *)0) == 0,
          "clone mask cleanup");

    /* The callback receives the caller's argument and its result becomes the
     * child exit status, rather than falling through into the caller. */
    child = clone(callback, stack + STACK_SIZE, SIGCHLD, &result);
    CHECK(child > 0, "clone callback create");
    CHECK(waitpid(child, &status, 0) == child, "clone callback wait");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == result,
          "clone callback result");

    /* The parent-tid optional argument is the first vararg, while the child
     * tid form consumes ptid, tls, and ctid in that order. */
    errno = EINTR;
    child = clone(callback, parent_settid_stack + STACK_SIZE,
                  SIGCHLD | CLONE_PARENT_SETTID, &result, &parent_tid);
    CHECK(child > 0 && parent_tid == child, "clone parent tid");
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == result,
          "clone parent tid result");
    CHECK(errno == EINTR, "clone success errno");

    child = clone(child_settid_callback, child_settid_stack + STACK_SIZE,
                  SIGCHLD | CLONE_CHILD_SETTID, &child_settid,
                  (pid_t *)0, (void *)0, &child_tid);
    CHECK(child > 0, "clone child tid");
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == 43,
          "clone child tid result");

    errno = 0;
    CHECK(clone(callback, (void *)0, SIGCHLD, &result) == -1 && errno == EINVAL,
          "clone null stack error");
    errno = 0;
    CHECK(clone(callback, stack + STACK_SIZE, SIGCHLD | CLONE_THREAD, &result) == -1 &&
              errno == EINVAL,
          "clone thread error");
    errno = 0;
    CHECK(clone(callback, stack + STACK_SIZE, SIGCHLD | CLONE_SETTLS, &result) == -1 &&
              errno == EINVAL,
          "clone tls error");
    errno = 0;
    CHECK(clone(callback, stack + STACK_SIZE,
                SIGCHLD | CLONE_CHILD_CLEARTID, &result) == -1 && errno == EINVAL,
          "clone child tid clear error");

    puts("m4 clone exports ok");
    return 0;
}
