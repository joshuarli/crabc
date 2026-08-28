/* Pinned-musl/raw Linux/x86-64 child ownership and reaping reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4, "x86 int and pid_t width");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
               "x86 siginfo_t layout");
_Static_assert(offsetof(siginfo_t, si_signo) == 0 &&
                   offsetof(siginfo_t, si_errno) == 4 &&
                   offsetof(siginfo_t, si_code) == 8 &&
                   offsetof(siginfo_t, si_pid) == 16 &&
                   offsetof(siginfo_t, si_uid) == 20 &&
                   offsetof(siginfo_t, si_status) == 24,
               "x86 child siginfo offsets");
_Static_assert(SYS_clone == 56 && SYS_wait4 == 61 && SYS_waitid == 247,
               "x86 child-management syscall numbers");
_Static_assert(P_PID == 1 && WNOHANG == 1 && WEXITED == 4 &&
                   WNOWAIT == 0x01000000 && CLD_EXITED == 1,
               "x86 child-management constants");

enum lifecycle_kind {
    RAW_LIFECYCLE,
    MUSL_LIFECYCLE,
};

static int read_byte(int fd, char *byte)
{
    ssize_t result;

    do {
        result = read(fd, byte, 1);
    } while (result == -1 && errno == EINTR);
    return result == 1;
}

static int write_byte(int fd, char byte)
{
    ssize_t result;

    do {
        result = write(fd, &byte, 1);
    } while (result == -1 && errno == EINTR);
    return result == 1;
}

static int raw_wait4(pid_t child, int *status, int options)
{
    return (int)syscall(SYS_wait4, child, status, options, NULL);
}

static int raw_waitid(pid_t child, siginfo_t *info, int options)
{
    return (int)syscall(SYS_waitid, P_PID, (id_t)child, info, options, NULL);
}

static void child_wait_then_exit(const int parent_to_child[2],
                                 const int child_to_parent[2])
{
    char release;

    if (close(parent_to_child[1]) != 0 || close(child_to_parent[0]) != 0 ||
        !write_byte(child_to_parent[1], 'R') ||
        !read_byte(parent_to_child[0], &release))
        _exit(125);
    _exit(42);
}

static int wait_for_exit(enum lifecycle_kind kind, pid_t child, int *status)
{
    int result;

    do {
        result = kind == RAW_LIFECYCLE ? raw_wait4(child, status, 0)
                                       : waitpid(child, status, 0);
    } while (result == -1 && errno == EINTR);
    return result;
}

static int run_lifecycle(enum lifecycle_kind kind)
{
    int parent_to_child[2] = { -1, -1 };
    int child_to_parent[2] = { -1, -1 };
    pid_t child = -1;
    int status = 0;
    int reaped = 0;
    siginfo_t info;
    char ready;
    long clone_result;
    int result = 1;

    if (pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0)
        goto cleanup;

    if (kind == RAW_LIFECYCLE) {
        clone_result = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, NULL);
        if (clone_result == 0)
            child_wait_then_exit(parent_to_child, child_to_parent);
        if (clone_result < 0)
            goto cleanup;
        child = (pid_t)clone_result;
    } else {
        child = fork();
        if (child == 0)
            child_wait_then_exit(parent_to_child, child_to_parent);
        if (child < 0)
            goto cleanup;
    }

    if (close(parent_to_child[0]) != 0 || close(child_to_parent[1]) != 0)
        goto cleanup;
    parent_to_child[0] = -1;
    child_to_parent[1] = -1;

    if (!read_byte(child_to_parent[0], &ready) || ready != 'R')
        goto cleanup;

    status = 0x5a5a5a5a;
    if ((kind == RAW_LIFECYCLE ? raw_wait4(child, &status, WNOHANG)
                               : waitpid(child, &status, WNOHANG)) != 0 ||
        status != 0x5a5a5a5a)
        goto cleanup;

    if (!write_byte(parent_to_child[1], 'X'))
        goto cleanup;
    if (close(parent_to_child[1]) != 0)
        goto cleanup;
    parent_to_child[1] = -1;

    memset(&info, 0, sizeof(info));
    if ((kind == RAW_LIFECYCLE
             ? raw_waitid(child, &info, WEXITED | WNOWAIT)
             : waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT)) != 0 ||
        info.si_signo != SIGCHLD || info.si_code != CLD_EXITED ||
        info.si_pid != child || info.si_status != 42)
        goto cleanup;

    if (wait_for_exit(kind, child, &status) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 42)
        goto cleanup;
    reaped = 1;

    errno = 0;
    if ((kind == RAW_LIFECYCLE ? raw_wait4(child, &status, WNOHANG)
                               : waitpid(child, &status, WNOHANG)) != -1 ||
        errno != ECHILD)
        goto cleanup;

    result = 0;

cleanup:
    if (parent_to_child[0] >= 0)
        close(parent_to_child[0]);
    if (parent_to_child[1] >= 0)
        close(parent_to_child[1]);
    if (child_to_parent[0] >= 0)
        close(child_to_parent[0]);
    if (child_to_parent[1] >= 0)
        close(child_to_parent[1]);
    if (child > 0 && !reaped)
        (void)wait_for_exit(kind, child, &status);
    return result;
}

int main(void)
{
    if (run_lifecycle(RAW_LIFECYCLE) != 0 ||
        run_lifecycle(MUSL_LIFECYCLE) != 0)
        return 1;

    puts("clone=56 wait4=61 waitid=247 lifecycle=raw+musl nohang=0 nowait=preserved exit=42 reap=exact echild=post-reap child-contained");
    return 0;
}
