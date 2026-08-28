/* Static crabc-libc x86-64 child-reaping compatibility fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through the selected freestanding crabc archive. Fixture-local raw
 * clone/pipe/exit calls make each child state deterministic; they do not
 * select C fork/exec/process-supervisor APIs from the archive under test.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
    "x86 int and pid_t ABI");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
    "x86 siginfo_t ABI");
_Static_assert(__builtin_offsetof(siginfo_t, si_signo) == 0 &&
    __builtin_offsetof(siginfo_t, si_errno) == 4 &&
    __builtin_offsetof(siginfo_t, si_code) == 8 &&
    __builtin_offsetof(siginfo_t, si_pid) == 16 &&
    __builtin_offsetof(siginfo_t, si_uid) == 20 &&
    __builtin_offsetof(siginfo_t, si_status) == 24,
    "x86 child siginfo fields");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_pipe == 22 && SYS_clone == 56 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_waitid == 247,
    "x86 child-reaping syscall numbers");
_Static_assert(P_PID == 1 && WNOHANG == 1 && WEXITED == 4 &&
    WNOWAIT == 0x01000000 && CLD_EXITED == 1,
    "x86 child-reaping constants");

struct child_control {
    int parent_to_child[2];
    int child_to_parent[2];
    pid_t child;
    int reaped;
};

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
                         long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
                         long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
                         long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static __attribute__((noreturn)) void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

/* clone can resume in an independent child execution context. */
static __attribute__((noinline, returns_twice)) long raw_clone_sigchld(void)
{
    return raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
}

static int raw_close(int descriptor)
{
    return (int)raw_syscall1(SYS_close, descriptor);
}

static int raw_pipe(int descriptors[2])
{
    return (int)raw_syscall1(SYS_pipe, (long)descriptors);
}

static int raw_read_byte(int descriptor, char *byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_read, descriptor, (long)byte, 1);
    } while (result == -EINTR);
    return result == 1;
}

static int raw_write_byte(int descriptor, char byte)
{
    long result;

    do {
        result = raw_syscall3(SYS_write, descriptor, (long)&byte, 1);
    } while (result == -EINTR);
    return result == 1;
}

/* Cleanup deliberately avoids the selected wait family. */
static int raw_wait4_cleanup(pid_t child, int *status)
{
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)status, 0, 0);
    } while (result == -EINTR);
    return (int)result;
}

static void clear_siginfo(siginfo_t *info)
{
    unsigned char *bytes = (unsigned char *)info;
    unsigned long index;

    for (index = 0; index < sizeof(*info); ++index)
        bytes[index] = 0;
}

static void initialize_control(struct child_control *control)
{
    control->parent_to_child[0] = -1;
    control->parent_to_child[1] = -1;
    control->child_to_parent[0] = -1;
    control->child_to_parent[1] = -1;
    control->child = -1;
    control->reaped = 0;
}

static __attribute__((noreturn)) void child_wait_then_exit(
    const int parent_to_child[2], const int child_to_parent[2])
{
    char release;

    if (raw_close(parent_to_child[1]) != 0 ||
        raw_close(child_to_parent[0]) != 0 ||
        !raw_write_byte(child_to_parent[1], 'R') ||
        !raw_read_byte(parent_to_child[0], &release))
        raw_exit(125);
    raw_exit(42);
}

static int spawn_blocked_child(struct child_control *control)
{
    long clone_result;
    char ready;

    if (raw_pipe(control->parent_to_child) != 0 ||
        raw_pipe(control->child_to_parent) != 0)
        return 1;

    clone_result = raw_clone_sigchld();
    if (clone_result == 0)
        child_wait_then_exit(control->parent_to_child, control->child_to_parent);
    if (clone_result < 0)
        return 2;
    control->child = (pid_t)clone_result;

    if (raw_close(control->parent_to_child[0]) != 0)
        return 3;
    control->parent_to_child[0] = -1;
    if (raw_close(control->child_to_parent[1]) != 0)
        return 4;
    control->child_to_parent[1] = -1;
    if (!raw_read_byte(control->child_to_parent[0], &ready) || ready != 'R')
        return 5;
    return 0;
}

static int release_child(struct child_control *control)
{
    int result = raw_write_byte(control->parent_to_child[1], 'X');

    if (raw_close(control->parent_to_child[1]) != 0)
        result = 0;
    control->parent_to_child[1] = -1;
    return result;
}

static void cleanup_child(struct child_control *control)
{
    int status;

    if (control->parent_to_child[0] >= 0)
        (void)raw_close(control->parent_to_child[0]);
    if (control->parent_to_child[1] >= 0)
        (void)raw_close(control->parent_to_child[1]);
    if (control->child_to_parent[0] >= 0)
        (void)raw_close(control->child_to_parent[0]);
    if (control->child_to_parent[1] >= 0)
        (void)raw_close(control->child_to_parent[1]);
    if (control->child > 0 && !control->reaped)
        (void)raw_wait4_cleanup(control->child, &status);
}

static int check_waitid_report(const siginfo_t *info, pid_t child)
{
    return info->si_signo == SIGCHLD && info->si_errno == 0 &&
        info->si_code == CLD_EXITED && info->si_pid == child &&
        info->si_status == 42;
}

static int check_waitpid_nohang_and_waitid_nowait(void)
{
    struct child_control control;
    siginfo_t info;
    int status = 0;
    int result = 1;

    initialize_control(&control);
    if (spawn_blocked_child(&control) != 0)
        goto cleanup;

    status = 0x5a5a5a5a;
    errno = 0;
    if (waitpid(control.child, &status, WNOHANG) != 0 ||
        status != 0x5a5a5a5a)
        goto cleanup;

    clear_siginfo(&info);
    errno = 0;
    if (waitid(P_PID, (id_t)control.child, &info, WEXITED | WNOHANG) != 0 ||
        info.si_signo != 0 || info.si_pid != 0)
        goto cleanup;

    if (!release_child(&control))
        goto cleanup;

    clear_siginfo(&info);
    errno = 0;
    if (waitid(P_PID, (id_t)control.child, &info, WEXITED | WNOWAIT) != 0 ||
        !check_waitid_report(&info, control.child))
        goto cleanup;

    errno = 0;
    if (waitpid(control.child, &status, 0) != control.child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 42)
        goto cleanup;
    control.reaped = 1;

    errno = 0;
    if (waitpid(control.child, &status, WNOHANG) != -1 || errno != ECHILD)
        goto cleanup;
    clear_siginfo(&info);
    errno = 0;
    if (waitid(P_PID, (id_t)control.child, &info, WEXITED) != -1 ||
        errno != ECHILD)
        goto cleanup;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

static int check_wait_any(void)
{
    struct child_control control;
    int status = 0;
    int result = 1;

    initialize_control(&control);
    if (spawn_blocked_child(&control) != 0 || !release_child(&control))
        goto cleanup;
    errno = 0;
    if (wait(&status) != control.child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 42)
        goto cleanup;
    control.reaped = 1;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

static int check_waitid_consumes(void)
{
    struct child_control control;
    siginfo_t info;
    int status = 0;
    int result = 1;

    initialize_control(&control);
    if (spawn_blocked_child(&control) != 0 || !release_child(&control))
        goto cleanup;
    clear_siginfo(&info);
    errno = 0;
    if (waitid(P_PID, (id_t)control.child, &info, WEXITED) != 0 ||
        !check_waitid_report(&info, control.child))
        goto cleanup;
    control.reaped = 1;
    errno = 0;
    if (waitpid(control.child, &status, WNOHANG) != -1 || errno != ECHILD)
        goto cleanup;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

static int check_invalid_waitid_selector(void)
{
    siginfo_t info;

    clear_siginfo(&info);
    errno = 0;
    return waitid((idtype_t)99, 0, &info, WEXITED) == -1 && errno == EINVAL
        ? 0 : 1;
}

int crabc_x86_64_child_reaping_probe(void)
{
    int status = check_waitpid_nohang_and_waitid_nowait();

    if (status != 0)
        return 10 + status;
    status = check_wait_any();
    if (status != 0)
        return 20 + status;
    status = check_waitid_consumes();
    if (status != 0)
        return 30 + status;
    status = check_invalid_waitid_selector();
    return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_CHILD_REAPING_FREESTANDING
int main(void)
{
    return crabc_x86_64_child_reaping_probe();
}
#endif
