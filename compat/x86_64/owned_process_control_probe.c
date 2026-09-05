/* Installed Linux/x86-64 residual process-control C workload.
 *
 * Pinned musl 1.2.6 source mapping:
 * - src/process/{execve,execv,execvp,execl,execle,execlp,fexecve}.c;
 * - src/unistd/{nice,setpgid,setpgrp,setsid}.c;
 * - src/process/{wait,waitpid,waitid}.c and src/linux/{wait3,wait4}.c; and
 * - src/process/posix_spawnattr_{init,destroy,setflags,getflags,setpgroup,
 *   getpgroup,sched,setsigmask,getsigmask,setsigdefault,getsigdefault}.c.
 *
 * `owned_process_trio_probe.c` separately owns installed clone/vfork/daemon
 * behavior, and `owned_spawn_probe.c` separately owns posix_spawn/p plus its
 * file-action and child-execution matrix.  This workload deliberately does
 * not repeat either matrix.  Together the three cases cover the documented
 * 44-name process-control roster.
 *
 * Every process-state change and every blocking wait here lives in a raw
 * fixture child with a pipe handshake.  The raw plumbing is test control, not
 * a selected public fork/pipe/supervision API.  `wait`, `waitpid`, and
 * `waitid` retain their separate cancellation-point proof in
 * owned_sleep_wait_cancellation_probe.c; source `wait3`/`wait4` are direct
 * non-cancellation paths and are intentionally not treated as CPs here.
 *
 * The fexecve seccomp subcase records the project Linux-5.10 policy.  Musl
 * falls back from execveat(2) ENOSYS through /proc/self/fd and remaps a final
 * ENOENT to EBADF.  crabc deliberately exposes the direct ENOSYS without that
 * procfs fallback.  The runner compares that one stated difference explicitly
 * instead of weakening it into a generic oracle mismatch.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this workload requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sched.h>
#include <spawn.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CRABC_PROCESS_CONTROL_EXECUTABLE
#define CRABC_PROCESS_CONTROL_EXECUTABLE "/proc/self/exe"
#endif

extern char **environ;

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(pid_t) == 4,
    "x86 process-control scalar ABI");
_Static_assert(sizeof(posix_spawnattr_t) == 336 &&
    _Alignof(posix_spawnattr_t) == 8, "x86 posix_spawnattr ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_fork == 57 && SYS_exit == 60 && SYS_wait4 == 61 &&
    SYS_execveat == 322 && SYS_prctl == 157,
    "x86 process-control fixture syscalls");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execl),
    int (*)(const char *, const char *, ...)), "execl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execle),
    int (*)(const char *, const char *, ...)), "execle declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execlp),
    int (*)(const char *, const char *, ...)), "execlp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execv),
    int (*)(const char *, char *const [])), "execv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execve),
    int (*)(const char *, char *const [], char *const [])), "execve declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execvp),
    int (*)(const char *, char *const [])), "execvp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execvpe),
    int (*)(const char *, char *const [], char *const [])), "execvpe declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fexecve),
    int (*)(int, char *const [], char *const [])), "fexecve declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nice), int (*)(int)),
    "nice declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpgid),
    int (*)(pid_t, pid_t)), "setpgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpgrp),
    pid_t (*)(void)), "setpgrp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setsid),
    pid_t (*)(void)), "setsid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait),
    pid_t (*)(int *)), "wait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait3),
    pid_t (*)(int *, int, struct rusage *)), "wait3 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait4),
    pid_t (*)(pid_t, int *, int, struct rusage *)), "wait4 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&waitid),
    int (*)(idtype_t, id_t, siginfo_t *, int)), "waitid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&waitpid),
    pid_t (*)(pid_t, int *, int)), "waitpid declaration");

static long raw_syscall0(long number)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    __asm__ volatile("syscall" : "=a"(result)
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
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

static __attribute__((noinline, returns_twice)) long raw_fork(void)
{
    return raw_syscall0(SYS_fork);
}

static int raw_close(int descriptor)
{
    return (int)raw_syscall1(SYS_close, descriptor);
}

static int raw_pipe(int descriptors[2])
{
    return (int)raw_syscall1(SYS_pipe, (long)descriptors);
}

static int raw_read_full(int descriptor, void *destination, size_t length)
{
    unsigned char *cursor = destination;
    while (length != 0) {
        long result = raw_syscall3(SYS_read, descriptor, (long)cursor, (long)length);
        if (result == -EINTR)
            continue;
        if (result <= 0)
            return 0;
        cursor += result;
        length -= (size_t)result;
    }
    return 1;
}

static int raw_write_full(int descriptor, const void *source, size_t length)
{
    const unsigned char *cursor = source;
    while (length != 0) {
        long result = raw_syscall3(SYS_write, descriptor, (long)cursor, (long)length);
        if (result == -EINTR)
            continue;
        if (result <= 0)
            return 0;
        cursor += result;
        length -= (size_t)result;
    }
    return 1;
}

static int raw_wait_for(pid_t child, int *status)
{
    long result;
    do {
        result = raw_syscall4(SYS_wait4, child, (long)status, 0, 0);
    } while (result == -EINTR);
    return (int)result;
}

static int same_string(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static const char *environment_value(char *const environment[], const char *name)
{
    size_t name_length = 0;
    while (name[name_length] != '\0')
        ++name_length;
    for (; *environment != NULL; ++environment) {
        const char *entry = *environment;
        size_t index = 0;
        while (index < name_length && entry[index] == name[index])
            ++index;
        if (index == name_length && entry[index] == '=')
            return entry + name_length + 1;
    }
    return NULL;
}

static void fill_bytes(void *destination, unsigned char value, size_t length)
{
    unsigned char *bytes = destination;
    while (length != 0) {
        *bytes++ = value;
        --length;
    }
}

static void copy_bytes(void *destination, const void *source, size_t length)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    while (length != 0) {
        *out++ = *in++;
        --length;
    }
}

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const unsigned char *a = left;
    const unsigned char *b = right;
    while (length != 0) {
        if (*a++ != *b++)
            return 0;
        --length;
    }
    return 1;
}

static int bytes_are(const void *source, unsigned char value, size_t length)
{
    const unsigned char *bytes = source;
    while (length != 0) {
        if (*bytes++ != value)
            return 0;
        --length;
    }
    return 1;
}

static int usage_is_canonical(const struct rusage *usage)
{
    return usage->ru_utime.tv_sec >= 0 && usage->ru_utime.tv_usec >= 0 &&
        usage->ru_utime.tv_usec < 1000000 && usage->ru_stime.tv_sec >= 0 &&
        usage->ru_stime.tv_usec >= 0 && usage->ru_stime.tv_usec < 1000000 &&
        usage->ru_maxrss >= 0 && usage->ru_minflt >= 0 &&
        usage->ru_majflt >= 0 && usage->ru_nvcsw >= 0 && usage->ru_nivcsw >= 0;
}

static int exec_child(const char *mode, char *const environment[])
{
    const char *token = environment_value(environment, "EXEC_TOKEN");
    const char *expected = NULL;
    if (same_string(mode, "execl") || same_string(mode, "execlp") ||
        same_string(mode, "execv") || same_string(mode, "execvp"))
        expected = "parent";
    else if (same_string(mode, "execle"))
        expected = "execle";
    else if (same_string(mode, "execve"))
        expected = "execve";
    else if (same_string(mode, "execvpe"))
        expected = "execvpe";
    else if (same_string(mode, "fexecve"))
        expected = "fexecve";
    else
        return 90;
    return token != NULL && same_string(token, expected) ? 0 : 91;
}

enum exec_alias {
    EXEC_EXECL,
    EXEC_EXECLE,
    EXEC_EXECLP,
    EXEC_EXECV,
    EXEC_EXECVE,
    EXEC_EXECVP,
    EXEC_EXECVPE,
    EXEC_FEXECVE,
};

static const char *exec_alias_name(enum exec_alias alias)
{
    static const char *const names[] = {
        "execl", "execle", "execlp", "execv", "execve", "execvp",
        "execvpe", "fexecve",
    };
    return names[alias];
}

static void invoke_exec_alias(enum exec_alias alias) __attribute__((noreturn));

static void invoke_exec_alias(enum exec_alias alias)
{
    const char *mode = exec_alias_name(alias);
    char *arguments[] = { "consumer", "--exec-child", (char *)mode, NULL };
    char *environment[] = {
        "PATH=/", "EXEC_TOKEN=execle", "LC_ALL=C", NULL,
    };
    int descriptor;

    switch (alias) {
    case EXEC_EXECL:
        (void)execl(CRABC_PROCESS_CONTROL_EXECUTABLE, "consumer", "--exec-child",
            "execl", (char *)0);
        break;
    case EXEC_EXECLE:
        (void)execle(CRABC_PROCESS_CONTROL_EXECUTABLE, "consumer", "--exec-child",
            "execle", (char *)0, environment);
        break;
    case EXEC_EXECLP:
        (void)execlp("consumer", "consumer", "--exec-child", "execlp", (char *)0);
        break;
    case EXEC_EXECV:
        (void)execv(CRABC_PROCESS_CONTROL_EXECUTABLE, arguments);
        break;
    case EXEC_EXECVE:
        environment[1] = "EXEC_TOKEN=execve";
        (void)execve(CRABC_PROCESS_CONTROL_EXECUTABLE, arguments, environment);
        break;
    case EXEC_EXECVP:
        (void)execvp("consumer", arguments);
        break;
    case EXEC_EXECVPE:
        environment[1] = "EXEC_TOKEN=execvpe";
        (void)execvpe("consumer", arguments, environment);
        break;
    case EXEC_FEXECVE:
        environment[1] = "EXEC_TOKEN=fexecve";
        descriptor = open(CRABC_PROCESS_CONTROL_EXECUTABLE, O_RDONLY);
        if (descriptor >= 0)
            (void)fexecve(descriptor, arguments, environment);
        break;
    }
    raw_exit(120 + (errno & 0x7f));
}

static int check_exec_aliases(void)
{
    enum exec_alias alias;
    for (alias = EXEC_EXECL; alias <= EXEC_FEXECVE; ++alias) {
        int status = 0;
        long child = raw_fork();
        if (child == 0)
            invoke_exec_alias(alias);
        if (child <= 0 || raw_wait_for((pid_t)child, &status) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return 1 + (int)alias;
    }
    return 0;
}

struct bpf_instruction {
    unsigned short code;
    unsigned char yes;
    unsigned char no;
    unsigned value;
};

struct bpf_program {
    unsigned short count;
    struct bpf_instruction *instructions;
};

static int check_fexecve_seccomp(int *observed_errno)
{
    int report[2] = { -1, -1 };
    int status = 0;
    long child;
    if (raw_pipe(report) != 0)
        return 1;
    child = raw_fork();
    if (child == 0) {
        struct bpf_instruction instructions[] = {
            { 0x20, 0, 0, 0 }, { 0x15, 0, 1, SYS_execveat },
            { 0x06, 0, 0, 0x50000U | ENOSYS }, { 0x06, 0, 0, 0x7fff0000U },
        };
        struct bpf_program program = { 4, instructions };
        char *arguments[] = { "consumer", "--exec-child", "fexecve", NULL };
        char *environment[] = { "PATH=/", "EXEC_TOKEN=fexecve", "LC_ALL=C", NULL };
        int descriptor;
        int error;
        (void)raw_close(report[0]);
        if (raw_syscall5(SYS_prctl, 38, 1, 0, 0, 0) != 0 ||
            raw_syscall5(SYS_prctl, 22, 2, (long)&program, 0, 0) != 0)
            raw_exit(80);
        descriptor = open(CRABC_PROCESS_CONTROL_EXECUTABLE, O_RDONLY);
        if (descriptor < 0)
            raw_exit(81);
        if (fexecve(descriptor, arguments, environment) != -1)
            raw_exit(82);
        error = errno;
        if (!raw_write_full(report[1], &error, sizeof(error)))
            raw_exit(83);
        raw_exit(0);
    }
    (void)raw_close(report[1]);
    if (child <= 0 || !raw_read_full(report[0], observed_errno, sizeof(*observed_errno)) ||
        raw_wait_for((pid_t)child, &status) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        (void)raw_close(report[0]);
        return 2;
    }
    (void)raw_close(report[0]);
    return 0;
}

static int child_nice(void)
{
    errno = EDOM;
    if (nice(INT_MAX) != 19 || errno != EDOM)
        return 1;
    errno = E2BIG;
    if (nice(0) != 19 || errno != E2BIG)
        return 2;
    return 0;
}

static int child_setpgid(void)
{
    pid_t self = getpid();
    if (setpgid(0, 0) != 0 || getpgrp() != self)
        return 1;
    errno = 0;
    if (setsid() != -1 || errno != EPERM)
        return 2;
    return 0;
}

static int child_setpgrp(void)
{
    pid_t self = getpid();
    if (setpgrp() != 0 || getpgrp() != self)
        return 1;
    return 0;
}

static int child_setsid(void)
{
    pid_t self = getpid();
    if (setsid() != self || getsid(0) != self || getpgrp() != self)
        return 1;
    return 0;
}

static int run_mutating_child(int (*child_case)(void))
{
    int status = 0;
    long child = raw_fork();
    if (child == 0)
        raw_exit(child_case());
    if (child <= 0 || raw_wait_for((pid_t)child, &status) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;
    return 0;
}

struct controlled_child {
    int release[2];
    int ready[2];
    pid_t child;
    int reaped;
};

static void initialize_controlled_child(struct controlled_child *state)
{
    state->release[0] = state->release[1] = -1;
    state->ready[0] = state->ready[1] = -1;
    state->child = -1;
    state->reaped = 0;
}

static int start_controlled_child(struct controlled_child *state, int exit_status)
{
    char ready = 'R';
    char release;
    long child;
    if (raw_pipe(state->release) != 0 || raw_pipe(state->ready) != 0)
        return 1;
    child = raw_fork();
    if (child == 0) {
        (void)raw_close(state->release[1]);
        (void)raw_close(state->ready[0]);
        if (!raw_write_full(state->ready[1], &ready, 1) ||
            !raw_read_full(state->release[0], &release, 1))
            raw_exit(125);
        raw_exit(exit_status);
    }
    if (child <= 0)
        return 2;
    state->child = (pid_t)child;
    (void)raw_close(state->release[0]);
    state->release[0] = -1;
    (void)raw_close(state->ready[1]);
    state->ready[1] = -1;
    if (!raw_read_full(state->ready[0], &ready, 1) || ready != 'R')
        return 3;
    return 0;
}

static int release_controlled_child(struct controlled_child *state)
{
    char release = 'X';
    int result = state->release[1] >= 0 &&
        raw_write_full(state->release[1], &release, 1);
    if (state->release[1] >= 0)
        (void)raw_close(state->release[1]);
    state->release[1] = -1;
    return result;
}

static void cleanup_controlled_child(struct controlled_child *state)
{
    int status;
    if (state->release[0] >= 0) (void)raw_close(state->release[0]);
    if (state->release[1] >= 0) (void)raw_close(state->release[1]);
    if (state->ready[0] >= 0) (void)raw_close(state->ready[0]);
    if (state->ready[1] >= 0) (void)raw_close(state->ready[1]);
    if (state->child > 0 && !state->reaped)
        (void)raw_wait_for(state->child, &status);
}

static int exited_with(const int status, int expected)
{
    return WIFEXITED(status) && WEXITSTATUS(status) == expected;
}

static int check_waitpid(void)
{
    struct controlled_child state;
    int status = 0x5a5a5a5a;
    int result = 1;
    initialize_controlled_child(&state);
    if (start_controlled_child(&state, 42) != 0)
        goto done;
    if (waitpid(state.child, &status, WNOHANG) != 0 || status != 0x5a5a5a5a)
        goto done;
    if (!release_controlled_child(&state))
        goto done;
    if (waitpid(state.child, &status, 0) != state.child || !exited_with(status, 42))
        goto done;
    state.reaped = 1;
    result = 0;
done:
    cleanup_controlled_child(&state);
    return result;
}

static int check_wait_any(void)
{
    struct controlled_child state;
    int status = 0;
    int result = 1;
    initialize_controlled_child(&state);
    if (start_controlled_child(&state, 43) != 0 || !release_controlled_child(&state))
        goto done;
    if (wait(&status) != state.child || !exited_with(status, 43))
        goto done;
    state.reaped = 1;
    result = 0;
done:
    cleanup_controlled_child(&state);
    return result;
}

static int waitid_report_matches(const siginfo_t *info, pid_t child, int exit_status)
{
    return info->si_signo == SIGCHLD && info->si_errno == 0 &&
        info->si_code == CLD_EXITED && info->si_pid == child &&
        info->si_status == exit_status;
}

static int check_waitid(void)
{
    struct controlled_child state;
    siginfo_t info;
    int status = 0;
    int result = 1;
    initialize_controlled_child(&state);
    if (start_controlled_child(&state, 44) != 0)
        goto done;
    fill_bytes(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)state.child, &info, WEXITED | WNOHANG) != 0 ||
        info.si_signo != 0 || info.si_pid != 0)
        goto done;
    if (!release_controlled_child(&state))
        goto done;
    fill_bytes(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)state.child, &info, WEXITED | WNOWAIT) != 0 ||
        !waitid_report_matches(&info, state.child, 44))
        goto done;
    fill_bytes(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)state.child, &info, WEXITED) != 0 ||
        !waitid_report_matches(&info, state.child, 44))
        goto done;
    state.reaped = 1;
    errno = 0;
    if (waitpid(state.child, &status, WNOHANG) != -1 || errno != ECHILD)
        goto done;
    result = 0;
done:
    cleanup_controlled_child(&state);
    return result;
}

static int check_wait3(void)
{
    struct controlled_child state;
    struct rusage usage;
    int status = 0;
    int result = 1;
    initialize_controlled_child(&state);
    if (start_controlled_child(&state, 45) != 0 || !release_controlled_child(&state))
        goto done;
    fill_bytes(&usage, 0xa5, sizeof(usage));
    if (wait3(&status, 0, &usage) != state.child || !exited_with(status, 45) ||
        !usage_is_canonical(&usage))
        goto done;
    state.reaped = 1;
    result = 0;
done:
    cleanup_controlled_child(&state);
    return result;
}

static int check_wait4(void)
{
    struct controlled_child state;
    struct rusage usage;
    int status = 0;
    int result = 1;
    initialize_controlled_child(&state);
    if (start_controlled_child(&state, 46) != 0 || !release_controlled_child(&state))
        goto done;
    fill_bytes(&usage, 0xa5, sizeof(usage));
    if (wait4(state.child, &status, 0, &usage) != state.child ||
        !exited_with(status, 46) || !usage_is_canonical(&usage))
        goto done;
    state.reaped = 1;
    result = 0;
done:
    cleanup_controlled_child(&state);
    return result;
}

static int check_spawn_attributes(void)
{
    const short all_flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP |
        POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK |
        POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
        POSIX_SPAWN_USEVFORK | POSIX_SPAWN_SETSID;
    posix_spawnattr_t attributes;
    posix_spawnattr_t before;
    sigset_t defaults;
    sigset_t mask;
    sigset_t observed;
    struct sched_param parameter;
    short flags = -1;
    pid_t group = 0;
    int policy = 0x5a5a5a5a;

    fill_bytes(&attributes, 0xa5, sizeof(attributes));
    errno = E2BIG;
    if (posix_spawnattr_init(&attributes) != 0 ||
        !bytes_are(&attributes, 0, sizeof(attributes)) || errno != E2BIG)
        return 1;
    if (posix_spawnattr_getflags(&attributes, &flags) != 0 || flags != 0)
        return 2;
    if (posix_spawnattr_setflags(&attributes, all_flags) != 0 ||
        posix_spawnattr_getflags(&attributes, &flags) != 0 || flags != all_flags)
        return 3;
    copy_bytes(&before, &attributes, sizeof(before));
    errno = EDOM;
    if (posix_spawnattr_setflags(&attributes, (short)0x100) != EINVAL ||
        !bytes_equal(&attributes, &before, sizeof(attributes)) || errno != EDOM)
        return 4;
    if (posix_spawnattr_setpgroup(&attributes, (pid_t)-17) != 0 ||
        posix_spawnattr_getpgroup(&attributes, &group) != 0 || group != -17)
        return 5;
    if (sigemptyset(&defaults) != 0 || sigaddset(&defaults, SIGUSR1) != 0 ||
        sigaddset(&defaults, SIGUSR2) != 0 || sigemptyset(&mask) != 0 ||
        sigaddset(&mask, SIGTERM) != 0)
        return 6;
    fill_bytes(&observed, 0, sizeof(observed));
    if (posix_spawnattr_setsigdefault(&attributes, &defaults) != 0 ||
        posix_spawnattr_getsigdefault(&attributes, &observed) != 0 ||
        !bytes_equal(&defaults, &observed, sizeof(defaults)))
        return 7;
    fill_bytes(&observed, 0, sizeof(observed));
    if (posix_spawnattr_setsigmask(&attributes, &mask) != 0 ||
        posix_spawnattr_getsigmask(&attributes, &observed) != 0 ||
        !bytes_equal(&mask, &observed, sizeof(mask)))
        return 8;
    copy_bytes(&before, &attributes, sizeof(before));
    fill_bytes(&parameter, 0xa5, sizeof(parameter));
    errno = EDOM;
    if (posix_spawnattr_setschedparam(&attributes, &parameter) != ENOSYS ||
        posix_spawnattr_setschedparam(NULL, &parameter) != ENOSYS ||
        posix_spawnattr_setschedparam(&attributes, NULL) != ENOSYS ||
        posix_spawnattr_setschedparam(NULL, NULL) != ENOSYS ||
        posix_spawnattr_getschedparam(&attributes, &parameter) != ENOSYS ||
        posix_spawnattr_getschedparam(NULL, &parameter) != ENOSYS ||
        posix_spawnattr_getschedparam(&attributes, NULL) != ENOSYS ||
        posix_spawnattr_getschedparam(NULL, NULL) != ENOSYS ||
        posix_spawnattr_setschedpolicy(&attributes, 7) != ENOSYS ||
        posix_spawnattr_setschedpolicy(NULL, -1) != ENOSYS ||
        posix_spawnattr_getschedpolicy(&attributes, &policy) != ENOSYS ||
        posix_spawnattr_getschedpolicy(NULL, &policy) != ENOSYS ||
        posix_spawnattr_getschedpolicy(&attributes, NULL) != ENOSYS ||
        posix_spawnattr_getschedpolicy(NULL, NULL) != ENOSYS ||
        !bytes_equal(&attributes, &before, sizeof(attributes)) ||
        !bytes_are(&parameter, 0xa5, sizeof(parameter)) || policy != 0x5a5a5a5a ||
        errno != EDOM)
        return 9;
    copy_bytes(&before, &attributes, sizeof(before));
    errno = E2BIG;
    if (posix_spawnattr_destroy(&attributes) != 0 ||
        posix_spawnattr_destroy(NULL) != 0 ||
        !bytes_equal(&attributes, &before, sizeof(attributes)) || errno != E2BIG)
        return 10;
    return 0;
}

static void write_decimal(int value)
{
    char digits[16];
    unsigned magnitude;
    size_t count = 0;
    if (value < 0) {
        static const char minus = '-';
        (void)raw_write_full(1, &minus, 1);
        magnitude = (unsigned)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude != 0);
    while (count != 0) {
        --count;
        (void)raw_write_full(1, &digits[count], 1);
    }
}

int main(int argc, char **argv)
{
    static const char success[] = "owned-process-control-ok fexecve-seccomp=";
    static const char newline[] = "\n";
    int fexecve_errno = 0;
    int result;

    if (argc == 3 && same_string(argv[1], "--exec-child"))
        return exec_child(argv[2], environ);
    if (argc != 1)
        return 2;
    result = check_exec_aliases();
    if (result != 0)
        return 10 + result;
    if (check_fexecve_seccomp(&fexecve_errno) != 0)
        return 30;
    if (run_mutating_child(child_nice) != 0)
        return 31;
    if (run_mutating_child(child_setpgid) != 0 ||
        run_mutating_child(child_setpgrp) != 0 || run_mutating_child(child_setsid) != 0)
        return 32;
    if (check_waitpid() != 0 || check_wait_any() != 0 || check_waitid() != 0 ||
        check_wait3() != 0 || check_wait4() != 0)
        return 33;
    if (check_spawn_attributes() != 0)
        return 34;
    (void)raw_write_full(1, success, sizeof(success) - 1);
    write_decimal(fexecve_errno);
    (void)raw_write_full(1, newline, sizeof(newline) - 1);
    return 0;
}
