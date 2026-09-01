/* Static crabc-libc x86-64 GNU/BSD wait3/wait4 compatibility fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through a true static crabc archive candidate. Raw fork/pipe/exit
 * plumbing controls child state without selecting C process lifecycle APIs.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4 && sizeof(long) == 8,
    "x86 wait-extension scalar ABI");
_Static_assert(sizeof(struct rusage) == 272 && _Alignof(struct rusage) == 8 &&
    offsetof(struct rusage, ru_utime) == 0 &&
    offsetof(struct rusage, ru_stime) == 16 &&
    offsetof(struct rusage, ru_maxrss) == 32 &&
    offsetof(struct rusage, ru_nivcsw) == 136 &&
    offsetof(struct rusage, __reserved) == 144 &&
    sizeof(((struct rusage *)0)->__reserved) == 128,
    "x86 public wait4 rusage ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_pipe == 22 && SYS_fork == 57 && SYS_exit == 60 && SYS_wait4 == 61 &&
    SYS_setpgid == 109,
    "x86 wait-extension and fixture syscall numbers");
_Static_assert(WNOHANG == 1 && WUNTRACED == 2 && WCONTINUED == 8,
    "wait4 option values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait3),
    pid_t (*)(int *, int, struct rusage *)), "wait3 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait4),
    pid_t (*)(pid_t, int *, int, struct rusage *)), "wait4 declaration");

struct child_control {
    int parent_to_child[2];
    int child_to_parent[2];
    pid_t child;
    int reaped;
};

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
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
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

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

/* The raw fork syscall can resume in an independent child context. */
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

/* Cleanup deliberately avoids both selected wait-extension entry points. */
static int raw_wait4_cleanup(pid_t child, int *status)
{
    long result;
    do {
        result = raw_syscall4(SYS_wait4, child, (long)status, 0, 0);
    } while (result == -EINTR);
    return (int)result;
}

static void fill_bytes(void *destination, unsigned char value, size_t length)
{
    unsigned char *bytes = destination;
    size_t index;
    for (index = 0; index < length; ++index)
        bytes[index] = value;
}

static int bytes_are(const void *source, unsigned char value, size_t length)
{
    const unsigned char *bytes = source;
    size_t index;
    for (index = 0; index < length; ++index) {
        if (bytes[index] != value)
            return 0;
    }
    return 1;
}

static int usage_is_canonical(const struct rusage *usage)
{
    return usage->ru_utime.tv_sec >= 0 && usage->ru_utime.tv_usec >= 0 &&
        usage->ru_utime.tv_usec < 1000000 && usage->ru_stime.tv_sec >= 0 &&
        usage->ru_stime.tv_usec >= 0 && usage->ru_stime.tv_usec < 1000000 &&
        usage->ru_maxrss >= 0 && usage->ru_ixrss >= 0 &&
        usage->ru_idrss >= 0 && usage->ru_isrss >= 0 &&
        usage->ru_minflt >= 0 && usage->ru_majflt >= 0 &&
        usage->ru_nswap >= 0 && usage->ru_inblock >= 0 &&
        usage->ru_oublock >= 0 && usage->ru_msgsnd >= 0 &&
        usage->ru_msgrcv >= 0 && usage->ru_nsignals >= 0 &&
        usage->ru_nvcsw >= 0 && usage->ru_nivcsw >= 0;
}

static int usage_tail_is_unchanged(const struct rusage *usage)
{
    const unsigned char *tail = (const unsigned char *)usage +
        offsetof(struct rusage, __reserved);
    return bytes_are(tail, 0xa5, sizeof(usage->__reserved));
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

static void child_wait_then_exit(const int parent_to_child[2],
    const int child_to_parent[2], int separate_group, int exit_status)
    __attribute__((noreturn));

static void child_wait_then_exit(const int parent_to_child[2],
    const int child_to_parent[2], int separate_group, int exit_status)
{
    char release;
    if (separate_group && raw_syscall2(SYS_setpgid, 0, 0) != 0)
        raw_exit(124);
    if (raw_close(parent_to_child[1]) != 0 ||
        raw_close(child_to_parent[0]) != 0 ||
        !raw_write_byte(child_to_parent[1], 'R') ||
        !raw_read_byte(parent_to_child[0], &release))
        raw_exit(125);
    raw_exit(exit_status);
}

static int spawn_blocked_child(struct child_control *control, int separate_group,
    int exit_status)
{
    long fork_result;
    char ready;
    if (raw_pipe(control->parent_to_child) != 0 ||
        raw_pipe(control->child_to_parent) != 0)
        return 1;
    fork_result = raw_fork();
    if (fork_result == 0)
        child_wait_then_exit(control->parent_to_child, control->child_to_parent,
            separate_group, exit_status);
    if (fork_result < 0)
        return 2;
    control->child = (pid_t)fork_result;
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

static int check_wait4_rusage_and_errno(void)
{
    struct child_control control;
    struct rusage usage;
    int status = 0;
    int result = 1;

    initialize_control(&control);
    if (spawn_blocked_child(&control, 0, 42) != 0)
        goto cleanup;
    status = 0x5a5a5a5a;
    fill_bytes(&usage, 0xa5, sizeof(usage));
    errno = 0;
    if (wait4(control.child, &status, WNOHANG, &usage) != 0 ||
        status != 0x5a5a5a5a || !bytes_are(&usage, 0xa5, sizeof(usage)))
        goto cleanup;
    if (!release_child(&control))
        goto cleanup;
    errno = 0;
    if (wait4(control.child, &status, 0, &usage) != control.child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 42 ||
        !usage_is_canonical(&usage) || !usage_tail_is_unchanged(&usage))
        goto cleanup;
    control.reaped = 1;
    errno = 0;
    if (wait4(control.child, &status, WNOHANG, &usage) != -1 || errno != ECHILD)
        goto cleanup;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

static int check_wait3_wait_any_and_rusage(void)
{
    struct child_control control;
    struct rusage usage;
    int status = 0;
    int result = 1;

    initialize_control(&control);
    /* A separate child process group distinguishes musl's wait4(-1, ...) from
     * a tempting but wrong wait4(0, ...) implementation. */
    if (spawn_blocked_child(&control, 1, 43) != 0)
        goto cleanup;
    status = 0x6b6b6b6b;
    fill_bytes(&usage, 0xa5, sizeof(usage));
    errno = 0;
    if (wait3(&status, WNOHANG, &usage) != 0 || status != 0x6b6b6b6b ||
        !bytes_are(&usage, 0xa5, sizeof(usage)))
        goto cleanup;
    if (!release_child(&control))
        goto cleanup;
    errno = 0;
    if (wait3(&status, 0, &usage) != control.child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 43 || !usage_is_canonical(&usage) ||
        !usage_tail_is_unchanged(&usage))
        goto cleanup;
    control.reaped = 1;
    errno = 0;
    if (wait3(&status, WNOHANG, &usage) != -1 || errno != ECHILD)
        goto cleanup;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

static int check_optional_outputs(void)
{
    struct child_control control;
    int result = 1;

    initialize_control(&control);
    if (spawn_blocked_child(&control, 0, 44) != 0 || !release_child(&control))
        goto cleanup;
    if (wait4(control.child, (int *)0, 0, (struct rusage *)0) != control.child)
        goto cleanup;
    control.reaped = 1;
    cleanup_child(&control);
    initialize_control(&control);
    if (spawn_blocked_child(&control, 1, 45) != 0 || !release_child(&control))
        goto cleanup;
    if (wait3((int *)0, 0, (struct rusage *)0) != control.child)
        goto cleanup;
    control.reaped = 1;
    result = 0;

cleanup:
    cleanup_child(&control);
    return result;
}

int crabc_x86_64_wait_extensions_probe(void)
{
    int status = check_wait4_rusage_and_errno();
    if (status != 0)
        return 10 + status;
    status = check_wait3_wait_any_and_rusage();
    if (status != 0)
        return 20 + status;
    status = check_optional_outputs();
    return status == 0 ? 0 : 30 + status;
}

#ifndef CRABC_WAIT_EXTENSIONS_FREESTANDING
int main(void)
{
    return crabc_x86_64_wait_extensions_probe();
}
#endif
