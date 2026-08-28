/* Static crabc-libc x86-64 selected process-context fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6
 * and then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects the scalar identity, process-group/session, and
 * umask C boundary. Fixture-local raw fork/wait/exit calls contain the three
 * state-changing group/session checks in children; they do not select C fork,
 * wait, exec, a process supervisor, CRT, pthreads, loader, or sysroot.
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
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t layout");
_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4 &&
    (uid_t)-1 > (uid_t)0, "x86 uid_t layout");
_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4 &&
    (gid_t)-1 > (gid_t)0, "x86 gid_t layout");
_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
    (mode_t)-1 > (mode_t)0, "x86 mode_t layout");
_Static_assert(SYS_getpid == 39 && SYS_fork == 57 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_umask == 95 && SYS_getuid == 102 &&
    SYS_getgid == 104 && SYS_geteuid == 107 && SYS_getegid == 108 &&
    SYS_setpgid == 109 && SYS_getppid == 110 && SYS_setsid == 112 &&
    SYS_getpgid == 121 && SYS_getsid == 124,
    "x86 selected process-context syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpid),
    pid_t (*)(void)), "getpid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getppid),
    pid_t (*)(void)), "getppid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getuid),
    uid_t (*)(void)), "getuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getgid),
    gid_t (*)(void)), "getgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&geteuid),
    uid_t (*)(void)), "geteuid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getegid),
    gid_t (*)(void)), "getegid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&umask),
    mode_t (*)(mode_t)), "umask declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setsid),
    pid_t (*)(void)), "setsid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpgid),
    int (*)(pid_t, pid_t)), "setpgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpgid),
    pid_t (*)(pid_t)), "getpgid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getsid),
    pid_t (*)(pid_t)), "getsid declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpgrp),
    pid_t (*)(void)), "getpgrp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpgrp),
    int (*)(void)), "setpgrp declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

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

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile("pause" ::: "memory");
}

static int check_identity_scalars(void)
{
    if ((long)getpid() != raw_syscall0(SYS_getpid))
        return 1;
    if ((long)getppid() != raw_syscall0(SYS_getppid))
        return 2;
    if ((unsigned long)getuid() != (unsigned long)raw_syscall0(SYS_getuid))
        return 3;
    if ((unsigned long)getgid() != (unsigned long)raw_syscall0(SYS_getgid))
        return 4;
    if ((unsigned long)geteuid() != (unsigned long)raw_syscall0(SYS_geteuid))
        return 5;
    if ((unsigned long)getegid() != (unsigned long)raw_syscall0(SYS_getegid))
        return 6;
    return 0;
}

static int check_current_group_and_session(void)
{
    long raw_group = raw_syscall1(SYS_getpgid, 0);
    long raw_session = raw_syscall1(SYS_getsid, 0);

    if (raw_group <= 0 || raw_session <= 0)
        return 1;
    if ((long)getpgrp() != raw_group)
        return 2;
    if ((long)getpgid(0) != raw_group)
        return 3;
    if ((long)getsid(0) != raw_session)
        return 4;
    return 0;
}

static int check_failure_translation(void)
{
    long raw_result;

    raw_result = raw_syscall1(SYS_getpgid, -1);
    if (raw_result >= 0)
        return 1;
    errno = 0;
    if (getpgid(-1) != -1 || errno != (int)-raw_result)
        return 2;

    raw_result = raw_syscall1(SYS_getsid, -1);
    if (raw_result >= 0)
        return 3;
    errno = 0;
    if (getsid(-1) != -1 || errno != (int)-raw_result)
        return 4;

    raw_result = raw_syscall1(SYS_setpgid, -1);
    if (raw_result >= 0)
        return 5;
    errno = 0;
    if (setpgid(-1, 0) != -1 || errno != (int)-raw_result)
        return 6;
    return 0;
}

static int check_umask_exchange(void)
{
    mode_t original = umask(0027);
    mode_t observed = umask(original);

    return observed == 0027 ? 0 : 1;
}

static int child_setpgrp_case(void)
{
    pid_t self = getpid();

    if (setpgrp() != 0)
        return 1;
    if (getpgrp() != self || getpgid(0) != self)
        return 2;
    errno = 0;
    if (setsid() != -1 || errno != EPERM)
        return 3;
    return 0;
}

static int child_setpgid_case(void)
{
    pid_t self = getpid();

    if (setpgid(0, 0) != 0)
        return 1;
    if (getpgrp() != self || getpgid(0) != self)
        return 2;
    return 0;
}

static int child_setsid_case(void)
{
    pid_t self = getpid();

    if (setsid() != self)
        return 1;
    if (getsid(0) != self || getpgrp() != self || getpgid(0) != self)
        return 2;
    return 0;
}

static int run_child_case(int (*child_case)(void))
{
    long child = raw_syscall0(SYS_fork);
    int status = -1;
    long waited;

    if (child == 0)
        raw_exit(child_case());
    if (child < 0)
        return 1;

    do {
        waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    } while (waited == -EINTR);
    if (waited != child)
        return 2;
    return status == 0 ? 0 : 3;
}

int crabc_x86_64_process_context_probe(void)
{
    int status;

    status = check_identity_scalars();
    if (status != 0)
        return 10 + status;
    status = check_current_group_and_session();
    if (status != 0)
        return 20 + status;
    status = check_failure_translation();
    if (status != 0)
        return 30 + status;
    status = check_umask_exchange();
    if (status != 0)
        return 40 + status;
    status = run_child_case(child_setpgrp_case);
    if (status != 0)
        return 50 + status;
    status = run_child_case(child_setpgid_case);
    if (status != 0)
        return 60 + status;
    status = run_child_case(child_setsid_case);
    if (status != 0)
        return 70 + status;
    return 0;
}

#ifndef CRABC_PROCESS_CONTEXT_FREESTANDING
int main(void)
{
    return crabc_x86_64_process_context_probe();
}
#endif
