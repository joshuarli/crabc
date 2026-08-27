/* Pinned-musl Linux/x86-64 setpriority behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(PRIO_PROCESS == 0, "x86 PRIO_PROCESS value");
_Static_assert(PRIO_PGRP == 1, "x86 PRIO_PGRP value");
_Static_assert(PRIO_USER == 2, "x86 PRIO_USER value");
_Static_assert(SYS_getpriority == 140, "x86 getpriority syscall number");
_Static_assert(SYS_setpriority == 141, "x86 setpriority syscall number");

static int raw_setpriority(int which, id_t who, int priority)
{
    return syscall(SYS_setpriority, which, who, priority) == 0;
}

static int raw_priority_is(int expected)
{
    errno = 0;
    const long encoded = syscall(SYS_getpriority, PRIO_PROCESS, 0);

    return encoded == 20 - expected && errno == 0;
}

static int mutation_case(void)
{
    errno = 0;
    if (!raw_setpriority(PRIO_PROCESS, 0, 19))
        return 10;

    errno = 0;
    if (getpriority(PRIO_PROCESS, 0) != 19 || errno != 0)
        return 11;

    /* Musl's wrapper can make an equivalent no-op write after the raw set. */
    if (setpriority(PRIO_PROCESS, 0, 19) != 0)
        return 12;
    if (!raw_priority_is(19))
        return 13;

    errno = 0;
    if (raw_setpriority(99, 0, 0) || errno != EINVAL)
        return 14;
    errno = 0;
    if (raw_setpriority(PRIO_PROCESS, INT_MAX, 19) || errno != ESRCH)
        return 15;
    errno = 0;
    if (setpriority(PRIO_PROCESS, INT_MAX, 19) != -1 || errno != ESRCH)
        return 16;
    errno = 0;
    if (raw_setpriority(PRIO_PGRP, INT_MAX, 19) || errno != ESRCH)
        return 17;
    errno = 0;
    if (setpriority(PRIO_PGRP, INT_MAX, 19) != -1 || errno != ESRCH)
        return 18;
    errno = 0;
    if (raw_setpriority(PRIO_USER, UINT_MAX, 19) || errno != ESRCH)
        return 19;
    errno = 0;
    if (setpriority(PRIO_USER, UINT_MAX, 19) != -1 || errno != ESRCH)
        return 20;
    return 0;
}

static int run_in_child(void)
{
    const pid_t child = fork();
    int status;

    if (child < 0)
        return 20;
    if (child == 0)
        _exit(mutation_case());
    if (waitpid(child, &status, 0) != child)
        return 21;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 22;
    return 0;
}

int main(void)
{
    if (run_in_child() != 0)
        return 1;

    puts("selectors=0,1,2 syscalls=get140,set141 lifecycle=raw-set:musl-read:musl-noop:raw-read invalid=EINVAL missing=process,pgrp,user:ESRCH child-contained");
    return 0;
}
