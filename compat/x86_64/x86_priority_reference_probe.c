/* Pinned-musl Linux/x86-64 getpriority behavior reference. */

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
#include <unistd.h>

_Static_assert(PRIO_PROCESS == 0, "x86 PRIO_PROCESS value");
_Static_assert(PRIO_PGRP == 1, "x86 PRIO_PGRP value");
_Static_assert(PRIO_USER == 2, "x86 PRIO_USER value");
_Static_assert(SYS_getpriority == 140, "x86 getpriority syscall number");

static int read_priority(int which, id_t who, int *value) {
    errno = 0;
    int result = getpriority(which, who);
    if (result < -20 || result > 19) {
        return 1;
    }
    if (result == -1 && errno != 0) {
        return 2;
    }
    *value = result;
    return 0;
}

int main(void) {
    pid_t pid = getpid();
    pid_t pgid = getpgrp();
    uid_t effective_uid = geteuid();
    int process;
    int process_shorthand;
    int process_group;
    int process_group_shorthand;
    int user;
    int user_shorthand;

    if (pid <= 0 || pgid <= 0 || read_priority(PRIO_PROCESS, (id_t)pid, &process) != 0 ||
        read_priority(PRIO_PROCESS, 0, &process_shorthand) != 0 ||
        read_priority(PRIO_PGRP, (id_t)pgid, &process_group) != 0 ||
        read_priority(PRIO_PGRP, 0, &process_group_shorthand) != 0 ||
        read_priority(PRIO_USER, (id_t)effective_uid, &user) != 0 ||
        read_priority(PRIO_USER, 0, &user_shorthand) != 0) {
        return 1;
    }
    if (process != process_shorthand || process_group != process_group_shorthand ||
        user != user_shorthand || process_group > process || user > process) {
        return 2;
    }

    errno = 0;
    long encoded = syscall(SYS_getpriority, PRIO_PROCESS, (id_t)pid);
    if (encoded < 1 || encoded > 40 || (int)(20 - encoded) != process || errno != 0) {
        return 3;
    }

    errno = 0;
    if (getpriority(PRIO_PROCESS, (id_t)INT_MAX) != -1 || errno != ESRCH) {
        return 4;
    }

    puts("process=valid process-group=valid user=valid encoding=preserved missing=ESRCH");
    return 0;
}
