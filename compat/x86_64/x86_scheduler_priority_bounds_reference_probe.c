/* Pinned-musl Linux/x86-64 scheduler-priority bounds reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>

_Static_assert(SCHED_OTHER == 0, "x86 SCHED_OTHER value");
_Static_assert(SCHED_FIFO == 1, "x86 SCHED_FIFO value");
_Static_assert(SCHED_RR == 2, "x86 SCHED_RR value");
_Static_assert(SYS_sched_get_priority_max == 146, "x86 sched_get_priority_max syscall");
_Static_assert(SYS_sched_get_priority_min == 147, "x86 sched_get_priority_min syscall");

static int check_bounds(int policy, int expected_minimum, int expected_maximum) {
    errno = 0;
    int minimum = sched_get_priority_min(policy);
    if (minimum != expected_minimum || errno != 0) {
        return 1;
    }

    errno = 0;
    int maximum = sched_get_priority_max(policy);
    if (maximum != expected_maximum || errno != 0) {
        return 2;
    }
    return 0;
}

static int check_invalid_policy(void) {
    errno = 0;
    if (sched_get_priority_min(-1) != -1 || errno != EINVAL) {
        return 1;
    }

    errno = 0;
    if (sched_get_priority_max(-1) != -1 || errno != EINVAL) {
        return 2;
    }
    return 0;
}

int main(void) {
    if (check_bounds(SCHED_OTHER, 0, 0) != 0 ||
        check_bounds(SCHED_FIFO, 1, 99) != 0 ||
        check_bounds(SCHED_RR, 1, 99) != 0 ||
        check_invalid_policy() != 0) {
        return 1;
    }

    puts("other=0:0 fifo=1:99 rr=1:99 invalid=EINVAL");
    return 0;
}
