/* Pinned-musl Linux/x86-64 thread observation/yield behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_gettid == 186, "x86 gettid syscall");
_Static_assert(SYS_getcpu == 309, "x86 getcpu syscall");
_Static_assert(SYS_sched_yield == 24, "x86 sched_yield syscall");

int main(void) {
    pid_t first = gettid();
    pid_t second = gettid();
    int first_cpu = sched_getcpu();
    int second_cpu = sched_getcpu();

    if (first <= 0 || second != first || first_cpu < 0 ||
        second_cpu < 0 || first_cpu >= CPU_SETSIZE ||
        second_cpu >= CPU_SETSIZE) {
        return 1;
    }
    if (sched_yield() != 0) {
        return 2;
    }

    puts("gettid=positive-stable cpu=bounded sched_yield=0");
    return 0;
}
